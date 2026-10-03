using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Policy;
using SubactId.Core.Storage;
using SubactId.Core.Tokens;
using SubactId.Core.Validation;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Grants;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Tokens;

/// <summary>
/// The refresh grant of spec section 5. Agent authentication comes first, then the spec's checks
/// in its order: grant, task not revoked or expired, task not ending, sponsor. One check the spec
/// does not number sits between its steps 5 and 6: the resource must be the task's audience. Then
/// the scope must be within the grant as its last refresh left it, and the policy engine runs
/// again against the agent's current registration. A new token with a new <c>jti</c> is issued
/// under the same task, carrying the scope the policy allows. The grant keeps the scope the
/// refresh asked for from then on, so a change to the registration narrows a token but never the
/// grant. The grant's use is counted in the same transaction as any <c>token.refreshed</c> record
/// (see <see cref="RenewalSummary"/>). Every denial writes <c>token.denied</c>.
/// </summary>
public sealed class TokenRefreshService(
    ClientAssertionAuthenticator actors,
    TaskGrantRedeemer redeemer,
    SponsorGate sponsors,
    ITaskGrantRepository grants,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    TokenAudit denials,
    RenewalSummary summaries,
    SigningKeySet keys,
    SubactIdOptions options,
    TimeProvider clock)
{
    /// <summary>Audit reason when the requested scope is not within the granted scope.</summary>
    public const string ScopeWidened = "scope_widened";

    /// <summary>Audit reason when the resource is not the task's audience.</summary>
    public const string AudienceMismatch = "audience_mismatch";

    /// <summary>Audit reason when the grant was revoked between being read and being used.</summary>
    public const string GrantRevokedDuringRefresh = "grant_revoked_during_refresh";

    /// <summary>Audit reason when the task's actor chain cannot be rebuilt. Only depth 1 tasks exist in v0.1.</summary>
    public const string DelegationChainUnavailable = "delegation_chain_unavailable";

    /// <summary>Audit reason when the task has less than the minimum token lifetime left.</summary>
    public const string TaskEnding = "task_ending";

    /// <summary>Runs the refresh for <paramref name="request"/>.</summary>
    /// <param name="request">The parsed form.</param>
    /// <param name="formErrors">Problems found while reading the form, reported with the request's own.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<TokenOutcome> RefreshAsync(RefreshTokenRequest request, IReadOnlyList<ValidationError> formErrors, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(formErrors);

        var errors = formErrors.Concat(request.Validate()).ToList();
        if (errors.Count > 0)
        {
            var fields = string.Join(", ", errors.Select(e => $"{e.Field} {e.Message}"));
            return await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, $"The request is invalid: {fields}", OAuthErrorResponse.InvalidRequest);
        }

        // 1. Who is asking, with the same rules as the exchange.
        var actor = await actors.AuthenticateAsync(request.ClientAssertion, request.ClientId, cancellationToken);
        if (actor.Agent is not { } agent)
        {
            return await denials.DenyActorAsync(actor);
        }

        // 2. The grant, for this agent only, and the task under it.
        var now = clock.GetUtcNow();
        var requestedScope = string.Join(' ', request.Scopes);
        var redemption = await redeemer.RedeemAsync(agent, request.RefreshToken, now, cancellationToken);
        if (!redemption.IsAccepted)
        {
            // Attributed to the task and its sponsor whenever the grant was found.
            var sponsor = redemption.Task?.Sponsor;
            var audience = redemption.Task?.Audience;
            return redemption.Reason switch
            {
                TaskGrantRejection.TaskRevoked => await denials.DenyAsync(OAuthErrorResponse.AccessDenied, "The task has been revoked.", "task_revoked", agent.AgentId, sponsor, audience, requestedScope, redemption.TaskId),
                TaskGrantRejection.TaskExpired => await denials.DenyAsync(OAuthErrorResponse.AccessDenied, "The task has expired.", "task_expired", agent.AgentId, sponsor, audience, requestedScope, redemption.TaskId),
                _ => await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The refresh token is unknown, revoked or expired.", AuditReason.Of("grant", redemption.Reason), agent.AgentId, sponsor, audience, requestedScope, redemption.TaskId),
            };
        }

        var grant = redemption.Grant!;
        var task = redemption.Task!;

        // Refuse when the task has less than the minimum token lifetime left, so no token is
        // issued that is about to expire.
        if (task.ExpiresAt - now < TaskTokenClaims.MinimumLifetime)
        {
            return await denials.DenyAsync(OAuthErrorResponse.AccessDenied, "The task has too little left to issue a token for.", TaskEnding, agent.AgentId, task.Sponsor, task.Audience, requestedScope, task.TaskId);
        }

        // 3. Whether this human may still be acted for. An unknown status is a refusal. A cached
        // upstream answer may be no older than the token's lifetime, nor older than the task: an
        // answer another task of the same person cached before this one existed could predate a
        // disable that happened since the exchange.
        var tokenLifetime = Min(options.Agents.Bound(agent).MaxTokenTtl, task.ExpiresAt - now);
        var maxAge = Min(tokenLifetime, now - task.CreatedAt);
        if (SponsorGate.Refusal(await sponsors.GetAsync(task.SponsorKey, task.Sponsor, maxAge, cancellationToken)) is { } refusal)
        {
            return await denials.DenyAsync(refusal.Error, refusal.Description, refusal.Reason, agent.AgentId, task.Sponsor, task.Audience, requestedScope, task.TaskId);
        }

        // 4. What is asked for, against what was granted and against the agent's registration as it is now.
        if (!string.Equals(request.Resource, task.Audience, StringComparison.Ordinal))
        {
            return await denials.DenyAsync(OAuthErrorResponse.InvalidTarget, "The resource is not the task's audience.", AudienceMismatch, agent.AgentId, task.Sponsor, request.Resource, requestedScope, task.TaskId);
        }

        // The grant's scope is the scope of its last successful refresh, so a narrowing sticks. The
        // use is recorded only while the grant still holds the scope this decision was made against.
        // If a concurrent refresh narrowed it first, the decision is made again against the narrower
        // scope. The stored scope only ever shrinks, so this ends.
        var held = grant.Scopes;
        while (true)
        {
            if (request.Scopes.Any(s => !held.Contains(s, StringComparer.Ordinal)))
            {
                return await denials.DenyAsync(OAuthErrorResponse.InvalidScope, "The requested scope is wider than the grant.", ScopeWidened, agent.AgentId, task.Sponsor, task.Audience, requestedScope, task.TaskId);
            }

            var decision = PolicyEngine.Evaluate(held, agent, request.Scopes, task.Audience, task.DelegationDepth);
            if (!decision.IsAllowed)
            {
                return await denials.DenyPolicyAsync(decision, agent.AgentId, task.Sponsor, task.Audience, requestedScope, task.TaskId);
            }

            if (task.DelegationDepth != 1)
            {
                return await denials.DenyAsync(OAuthErrorResponse.AccessDenied, "The task's delegation chain cannot be rebuilt.", DelegationChainUnavailable, agent.AgentId, task.Sponsor, task.Audience, requestedScope, task.TaskId);
            }

            // 5. Issue under the same task, recording the use and the narrowed scope in the same
            // transaction as the record. The grant narrows to what was asked for, not to what the
            // registration allows today, so a registration change narrows this token only. The
            // grant keeps its own order, so only a narrowing changes it. What was asked for is
            // within what is held, so the stored scope only ever shrinks.
            var scope = string.Join(' ', decision.EffectiveScopes);
            var narrowed = held.Where(s => request.Scopes.Contains(s, StringComparer.Ordinal)).ToList();
            var issuing = options.Agents.Bound(agent);
            var claims = TaskTokenClaims.Issue(options.Issuer, task, issuing, decision.EffectiveScopes, actor.Instance, delegatedFrom: null, issuing.MaxTokenTtl, now, OpaqueId.New(OpaqueId.TokenPrefix, now));
            var token = TaskTokenSerializer.Sign(keys, claims);

            var used = await unitOfWork.RunAsync(
                async ct =>
                {
                    if (await grants.MarkUsedAsync(agent.AgentId, grant.GrantHash, held, narrowed, now, ct) is not { } renewals)
                    {
                        return false;
                    }

                    // The first renewal gets its own record. The rest are counted on the grant and
                    // summarised when the task ends.
                    if (summaries.WritesThrough(renewals))
                    {
                        await audit.AppendAsync(new AuditEvent(now, AuditEvents.TokenRefreshed, task.TaskId, agent.AgentId, task.Sponsor, task.Audience, scope, claims.Jti, task.DelegationDepth, AuditDecision.Allow), ct);
                    }

                    return true;
                },
                cancellationToken);
            if (used)
            {
                var expiresIn = claims.ExpiresAt.ToUnixTimeSeconds() - now.ToUnixTimeSeconds();
                return new TokenOutcome(new TokenResponse(token, ExchangeTokenRequest.AccessTokenType, TokenResponse.Bearer, expiresIn, scope, request.RefreshToken!, task.TaskId, task.ExpiresAt), null);
            }

            // Revoked, or narrowed by a concurrent refresh. Only a strictly narrower scope is decided
            // again; anything else is refused.
            var current = await grants.FindAsync(agent.AgentId, grant.GrantHash, cancellationToken);
            if (current is not { RevokedAt: null } || current.Scopes.Count >= held.Count || current.Scopes.Any(s => !held.Contains(s, StringComparer.Ordinal)))
            {
                return await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The refresh token has been revoked.", GrantRevokedDuringRefresh, agent.AgentId, task.Sponsor, task.Audience, requestedScope, task.TaskId);
            }

            held = current.Scopes;
        }
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;
}
