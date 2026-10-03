using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Policy;
using SubactId.Core.Revocation;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Core.Tokens;
using SubactId.Core.Validation;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Revocation;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Tokens;

/// <summary>
/// The token-exchange grant of spec section 3, with checks in the spec's order: request shape,
/// agent authentication, subject token, sponsor status, policy. Then the task, grant, token and
/// audit record are created in one transaction. Every denial writes <c>token.denied</c> before
/// it is answered.
/// </summary>
public sealed class TokenExchangeService(
    ClientAssertionAuthenticator actors,
    UpstreamTokenValidator subjects,
    SponsorGate sponsors,
    ISponsorRepository blocks,
    IRevocationFence fence,
    IRevocationRepository revocations,
    ITaskRepository tasks,
    ITaskGrantRepository grants,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    TokenAudit denials,
    SigningKeySet keys,
    SubactIdOptions options,
    TimeProvider clock,
    SignOutRetentionCheck? retention = null)
{
    /// <summary>Audit reason when the subject token names an agent rather than a human.</summary>
    public const string SubjectIsAgent = "subject_is_agent";

    /// <summary>
    /// Audit reason when the subject token's sponsor key claim is absent, not a string, empty, too
    /// long, or contains whitespace or a control character.
    /// </summary>
    public const string SponsorKeyMissing = "sponsor_key_missing";

    /// <summary>The identity provider's session claim. A back-channel logout for it ends the tasks it started.</summary>
    public const string SessionClaim = "sid";

    /// <summary>Audit reason when the subject token's <c>sid</c> carries a control character, which could not be stored.</summary>
    public const string SessionIdMalformed = "session_id_malformed";

    /// <summary>
    /// Audit reason when the subject token was signed out before it was presented: its session was
    /// logged out, or the person was logged out or had their sessions revoked after it was issued.
    /// </summary>
    public const string SubjectLoggedOut = "subject_logged_out";

    /// <summary>Runs the exchange for <paramref name="request"/>.</summary>
    /// <param name="request">The parsed form.</param>
    /// <param name="formErrors">Problems found while reading the form, reported with the request's own.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<TokenOutcome> ExchangeAsync(ExchangeTokenRequest request, IReadOnlyList<ValidationError> formErrors, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(formErrors);

        var errors = formErrors.Concat(request.Validate()).ToList();
        if (errors.Count > 0)
        {
            var fields = string.Join(", ", errors.Select(e => $"{e.Field} {e.Message}"));
            return await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, $"The request is invalid: {fields}", OAuthErrorResponse.InvalidRequest);
        }

        // 1. Who is asking.
        var actor = await actors.AuthenticateAsync(request.ActorToken, request.ClientId, cancellationToken);
        if (actor.Agent is not { } agent)
        {
            return await denials.DenyActorAsync(actor);
        }

        // 2. On whose behalf.
        var subject = await subjects.ValidateAsync(request.SubjectToken, cancellationToken);
        if (subject.Principal is not { } principal)
        {
            return subject.Reason == UpstreamRejection.KeysUnavailable
                ? await denials.DenyAsync(OAuthErrorResponse.TemporarilyUnavailable, "The identity provider's keys could not be fetched; retry later.", AuditReason.Of("subject", subject.Reason), agent.AgentId)
                : await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The subject token is expired, invalid or from an untrusted issuer.", AuditReason.Of("subject", subject.Reason), agent.AgentId);
        }

        // A token that outlives the time a sign-out is kept could outlive the sign-out too. Reported
        // once, so the operator raises the retention; not refused (see SignOutRetentionCheck).
        retention?.Observe(principal.IssuedAt, principal.ExpiresAt, clock.GetUtcNow());

        if (ActorClaim.IsAgentSubject(principal.Subject))
        {
            return await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The subject token must identify a human.", SubjectIsAgent, agent.AgentId);
        }

        // 3. Whether this human may still be acted for. Checked before policy so a blocked person
        // is recorded as blocked.
        var now = clock.GetUtcNow();
        var requestedScope = string.Join(' ', request.Scopes);

        // The key later signals will name this person by. Without a well-formed one, no block
        // could reach the task, so the request is refused. Same rule as the admin API.
        var sponsorKey = principal.FindStringClaim(options.UpstreamIdp.SponsorKeyClaim);
        if (!SponsorKey.IsWellFormed(sponsorKey))
        {
            return await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The subject token does not carry a usable value for the claim this control plane identifies users by.", SponsorKeyMissing, agent.AgentId, principal.Subject, request.Resource, requestedScope);
        }

        // The provider's session, if any, is stored with the task so a logout for it can end it.
        // One with a control character is refused rather than handed to storage, which rejects a
        // NUL in text.
        var sessionId = principal.FindStringClaim(SessionClaim);
        if (sessionId?.Any(char.IsControl) ?? false)
        {
            return await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The subject token's session identifier is not usable.", SessionIdMalformed, agent.AgentId, principal.Subject, request.Resource, requestedScope);
        }

        // Checked as of now, bypassing and not filling the cache, so the first renewal reads a
        // fresh status.
        if (SponsorGate.Refusal(await sponsors.GetAsync(sponsorKey, principal.Subject, SponsorGate.AsOfNow, cancellationToken)) is { } refusal)
        {
            return await denials.DenyAsync(refusal.Error, refusal.Description, refusal.Reason, agent.AgentId, principal.Subject, request.Resource, requestedScope);
        }

        // 4. What they may have.
        var decision = PolicyEngine.Evaluate(principal.Scopes, agent, request.Scopes, request.Resource, depth: 1);
        if (!decision.IsAllowed)
        {
            return await denials.DenyPolicyAsync(decision, agent.AgentId, principal.Subject, request.Resource, requestedScope);
        }

        // 5. Issue. The task, the grant, the token and the audit record commit together or not at all.
        var issuing = options.Agents.Bound(agent);
        var scope = string.Join(' ', decision.EffectiveScopes);
        var task = new DelegationTask(
            OpaqueId.New(OpaqueId.TaskPrefix, now),
            agent.AgentId,
            principal.Subject,
            sponsorKey,
            // The provider's session, if any. A task without one cannot be ended by session logout.
            sessionId,
            ParentTaskId: null,
            DelegationDepth: 1,
            request.Resource!,
            decision.EffectiveScopes,
            DelegationTaskStatus.Active,
            now,
            // The agent's own max_task_ttl, held to the server-wide bound as it is now: a bound
            // lowered since registration applies at once (see Bound).
            now + issuing.MaxTaskTtl,
            RevokedAt: null,
            RevocationReason: null);
        var claims = TaskTokenClaims.Issue(options.Issuer, task, issuing, decision.EffectiveScopes, actor.Instance, delegatedFrom: null, issuing.MaxTokenTtl, now, OpaqueId.New(OpaqueId.TokenPrefix, now));
        var grantValue = TaskGrantSecret.New();
        var grant = new TaskGrant(TaskGrantSecret.Hash(grantValue), task.TaskId, agent.AgentId, decision.EffectiveScopes, now, task.ExpiresAt, RevokedAt: null, LastUsedAt: null);
        var token = TaskTokenSerializer.Sign(keys, claims);

        var signIn = new SignIn(principal.Subject, sponsorKey, sessionId, principal.IssuedAt);
        var (blockedSince, signedOut) = await unitOfWork.RunAsync(
            async ct =>
            {
                // A block, kill switch or logout for this person, session or agent that is under way
                // finishes first; one that starts later waits for this task and then ends it.
                // The sponsor check above ran before this, so a block that committed in between
                // is read again here, from storage only, and refuses the task. So is a logout: a
                // subject token whose session, or whose person, was signed out after it was issued
                // cannot start a task, even though it has not expired.
                await fence.EnterIssueAsync(sponsorKey, principal.Subject, sessionId, agent.AgentId, ct);
                if (await blocks.FindAsync(sponsorKey, ct) is { } block)
                {
                    return (block, false);
                }

                if (await revocations.IsSignedOutAsync(signIn, ct))
                {
                    return ((SponsorBlock?)null, true);
                }

                await tasks.AddAsync(task, ct);
                await grants.AddAsync(grant, ct);
                // This one record covers both the task's creation and the token's issue.
                await audit.AppendAsync(
                    new AuditEvent(now, AuditEvents.TokenIssued, task.TaskId, agent.AgentId, principal.Subject, task.Audience, scope, claims.Jti, DelegationDepth: 1, Decision: AuditDecision.Allow),
                    ct);
                return (null, false);
            },
            cancellationToken);

        if (blockedSince is not null)
        {
            var refused = SponsorGate.Refusal(SponsorGate.StatusOf(blockedSince))!.Value;
            return await denials.DenyAsync(refused.Error, refused.Description, refused.Reason, agent.AgentId, principal.Subject, request.Resource, requestedScope);
        }

        // The person is not refused, this sign-in is: invalid_grant, as for any subject token that
        // is no longer good. A new sign-in starts a task.
        if (signedOut)
        {
            return await denials.DenyAsync(OAuthErrorResponse.InvalidGrant, "The subject token's session has ended; sign in again.", SubjectLoggedOut, agent.AgentId, principal.Subject, request.Resource, requestedScope);
        }

        var expiresIn = claims.ExpiresAt.ToUnixTimeSeconds() - now.ToUnixTimeSeconds();
        return new TokenOutcome(new TokenResponse(token, ExchangeTokenRequest.AccessTokenType, TokenResponse.Bearer, expiresIn, scope, grantValue, task.TaskId, task.ExpiresAt), null);
    }
}
