using SubactId.Core.Audit;
using SubactId.Core.Policy;
using SubactId.Server.Audit;
using SubactId.Server.Contracts;
using SubactId.Tokens.ClientAuth;

namespace SubactId.Server.Tokens;

/// <summary>Outcome of a token request: exactly one of a response or an error.</summary>
/// <param name="Response">The issued token, on success.</param>
/// <param name="Error">The OAuth error, on denial.</param>
public sealed record TokenOutcome(TokenResponse? Response, OAuthErrorResponse? Error);

/// <summary>
/// Denies token requests: writes a <c>token.denied</c> record, then returns the error. The record
/// names the agent whenever it is known. The write is not cancellable by the caller.
/// </summary>
public sealed class TokenAudit(IAuditWriter audit, TimeProvider clock, DenialAggregator aggregator)
{
    /// <summary>
    /// Writes the denial and returns the error. An <c>access_denied</c> for an agent that has
    /// authenticated also tells it <paramref name="reason"/> (spec section 8). Every other error,
    /// and every answer to a caller that has not proved an agent's key, carries only the code and
    /// the description.
    /// </summary>
    /// <param name="error">The OAuth error code.</param>
    /// <param name="description">The human-readable description; must not include a token.</param>
    /// <param name="reason">The machine-readable audit reason.</param>
    /// <param name="agentId">The agent, once it has proved its key. Never set before then.</param>
    /// <param name="sponsor">The human, once known.</param>
    /// <param name="audience">The requested audience, once checked.</param>
    /// <param name="scope">The requested scope, once checked.</param>
    /// <param name="taskId">The task, once known.</param>
    public async Task<TokenOutcome> DenyAsync(string error, string description, string reason, string? agentId = null, string? sponsor = null, string? audience = null, string? scope = null, string? taskId = null)
    {
        var record = new AuditEvent(clock.GetUtcNow(), AuditEvents.TokenDenied, taskId, agentId, sponsor, audience, scope, Decision: AuditDecision.Deny, Reason: reason);
        await aggregator.RecordAsync(record, audit);

        var tellsReason = agentId is not null && string.Equals(error, OAuthErrorResponse.AccessDenied, StringComparison.Ordinal);
        return new TokenOutcome(null, new OAuthErrorResponse(error, description, tellsReason ? reason : null));
    }

    /// <summary>
    /// Denies a request whose client assertion was rejected. A disabled agent gets <c>access_denied</c>
    /// (spec section 8), reported only for an assertion that verified, so agents cannot be enumerated.
    /// An unreachable JWKS gets <c>temporarily_unavailable</c>.
    /// </summary>
    /// <remarks>
    /// The record names the agent if the assertion's signature verified, and nobody otherwise.
    /// Denials are always audited.
    /// </remarks>
    /// <param name="actor">The failed authentication.</param>
    public Task<TokenOutcome> DenyActorAsync(ClientAuthentication actor)
    {
        ArgumentNullException.ThrowIfNull(actor);

        var (error, description, reason) = actor.Reason switch
        {
            ClientAssertionRejection.AgentDisabled => (OAuthErrorResponse.AccessDenied, "The agent is disabled.", PolicyDenialReason.AgentDisabled.ToAuditReason()),
            ClientAssertionRejection.KeysUnavailable => (OAuthErrorResponse.TemporarilyUnavailable, "The agent's keys could not be fetched; retry later.", AuditReason.Of("actor", actor.Reason)),
            _ => (OAuthErrorResponse.InvalidClient, "Client authentication failed.", AuditReason.Of("actor", actor.Reason)),
        };

        return DenyAsync(error, description, reason, actor.AttributedAgentId);
    }

    /// <summary>Denies a request the policy engine refused, with the spec's error code and the engine's reason.</summary>
    /// <param name="decision">The denying decision.</param>
    /// <param name="agentId">The agent.</param>
    /// <param name="sponsor">The human.</param>
    /// <param name="audience">The requested audience.</param>
    /// <param name="scope">The requested scope.</param>
    /// <param name="taskId">The task, on refresh.</param>
    public Task<TokenOutcome> DenyPolicyAsync(PolicyDecision decision, string agentId, string sponsor, string? audience, string scope, string? taskId = null)
    {
        ArgumentNullException.ThrowIfNull(decision);

        var description = decision.Reason switch
        {
            PolicyDenialReason.EmptyScopeIntersection => "No requested scope is both held by the user and allowed for the agent.",
            PolicyDenialReason.AudienceMissing or PolicyDenialReason.AudienceNotAllowed => "The resource is not an allowed audience for the agent.",
            PolicyDenialReason.AgentDisabled => "The agent is disabled.",
            _ => "The delegation depth is not allowed.",
        };
        return DenyAsync(decision.Reason.ToErrorCode(), description, decision.Reason.ToAuditReason(), agentId, sponsor, audience, scope, taskId);
    }
}
