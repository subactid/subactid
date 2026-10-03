namespace SubactId.Core.Audit;

/// <summary>Outcome of an authorization decision as recorded in the ledger.</summary>
public enum AuditDecision
{
    /// <summary>The action was allowed.</summary>
    Allow,

    /// <summary>The action was denied. Denials must never be dropped.</summary>
    Deny,
}

/// <summary>
/// One record of the append-only audit ledger (spec section 7), before it is chained.
/// The sequence number and hashes are assigned by the writer.
/// </summary>
/// <param name="Ts">When the event happened.</param>
/// <param name="Event">Event name; see <see cref="AuditEvents"/>.</param>
/// <param name="TaskId">Task involved, if any.</param>
/// <param name="AgentId">Agent involved, if any.</param>
/// <param name="Sponsor">The human on whose behalf the action was taken, if any.</param>
/// <param name="Audience">Audience requested or issued, if any.</param>
/// <param name="Scope">Space-separated scope string, if any.</param>
/// <param name="Jti">Token identifier, if a token was involved.</param>
/// <param name="DelegationDepth">Delegation depth of the token, if any.</param>
/// <param name="Decision">The decision, for authorization events.</param>
/// <param name="Reason">Machine-readable reason; always present for a denial.</param>
/// <param name="Count">
/// How many events a summary record stands for. <c>null</c> on a single-event record, which
/// readers treat as one.
/// </param>
/// <param name="Detail">
/// Extra detail no other field can hold, otherwise <c>null</c>. Used by
/// <see cref="AuditEvents.AuditArchived"/> for the partition, checkpoint range, export and digest.
/// Omitted from the canonical JSON when null (see <see cref="AuditHash"/>).
/// </param>
public sealed record AuditEvent(
    DateTimeOffset Ts,
    string Event,
    string? TaskId = null,
    string? AgentId = null,
    string? Sponsor = null,
    string? Audience = null,
    string? Scope = null,
    string? Jti = null,
    int? DelegationDepth = null,
    AuditDecision? Decision = null,
    string? Reason = null,
    int? Count = null,
    string? Detail = null);

/// <summary>Event names. The spec lists all but the two admin ones, which are proposed additions.</summary>
public static class AuditEvents
{
    /// <summary>
    /// A task token was issued. The first one for a <c>task_id</c> also records the task's
    /// creation, with its scope, audience and delegation depth.
    /// </summary>
    public const string TokenIssued = "token.issued";

    /// <summary>A token request was denied.</summary>
    public const string TokenDenied = "token.denied";

    /// <summary>A task token was refreshed.</summary>
    public const string TokenRefreshed = "token.refreshed";

    /// <summary>A task was revoked.</summary>
    public const string TaskRevoked = "task.revoked";

    /// <summary>An agent was registered.</summary>
    public const string AgentRegistered = "agent.registered";

    /// <summary>An agent's registration was changed.</summary>
    public const string AgentUpdated = "agent.updated";

    /// <summary>A tool server reported a call (only when the SDK reports it back).</summary>
    public const string ToolCalled = "tool.called";

    /// <summary>An agent's registration was removed. Not in the spec's list; proposed addition.</summary>
    public const string AgentDeleted = "agent.deleted";

    /// <summary>An admin API call failed authentication. Not in the spec's list; proposed addition.</summary>
    public const string AdminDenied = "admin.denied";

    /// <summary>A task passed its expiry and was marked terminal by the sweeper.</summary>
    public const string TaskExpired = "task.expired";

    /// <summary>A single token was revoked by <c>jti</c> through <c>POST /oauth2/revoke</c>.</summary>
    public const string TokenRevoked = "token.revoked";

    /// <summary>A human was blocked. No agent may act for them until the block is lifted.</summary>
    public const string SponsorBlocked = "sponsor.blocked";

    /// <summary>A block on a human was lifted.</summary>
    public const string SponsorUnblocked = "sponsor.unblocked";

    /// <summary>An external signal about a human was accepted, such as a back-channel logout.</summary>
    public const string SponsorSignal = "sponsor.signal";

    /// <summary>A signal about a human was refused because it did not validate.</summary>
    public const string SignalDenied = "signal.denied";

    /// <summary>A request to the SCIM receiver was refused because it carried no usable credential.</summary>
    public const string ScimDenied = "scim.denied";

    /// <summary>A push to the Shared Signals receiver was refused because it carried no usable credential.</summary>
    public const string SsfDenied = "ssf.denied";

    /// <summary>
    /// A month of the ledger was exported and removed. Written before the partition is detached,
    /// so the next checkpoint seals it.
    /// </summary>
    public const string AuditArchived = "audit.archived";
}
