namespace SubactId.Core.Delegation;

/// <summary>A task: the unit of delegated authority every token belongs to (spec sections 3 and 4).</summary>
/// <param name="TaskId">Identifier, for example <c>task_01HQZX9K4M</c>.</param>
/// <param name="AgentId">The agent the task was issued to.</param>
/// <param name="Sponsor">The human the task acts on behalf of; always the <c>sub</c> of every token.</param>
/// <param name="SponsorKey">
/// The same human, as named by the configured key claim. Used to match signals about them to their
/// tasks. Usually equal to <paramref name="Sponsor"/>.
/// </param>
/// <param name="SessionId">
/// The identity provider's session (<c>sid</c>) from the subject token, used for back-channel logout.
/// Null when the provider sends no <c>sid</c>.
/// </param>
/// <param name="ParentTaskId">The task this one was delegated from, if any.</param>
/// <param name="DelegationDepth">Position in the delegation chain; 1 for a task created from a user token.</param>
/// <param name="Audience">The audience tokens under this task are issued for.</param>
/// <param name="Scopes">Scopes granted at creation. Later tokens and grants may only narrow these.</param>
/// <param name="Status">Lifecycle state.</param>
/// <param name="CreatedAt">When the task was created.</param>
/// <param name="ExpiresAt">When the task expires; no token may outlive this instant.</param>
/// <param name="RevokedAt">When the task was revoked, if it was.</param>
/// <param name="RevocationReason">Machine-readable reason for revocation, if any.</param>
public sealed record DelegationTask(
    string TaskId,
    string AgentId,
    string Sponsor,
    string SponsorKey,
    string? SessionId,
    string? ParentTaskId,
    int DelegationDepth,
    string Audience,
    IReadOnlyList<string> Scopes,
    DelegationTaskStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt,
    string? RevocationReason);
