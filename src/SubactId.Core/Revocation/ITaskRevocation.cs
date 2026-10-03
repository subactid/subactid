namespace SubactId.Core.Revocation;

/// <summary>A task that was just revoked, with the fields its audit record needs.</summary>
/// <param name="TaskId">The task.</param>
/// <param name="AgentId">The agent it was issued to.</param>
/// <param name="Sponsor">The human it acted for.</param>
/// <param name="Audience">Its audience.</param>
/// <param name="Scopes">Its scopes.</param>
/// <param name="DelegationDepth">Its delegation depth.</param>
/// <param name="ParentTaskId">The task it was delegated from, if any.</param>
/// <param name="IsRoot">Whether it was named by the revocation itself rather than reached through a parent.</param>
/// <param name="Renewals">How many times its grants were used to refresh, read when they were revoked.</param>
public sealed record RevokedTask(string TaskId, string AgentId, string Sponsor, string Audience, IReadOnlyList<string> Scopes, int DelegationDepth, string? ParentTaskId, bool IsRoot, int Renewals = 0);

/// <summary>Outcome of revoking a task tree.</summary>
/// <param name="Found">Whether the root task exists at all.</param>
/// <param name="Revoked">The tasks that were live and are now revoked, root first; empty when nothing was live.</param>
public sealed record TaskRevocationOutcome(bool Found, IReadOnlyList<RevokedTask> Revoked);

/// <summary>
/// Privileged revocation across all agents. Revoking a task also revokes all tasks delegated from
/// it and every live grant under them. The named task gets the caller's reason. Descendants get
/// <see cref="ParentRevoked"/>. Revoked and expired tasks are left unchanged, so revoking is
/// idempotent. Runs inside the caller's unit of work.
/// <para>
/// A task is live when it is active <em>and</em> its <c>expires_at</c> is after <c>at</c>. An
/// active task past its expiry is left for the sweeper to record as <c>task.expired</c>.
/// </para>
/// </summary>
public interface ITaskRevocation
{
    /// <summary>Reason recorded on a task revoked because a task above it was.</summary>
    public const string ParentRevoked = "parent_revoked";

    /// <summary>Revokes <paramref name="rootTaskId"/> and its descendants.</summary>
    /// <param name="rootTaskId">The task at the top of the tree.</param>
    /// <param name="at">When the revocation takes effect.</param>
    /// <param name="reason">Machine-readable reason recorded on every task in the tree.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<TaskRevocationOutcome> RevokeTreeAsync(string rootTaskId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default);

    /// <summary>Revokes every live task issued to <paramref name="agentId"/>, with their descendants.</summary>
    /// <param name="agentId">The agent.</param>
    /// <param name="at">When the revocation takes effect.</param>
    /// <param name="reason">Machine-readable reason recorded on every task.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<RevokedTask>> RevokeAgentTasksAsync(string agentId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every live task acting for <paramref name="sponsorKey"/>, with their descendants,
    /// across all agents. Matches the task's stored sponsor key, not its subject.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim named them.</param>
    /// <param name="at">When the revocation takes effect.</param>
    /// <param name="reason">Machine-readable reason recorded on every task the person sponsors.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<RevokedTask>> RevokeSponsorTasksAsync(string sponsorKey, DateTimeOffset at, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every live task whose sponsor is <paramref name="subject"/>, with their
    /// descendants. Matches the subject, not the sponsor key, because a back-channel logout names
    /// the person by their OpenID Connect <c>sub</c>.
    /// </summary>
    /// <param name="subject">The human's upstream <c>sub</c>.</param>
    /// <param name="at">When the revocation takes effect.</param>
    /// <param name="reason">Machine-readable reason recorded on every task the person sponsors.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<RevokedTask>> RevokeSubjectTasksAsync(string subject, DateTimeOffset at, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every live task started from <paramref name="sessionId"/>, with their descendants.
    /// A task with no session is never matched.
    /// </summary>
    /// <param name="sessionId">The identity provider's session identifier.</param>
    /// <param name="at">When the revocation takes effect.</param>
    /// <param name="reason">Machine-readable reason recorded on every task of the session.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<RevokedTask>> RevokeSessionTasksAsync(string sessionId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Takes now, for the rest of the unit of work, what revoking the tasks of every one of
    /// <paramref name="sponsorKeys"/> takes, all together and in a fixed order. For a unit of work
    /// that revokes for more than one person: otherwise its second revocation would start waiting
    /// for exchanges only after its first had written to the audit ledger, and an exchange waiting
    /// to write there could close a cycle with it. Also taken first by every writer of a person's
    /// block, before anything else about the person, so writers that decide from the same rows
    /// take turns.
    /// </summary>
    /// <param name="sponsorKeys">The people this unit of work will revoke for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task HoldSponsorsAsync(IReadOnlyCollection<string> sponsorKeys, CancellationToken cancellationToken = default);
}
