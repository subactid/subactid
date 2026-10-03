using Microsoft.EntityFrameworkCore;
using SubactId.Core.Revocation;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// Task revocation, except the tree walk, which each provider supplies. Revoking the grants and
/// shaping the result are shared.
/// </summary>
/// <param name="db">The context.</param>
public abstract class EfTaskRevocation(SubactIdDbContext db) : ITaskRevocation
{
    /// <summary>The context these statements run on.</summary>
    protected SubactIdDbContext Db { get; } = db;

    /// <inheritdoc />
    public async Task<TaskRevocationOutcome> RevokeTreeAsync(string rootTaskId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(rootTaskId);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        if (!await Db.Tasks.AsNoTracking().AnyAsync(t => t.TaskId == rootTaskId, cancellationToken))
        {
            return new TaskRevocationOutcome(false, []);
        }

        var revoked = await RevokeTreeRowsAsync(rootTaskId, at.ToUniversalTime(), reason, cancellationToken);
        return new TaskRevocationOutcome(true, await CompleteAsync(revoked, at.ToUniversalTime(), cancellationToken));
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<RevokedTask>> RevokeAgentTasksAsync(string agentId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        // Waits for every exchange already issuing a task in this scope, so the walk below sees it.
        await Db.Dialect.LockRevocationScopesAsync(Db, [RevocationScope.Agent(agentId)], exclusive: true, cancellationToken);
        var revoked = await RevokeAgentRowsAsync(agentId, at.ToUniversalTime(), reason, cancellationToken);
        return await CompleteAsync(revoked, at.ToUniversalTime(), cancellationToken);
    }

    /// <inheritdoc />
    public Task HoldSponsorsAsync(IReadOnlyCollection<string> sponsorKeys, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sponsorKeys);

        return Db.Dialect.LockRevocationScopesAsync(Db, sponsorKeys.Select(RevocationScope.Sponsor).ToList(), exclusive: true, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<RevokedTask>> RevokeSponsorTasksAsync(string sponsorKey, DateTimeOffset at, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        // Waits for every exchange already issuing a task in this scope, so the walk below sees it.
        await Db.Dialect.LockRevocationScopesAsync(Db, [RevocationScope.Sponsor(sponsorKey)], exclusive: true, cancellationToken);
        var revoked = await RevokeSponsorRowsAsync(sponsorKey, at.ToUniversalTime(), reason, cancellationToken);
        return await CompleteAsync(revoked, at.ToUniversalTime(), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<RevokedTask>> RevokeSubjectTasksAsync(string subject, DateTimeOffset at, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        // Waits for every exchange already issuing a task in this scope, so the walk below sees it.
        await Db.Dialect.LockRevocationScopesAsync(Db, [RevocationScope.Subject(subject)], exclusive: true, cancellationToken);
        var revoked = await RevokeSubjectRowsAsync(subject, at.ToUniversalTime(), reason, cancellationToken);
        return await CompleteAsync(revoked, at.ToUniversalTime(), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<RevokedTask>> RevokeSessionTasksAsync(string sessionId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        // Waits for every exchange already issuing a task in this scope, so the walk below sees it.
        await Db.Dialect.LockRevocationScopesAsync(Db, [RevocationScope.Session(sessionId)], exclusive: true, cancellationToken);
        var revoked = await RevokeSessionRowsAsync(sessionId, at.ToUniversalTime(), reason, cancellationToken);
        return await CompleteAsync(revoked, at.ToUniversalTime(), cancellationToken);
    }

    /// <summary>Flips every live task in the tree under <paramref name="rootTaskId"/> and returns what was flipped.</summary>
    /// <param name="rootTaskId">The task named by the revocation.</param>
    /// <param name="at">Revocation time, in UTC.</param>
    /// <param name="reason">The reason for the task named; anything below it gets <see cref="ITaskRevocation.ParentRevoked"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<RevokedTaskRow>> RevokeTreeRowsAsync(string rootTaskId, DateTimeOffset at, string reason, CancellationToken cancellationToken);

    /// <summary>Flips every live task of <paramref name="agentId"/>, and everything delegated from them, and returns what was flipped.</summary>
    /// <param name="agentId">The agent.</param>
    /// <param name="at">Revocation time, in UTC.</param>
    /// <param name="reason">The reason for the agent's own tasks; anything below them gets <see cref="ITaskRevocation.ParentRevoked"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<RevokedTaskRow>> RevokeAgentRowsAsync(string agentId, DateTimeOffset at, string reason, CancellationToken cancellationToken);

    /// <summary>
    /// Flips every live task acting for <paramref name="sponsorKey"/>, and everything delegated
    /// from them, and returns what was flipped.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim named them.</param>
    /// <param name="at">Revocation time, in UTC.</param>
    /// <param name="reason">The reason for the person's own tasks; anything below them gets <see cref="ITaskRevocation.ParentRevoked"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<RevokedTaskRow>> RevokeSponsorRowsAsync(string sponsorKey, DateTimeOffset at, string reason, CancellationToken cancellationToken);

    /// <summary>Flips every live task whose sponsor is <paramref name="subject"/>, and everything delegated from them.</summary>
    /// <param name="subject">The human's upstream <c>sub</c>.</param>
    /// <param name="at">Revocation time, in UTC.</param>
    /// <param name="reason">The reason for the person's own tasks; anything below them gets <see cref="ITaskRevocation.ParentRevoked"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<RevokedTaskRow>> RevokeSubjectRowsAsync(string subject, DateTimeOffset at, string reason, CancellationToken cancellationToken);

    /// <summary>Flips every live task started from <paramref name="sessionId"/>, and everything delegated from them.</summary>
    /// <param name="sessionId">The identity provider's session identifier.</param>
    /// <param name="at">Revocation time, in UTC.</param>
    /// <param name="reason">The reason for the session's own tasks; anything below them gets <see cref="ITaskRevocation.ParentRevoked"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<RevokedTaskRow>> RevokeSessionRowsAsync(string sessionId, DateTimeOffset at, string reason, CancellationToken cancellationToken);

    /// <summary>Revokes the grants of every task flipped, counts their renewals under the same locks, then returns the tasks root first.</summary>
    private async Task<IReadOnlyList<RevokedTask>> CompleteAsync(IReadOnlyList<RevokedTaskRow> rows, DateTimeOffset at, CancellationToken cancellationToken)
    {
        var renewals = new Dictionary<string, int>(StringComparer.Ordinal);
        if (rows.Count > 0)
        {
            var taskIds = rows.Select(r => r.TaskId).ToArray();
            await Db.TaskGrants
                .Where(g => taskIds.Contains(g.TaskId) && g.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(g => g.RevokedAt, at), cancellationToken);

            // Read after the revocation in the same transaction, under the grants' row locks, so every
            // refresh that succeeded is counted.
            renewals = await EfTaskExpirySweep.RenewalsAsync(Db, taskIds, cancellationToken);
        }

        return rows
            .OrderBy(r => r.Level).ThenBy(r => r.TaskId, StringComparer.Ordinal)
            .Select(r => new RevokedTask(r.TaskId, r.AgentId, r.Sponsor, r.Audience, r.Scopes, r.DelegationDepth, r.ParentTaskId, r.Level == 0, renewals.GetValueOrDefault(r.TaskId)))
            .ToList();
    }
}

/// <summary>One task a revocation flipped, with how far below the task named it sat.</summary>
public sealed class RevokedTaskRow
{
    /// <summary>The task.</summary>
    public required string TaskId { get; init; }

    /// <summary>The agent it was issued to.</summary>
    public required string AgentId { get; init; }

    /// <summary>The human it acted for.</summary>
    public required string Sponsor { get; init; }

    /// <summary>Its audience.</summary>
    public required string Audience { get; init; }

    /// <summary>Its scopes.</summary>
    public required string[] Scopes { get; init; }

    /// <summary>Its delegation depth.</summary>
    public int DelegationDepth { get; init; }

    /// <summary>The task it was delegated from, if any.</summary>
    public string? ParentTaskId { get; init; }

    /// <summary>Zero for a task the revocation named, one more for each hop below it.</summary>
    public int Level { get; init; }
}
