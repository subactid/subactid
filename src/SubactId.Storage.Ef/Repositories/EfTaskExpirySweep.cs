using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// The expiry sweep, except the claim, which each provider supplies. Grants under expired tasks are
/// revoked in the same transaction, so an expired task never has a live grant.
/// </summary>
/// <param name="db">The context.</param>
public abstract class EfTaskExpirySweep(SubactIdDbContext db) : ITaskExpirySweep
{
    /// <summary>The context these statements run on.</summary>
    protected SubactIdDbContext Db { get; } = db;

    /// <inheritdoc />
    public async Task<IReadOnlyList<ExpiredTask>> ExpireDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(batchSize, 0);

        var at = now.ToUniversalTime();
        var expired = await ClaimDueAsync(at, batchSize, cancellationToken);
        if (expired.Count == 0)
        {
            return expired;
        }

        var taskIds = expired.Select(e => e.TaskId).ToArray();
        await Db.TaskGrants
            .Where(g => taskIds.Contains(g.TaskId) && g.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(g => g.RevokedAt, at), cancellationToken);

        // Read after the revocation in the same transaction, under the grants' row locks, so every
        // refresh that succeeded is counted.
        var renewals = await RenewalsAsync(Db, taskIds, cancellationToken);
        return expired.Select(e => e with { Renewals = renewals.GetValueOrDefault(e.TaskId) }).ToList();
    }

    /// <summary>How many times the grants under each of <paramref name="taskIds"/> were used to refresh, summed per task.</summary>
    /// <param name="db">The context.</param>
    /// <param name="taskIds">The tasks.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal static async Task<Dictionary<string, int>> RenewalsAsync(SubactIdDbContext db, string[] taskIds, CancellationToken cancellationToken)
    {
        var counts = await db.TaskGrants.AsNoTracking()
            .Where(g => taskIds.Contains(g.TaskId))
            .GroupBy(g => g.TaskId)
            .Select(g => new { TaskId = g.Key, Renewals = g.Sum(x => x.Renewals) })
            .ToListAsync(cancellationToken);
        return counts.ToDictionary(c => c.TaskId, c => c.Renewals, StringComparer.Ordinal);
    }

    /// <summary>Claims due tasks and marks them expired, so that two sweepers never take the same row.</summary>
    /// <param name="at">The sweep time, in UTC.</param>
    /// <param name="batchSize">Most tasks to claim.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<ExpiredTask>> ClaimDueAsync(DateTimeOffset at, int batchSize, CancellationToken cancellationToken);
}
