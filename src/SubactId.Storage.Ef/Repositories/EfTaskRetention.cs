using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// The retention purge: reads a bounded batch of terminal tasks past the cutoff, then deletes their
/// grants and then the tasks. Grants are deleted explicitly rather than relying on a cascade. The
/// task delete filters on status again, so an active task is never removed. Concurrent purges are safe.
/// </summary>
/// <param name="db">The context.</param>
public sealed class EfTaskRetention(SubactIdDbContext db) : ITaskRetention
{
    /// <inheritdoc />
    public async Task<int> PurgeTerminalAsync(DateTimeOffset before, int batchSize, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(batchSize, 0);

        var cutoff = before.ToUniversalTime();
        var taskIds = await db.Tasks.AsNoTracking()
            .Where(t => t.Status != TaskRow.StatusActive
                && t.ExpiresAt <= cutoff
                && !db.Tasks.Any(child => child.ParentTaskId == t.TaskId))
            .OrderBy(t => t.ExpiresAt)
            .Take(batchSize)
            .Select(t => t.TaskId)
            .ToArrayAsync(cancellationToken);
        if (taskIds.Length == 0)
        {
            return 0;
        }

        await db.TaskGrants
            .Where(g => taskIds.Contains(g.TaskId))
            .ExecuteDeleteAsync(cancellationToken);
        return await db.Tasks
            .Where(t => taskIds.Contains(t.TaskId) && t.Status != TaskRow.StatusActive)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
