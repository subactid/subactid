using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Sqlite.Repositories;

/// <summary>
/// SQLite's expiry claim: reads the due tasks, then marks those still active as expired. The
/// unit of work holds the write lock throughout, so no row changes in between.
/// </summary>
/// <param name="db">The context.</param>
public sealed class SqliteTaskExpirySweep(SubactIdDbContext db) : EfTaskExpirySweep(db)
{
    /// <inheritdoc />
    protected override async Task<IReadOnlyList<ExpiredTask>> ClaimDueAsync(DateTimeOffset at, int batchSize, CancellationToken cancellationToken)
    {
        var due = await Db.Tasks.AsNoTracking()
            .Where(t => t.Status == TaskRow.StatusActive && t.ExpiresAt <= at)
            .OrderBy(t => t.ExpiresAt)
            .Take(batchSize)
            .Select(t => new ExpiredTask(t.TaskId, t.AgentId, t.Sponsor, t.Audience, t.Scopes, t.DelegationDepth, t.ExpiresAt))
            .ToListAsync(cancellationToken);
        if (due.Count == 0)
        {
            return due;
        }

        var taskIds = due.Select(t => t.TaskId).ToArray();
        await Db.Tasks
            .Where(t => taskIds.Contains(t.TaskId) && t.Status == TaskRow.StatusActive)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.Status, TaskRow.StatusExpired), cancellationToken);
        return due;
    }
}
