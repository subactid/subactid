using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>Tasks. Every query is filtered by agent.</summary>
public sealed class EfTaskRepository(SubactIdDbContext db, IStorageDialect dialect) : ITaskRepository
{
    /// <inheritdoc />
    public async Task AddAsync(DelegationTask task, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(task);

        db.Tasks.Add(task.ToRow());
        await UniqueViolation.SaveOrThrowDuplicateAsync(db, dialect, "task", task.TaskId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<DelegationTask?> FindAsync(string agentId, string taskId, CancellationToken cancellationToken = default)
    {
        var row = await db.Tasks.AsNoTracking()
            .SingleOrDefaultAsync(t => t.AgentId == agentId && t.TaskId == taskId, cancellationToken);
        return row?.ToDomain();
    }
}
