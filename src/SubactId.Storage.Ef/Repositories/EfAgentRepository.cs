using Microsoft.EntityFrameworkCore;
using SubactId.Core.Agents;
using SubactId.Core.Storage;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>The agent registry.</summary>
public sealed class EfAgentRepository(SubactIdDbContext db, IStorageDialect dialect) : IAgentRepository
{
    /// <inheritdoc />
    public async Task<Agent?> FindAsync(string agentId, CancellationToken cancellationToken = default)
    {
        var row = await db.Agents.AsNoTracking().SingleOrDefaultAsync(a => a.AgentId == agentId, cancellationToken);
        return row?.ToDomain();
    }

    /// <inheritdoc />
    public async Task<Agent?> FindForUpdateAsync(string agentId, CancellationToken cancellationToken = default)
    {
        // The lock first, then the read, so the read sees whatever the previous holder committed.
        await dialect.LockAgentAsync(db, agentId, cancellationToken);
        return await FindAsync(agentId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task AddAsync(Agent agent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agent);

        db.Agents.Add(agent.ToRow());
        await UniqueViolation.SaveOrThrowDuplicateAsync(db, dialect, "agent", agent.AgentId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> UpdateAsync(Agent agent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agent);

        var row = await db.Agents.SingleOrDefaultAsync(a => a.AgentId == agent.AgentId, cancellationToken);
        if (row is null)
        {
            return false;
        }

        row.CopyFrom(agent);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(string agentId, CancellationToken cancellationToken = default)
    {
        try
        {
            var deleted = await db.Agents.Where(a => a.AgentId == agentId).ExecuteDeleteAsync(cancellationToken);
            return deleted == 1;
        }
        catch (Exception exception) when (dialect.IsForeignKeyViolation(exception) || (exception.InnerException is { } inner && dialect.IsForeignKeyViolation(inner)))
        {
            throw new DependentEntitiesException("agent", agentId);
        }
    }
}
