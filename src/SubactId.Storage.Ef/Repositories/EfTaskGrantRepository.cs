using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>Task grants. Every query is filtered by agent.</summary>
public sealed class EfTaskGrantRepository(SubactIdDbContext db, IStorageDialect dialect) : ITaskGrantRepository
{
    /// <inheritdoc />
    public async Task AddAsync(TaskGrant grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);

        db.TaskGrants.Add(grant.ToRow());
        await UniqueViolation.SaveOrThrowDuplicateAsync(db, dialect, "task grant", Convert.ToHexString(grant.GrantHash.Span), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<TaskGrant?> FindAsync(string agentId, ReadOnlyMemory<byte> grantHash, CancellationToken cancellationToken = default)
    {
        var hash = grantHash.ToArray();
        var row = await db.TaskGrants.AsNoTracking()
            .SingleOrDefaultAsync(g => g.AgentId == agentId && g.GrantHash == hash, cancellationToken);
        return row?.ToDomain();
    }

    /// <inheritdoc />
    public async Task<int?> MarkUsedAsync(string agentId, ReadOnlyMemory<byte> grantHash, IReadOnlyList<string> heldScopes, IReadOnlyList<string> scopes, DateTimeOffset usedAt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(heldScopes);
        ArgumentNullException.ThrowIfNull(scopes);

        var hash = grantHash.ToArray();
        var lastUsedAt = dialect.Timestamp(usedAt);
        var held = dialect.StringList(heldScopes);

        // One statement, so the returned count is the one this update wrote. Concurrent uses wait
        // on the row lock, and one that finds the scopes changed under it updates nothing, so a
        // narrowing is never written over by a use decided against the wider scopes. Hand-written
        // because the update pipeline cannot return a column. The grant hash is bound, never
        // interpolated. Most refreshes keep the scope they hold, and rewriting the list costs
        // more than comparing it, so the list is written only when it narrows.
        var query = scopes.SequenceEqual(heldScopes, StringComparer.Ordinal)
            ? db.Database.SqlQuery<int>($"""
                UPDATE task_grants
                SET last_used_at = {lastUsedAt}, renewals = renewals + 1
                WHERE agent_id = {agentId} AND grant_hash = {hash} AND revoked_at IS NULL AND scopes = {held}
                RETURNING renewals AS "Value"
                """)
            : db.Database.SqlQuery<int>($"""
                UPDATE task_grants
                SET last_used_at = {lastUsedAt}, renewals = renewals + 1, scopes = {dialect.StringList(scopes)}
                WHERE agent_id = {agentId} AND grant_hash = {hash} AND revoked_at IS NULL AND scopes = {held}
                RETURNING renewals AS "Value"
                """);
        var renewals = await query.ToListAsync(cancellationToken);
        return renewals.Count == 1 ? renewals[0] : null;
    }

    /// <inheritdoc />
    public async Task<int> RevokeByTaskAsync(string agentId, string taskId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var at = revokedAt.ToUniversalTime();
        return await db.TaskGrants
            .Where(g => g.AgentId == agentId && g.TaskId == taskId && g.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(g => g.RevokedAt, at), cancellationToken);
    }
}
