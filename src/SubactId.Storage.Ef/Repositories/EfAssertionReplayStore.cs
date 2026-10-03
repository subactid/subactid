using Microsoft.EntityFrameworkCore;
using SubactId.Core.Agents;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// Replay protection backed by the <c>assertion_replays</c> table. Recording is one
/// <c>INSERT ... ON CONFLICT DO NOTHING</c>, so concurrent uses of one assertion have one winner.
/// </summary>
public sealed class EfAssertionReplayStore(SubactIdDbContext db, IStorageDialect dialect) : IAssertionReplayStore
{
    /// <inheritdoc />
    public async Task<bool> TryRecordAsync(string agentId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var expires = dialect.Timestamp(expiresAt);
        var inserted = await db.Database.ExecuteSqlAsync(
            $"INSERT INTO assertion_replays (agent_id, jti, expires_at) VALUES ({agentId}, {jti}, {expires}) ON CONFLICT DO NOTHING",
            cancellationToken);
        return inserted == 1;
    }

    /// <inheritdoc />
    public Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var cutoff = now.ToUniversalTime();
        return db.AssertionReplays.Where(r => r.ExpiresAt < cutoff).ExecuteDeleteAsync(cancellationToken);
    }
}
