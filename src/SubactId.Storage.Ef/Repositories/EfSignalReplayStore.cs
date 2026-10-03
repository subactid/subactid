using Microsoft.EntityFrameworkCore;
using SubactId.Core.Signals;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// Replay protection for inbound signals, backed by the <c>signal_replays</c> table. Recording is
/// one <c>INSERT ... ON CONFLICT DO NOTHING</c>, so of two concurrent deliveries one is a replay.
/// </summary>
public sealed class EfSignalReplayStore(SubactIdDbContext db, IStorageDialect dialect) : ISignalReplayStore
{
    /// <inheritdoc />
    public async Task<bool> TryRecordAsync(string issuer, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var expires = dialect.Timestamp(expiresAt);
        var inserted = await db.Database.ExecuteSqlAsync(
            $"INSERT INTO signal_replays (issuer, jti, expires_at) VALUES ({issuer}, {jti}, {expires}) ON CONFLICT DO NOTHING",
            cancellationToken);
        return inserted == 1;
    }

    /// <inheritdoc />
    public Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var cutoff = now.ToUniversalTime();
        return db.SignalReplays.Where(r => r.ExpiresAt < cutoff).ExecuteDeleteAsync(cancellationToken);
    }
}
