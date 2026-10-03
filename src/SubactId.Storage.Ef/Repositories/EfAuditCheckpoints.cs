using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// Reads the signed checkpoints, in id order or by covered record. The checkpoint sealing a record
/// is the one with the smallest <c>last_seq</c> at or above the record's sequence number.
/// </summary>
public sealed class EfAuditCheckpointQuery(SubactIdDbContext db) : IAuditCheckpointQuery
{
    /// <inheritdoc />
    public Task<IReadOnlyList<AuditCheckpoint>> ReadAsync(long afterId, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        return db.AuditCheckpoints.AsNoTracking()
            .Where(c => c.CheckpointId > afterId)
            .OrderBy(c => c.CheckpointId)
            .Take(limit)
            .ToCheckpointsAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<AuditCheckpoint?> SealingAsync(long seq, CancellationToken cancellationToken = default)
    {
        var found = await db.AuditCheckpoints.AsNoTracking()
            .Where(c => c.LastSeq >= seq && c.FirstSeq <= seq)
            .OrderBy(c => c.LastSeq)
            .Take(1)
            .ToCheckpointsAsync(cancellationToken);

        return found.Count == 0 ? null : found[0];
    }

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<long, long>> SealingAsync(IReadOnlyList<long> seqs, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(seqs);

        if (seqs.Count == 0)
        {
            return new Dictionary<long, long>();
        }

        // One read, of only the checkpoints that seal a record on the page: at most one per record,
        // however long the span between the page's first and last record. The range bounds keep
        // it on the last_seq index; the EXISTS drops the checkpoints in between.
        var wanted = seqs.Distinct().ToList();
        var lowest = wanted.Min();
        var highest = wanted.Max();
        var covering = await db.AuditCheckpoints.AsNoTracking()
            .Where(c => c.LastSeq >= lowest && c.FirstSeq <= highest)
            .Where(c => wanted.Any(s => c.FirstSeq <= s && s <= c.LastSeq))
            .OrderBy(c => c.FirstSeq)
            .Select(c => new { c.CheckpointId, c.FirstSeq, c.LastSeq })
            .ToListAsync(cancellationToken);

        // Checkpoints never overlap, so in FirstSeq order the one sealing a record is the last
        // that starts at or before it, if it also ends at or after it.
        var starts = covering.Select(c => c.FirstSeq).ToArray();
        var sealing = new Dictionary<long, long>(wanted.Count);
        foreach (var seq in wanted)
        {
            var index = Array.BinarySearch(starts, seq);
            index = index >= 0 ? index : ~index - 1;
            if (index >= 0 && seq <= covering[index].LastSeq)
            {
                sealing[seq] = covering[index].CheckpointId;
            }
        }

        return sealing;
    }
}

/// <summary>
/// Writes checkpoints, and reads where the sealed ledger ends and how far it may safely seal.
/// Both are read inside the sealing pass's transactions and never cached.
/// </summary>
public sealed class EfAuditCheckpointRepository(SubactIdDbContext db, IStorageDialect dialect) : IAuditCheckpointRepository
{
    /// <inheritdoc />
    public async Task<AuditCheckpoint?> LastAsync(CancellationToken cancellationToken = default)
    {
        var found = await db.AuditCheckpoints.AsNoTracking()
            .OrderByDescending(c => c.CheckpointId)
            .Take(1)
            .ToCheckpointsAsync(cancellationToken);

        return found.Count == 0 ? null : found[0];
    }

    /// <inheritdoc />
    public async Task AppendAsync(AuditCheckpoint checkpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        db.AuditCheckpoints.Add(checkpoint.ToRow());
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<long> FenceHighWaterMarkAsync(CancellationToken cancellationToken = default)
    {
        // Take the fence first. Once held exclusively, every append with a sequence number has
        // committed, so nothing can still appear below the maximum read next.
        await dialect.LockAuditSealAsync(db, cancellationToken);
        return await db.AuditEvents.AsNoTracking().MaxAsync(e => (long?)e.Seq, cancellationToken) ?? 0;
    }

    /// <inheritdoc />
    public Task<bool> TryClaimSealAsync(CancellationToken cancellationToken = default) =>
        dialect.TryClaimAuditSealAsync(db, cancellationToken);
}
