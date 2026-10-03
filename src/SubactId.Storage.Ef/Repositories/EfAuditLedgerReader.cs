using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>The <see cref="IAuditLedgerReader"/>: one ordered, bounded, projected query per page.</summary>
public sealed class EfAuditLedgerReader(SubactIdDbContext db) : IAuditLedgerReader
{
    /// <inheritdoc />
    public Task<IReadOnlyList<AuditLedgerRecord>> ReadAsync(long afterSeq, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        return db.AuditEvents.AsNoTracking().Where(e => e.Seq > afterSeq).OrderBy(e => e.Seq).Take(limit).ToLedgerRecordsAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<AuditLedgerRecord>> ReadBySeqAsync(IReadOnlyList<long> seqs, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(seqs);

        var wanted = seqs.ToArray();
        return db.AuditEvents.AsNoTracking().Where(e => wanted.Contains(e.Seq)).OrderBy(e => e.Seq).ToLedgerRecordsAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<AuditLedgerRecord>> ReadRangeAsync(long afterSeq, long throughSeq, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        return db.AuditEvents.AsNoTracking()
            .Where(e => e.Seq > afterSeq && e.Seq <= throughSeq)
            .OrderBy(e => e.Seq)
            .Take(limit)
            .ToLedgerRecordsAsync(cancellationToken);
    }
}
