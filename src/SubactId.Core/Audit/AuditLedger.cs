namespace SubactId.Core.Audit;

/// <summary>
/// One ledger record as read back: its sequence number and the event. The row holds no hashes.
/// It is sealed by the signed checkpoint in <c>audit_checkpoints</c> that covers its sequence number.
/// </summary>
/// <param name="Seq">Sequence number.</param>
/// <param name="Event">The record as written.</param>
public sealed record AuditLedgerRecord(long Seq, AuditEvent Event);

/// <summary>Read-only, paginated access to the ledger for verification and sealing. One projected query per page.</summary>
public interface IAuditLedgerReader
{
    /// <summary>Up to <paramref name="limit"/> records with a sequence number above <paramref name="afterSeq"/>, in sequence order.</summary>
    Task<IReadOnlyList<AuditLedgerRecord>> ReadAsync(long afterSeq, int limit, CancellationToken cancellationToken = default);

    /// <summary>The records with the given sequence numbers, in sequence order; missing ones are simply absent.</summary>
    Task<IReadOnlyList<AuditLedgerRecord>> ReadBySeqAsync(IReadOnlyList<long> seqs, CancellationToken cancellationToken = default);

    /// <summary>
    /// Up to <paramref name="limit"/> records in <c>(afterSeq, throughSeq]</c>, in sequence order.
    /// These are the leaves of a checkpoint's range.
    /// </summary>
    Task<IReadOnlyList<AuditLedgerRecord>> ReadRangeAsync(long afterSeq, long throughSeq, int limit, CancellationToken cancellationToken = default);
}
