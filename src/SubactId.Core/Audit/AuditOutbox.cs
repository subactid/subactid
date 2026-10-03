namespace SubactId.Core.Audit;

/// <summary>One pending delivery in the outbox.</summary>
/// <param name="Id">The outbox entry.</param>
/// <param name="AuditSeq">The ledger record to deliver.</param>
/// <param name="Attempts">Deliveries tried so far.</param>
public sealed record AuditOutboxEntry(long Id, long AuditSeq, int Attempts);

/// <summary>
/// Ledger records waiting to be delivered to the external sink. A claim is exclusive for the
/// caller's unit of work, so concurrent drains never deliver the same entry. Delivered entries are removed.
/// </summary>
public interface IAuditOutboxQueue
{
    /// <summary>Claims up to <paramref name="batchSize"/> entries whose next attempt is due, oldest first. Runs inside the caller's unit of work.</summary>
    Task<IReadOnlyList<AuditOutboxEntry>> ClaimDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default);

    /// <summary>Removes the entries the sink has taken. Runs inside the caller's unit of work. If it does not commit, the entries stay queued.</summary>
    Task RemoveDeliveredAsync(IReadOnlyList<long> ids, CancellationToken cancellationToken = default);

    /// <summary>Records a failed attempt on the entries and when to try again. The error is truncated to what the store holds and must not carry a secret.</summary>
    Task MarkFailedAsync(IReadOnlyList<long> ids, DateTimeOffset now, string error, DateTimeOffset nextAttemptAt, CancellationToken cancellationToken = default);
}

/// <summary>Where ledger records are delivered to. Throws on any failure, and the drain retries later.</summary>
public interface IAuditSink
{
    /// <summary>Delivers <paramref name="records"/>, in order, all or nothing.</summary>
    /// <param name="records">The records to deliver, in sequence order.</param>
    /// <param name="sealing">The checkpoint sealing each record, by sequence number. Records not yet sealed are absent.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeliverAsync(IReadOnlyList<AuditLedgerRecord> records, IReadOnlyDictionary<long, long> sealing, CancellationToken cancellationToken = default);
}
