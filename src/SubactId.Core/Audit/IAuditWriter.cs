namespace SubactId.Core.Audit;

/// <summary>Appends to the audit ledger. Every authorization decision and every admin mutation goes through here.</summary>
public interface IAuditWriter
{
    /// <summary>Appends <paramref name="auditEvent"/> as the next record of the chain and returns its sequence number.</summary>
    Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Appends <paramref name="auditEvents"/> in order as consecutive records of the chain, taking
    /// the chain lock once for all of them. For callers that record many events in one transaction.
    /// </summary>
    Task AppendAsync(IReadOnlyList<AuditEvent> auditEvents, CancellationToken cancellationToken = default);
}
