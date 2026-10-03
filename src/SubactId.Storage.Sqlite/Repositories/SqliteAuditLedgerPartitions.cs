using SubactId.Core.Audit;

namespace SubactId.Storage.Sqlite.Repositories;

/// <summary>
/// SQLite has no partitioning, so the ledger is one table and nothing is created ahead of time.
/// The ledger stays append-only and sealed, but there is no retention: records are never removed.
/// </summary>
public sealed class SqliteAuditLedgerPartitions : IAuditLedgerPartitions
{
    /// <inheritdoc />
    public Task<AuditLedgerLayout> InspectAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(new AuditLedgerLayout(false, []));

    /// <inheritdoc />
    public Task<int> EnsureAsync(DateTimeOffset from, int monthsAhead, CancellationToken cancellationToken = default) =>
        Task.FromResult(0);
}
