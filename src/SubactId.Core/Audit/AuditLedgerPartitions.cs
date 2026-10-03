namespace SubactId.Core.Audit;

/// <summary>
/// One ledger partition in the database, and whether each of its two guards is in place.
/// A partition is guarded only when both are.
/// </summary>
/// <param name="Name">The partition's table name.</param>
/// <param name="Month">The month it holds, taken from its name, or <c>null</c> if the name is not one the control plane gives a partition.</param>
/// <param name="RefusesTruncate">Whether an enabled <c>BEFORE TRUNCATE</c> trigger is on the partition itself.</param>
/// <param name="PrivilegesRevoked">Whether this connection's role holds none of <c>UPDATE</c>, <c>DELETE</c> or <c>TRUNCATE</c> on it.</param>
public sealed record AuditLedgerPartition(string Name, DateOnly? Month, bool RefusesTruncate, bool PrivilegesRevoked)
{
    /// <summary>Whether the partition carries both guards and is one the control plane made.</summary>
    public bool Guarded => RefusesTruncate && PrivilegesRevoked && Month is not null;
}

/// <summary>
/// How the ledger is laid out in this database: whether it is partitioned, and its partitions.
/// </summary>
/// <param name="Partitioned">Whether the ledger is a partitioned table. False when the provider has no partitioning or migrations are not applied.</param>
/// <param name="Partitions">Every partition the database has, in month order.</param>
public sealed record AuditLedgerLayout(bool Partitioned, IReadOnlyList<AuditLedgerPartition> Partitions)
{
    /// <summary>The partition holding <paramref name="at"/>, or <c>null</c> when no partition covers that month.</summary>
    /// <param name="at">The instant to look for.</param>
    public AuditLedgerPartition? Covering(DateTimeOffset at)
    {
        var month = MonthOf(at);
        return Partitions.FirstOrDefault(p => p.Month == month);
    }

    /// <summary>
    /// How many consecutive months after the one holding <paramref name="at"/> have partitions,
    /// or <c>null</c> when that month has none. Zero means it is the last one.
    /// </summary>
    /// <param name="at">The instant to count from.</param>
    public int? MonthsAhead(DateTimeOffset at)
    {
        if (Covering(at) is null)
        {
            return null;
        }

        var month = MonthOf(at);
        var ahead = 0;
        while (Partitions.Any(p => p.Month == month.AddMonths(ahead + 1)))
        {
            ahead++;
        }

        return ahead;
    }

    /// <summary>The first day of the UTC month holding <paramref name="at"/>. Partitions are named by it.</summary>
    /// <param name="at">The instant.</param>
    public static DateOnly MonthOf(DateTimeOffset at)
    {
        var utc = at.UtcDateTime;
        return new DateOnly(utc.Year, utc.Month, 1);
    }
}

/// <summary>
/// Inspects and creates the ledger's monthly partitions.
/// <para>
/// Retention works by detaching partitions, which keeps the <c>UPDATE</c>, <c>DELETE</c> and
/// <c>TRUNCATE</c> guard intact. Partitions are created ahead of time. There is no default
/// partition, so appending to a month without one fails.
/// </para>
/// </summary>
public interface IAuditLedgerPartitions
{
    /// <summary>Reads the layout from the database. Never cached.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<AuditLedgerLayout> InspectAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Ensures partitions exist for the month holding <paramref name="from"/> and the
    /// <paramref name="monthsAhead"/> months after it. Returns how many were created. New
    /// partitions are created with their guard. A provider without partitioning creates none.
    /// </summary>
    /// <param name="from">The first month to cover.</param>
    /// <param name="monthsAhead">How many further months to cover.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int> EnsureAsync(DateTimeOffset from, int monthsAhead, CancellationToken cancellationToken = default);
}
