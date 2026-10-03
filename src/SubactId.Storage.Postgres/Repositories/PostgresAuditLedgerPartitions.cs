using System.Globalization;
using Npgsql;
using SubactId.Core.Audit;

namespace SubactId.Storage.Postgres.Repositories;

/// <summary>
/// The ledger's monthly partitions, read from the catalogue and created through the migration's
/// function, which also attaches their guards.
/// <para>
/// Partitions are created a year ahead, by <c>migrate</c> and by the top-up pass. There is no
/// default partition, so an append into a month without one fails.
/// </para>
/// <para>
/// Runs on its own connections, outside any unit of work.
/// </para>
/// </summary>
public sealed class PostgresAuditLedgerPartitions(NpgsqlDataSource dataSource) : IAuditLedgerPartitions
{
    /// <summary>What every partition of the ledger is named, before the month it holds.</summary>
    public const string NamePrefix = "audit_events_p";

    /// <summary>The function the migration installs. The only supported way to create a partition.</summary>
    public const string AddPartitionFunction = "audit_events_add_partition";

    /// <summary>
    /// Every partition, with the two guards that must be on the partition itself.
    /// <para>
    /// The trigger test matches an enabled <c>BEFORE TRUNCATE</c> statement trigger by its catalogue
    /// bits. The privilege test checks the role of this connection.
    /// </para>
    /// </summary>
    private const string InspectSql = """
        SELECT part.relname,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_trigger t
                   WHERE t.tgrelid = part.oid
                     AND t.tgenabled <> 'D'
                     AND (t.tgtype & 32) <> 0
                     AND (t.tgtype & 1) = 0
                     AND (t.tgtype & 66) = 2
                     AND t.tgfoid = to_regproc('audit_events_append_only')::oid
               ) AS refuses_truncate,
               NOT (
                   pg_catalog.has_table_privilege(part.oid, 'UPDATE')
                   OR pg_catalog.has_table_privilege(part.oid, 'DELETE')
                   OR pg_catalog.has_table_privilege(part.oid, 'TRUNCATE')
               ) AS privileges_revoked
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class part ON part.oid = i.inhrelid
        WHERE i.inhparent = to_regclass('audit_events')
        ORDER BY part.relname
        """;

    /// <summary>Whether the ledger is a partitioned table here at all. <c>relkind</c> <c>p</c> is the partitioned parent.</summary>
    private const string PartitionedSql = """
        SELECT COALESCE((SELECT c.relkind = 'p' FROM pg_catalog.pg_class c WHERE c.oid = to_regclass('audit_events')), false)
        """;

    /// <inheritdoc />
    public async Task<AuditLedgerLayout> InspectAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = PartitionedSql;
            if (await command.ExecuteScalarAsync(cancellationToken) is not true)
            {
                return new AuditLedgerLayout(false, []);
            }
        }

        var partitions = new List<AuditLedgerPartition>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = InspectSql;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var name = reader.GetString(0);
                partitions.Add(new AuditLedgerPartition(name, MonthOf(name), reader.GetBoolean(1), reader.GetBoolean(2)));
            }
        }

        // Sorted by month, so partitions with unrecognised names sort predictably.
        partitions.Sort((left, right) =>
        {
            var byMonth = Nullable.Compare(left.Month, right.Month);
            return byMonth != 0 ? byMonth : string.CompareOrdinal(left.Name, right.Name);
        });
        return new AuditLedgerLayout(true, partitions);
    }

    /// <inheritdoc />
    public async Task<int> EnsureAsync(DateTimeOffset from, int monthsAhead, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(monthsAhead);

        var first = AuditLedgerLayout.MonthOf(from);
        var created = 0;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        for (var ahead = 0; ahead <= monthsAhead; ahead++)
        {
            // One statement per month, each committing on its own, so one failure does not undo
            // the others. The function is idempotent, so a concurrent create is not an error.
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT {AddPartitionFunction}(@month)";
            command.Parameters.AddWithValue("month", first.AddMonths(ahead));
            if (await command.ExecuteScalarAsync(cancellationToken) is true)
            {
                created++;
            }
        }

        return created;
    }

    /// <summary>
    /// The month a partition's name says it holds, or <c>null</c> when the name does not follow
    /// this control plane's partition naming.
    /// </summary>
    /// <param name="name">The partition's table name.</param>
    public static DateOnly? MonthOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (!name.StartsWith(NamePrefix, StringComparison.Ordinal))
        {
            return null;
        }

        // Parsed digit by digit so only the exact expected format is accepted.
        var suffix = name.AsSpan(NamePrefix.Length);
        if (suffix.Length != 6
            || suffix.ContainsAnyExcept("0123456789")
            || !int.TryParse(suffix[..4], NumberStyles.None, CultureInfo.InvariantCulture, out var year)
            || !int.TryParse(suffix[4..], NumberStyles.None, CultureInfo.InvariantCulture, out var month)
            || year is < 1 or > 9999
            || month is < 1 or > 12)
        {
            return null;
        }

        return new DateOnly(year, month, 1);
    }
}
