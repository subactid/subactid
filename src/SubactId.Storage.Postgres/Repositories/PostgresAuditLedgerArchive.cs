using System.Globalization;
using Npgsql;
using SubactId.Core.Audit;

namespace SubactId.Storage.Postgres.Repositories;

/// <summary>
/// Archives a month of the ledger: exports a range of sequence numbers, then detaches and drops
/// the partition once the export is verified.
/// <para>
/// The export uses <c>COPY … TO STDOUT</c>. Timestamps are formatted as UTC with microsecond
/// precision by the database, so the export does not depend on session settings.
/// </para>
/// <para>
/// Runs on its own connections, outside any unit of work.
/// </para>
/// </summary>
public sealed class PostgresAuditLedgerArchive(NpgsqlDataSource dataSource) : IAuditLedgerArchive
{
    /// <summary>How much of the export is held in memory at once while it is copied out.</summary>
    private const int BufferSize = 16 * 1024;

    /// <summary>
    /// The ledger's timestamp as exported: UTC, formatted by the database, independent of the
    /// session's time zone and date style.
    /// </summary>
    private const string TimestampExpression = """
        to_char("ts" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        """;

    /// <summary>The columns of a record's line, in the order the format reads them back.</summary>
    private static readonly string SelectList = string.Join(
        ", ",
        AuditArchiveFormat.Columns.Select(column => column == "ts" ? TimestampExpression : $"\"{column}\""));

    /// <inheritdoc />
    public async Task<long> ExportAsync(long firstSeq, long lastSeq, TextWriter destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfLessThan(firstSeq, 1);

        if (lastSeq < firstSeq)
        {
            // An empty range exports nothing.
            return 0;
        }

        // COPY takes no parameters. The bounds are computed numbers, not input.
        var sql = string.Create(
            CultureInfo.InvariantCulture,
            $"""COPY (SELECT {SelectList} FROM "audit_events" WHERE "seq" >= {firstSeq} AND "seq" <= {lastSeq} ORDER BY "seq") TO STDOUT""");

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        using var reader = await connection.BeginTextExportAsync(sql, cancellationToken);

        // Copied in blocks. Records are counted by newlines, since newlines inside values are escaped.
        var buffer = new char[BufferSize];
        var records = 0L;
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            for (var at = 0; at < read; at++)
            {
                if (buffer[at] == '\n')
                {
                    records++;
                }
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        return records;
    }

    /// <inheritdoc />
    public async Task<long?> HighestSeqAsync(string partition, CancellationToken cancellationToken = default)
    {
        var name = Quote(partition);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT max(\"seq\") FROM {name}";
        return await command.ExecuteScalarAsync(cancellationToken) is long seq ? seq : null;
    }

    /// <inheritdoc />
    public async Task<long?> DropAsync(string partition, long exportedThrough, CancellationToken cancellationToken = default)
    {
        var name = Quote(partition);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);

        // The detach and the check run in one transaction. The drop runs separately.
        //
        // Once DETACH holds its lock, no append is in flight, so the partition's highest sequence
        // number shows whether a record arrived after the export. If one did, the detach is rolled
        // back and the problem reported, since that record is in no export.
        //
        // If the drop fails, the detached partition is left for an operator to drop.
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
        {
            await using (var detach = connection.CreateCommand())
            {
                detach.Transaction = transaction;
                detach.CommandText = $"ALTER TABLE \"audit_events\" DETACH PARTITION {name}";
                await detach.ExecuteNonQueryAsync(cancellationToken);
            }

            long? highest;
            await using (var check = connection.CreateCommand())
            {
                check.Transaction = transaction;
                check.CommandText = $"SELECT max(\"seq\") FROM {name}";
                highest = await check.ExecuteScalarAsync(cancellationToken) is long seq ? seq : null;
            }

            if (highest > exportedThrough)
            {
                await transaction.RollbackAsync(cancellationToken);
                return highest;
            }

            await transaction.CommitAsync(cancellationToken);
        }

        await using (var drop = connection.CreateCommand())
        {
            drop.CommandText = $"DROP TABLE {name}";
            await drop.ExecuteNonQueryAsync(cancellationToken);
        }

        return null;
    }

    /// <summary>
    /// The partition's name, quoted, only if it follows this control plane's partition naming.
    /// Any other name is refused, so no other table can be dropped.
    /// </summary>
    /// <param name="partition">The partition's table name.</param>
    private static string Quote(string partition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partition);

        if (PostgresAuditLedgerPartitions.MonthOf(partition) is null)
        {
            throw new ArgumentException($"'{partition}' is not a name this control plane gives a ledger partition.", nameof(partition));
        }

        return $"\"{partition}\"";
    }
}
