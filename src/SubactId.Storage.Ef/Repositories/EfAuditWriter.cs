using System.Data.Common;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// Appends records to <c>audit_events</c>. Records are sealed later by the sealing pass. Runs
/// inside the caller's unit of work, so a record commits with the mutation it records. When a sink
/// is configured, each record is also queued in the outbox in the same transaction. The sink itself
/// is never called here.
/// <para>
/// The insert takes the seal fence in shared mode in the same statement and holds it until commit,
/// so a late commit cannot land under an already signed root.
/// </para>
/// <para>
/// The SQL is hand-written and bypasses change tracking, since this is the busiest write path.
/// </para>
/// </summary>
public sealed class EfAuditWriter(SubactIdDbContext db, IUnitOfWork unitOfWork, IStorageDialect dialect, AuditOutboxSettings? outbox = null) : IAuditWriter
{
    /// <summary>Read back so each record can be told the sequence number the database gave it.</summary>
    private const string InsertedSeq = """ RETURNING "seq" """;

    /// <summary>The ledger's columns in the order <see cref="InsertAsync"/> binds them. Not <c>seq</c>, which the database allocates.</summary>
    private static readonly string[] EventColumns =
    [
        "ts", "event", "task_id", "agent_id", "sponsor", "audience", "scope",
        "jti", "delegation_depth", "decision", "reason", "count", "detail",
    ];

    /// <summary>The outbox columns in the order <see cref="QueueAsync"/> binds them.</summary>
    private static readonly string[] OutboxColumns = ["audit_seq", "created_at", "next_attempt_at", "attempts"];

    private readonly AuditOutboxSettings outbox = outbox ?? AuditOutboxSettings.Disabled;

    /// <inheritdoc />
    public async Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        var rows = await AppendRowsAsync([auditEvent], cancellationToken);
        return rows[0].Seq;
    }

    /// <inheritdoc />
    public async Task AppendAsync(IReadOnlyList<AuditEvent> auditEvents, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvents);

        if (auditEvents.Count > 0)
        {
            await AppendRowsAsync(auditEvents, cancellationToken);
        }
    }

    /// <summary>Inserts every record in one round trip and reads back the sequence numbers they were given.</summary>
    private Task<List<AuditEventRow>> AppendRowsAsync(IReadOnlyList<AuditEvent> auditEvents, CancellationToken cancellationToken)
    {
        // Each statement depends only on the record count.
        var insertSql = InsertSql("audit_events", EventColumns, auditEvents.Count, InsertedSeq);
        var outboxSql = this.outbox.Enabled ? InsertSql("audit_outbox", OutboxColumns, auditEvents.Count, string.Empty) : null;

        return unitOfWork.RunAsync(
            async ct =>
            {
                // Inside the unit of work, where the provider also checks the transaction kind.
                var insert = dialect.FenceAppend(db, insertSql);
                var written = auditEvents.Select(Row).ToList();
                await InsertAsync(insert, written, ct);

                // Queued in the same transaction, so only committed records are delivered.
                if (outboxSql is not null)
                {
                    await QueueAsync(outboxSql, written, ct);
                }

                return written;
            },
            cancellationToken);
    }

    /// <summary>One record, as the row it is stored as.</summary>
    private static AuditEventRow Row(AuditEvent auditEvent) =>
        new()
        {
            Ts = auditEvent.Ts.ToUniversalTime(),
            Event = auditEvent.Event,
            TaskId = auditEvent.TaskId,
            AgentId = auditEvent.AgentId,
            Sponsor = auditEvent.Sponsor,
            Audience = auditEvent.Audience,
            Scope = auditEvent.Scope,
            Jti = auditEvent.Jti,
            DelegationDepth = auditEvent.DelegationDepth,
            Decision = AuditDecisionCodes.ToCode(auditEvent.Decision),
            Reason = auditEvent.Reason,
            Count = auditEvent.Count,
            Detail = auditEvent.Detail,
        };

    /// <summary>Inserts the records in one statement and tells each the sequence number it was given.</summary>
    private async Task InsertAsync(FencedAppend insert, List<AuditEventRow> rows, CancellationToken cancellationToken)
    {
        await using var command = Command(insert.Sql);
        foreach (var row in rows)
        {
            Bind(command, dialect.Timestamp(row.Ts));
            Bind(command, row.Event);
            Bind(command, row.TaskId);
            Bind(command, row.AgentId);
            Bind(command, row.Sponsor);
            Bind(command, row.Audience);
            Bind(command, row.Scope);
            Bind(command, row.Jti);
            Bind(command, row.DelegationDepth);
            Bind(command, row.Decision);
            Bind(command, row.Reason);
            Bind(command, row.Count);
            Bind(command, row.Detail);
        }

        var assigned = new List<long>(rows.Count);
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            for (var skipped = 0; skipped < insert.ResultSetsBefore; skipped++)
            {
                // The seal fence's result sets come first and hold no records.
                await reader.NextResultAsync(cancellationToken);
            }

            while (await reader.ReadAsync(cancellationToken))
            {
                assigned.Add(reader.GetInt64(0));
            }
        }

        if (assigned.Count != rows.Count)
        {
            // Fail the transaction rather than queue a record under the wrong sequence number.
            throw new InvalidOperationException("The ledger did not return every appended record.");
        }

        // RETURNING order is not guaranteed, but sequence numbers are allocated in insert order,
        // so sorting them pairs each record with its own.
        assigned.Sort();
        for (var i = 0; i < rows.Count; i++)
        {
            rows[i].Seq = assigned[i];
        }
    }

    /// <summary>Queues each appended record for the external sink, in the transaction that appended it.</summary>
    private async Task QueueAsync(string sql, List<AuditEventRow> rows, CancellationToken cancellationToken)
    {
        var queuedAt = dialect.Timestamp(rows[0].Ts);
        await using var command = Command(sql);
        foreach (var row in rows)
        {
            Bind(command, row.Seq);
            Bind(command, queuedAt);
            Bind(command, queuedAt);
            Bind(command, 0);
        }

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>An <c>INSERT</c> of <paramref name="rows"/> rows, its placeholders numbered in the order <see cref="Bind"/> fills them.</summary>
    private static string InsertSql(string table, string[] columns, int rows, string tail)
    {
        var sql = new StringBuilder("INSERT INTO \"").Append(table).Append("\" (");
        for (var column = 0; column < columns.Length; column++)
        {
            sql.Append(column == 0 ? "\"" : ", \"").Append(columns[column]).Append('"');
        }

        sql.Append(") VALUES ");
        var placeholder = 0;
        for (var row = 0; row < rows; row++)
        {
            sql.Append(row == 0 ? "(" : ", (");
            for (var column = 0; column < columns.Length; column++)
            {
                sql.Append(column == 0 ? "@p" : ", @p").Append(placeholder++);
            }

            sql.Append(')');
        }

        return sql.Append(tail).ToString();
    }

    /// <summary>A statement on the unit of work's own connection and transaction, so it commits with the mutation it records.</summary>
    private DbCommand Command(string sql)
    {
        var transaction = db.Database.CurrentTransaction
            ?? throw new InvalidOperationException("An append to the audit ledger must run inside a unit of work.");

        var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction.GetDbTransaction();
        if (db.Database.GetCommandTimeout() is { } timeout)
        {
            command.CommandTimeout = timeout;
        }

        return command;
    }

    /// <summary>Binds the next placeholder. Values are never interpolated into the statement, only bound to it.</summary>
    private static void Bind(DbCommand command, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = $"@p{command.Parameters.Count}";
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
