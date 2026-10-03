using System.Globalization;
using Npgsql;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using Xunit;

namespace SubactId.IntegrationTests.Audit;

/// <summary>
/// The ledger is partitioned by month, and the append-only guard must be on every partition, not
/// only the parent. A <c>TRUNCATE</c> naming a partition checks the partition's privileges and
/// fires only its own triggers. These tests address a real partition by name, with records in it.
/// </summary>
[Collection(PostgresCollection.Name)]
public class AuditPartitionTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    public Task InitializeAsync() => postgres.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task The_ledger_is_partitioned_by_month_with_its_runway_ahead_and_every_partition_guarded()
    {
        var layout = await InspectAsync();

        Assert.True(layout.Partitioned);
        var now = DateTimeOffset.UtcNow;
        Assert.NotNull(layout.Covering(now));
        Assert.True(layout.MonthsAhead(now) >= AuditOptions.DefaultPartitionMonthsAhead,
            $"the ledger has {layout.MonthsAhead(now)} month(s) of runway, fewer than the {AuditOptions.DefaultPartitionMonthsAhead} migrate leaves behind it");

        Assert.All(layout.Partitions, partition =>
        {
            Assert.True(partition.RefusesTruncate, $"'{partition.Name}' has no BEFORE TRUNCATE trigger of its own");
            Assert.True(partition.PrivilegesRevoked, $"'{partition.Name}' still grants UPDATE, DELETE or TRUNCATE");
            Assert.NotNull(partition.Month);
        });
    }

    /// <summary>
    /// Truncating a partition by name is refused. The privilege is granted back so that the trigger
    /// is what refuses.
    /// </summary>
    [Fact]
    public async Task A_partition_refuses_truncate_by_name_even_with_the_privilege_granted_back()
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var (partition, seq) = await AppendToTodaysPartitionAsync(connection);
        var before = await CountAsync(connection, partition);
        Assert.True(before > 0);

        var denied = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, $"TRUNCATE TABLE {partition}"));
        Assert.Equal("42501", denied.SqlState);

        await ExecuteAsync(connection, $"GRANT TRUNCATE ON {partition} TO {postgres.ApplicationRole}");
        try
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, $"TRUNCATE TABLE {partition}"));
            Assert.Equal("P0001", blocked.SqlState);
            Assert.Contains("append-only", blocked.MessageText, StringComparison.Ordinal);
        }
        finally
        {
            await ExecuteAsync(connection, $"REVOKE TRUNCATE ON {partition} FROM {postgres.ApplicationRole}");
        }

        Assert.Equal(before, await CountAsync(connection, partition));
        Assert.Equal(1L, await ScalarAsync(connection, $"SELECT count(*) FROM audit_events WHERE seq = {seq}"));
    }

    [Theory]
    [InlineData("UPDATE {0} SET reason = 'tampered' WHERE seq = {1}")]
    [InlineData("DELETE FROM {0} WHERE seq = {1}")]
    public async Task A_partition_refuses_a_change_by_name_even_with_the_privilege_granted_back(string sql)
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var (partition, seq) = await AppendToTodaysPartitionAsync(connection);
        var statement = string.Format(CultureInfo.InvariantCulture, sql, partition, seq);

        var denied = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, statement));
        Assert.Equal("42501", denied.SqlState);

        // The row trigger is cloned from the parent onto every partition.
        await ExecuteAsync(connection, $"GRANT UPDATE, DELETE ON {partition} TO {postgres.ApplicationRole}");
        try
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, statement));
            Assert.Equal("P0001", blocked.SqlState);
            Assert.Contains("append-only", blocked.MessageText, StringComparison.Ordinal);
        }
        finally
        {
            await ExecuteAsync(connection, $"REVOKE UPDATE, DELETE ON {partition} FROM {postgres.ApplicationRole}");
        }

        Assert.Equal(1L, await ScalarAsync(connection, $"SELECT count(*) FROM audit_events WHERE seq = {seq} AND reason = 'partition-guard'"));
    }

    /// <summary>
    /// Truncating the parent is refused by the privilege, and then by the parent's own trigger.
    /// </summary>
    [Fact]
    public async Task The_parent_refuses_truncate_even_with_the_privilege_granted_back()
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var (_, seq) = await AppendToTodaysPartitionAsync(connection);

        var denied = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, "TRUNCATE TABLE audit_events"));
        Assert.Equal("42501", denied.SqlState);

        await ExecuteAsync(connection, $"GRANT TRUNCATE ON audit_events TO {postgres.ApplicationRole}");
        try
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, "TRUNCATE TABLE audit_events"));
            Assert.Equal("P0001", blocked.SqlState);
        }
        finally
        {
            await ExecuteAsync(connection, $"REVOKE TRUNCATE ON audit_events FROM {postgres.ApplicationRole}");
        }

        Assert.Equal(1L, await ScalarAsync(connection, $"SELECT count(*) FROM audit_events WHERE seq = {seq}"));
    }

    /// <summary>
    /// With the parent's trigger dropped and the privilege granted, truncating the parent is still
    /// refused, because every partition's own trigger fires. Runs in a transaction that is rolled
    /// back, since <c>TRUNCATE</c> is transactional.
    /// </summary>
    [Fact]
    public async Task With_the_parents_trigger_gone_a_partitions_own_trigger_still_refuses()
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var (_, seq) = await AppendToTodaysPartitionAsync(connection);

        await using (var transaction = await connection.BeginTransactionAsync())
        {
            await ExecuteAsync(connection, "DROP TRIGGER audit_events_no_truncate ON audit_events");
            await ExecuteAsync(connection, $"GRANT TRUNCATE ON audit_events TO {postgres.ApplicationRole}");

            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, "TRUNCATE TABLE audit_events"));
            Assert.Equal("P0001", blocked.SqlState);
            Assert.Contains("append-only", blocked.MessageText, StringComparison.Ordinal);

            await transaction.RollbackAsync();
        }

        Assert.Equal(1L, await ScalarAsync(connection, $"SELECT count(*) FROM audit_events WHERE seq = {seq}"));
    }

    /// <summary>A record goes into the partition for its own month, not into a catch-all.</summary>
    [Fact]
    public async Task A_record_lands_in_the_partition_for_its_month_and_there_is_no_catch_all()
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var (partition, _) = await AppendToTodaysPartitionAsync(connection);

        Assert.Equal(PartitionNameFor(DateTimeOffset.UtcNow), partition);

        // There must be no default partition: a record in it would never be detached.
        Assert.Equal(0L, await ScalarAsync(
            connection,
            """
            SELECT count(*)
            FROM pg_catalog.pg_inherits i
            JOIN pg_catalog.pg_class p ON p.oid = i.inhrelid
            WHERE i.inhparent = to_regclass('audit_events')
              AND pg_catalog.pg_get_expr(p.relpartbound, p.oid) = 'DEFAULT'
            """));
    }

    /// <summary>A month with no partition is refused, not written somewhere else.</summary>
    [Fact]
    public async Task A_record_for_a_month_with_no_partition_is_refused()
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();

        // Forty years before this ledger existed, so no partition covers it.
        var outsideEveryPartition = DateTimeOffset.UtcNow.AddYears(-40).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var refused = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(
            connection,
            $"INSERT INTO audit_events (ts, event, decision, reason) VALUES ('{outsideEveryPartition} 00:00:00+00', 'token.denied', 'deny', 'no-partition')"));

        // A check violation, not a row written into a catch-all.
        Assert.Equal("23514", refused.SqlState);
    }

    [Fact]
    public async Task Topping_up_creates_a_missing_month_with_its_guard_and_does_nothing_the_second_time()
    {
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        var partitions = new PostgresAuditLedgerPartitions(dataSource);
        var month = DateTimeOffset.UtcNow.AddYears(30);

        var created = await partitions.EnsureAsync(month, 0);
        var again = await partitions.EnsureAsync(month, 0);

        Assert.Equal(1, created);
        Assert.Equal(0, again);

        var made = (await partitions.InspectAsync()).Covering(month);
        Assert.NotNull(made);
        Assert.True(made.Guarded, $"'{made.Name}' was created without its guard");
    }

    /// <summary>A partition whose trigger was dropped is reported.</summary>
    [Fact]
    public async Task A_partition_that_lost_its_trigger_is_reported()
    {
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        var partitions = new PostgresAuditLedgerPartitions(dataSource);
        var month = DateTimeOffset.UtcNow.AddYears(20);
        await partitions.EnsureAsync(month, 0);
        var name = PartitionNameFor(month);

        await using var connection = await postgres.OpenApplicationConnectionAsync();
        await ExecuteAsync(connection, $"DROP TRIGGER audit_events_no_truncate ON {name}");
        try
        {
            var reported = (await partitions.InspectAsync()).Partitions.Single(p => p.Name == name);

            Assert.False(reported.RefusesTruncate);
            Assert.False(reported.Guarded);
        }
        finally
        {
            await ExecuteAsync(connection, $"CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON {name} FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only()");
        }
    }

    /// <summary>A disabled trigger refuses nothing, so a partition carrying one is not guarded.</summary>
    [Fact]
    public async Task A_partition_whose_trigger_is_disabled_is_reported()
    {
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        var partitions = new PostgresAuditLedgerPartitions(dataSource);
        var month = DateTimeOffset.UtcNow.AddYears(25);
        await partitions.EnsureAsync(month, 0);
        var name = PartitionNameFor(month);

        await using var connection = await postgres.OpenApplicationConnectionAsync();
        await ExecuteAsync(connection, $"ALTER TABLE {name} DISABLE TRIGGER audit_events_no_truncate");
        try
        {
            Assert.False((await partitions.InspectAsync()).Partitions.Single(p => p.Name == name).RefusesTruncate);
        }
        finally
        {
            await ExecuteAsync(connection, $"ALTER TABLE {name} ENABLE TRIGGER audit_events_no_truncate");
        }
    }

    /// <summary>
    /// A partition's indexes are named after the parent index they copy, so query plans and index
    /// statistics show which index is which.
    /// </summary>
    [Fact]
    public async Task A_partitions_indexes_are_named_after_the_index_on_the_parent()
    {
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var partition = PartitionNameFor(DateTimeOffset.UtcNow);

        var named = new List<string>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT child.relname
                FROM pg_catalog.pg_index ix
                JOIN pg_catalog.pg_class child ON child.oid = ix.indexrelid
                WHERE ix.indrelid = to_regclass(@partition)
                  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conindid = ix.indexrelid)
                """;
            command.Parameters.AddWithValue("partition", partition);
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                named.Add(reader.GetString(0));
            }
        }

        var month = DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyyMM", CultureInfo.InvariantCulture);
        string[] onTheParent =
        [
            "ix_audit_events_agent_id_fingerprint_ts_seq",
            "ix_audit_events_deny_ts_seq",
            "ix_audit_events_jti",
            "ix_audit_events_sponsor_fingerprint_ts_seq",
            "ix_audit_events_task_id",
            "ix_audit_events_ts_seq",
        ];

        Assert.Equal(
            onTheParent.Select(parent => $"{parent}_{month}").Order(StringComparer.Ordinal),
            named.Order(StringComparer.Ordinal));
    }

    /// <summary>What the partition holding <paramref name="at"/> is called.</summary>
    private static string PartitionNameFor(DateTimeOffset at) =>
        PostgresAuditLedgerPartitions.NamePrefix + at.UtcDateTime.ToString("yyyyMM", CultureInfo.InvariantCulture);

    private async Task<AuditLedgerLayout> InspectAsync()
    {
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        return await new PostgresAuditLedgerPartitions(dataSource).InspectAsync();
    }

    /// <summary>Appends one record through the parent and returns the partition it landed in.</summary>
    private static async Task<(string Partition, long Seq)> AppendToTodaysPartitionAsync(NpgsqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO audit_events (ts, event, decision, reason)
            VALUES (now(), 'token.denied', 'deny', 'partition-guard')
            RETURNING seq, tableoid::regclass::text
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetString(1), reader.GetInt64(0));
    }

    private static async Task<long> CountAsync(NpgsqlConnection connection, string table) =>
        await ScalarAsync(connection, $"SELECT count(*) FROM {table}");

    private static async Task<long> ScalarAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
