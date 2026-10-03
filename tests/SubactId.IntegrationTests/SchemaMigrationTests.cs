using Npgsql;
using SubactId.Storage.Postgres;
using Xunit;

namespace SubactId.IntegrationTests;

[Collection(PostgresCollection.Name)]
public class SchemaMigrationTests(PostgresDatabaseFixture postgres)
{
    private static readonly string[] ExpectedTables =
    [
        "agents", "tasks", "task_grants", "audit_events", "audit_checkpoints", "audit_archives", "audit_outbox", "revocations", "assertion_replays",
    ];

    [Fact]
    public async Task Migrations_apply_to_a_clean_database_and_are_idempotent()
    {
        await postgres.EnsureMigratedAsync();

        var second = await MigrationRunner.ApplyAsync(postgres.ApplicationConnectionString);

        Assert.Empty(second.AppliedNow);
        Assert.NotEmpty(second.AllApplied);

        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var tables = await QueryStringsAsync(
            connection,
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'");

        foreach (var table in ExpectedTables)
        {
            Assert.Contains(table, tables);
        }
    }

    /// <summary>
    /// The checkpoints are guarded like the ledger: the privilege is revoked from every role, and a
    /// trigger refuses regardless of privileges.
    /// </summary>
    [Theory]
    [InlineData("audit_events", "UPDATE", false)]
    [InlineData("audit_events", "DELETE", false)]
    [InlineData("audit_events", "TRUNCATE", false)]
    [InlineData("audit_events", "INSERT", true)]
    [InlineData("audit_events", "SELECT", true)]
    [InlineData("audit_checkpoints", "UPDATE", false)]
    [InlineData("audit_checkpoints", "DELETE", false)]
    [InlineData("audit_checkpoints", "TRUNCATE", false)]
    [InlineData("audit_checkpoints", "INSERT", true)]
    [InlineData("audit_checkpoints", "SELECT", true)]
    public async Task Application_role_privileges_on_the_ledger_and_its_seal(string table, string privilege, bool expected)
    {
        await postgres.EnsureMigratedAsync();
        await using var connection = await postgres.OpenApplicationConnectionAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT has_table_privilege(@role, @table, @privilege)";
        command.Parameters.AddWithValue("role", postgres.ApplicationRole);
        command.Parameters.AddWithValue("table", table);
        command.Parameters.AddWithValue("privilege", privilege);

        Assert.Equal(expected, (bool)(await command.ExecuteScalarAsync())!);
    }

    [Theory]
    [InlineData("chain")]
    [InlineData("prev_hash")]
    [InlineData("hash")]
    public async Task The_ledger_no_longer_carries_the_chain(string column)
    {
        await postgres.EnsureMigratedAsync();
        await using var connection = await postgres.OpenApplicationConnectionAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'audit_events' AND column_name = @column";
        command.Parameters.AddWithValue("column", column);

        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
    }

    [Theory]
    [InlineData("audit_events", "UPDATE audit_events SET reason = 'tampered' WHERE seq = @seq")]
    [InlineData("audit_events", "DELETE FROM audit_events WHERE seq = @seq")]
    [InlineData("audit_checkpoints", "UPDATE audit_checkpoints SET tree_size = 99 WHERE checkpoint_id = @seq")]
    [InlineData("audit_checkpoints", "DELETE FROM audit_checkpoints WHERE checkpoint_id = @seq")]
    public async Task The_ledger_and_its_seal_reject_changes_even_if_the_privilege_is_granted_back(string table, string sql)
    {
        await postgres.EnsureMigratedAsync();
        await using var connection = await postgres.OpenApplicationConnectionAsync();
        var seq = table == "audit_events" ? await InsertAuditEventAsync(connection) : await InsertCheckpointAsync(connection);

        // Without the privilege Postgres refuses outright.
        var denied = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, sql, seq));
        Assert.Equal("42501", denied.SqlState);

        // The role owns the table, so it can grant the privilege back to itself; the trigger still refuses.
        await ExecuteAsync(connection, $"GRANT UPDATE, DELETE ON {table} TO {postgres.ApplicationRole}", seq);
        try
        {
            var blocked = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, sql, seq));
            Assert.Equal("P0001", blocked.SqlState);
            Assert.Contains("append-only", blocked.MessageText, StringComparison.Ordinal);
        }
        finally
        {
            await ExecuteAsync(connection, $"REVOKE UPDATE, DELETE ON {table} FROM {postgres.ApplicationRole}", seq);
        }
    }

    private static async Task<long> InsertAuditEventAsync(NpgsqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO audit_events (ts, event, decision, reason) VALUES (now(), 'token.denied', 'deny', 'test') RETURNING seq";
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static async Task<long> InsertCheckpointAsync(NpgsqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        // One past the last in every unique or ordered column: this class shares a database, so a
        // second call must not collide with the first.
        command.CommandText = """
            INSERT INTO audit_checkpoints (checkpoint_id, first_seq, last_seq, tree_size, root_hash, prev_checkpoint_hash, closed_at, kid, signature)
            SELECT next.id, next.id, next.id, 1, @root, NULL, now(), 'test-key', @signature
            FROM (SELECT COALESCE(MAX(checkpoint_id), 0) + 1 AS id FROM audit_checkpoints) AS next
            RETURNING checkpoint_id
            """;
        command.Parameters.AddWithValue("root", Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        command.Parameters.AddWithValue("signature", new byte[64]);
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, long seq)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        if (sql.Contains("@seq", StringComparison.Ordinal))
        {
            command.Parameters.AddWithValue("seq", seq);
        }

        await command.ExecuteNonQueryAsync();
    }

    private static async Task<List<string>> QueryStringsAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync();
        var values = new List<string>();
        while (await reader.ReadAsync())
        {
            values.Add(reader.GetString(0));
        }

        return values;
    }
}
