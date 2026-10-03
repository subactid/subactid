using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Storage;

/// <summary>
/// What the embedded provider must get right on its own: the schema, the ledger guard, the
/// foreign keys, and the outbox claim without a skip-locked read.
/// </summary>
[Collection(SqliteCollection.Name)]
public class SqliteStorageTests(SqliteDatabaseFixture storage) : IAsyncLifetime
{
    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Migrations_apply_to_a_clean_database_and_are_idempotent()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"subactid-migrate-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "subactid.db");
        try
        {
            var first = await SubactId.Storage.Sqlite.MigrationRunner.ApplyAsync(path);
            var second = await SubactId.Storage.Sqlite.MigrationRunner.ApplyAsync(path);

            Assert.NotEmpty(first.AppliedNow);
            Assert.Equal(first.AppliedNow, first.AllApplied);
            Assert.Empty(second.AppliedNow);
            Assert.Equal(first.AllApplied, second.AllApplied);
            Assert.True(File.Exists(path));

            // Write-ahead logging is set once, on the file, so every later connection inherits it.
            await using var db = SubactId.Storage.Sqlite.SubactIdSqliteDbContextFactory.Create(path);
            Assert.Equal("wal", await ScalarAsync(db, "PRAGMA journal_mode"), StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("UPDATE audit_events SET reason = 'rewritten'")]
    [InlineData("DELETE FROM audit_events")]
    public async Task The_ledger_refuses_to_be_changed_or_emptied(string sql)
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: UniqueId("append-only"), Decision: AuditDecision.Allow));

        var exception = await Assert.ThrowsAsync<SqliteException>(() => db.Database.ExecuteSqlRawAsync(sql));

        Assert.Contains("append-only", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_append_under_a_transaction_that_does_not_hold_the_write_lock_is_refused()
    {
        await using var db = storage.CreateDbContext();

        // A transaction begun outside the unit of work is deferred, so it holds no write lock and
        // another writer could append before it commits.
        await using var deferred = await db.Database.BeginTransactionAsync();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: UniqueId("unlocked"), Decision: AuditDecision.Allow)));

        Assert.Contains("unit of work", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A batched append reads its sequence numbers back from the insert. A wrong number would look
    /// fine in the ledger but deliver a record to the sink as its neighbour, so the numbers are
    /// checked through the outbox. <see cref="SubactId.IntegrationTests.Audit.AuditWriterTests"/> covers
    /// appends on both providers; this covers a batch on the embedded provider.
    /// </summary>
    [Fact]
    public async Task A_batched_append_queues_each_record_under_the_sequence_number_it_was_given()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect, new AuditOutboxSettings(true));
        var agentId = UniqueId("batch");
        var first = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: agentId, Decision: AuditDecision.Allow));
        var batch = Enumerable.Range(0, 4)
            .Select(i => new AuditEvent(Now.AddSeconds(i + 1), AuditEvents.TaskExpired, $"task_{i}", agentId, Reason: "task_ttl_elapsed"))
            .ToList();

        await writer.AppendAsync(batch);

        var rows = await db.AuditEvents.AsNoTracking().Where(e => e.Seq >= first).OrderBy(e => e.Seq).ToListAsync();
        Assert.Equal(batch.Select(b => b.TaskId), rows.Skip(1).Select(r => r.TaskId));
        var queued = await db.AuditOutbox.AsNoTracking().Where(o => o.AuditSeq >= first).OrderBy(o => o.Id).Select(o => o.AuditSeq).ToListAsync();
        Assert.Equal(rows.Select(r => r.Seq), queued);
    }

    [Fact]
    public async Task Foreign_keys_are_enforced_so_a_task_cannot_name_an_agent_that_is_not_there()
    {
        await using var db = storage.CreateDbContext();
        var tasks = new EfTaskRepository(db, storage.Dialect);

        await Assert.ThrowsAnyAsync<DbUpdateException>(() => tasks.AddAsync(NewTask(UniqueId("absent"))));
    }

    [Fact]
    public async Task An_agent_with_tasks_cannot_be_deleted()
    {
        var agentId = UniqueId("in-use");
        await using var db = storage.CreateDbContext();
        await new EfAgentRepository(db, storage.Dialect).AddAsync(NewAgent(agentId));
        await new EfTaskRepository(db, storage.Dialect).AddAsync(NewTask(agentId));

        await Assert.ThrowsAsync<DependentEntitiesException>(() => new EfAgentRepository(db, storage.Dialect).DeleteAsync(agentId));
    }

    [Fact]
    public async Task The_outbox_hands_out_a_queued_record_once_and_holds_a_failed_one_back_until_its_next_attempt()
    {
        await using var db = storage.CreateDbContext();
        var unitOfWork = new EfUnitOfWork(db, storage.Dialect);
        var writer = new EfAuditWriter(db, unitOfWork, storage.Dialect, new AuditOutboxSettings(true));
        var queue = storage.OutboxQueue(db);
        var now = DateTimeOffset.UtcNow;

        // Whatever an earlier test queued is delivered out of the way first.
        await unitOfWork.RunAsync(async ct =>
        {
            while (await queue.ClaimDueAsync(now, 100, ct) is { Count: > 0 } pending)
            {
                await queue.RemoveDeliveredAsync(pending.Select(e => e.Id).ToList(), ct);
            }

            return true;
        });

        var seq = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.TokenIssued, AgentId: UniqueId("outbox"), Decision: AuditDecision.Allow));

        var claimed = await unitOfWork.RunAsync(ct => queue.ClaimDueAsync(now, 10, ct));
        var entry = Assert.Single(claimed);
        Assert.Equal(seq, entry.AuditSeq);
        Assert.Equal(0, entry.Attempts);

        // A failed delivery comes back only when its next attempt is due.
        await unitOfWork.RunAsync(ct => Mark(queue, entry.Id, now, ct));
        Assert.Empty(await unitOfWork.RunAsync(ct => queue.ClaimDueAsync(now, 10, ct)));
        var retried = Assert.Single(await unitOfWork.RunAsync(ct => queue.ClaimDueAsync(now.AddMinutes(1), 10, ct)));
        Assert.Equal(entry.Id, retried.Id);
        Assert.Equal(1, retried.Attempts);

        await unitOfWork.RunAsync(async ct =>
        {
            await queue.RemoveDeliveredAsync([entry.Id], ct);
            return true;
        });
        Assert.Empty(await unitOfWork.RunAsync(ct => queue.ClaimDueAsync(now.AddDays(1), 10, ct)));

        // Delivered, so the row is deleted.
        Assert.Equal(0, await db.AuditOutbox.AsNoTracking().CountAsync(o => o.Id == entry.Id));
    }

    private static async Task<bool> Mark(IAuditOutboxQueue queue, long id, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await queue.MarkFailedAsync([id], now, "the sink answered 500", now.AddSeconds(30), cancellationToken);
        return true;
    }

    private static async Task<string> ScalarAsync(SubactIdDbContext db, string sql)
    {
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = sql;
            return (string)(await command.ExecuteScalarAsync())!;
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }
}
