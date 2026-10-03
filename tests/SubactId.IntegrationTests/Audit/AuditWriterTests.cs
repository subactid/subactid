using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

public abstract class AuditWriterTests(IStorageFixture storage) : IAsyncLifetime
{
    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_record_is_written_as_it_was_given_and_told_the_sequence_number_it_got()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        var first = new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: UniqueId("agent"), Decision: AuditDecision.Allow);
        var second = new AuditEvent(Now.AddSeconds(1), AuditEvents.TokenDenied, AgentId: first.AgentId, Decision: AuditDecision.Deny, Reason: "invalid_scope");

        var firstSeq = await writer.AppendAsync(first);
        var secondSeq = await writer.AppendAsync(second);

        Assert.Equal(firstSeq + 1, secondSeq);
        var rows = await db.AuditEvents.AsNoTracking().Where(e => e.Seq >= firstSeq).OrderBy(e => e.Seq).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal((first.AgentId, "allow", (string?)null), (rows[0].AgentId, rows[0].Decision, rows[0].Reason));
        Assert.Equal(("deny", "invalid_scope"), (rows[1].Decision, rows[1].Reason));
        Assert.Equal(second.Ts, rows[1].Ts);
    }

    [Fact]
    public async Task A_bulk_append_writes_every_record_in_order_and_numbers_them_that_way()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        var agentId = UniqueId("bulk");
        var before = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: agentId, Decision: AuditDecision.Allow));
        var batch = Enumerable.Range(0, 5).Select(i => new AuditEvent(Now.AddSeconds(i + 1), AuditEvents.TaskExpired, $"task_{i}", agentId, Reason: "task_ttl_elapsed")).ToList();

        await writer.AppendAsync(batch);
        await writer.AppendAsync([]);
        var after = await writer.AppendAsync(new AuditEvent(Now.AddSeconds(10), AuditEvents.AgentDeleted, AgentId: agentId));

        var rows = await db.AuditEvents.AsNoTracking().Where(e => e.Seq >= before && e.Seq <= after).OrderBy(e => e.Seq).ToListAsync();
        Assert.Equal(7, rows.Count);

        // Records are numbered in the order the caller gave them, so a checkpoint's leaves are reproducible.
        Assert.Equal(batch.Select(b => b.TaskId), rows.Skip(1).Take(5).Select(r => r.TaskId));
        for (var i = 1; i < rows.Count; i++)
        {
            Assert.Equal(rows[i - 1].Seq + 1, rows[i].Seq);
        }
    }

    /// <summary>
    /// Appends take the seal fence shared, so they never wait on each other. Every record must
    /// arrive exactly once, with its own sequence number.
    /// </summary>
    [Fact]
    public async Task Concurrent_writers_from_separate_contexts_each_get_their_own_sequence_number()
    {
        var marker = UniqueId("burst");
        await Parallel.ForAsync(0, 16, async (worker, ct) =>
        {
            await using var db = storage.CreateDbContext();
            var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
            for (var i = 0; i < 10; i++)
            {
                await writer.AppendAsync(new AuditEvent(Now.AddMilliseconds(i), AuditEvents.TokenIssued, TaskId: marker, AgentId: $"w{worker}", DelegationDepth: 1, Decision: AuditDecision.Allow), ct);
            }
        });

        await using var read = storage.CreateDbContext();
        var burst = await read.AuditEvents.AsNoTracking().Where(e => e.TaskId == marker).OrderBy(e => e.Seq).ToListAsync();

        Assert.Equal(160, burst.Count);
        Assert.Equal(160, burst.Select(e => e.Seq).Distinct().Count());
        Assert.Equal(16, burst.Select(e => e.AgentId).Distinct().Count());
    }

    [Fact]
    public async Task An_audit_record_rolls_back_with_the_unit_of_work_it_runs_in()
    {
        await using var db = storage.CreateDbContext();
        var unitOfWork = new EfUnitOfWork(db, storage.Dialect);
        var writer = new EfAuditWriter(db, unitOfWork, storage.Dialect);
        var marker = UniqueId("rollback");

        await Assert.ThrowsAsync<InvalidOperationException>(() => unitOfWork.RunAsync<int>(async ct =>
        {
            await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: marker, Decision: AuditDecision.Allow), ct);
            throw new InvalidOperationException("mutation failed after the audit record");
        }));

        await using var read = storage.CreateDbContext();
        Assert.False(await read.AuditEvents.AnyAsync(e => e.AgentId == marker));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresAuditWriterTests(PostgresDatabaseFixture storage) : AuditWriterTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteAuditWriterTests(SqliteDatabaseFixture storage) : AuditWriterTests(storage);
