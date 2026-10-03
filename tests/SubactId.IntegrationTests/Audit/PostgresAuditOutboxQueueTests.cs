using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

[Collection(PostgresCollection.Name)]
public class PostgresAuditOutboxQueueTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();

        // Deliver anything an earlier run left pending, so the claims below see only this test's entries.
        await using var db = postgres.CreateDbContext();
        var queue = new PostgresAuditOutboxQueue(db);
        var unitOfWork = new EfUnitOfWork(db, postgres.Dialect);
        while (await unitOfWork.RunAsync(async ct =>
        {
            var leftovers = await queue.ClaimDueAsync(DateTimeOffset.UtcNow.AddYears(1), 500, ct);
            await queue.RemoveDeliveredAsync(leftovers.Select(e => e.Id).ToList(), ct);
            return leftovers.Count == 500;
        }))
        {
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task The_writer_queues_one_entry_per_record_only_when_delivery_is_on()
    {
        await using var db = postgres.CreateDbContext();
        var silent = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
        var queuing = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect, new AuditOutboxSettings(true));
        var agentId = UniqueId("outbox");

        var unqueued = await silent.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: agentId));
        var single = await queuing.AppendAsync(new AuditEvent(Now.AddSeconds(1), AuditEvents.AgentUpdated, AgentId: agentId));
        await queuing.AppendAsync([new AuditEvent(Now.AddSeconds(2), AuditEvents.TaskExpired, "task_a", agentId), new AuditEvent(Now.AddSeconds(3), AuditEvents.TaskExpired, "task_b", agentId)]);

        var entries = await db.AuditOutbox.AsNoTracking().Where(o => o.AuditSeq >= unqueued).OrderBy(o => o.Id).ToListAsync();
        Assert.Equal([single, single + 1, single + 2], entries.Select(e => e.AuditSeq));
        Assert.All(entries, e => Assert.Equal((0, null), (e.Attempts, e.LastError)));
        Assert.Equal([Now.AddSeconds(1), Now.AddSeconds(2), Now.AddSeconds(2)], entries.Select(e => e.NextAttemptAt));
        Assert.Equal(entries.Select(e => e.NextAttemptAt), entries.Select(e => e.CreatedAt));
    }

    [Fact]
    public async Task A_rolled_back_append_queues_nothing()
    {
        await using var db = postgres.CreateDbContext();
        var unitOfWork = new EfUnitOfWork(db, postgres.Dialect);
        var writer = new EfAuditWriter(db, unitOfWork, postgres.Dialect, new AuditOutboxSettings(true));
        var agentId = UniqueId("rollback");

        await Assert.ThrowsAsync<InvalidOperationException>(() => unitOfWork.RunAsync<int>(async ct =>
        {
            await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: agentId), ct);
            throw new InvalidOperationException("the mutation failed after the audit append");
        }));

        Assert.Equal(0, await db.AuditEvents.AsNoTracking().CountAsync(e => e.AgentId == agentId));
        Assert.Empty(await new EfUnitOfWork(db, postgres.Dialect).RunAsync(ct => new PostgresAuditOutboxQueue(db).ClaimDueAsync(DateTimeOffset.UtcNow.AddYears(1), 10, ct)));
    }

    [Fact]
    public async Task Claims_take_due_pending_entries_oldest_first_and_skip_what_another_drain_holds()
    {
        var agentId = UniqueId("claim");
        long firstSeq;
        await using (var setup = postgres.CreateDbContext())
        {
            var writer = new EfAuditWriter(setup, new EfUnitOfWork(setup, postgres.Dialect), postgres.Dialect, new AuditOutboxSettings(true));
            firstSeq = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: agentId));
            await writer.AppendAsync([new AuditEvent(Now, AuditEvents.TokenIssued, "t1", agentId), new AuditEvent(Now, AuditEvents.TokenRefreshed, "t1", agentId), new AuditEvent(Now, AuditEvents.TokenRefreshed, "t1", agentId)]);
        }

        await using var dbA = postgres.CreateDbContext();
        await using var dbB = postgres.CreateDbContext();
        var queueA = new PostgresAuditOutboxQueue(dbA);
        var queueB = new PostgresAuditOutboxQueue(dbB);

        // Not due yet: nothing to claim.
        Assert.Empty(await new EfUnitOfWork(dbA, postgres.Dialect).RunAsync(ct => queueA.ClaimDueAsync(Now.AddMilliseconds(-1), 10, ct)));

        // A holds the first two for the length of its transaction; B gets the rest, and A's mark commits with its claim.
        var claimedByA = await new EfUnitOfWork(dbA, postgres.Dialect).RunAsync(async ct =>
        {
            var claimed = await queueA.ClaimDueAsync(Now, 2, ct);
            var claimedByB = await new EfUnitOfWork(dbB, postgres.Dialect).RunAsync(ctB => queueB.ClaimDueAsync(Now, 10, ctB), ct);
            Assert.Equal([firstSeq + 2, firstSeq + 3], claimedByB.Select(e => e.AuditSeq));
            await queueA.MarkFailedAsync(claimed.Select(e => e.Id).ToList(), Now, "AuditSinkException: The audit sink answered 503.", Now.AddSeconds(30), ct);
            return claimed;
        });
        Assert.Equal([firstSeq, firstSeq + 1], claimedByA.Select(e => e.AuditSeq));
        Assert.All(claimedByA, e => Assert.Equal(0, e.Attempts));

        // The failed pair waits for its backoff; the other two are still due and now carry the attempt count.
        var due = await new EfUnitOfWork(dbB, postgres.Dialect).RunAsync(ct => queueB.ClaimDueAsync(Now.AddSeconds(29), 10, ct));
        Assert.Equal([firstSeq + 2, firstSeq + 3], due.Select(e => e.AuditSeq));
        var later = await new EfUnitOfWork(dbB, postgres.Dialect).RunAsync(ct => queueB.ClaimDueAsync(Now.AddSeconds(30), 10, ct));
        Assert.Equal([(firstSeq, 1), (firstSeq + 1, 1), (firstSeq + 2, 0), (firstSeq + 3, 0)], later.Select(e => (e.AuditSeq, e.Attempts)));

        // Delivered entries are deleted, not marked.
        await queueB.RemoveDeliveredAsync(later.Select(e => e.Id).ToList());
        Assert.Empty(await new EfUnitOfWork(dbA, postgres.Dialect).RunAsync(ct => queueA.ClaimDueAsync(Now.AddYears(1), 10, ct)));
        Assert.Empty(await dbA.AuditOutbox.AsNoTracking().Where(o => o.AuditSeq >= firstSeq).ToListAsync());
    }

    [Fact]
    public async Task A_failure_message_is_cut_to_what_the_store_holds()
    {
        await using var db = postgres.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect, new AuditOutboxSettings(true));
        var queue = new PostgresAuditOutboxQueue(db);
        var seq = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: UniqueId("long")));
        var id = await db.AuditOutbox.AsNoTracking().Where(o => o.AuditSeq == seq).Select(o => o.Id).SingleAsync();

        await queue.MarkFailedAsync([id], Now, new string('x', 5000), Now.AddYears(1));

        var stored = await db.AuditOutbox.AsNoTracking().Where(o => o.Id == id).Select(o => o.LastError).SingleAsync();
        Assert.Equal(PostgresAuditOutboxQueue.MaxErrorLength, stored!.Length);
    }
}
