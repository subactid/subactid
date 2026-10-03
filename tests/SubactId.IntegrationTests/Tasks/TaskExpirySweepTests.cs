using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Tasks;

public abstract class TaskExpirySweepTests(IStorageFixture storage) : IAsyncLifetime
{
    /// <summary>An agent unique to this test class, so its tasks are never another class's.</summary>
    protected string AgentId { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        AgentId = UniqueId("sweep");
        await using var db = storage.CreateDbContext();
        await new EfAgentRepository(db, storage.Dialect).AddAsync(NewAgent(AgentId));

        // Other test classes leave expired tasks in the shared database. Clear them so each claim here is about this test's tasks.
        var sweep = storage.ExpirySweep(db);
        while ((await sweep.ExpireDueAsync(DateTimeOffset.UtcNow, 1000)).Count > 0)
        {
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Expires_only_active_tasks_whose_time_has_passed_and_revokes_their_grants()
    {
        var now = DateTimeOffset.UtcNow;
        var due = NewTask(AgentId) with { ExpiresAt = now.AddSeconds(-1) };
        var exactlyNow = NewTask(AgentId) with { ExpiresAt = now };
        var live = NewTask(AgentId) with { ExpiresAt = now.AddMinutes(10) };
        var revoked = NewTask(AgentId) with { ExpiresAt = now.AddMinutes(-5), Status = DelegationTaskStatus.Revoked, RevokedAt = now.AddMinutes(-6), RevocationReason = "operator_kill_switch" };
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            var grants = new EfTaskGrantRepository(db, storage.Dialect);
            var hashes = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
            foreach (var task in new[] { due, exactlyNow, live, revoked })
            {
                await tasks.AddAsync(task);
                var grant = NewGrant(AgentId, task.TaskId) with { ExpiresAt = task.ExpiresAt };
                await grants.AddAsync(grant);
                hashes[task.TaskId] = grant.GrantHash;
            }

            // Two renewals on the task that is due, so the sweep can be seen to carry the count out with it.
            Assert.Equal(1, await grants.MarkUsedAsync(AgentId, hashes[due.TaskId], GrantScopes, GrantScopes, now.AddMinutes(-2)));
            Assert.Equal(2, await grants.MarkUsedAsync(AgentId, hashes[due.TaskId], GrantScopes, GrantScopes, now.AddMinutes(-1)));
        }

        await using var sweepDb = storage.CreateDbContext();
        var expired = (await storage.ExpirySweep(sweepDb).ExpireDueAsync(now, batchSize: 100)).Where(e => e.AgentId == AgentId).ToList();

        Assert.Equal([due.TaskId, exactlyNow.TaskId], expired.Select(e => e.TaskId).OrderBy(id => id == due.TaskId ? 0 : 1));
        var first = expired.Single(e => e.TaskId == due.TaskId);
        Assert.Equal((AgentId, due.Sponsor, due.Audience, 1), (first.AgentId, first.Sponsor, first.Audience, first.DelegationDepth));
        Assert.Equal(due.Scopes, first.Scopes);
        Assert.Equal(due.ExpiresAt, first.ExpiresAt, TimeSpan.FromMilliseconds(1));
        Assert.Equal((2, 0), (first.Renewals, expired.Single(e => e.TaskId == exactlyNow.TaskId).Renewals));

        await using var check = storage.CreateDbContext();
        var rows = await check.Tasks.AsNoTracking().Where(t => t.AgentId == AgentId).ToDictionaryAsync(t => t.TaskId, t => t.Status);
        Assert.Equal((TaskRow.StatusExpired, TaskRow.StatusExpired, TaskRow.StatusActive, TaskRow.StatusRevoked), (rows[due.TaskId], rows[exactlyNow.TaskId], rows[live.TaskId], rows[revoked.TaskId]));
        var grantRows = await check.TaskGrants.AsNoTracking().Where(g => g.AgentId == AgentId).ToDictionaryAsync(g => g.TaskId, g => g.RevokedAt);
        Assert.NotNull(grantRows[due.TaskId]);
        Assert.NotNull(grantRows[exactlyNow.TaskId]);
        Assert.Null(grantRows[live.TaskId]);

        Assert.DoesNotContain(await storage.ExpirySweep(check).ExpireDueAsync(now, batchSize: 100), e => e.AgentId == AgentId);
    }

    [Fact]
    public async Task Batch_size_bounds_one_claim_and_must_be_positive()
    {
        var now = DateTimeOffset.UtcNow;
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            for (var i = 0; i < 3; i++) await tasks.AddAsync(NewTask(AgentId) with { ExpiresAt = now.AddSeconds(-1) });
        }

        await using var sweepDb = storage.CreateDbContext();
        var sweep = storage.ExpirySweep(sweepDb);
        Assert.Equal(2, (await sweep.ExpireDueAsync(now, batchSize: 2)).Count(e => e.AgentId == AgentId));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => sweep.ExpireDueAsync(now, batchSize: 0));
    }
}

/// <summary>The same tests against Postgres, plus the claim two sweepers make at the same moment.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresTaskExpirySweepTests(PostgresDatabaseFixture storage) : TaskExpirySweepTests(storage)
{
    [Fact]
    public async Task Two_sweepers_running_at_once_never_claim_the_same_task()
    {
        var now = DateTimeOffset.UtcNow;
        var ids = new List<string>();
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            for (var i = 0; i < 5; i++)
            {
                var task = NewTask(AgentId) with { ExpiresAt = now.AddSeconds(-i - 1) };
                ids.Add(task.TaskId);
                await tasks.AddAsync(task);
            }
        }

        // Sweeper A claims a batch and holds its transaction open; sweeper B runs meanwhile and must skip A's rows.
        await using var dbA = storage.CreateDbContext();
        await using var dbB = storage.CreateDbContext();
        await using var txA = await dbA.Database.BeginTransactionAsync();
        var claimedByA = await storage.ExpirySweep(dbA).ExpireDueAsync(now, batchSize: 3);
        await using var txB = await dbB.Database.BeginTransactionAsync();
        var claimedByB = await storage.ExpirySweep(dbB).ExpireDueAsync(now, batchSize: 100);
        await txA.CommitAsync();
        await txB.CommitAsync();

        var all = claimedByA.Concat(claimedByB).Select(e => e.TaskId).Where(ids.Contains).ToList();
        Assert.Equal(3, claimedByA.Count(e => e.AgentId == AgentId));
        Assert.Equal(5, all.Count);
        Assert.Equal(5, all.Distinct().Count());

        await using var after = storage.CreateDbContext();
        Assert.DoesNotContain(await storage.ExpirySweep(after).ExpireDueAsync(now, batchSize: 100), e => e.AgentId == AgentId);
    }
}

/// <summary>
/// The same tests against the embedded database. SQLite needs no skip-locked claim: a unit of
/// work holds the only write lock, so sweepers run one after another.
/// </summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteTaskExpirySweepTests(SqliteDatabaseFixture storage) : TaskExpirySweepTests(storage)
{
    [Fact]
    public async Task A_sweeper_that_runs_after_another_finds_nothing_left_to_claim()
    {
        var now = DateTimeOffset.UtcNow;
        var ids = new List<string>();
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            for (var i = 0; i < 5; i++)
            {
                var task = NewTask(AgentId) with { ExpiresAt = now.AddSeconds(-i - 1) };
                ids.Add(task.TaskId);
                await tasks.AddAsync(task);
            }
        }

        await using var first = storage.CreateDbContext();
        var claimed = await storage.ExpirySweep(first).ExpireDueAsync(now, batchSize: 100);

        await using var second = storage.CreateDbContext();
        var afterwards = await storage.ExpirySweep(second).ExpireDueAsync(now, batchSize: 100);

        Assert.Equal(5, claimed.Count(e => e.AgentId == AgentId));
        Assert.DoesNotContain(afterwards, e => e.AgentId == AgentId);
        Assert.Equal(5, claimed.Select(e => e.TaskId).Where(ids.Contains).Distinct().Count());
    }
}
