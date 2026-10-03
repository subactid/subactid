using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Tasks;

/// <summary>
/// The retention purge on both databases: only inactive tasks that expired before the cutoff are
/// removed, their grants go with them, and then the agent that ran them can be deleted.
/// </summary>
public abstract class TaskRetentionTests(IStorageFixture storage) : IAsyncLifetime
{
    private string agentId = null!;

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        agentId = UniqueId("retention");
        await using var db = storage.CreateDbContext();
        await new EfAgentRepository(db, storage.Dialect).AddAsync(NewAgent(agentId));

        // The purge counts every task it removes, and other tests leave finished tasks in the shared
        // database. Clear them first so the counts below are about this test's tasks.
        var purge = new EfTaskRetention(db);
        while (await purge.PurgeTerminalAsync(DateTimeOffset.UtcNow.AddYears(100), 1000) > 0)
        {
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Removes_only_terminal_tasks_that_expired_before_the_cutoff_with_their_grants()
    {
        var cutoff = Now;
        var oldExpired = NewTask(agentId) with { Status = DelegationTaskStatus.Expired, ExpiresAt = cutoff.AddDays(-1) };
        var oldRevoked = NewTask(agentId) with { Status = DelegationTaskStatus.Revoked, ExpiresAt = cutoff, RevokedAt = cutoff.AddDays(-2), RevocationReason = "operator_kill_switch" };
        var recentExpired = NewTask(agentId) with { Status = DelegationTaskStatus.Expired, ExpiresAt = cutoff.AddSeconds(1) };
        var activeButOverdue = NewTask(agentId) with { Status = DelegationTaskStatus.Active, ExpiresAt = cutoff.AddDays(-1) };
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            var grants = new EfTaskGrantRepository(db, storage.Dialect);
            foreach (var task in new[] { oldExpired, oldRevoked, recentExpired, activeButOverdue })
            {
                await tasks.AddAsync(task);
                await grants.AddAsync(NewGrant(agentId, task.TaskId));
            }
        }

        await using var purgeDb = storage.CreateDbContext();
        var removed = await new EfTaskRetention(purgeDb).PurgeTerminalAsync(cutoff, batchSize: 100);

        Assert.Equal(2, removed);
        await using var check = storage.CreateDbContext();
        var remaining = await check.Tasks.AsNoTracking().Where(t => t.AgentId == agentId).Select(t => t.TaskId).ToListAsync();
        Assert.Equal([recentExpired.TaskId, activeButOverdue.TaskId], remaining.OrderBy(id => id == recentExpired.TaskId ? 0 : 1));
        var grantsLeft = await check.TaskGrants.AsNoTracking().Where(g => g.AgentId == agentId).Select(g => g.TaskId).ToListAsync();
        Assert.Equal(remaining.OrderBy(id => id, StringComparer.Ordinal), grantsLeft.OrderBy(id => id, StringComparer.Ordinal));

        // Nothing else old enough is left, so a second purge is a no-op.
        Assert.Equal(0, await new EfTaskRetention(check).PurgeTerminalAsync(cutoff, batchSize: 100));
    }

    [Fact]
    public async Task A_task_another_task_was_delegated_from_waits_for_that_task()
    {
        var parent = NewTask(agentId) with { Status = DelegationTaskStatus.Revoked, ExpiresAt = Now.AddDays(-2), RevokedAt = Now.AddDays(-2), RevocationReason = "operator_kill_switch" };
        var child = NewTask(agentId, parentTaskId: parent.TaskId) with { Status = DelegationTaskStatus.Revoked, ExpiresAt = Now.AddDays(-1), RevokedAt = Now.AddDays(-2), RevocationReason = "parent_revoked" };
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            await tasks.AddAsync(parent);
            await tasks.AddAsync(child);
        }

        // The child expired more recently than the cutoff, so it stays, and the parent stays with it.
        await using var first = storage.CreateDbContext();
        Assert.Equal(0, await new EfTaskRetention(first).PurgeTerminalAsync(Now.AddDays(-1).AddSeconds(-1), batchSize: 100));

        // Once the child is old enough both go, the child in the first pass and the parent in the next.
        await using var second = storage.CreateDbContext();
        var purge = new EfTaskRetention(second);
        Assert.Equal(1, await purge.PurgeTerminalAsync(Now, batchSize: 100));
        Assert.Equal(1, await purge.PurgeTerminalAsync(Now, batchSize: 100));
        Assert.Equal(0, await purge.PurgeTerminalAsync(Now, batchSize: 100));
    }

    [Fact]
    public async Task Batch_size_bounds_one_purge_and_must_be_positive()
    {
        await using (var db = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(db, storage.Dialect);
            for (var i = 0; i < 3; i++)
            {
                await tasks.AddAsync(NewTask(agentId) with { Status = DelegationTaskStatus.Expired, ExpiresAt = Now.AddDays(-1) });
            }
        }

        await using var purgeDb = storage.CreateDbContext();
        var purge = new EfTaskRetention(purgeDb);
        Assert.Equal(2, await purge.PurgeTerminalAsync(Now, batchSize: 2));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => purge.PurgeTerminalAsync(Now, batchSize: 0));
    }

    [Fact]
    public async Task An_agent_can_be_deleted_once_its_finished_tasks_are_gone()
    {
        await using (var db = storage.CreateDbContext())
        {
            await new EfTaskRepository(db, storage.Dialect).AddAsync(NewTask(agentId) with { Status = DelegationTaskStatus.Expired, ExpiresAt = Now.AddDays(-1) });
        }

        await using (var before = storage.CreateDbContext())
        {
            await Assert.ThrowsAsync<SubactId.Core.Storage.DependentEntitiesException>(() => new EfAgentRepository(before, storage.Dialect).DeleteAsync(agentId));
        }

        await using (var purgeDb = storage.CreateDbContext())
        {
            Assert.Equal(1, await new EfTaskRetention(purgeDb).PurgeTerminalAsync(Now, batchSize: 100));
        }

        await using var after = storage.CreateDbContext();
        Assert.True(await new EfAgentRepository(after, storage.Dialect).DeleteAsync(agentId));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresTaskRetentionTests(PostgresDatabaseFixture storage) : TaskRetentionTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteTaskRetentionTests(SqliteDatabaseFixture storage) : TaskRetentionTests(storage);
