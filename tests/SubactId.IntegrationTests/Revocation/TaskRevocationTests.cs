using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Revocation;

public abstract class TaskRevocationTests(IStorageFixture storage) : IAsyncLifetime
{
    private string agentA = null!;
    private string agentB = null!;

    // A fresh instance per test, so these are unique per test as the agent ids are.
    private readonly string liveId = UniqueId("task-live");
    private readonly string endedId = UniqueId("task-ended");

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        agentA = UniqueId("rev-a");
        agentB = UniqueId("rev-b");
        await using var db = storage.CreateDbContext();
        var agents = new EfAgentRepository(db, storage.Dialect);
        await agents.AddAsync(NewAgent(agentA));
        await agents.AddAsync(NewAgent(agentB));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>root (A) -> child (B) -> grandchild (A), plus an unrelated task of A; every task has a grant.</summary>
    private async Task<(string Root, string Child, string Grandchild, string Other)> SeedTreeAsync()
    {
        await using var db = storage.CreateDbContext();
        var tasks = new EfTaskRepository(db, storage.Dialect);
        var grants = new EfTaskGrantRepository(db, storage.Dialect);
        var root = LiveTask(agentA);
        var child = LiveTask(agentB, parentTaskId: root.TaskId);
        var grandchild = LiveTask(agentA, parentTaskId: child.TaskId) with { DelegationDepth = 3 };
        var other = LiveTask(agentA);
        foreach (var task in new[] { root, child, grandchild, other })
        {
            await tasks.AddAsync(task);
            var grant = NewGrant(task.AgentId, task.TaskId);
            await grants.AddAsync(grant);
            if (task.TaskId == root.TaskId)
            {
                // Two renewals on the root, so a revocation can be seen to carry the count out with it.
                Assert.Equal(1, await grants.MarkUsedAsync(agentA, grant.GrantHash, GrantScopes, GrantScopes, DateTimeOffset.UtcNow.AddMinutes(-2)));
                Assert.Equal(2, await grants.MarkUsedAsync(agentA, grant.GrantHash, GrantScopes, GrantScopes, DateTimeOffset.UtcNow.AddMinutes(-1)));
            }
        }

        return (root.TaskId, child.TaskId, grandchild.TaskId, other.TaskId);
    }

    [Fact]
    public async Task Revoking_a_root_revokes_the_whole_tree_across_agents_root_first_and_their_grants_and_is_idempotent()
    {
        var (root, child, grandchild, other) = await SeedTreeAsync();
        var at = DateTimeOffset.UtcNow;

        await using var db = storage.CreateDbContext();
        var revocation = storage.Revocation(db);
        var outcome = await revocation.RevokeTreeAsync(root, at, "operator_kill_switch");

        Assert.True(outcome.Found);
        Assert.Equal([root, child, grandchild], outcome.Revoked.Select(r => r.TaskId));
        Assert.Equal([agentA, agentB, agentA], outcome.Revoked.Select(r => r.AgentId));
        Assert.Equal([1, 2, 3], outcome.Revoked.Select(r => r.DelegationDepth));
        Assert.Equal([null, root, child], outcome.Revoked.Select(r => r.ParentTaskId));
        Assert.Equal([2, 0, 0], outcome.Revoked.Select(r => r.Renewals));

        await using var check = storage.CreateDbContext();
        var rows = await check.Tasks.AsNoTracking().Where(t => t.AgentId == agentA || t.AgentId == agentB).ToDictionaryAsync(t => t.TaskId);
        Assert.Equal([true, false, false], outcome.Revoked.Select(r => r.IsRoot));
        Assert.Equal((TaskRow.StatusRevoked, "operator_kill_switch"), (rows[root].Status, rows[root].RevocationReason));
        Assert.All(new[] { child, grandchild }, id => Assert.Equal((TaskRow.StatusRevoked, "parent_revoked"), (rows[id].Status, rows[id].RevocationReason)));
        Assert.Equal(at, rows[root].RevokedAt!.Value, TimeSpan.FromMilliseconds(1));
        Assert.Equal((TaskRow.StatusActive, null), (rows[other].Status, rows[other].RevocationReason));
        var grantRows = await check.TaskGrants.AsNoTracking().Where(g => g.AgentId == agentA || g.AgentId == agentB).ToDictionaryAsync(g => g.TaskId, g => g.RevokedAt);
        Assert.All(new[] { root, child, grandchild }, id => Assert.NotNull(grantRows[id]));
        Assert.Null(grantRows[other]);

        var again = await storage.Revocation(check).RevokeTreeAsync(root, at.AddSeconds(1), "operator_kill_switch");
        Assert.True(again.Found);
        Assert.Empty(again.Revoked);
        Assert.Equal(at, (await check.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == root)).RevokedAt!.Value, TimeSpan.FromMilliseconds(1));

        Assert.False((await storage.Revocation(check).RevokeTreeAsync(UniqueId("missing"), at, "operator_kill_switch")).Found);
    }

    [Fact]
    public async Task Revoking_a_child_leaves_its_parent_alive_and_a_revoked_middle_does_not_shield_its_descendants()
    {
        var (root, child, grandchild, _) = await SeedTreeAsync();
        var at = DateTimeOffset.UtcNow;
        await using var db = storage.CreateDbContext();
        var revocation = storage.Revocation(db);

        Assert.Equal([child, grandchild], (await revocation.RevokeTreeAsync(child, at, "client_revoked")).Revoked.Select(r => r.TaskId));
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == root)).Status);

        // Reset the grandchild to active: a live descendant under an already-revoked middle task. Revoking the root still reaches it.
        await db.Tasks.Where(t => t.TaskId == grandchild).ExecuteUpdateAsync(s => s.SetProperty(t => t.Status, TaskRow.StatusActive));
        Assert.Equal([root, grandchild], (await revocation.RevokeTreeAsync(root, at, "operator_kill_switch")).Revoked.Select(r => r.TaskId));
    }

    [Fact]
    public async Task Revoking_an_agents_tasks_takes_every_live_task_and_descendants_and_repeats_to_nothing()
    {
        var (root, child, grandchild, other) = await SeedTreeAsync();
        await using var db = storage.CreateDbContext();
        var revocation = storage.Revocation(db);

        var revoked = await revocation.RevokeAgentTasksAsync(agentA, DateTimeOffset.UtcNow, "operator_kill_switch");

        Assert.Equal(4, revoked.Count);
        Assert.Equal(new[] { root, child, grandchild, other }.OrderBy(x => x), revoked.Select(r => r.TaskId).OrderBy(x => x));
        // The grandchild is the agent's own task, so it is named by the revocation itself even though it is also reached through the child.
        Assert.Equal(new[] { root, other, grandchild }.OrderBy(x => x), revoked.Where(r => r.IsRoot).Select(r => r.TaskId).OrderBy(x => x));
        Assert.Equal("parent_revoked", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == child)).RevocationReason);
        Assert.Equal("operator_kill_switch", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == grandchild)).RevocationReason);
        Assert.Equal("operator_kill_switch", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == other)).RevocationReason);
        Assert.Empty(await revocation.RevokeAgentTasksAsync(agentA, DateTimeOffset.UtcNow, "operator_kill_switch"));
        Assert.Empty(await revocation.RevokeAgentTasksAsync(agentB, DateTimeOffset.UtcNow, "operator_kill_switch"));
    }

    [Fact]
    public async Task Revoking_a_humans_tasks_takes_every_agents_task_for_them_and_leaves_everyone_else_alone()
    {
        // Two people unique to this test. Other seeded tasks share one sponsor, so revoking that
        // human would reach rows other tests are using.
        var mine = UniqueId("human");
        var stranger = UniqueId("human");
        await using var db = storage.CreateDbContext();
        var tasks = new EfTaskRepository(db, storage.Dialect);
        var grants = new EfTaskGrantRepository(db, storage.Dialect);

        // One agent's task, another agent's task delegated from it, and a task of a different person.
        var root = LiveTask(agentA, sponsor: mine);
        var child = LiveTask(agentB, parentTaskId: root.TaskId, sponsor: mine);
        var theirs = LiveTask(agentA, sponsor: stranger);
        foreach (var task in (DelegationTask[])[root, child, theirs])
        {
            await tasks.AddAsync(task);
            await grants.AddAsync(NewGrant(task.AgentId, task.TaskId));
        }

        var revocation = storage.Revocation(db);
        var revoked = await revocation.RevokeSponsorTasksAsync(mine, DateTimeOffset.UtcNow, "sponsor_blocked");

        // Both of theirs, whichever agent holds them, and nothing of the other person's.
        Assert.Equal(new[] { root.TaskId, child.TaskId }.OrderBy(x => x, StringComparer.Ordinal), revoked.Select(r => r.TaskId).OrderBy(x => x, StringComparer.Ordinal));
        Assert.Equal("sponsor_blocked", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == root.TaskId)).RevocationReason);
        Assert.Equal("sponsor_blocked", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == child.TaskId)).RevocationReason);
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == theirs.TaskId)).Status);

        // Their grants went with them, the other person's did not, and a repeat finds nothing.
        Assert.False(await db.TaskGrants.AsNoTracking().AnyAsync(g => g.TaskId == root.TaskId && g.RevokedAt == null));
        Assert.True(await db.TaskGrants.AsNoTracking().AnyAsync(g => g.TaskId == theirs.TaskId && g.RevokedAt == null));
        Assert.Empty(await revocation.RevokeSponsorTasksAsync(mine, DateTimeOffset.UtcNow, "sponsor_blocked"));
    }

    [Fact]
    public async Task Revoking_by_subject_takes_the_person_named_by_a_logout_token_whatever_key_their_tasks_hold()
    {
        // A logout token names a person by their sub. When the sponsor key claim is something else
        // the two columns differ, and this walk must read the one the provider used.
        var subject = UniqueId("human");
        var key = UniqueId("oid");
        await using var db = storage.CreateDbContext();
        var tasks = new EfTaskRepository(db, storage.Dialect);
        var mine = LiveTask(agentA, sponsor: subject) with { SponsorKey = key };
        var theirs = LiveTask(agentA, sponsor: UniqueId("human"));
        await tasks.AddAsync(mine);
        await tasks.AddAsync(theirs);
        var revocation = storage.Revocation(db);

        var revoked = await revocation.RevokeSubjectTasksAsync(subject, DateTimeOffset.UtcNow, "sponsor_logged_out");

        Assert.Equal([mine.TaskId], revoked.Select(r => r.TaskId));
        Assert.Equal("sponsor_logged_out", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == mine.TaskId)).RevocationReason);
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == theirs.TaskId)).Status);
        Assert.Empty(await revocation.RevokeSubjectTasksAsync(subject, DateTimeOffset.UtcNow, "sponsor_logged_out"));
    }

    [Fact]
    public async Task Revoking_by_session_takes_that_session_only_and_never_a_task_without_one()
    {
        var subject = UniqueId("human");
        var session = UniqueId("session");
        await using var db = storage.CreateDbContext();
        var tasks = new EfTaskRepository(db, storage.Dialect);

        // The same person, signed in twice, plus a task from a provider that named no session.
        var here = LiveTask(agentA, sponsor: subject, sessionId: session);
        var elsewhere = LiveTask(agentB, sponsor: subject, sessionId: UniqueId("session"));
        var sessionless = LiveTask(agentA, sponsor: subject);
        foreach (var task in (DelegationTask[])[here, elsewhere, sessionless])
        {
            await tasks.AddAsync(task);
        }

        var revocation = storage.Revocation(db);
        var revoked = await revocation.RevokeSessionTasksAsync(session, DateTimeOffset.UtcNow, "sponsor_logged_out");

        Assert.Equal([here.TaskId], revoked.Select(r => r.TaskId));
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == elsewhere.TaskId)).Status);

        // A null session must never be matched, or one logout would end everything.
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == sessionless.TaskId)).Status);
    }

    [Fact]
    public async Task A_token_revocation_is_recorded_once_per_jti_while_task_and_agent_revocations_append()
    {
        await using var db = storage.CreateDbContext();
        var repository = new EfRevocationRepository(db, storage.Dialect);
        var jti = UniqueId("tok");
        var at = DateTimeOffset.UtcNow;

        Assert.True(await repository.AddAsync(new Core.Revocation.Revocation(jti, null, null, null, null, at, "client_revoked", agentA, at.AddMinutes(5))));
        Assert.False(await repository.AddAsync(new Core.Revocation.Revocation(jti, null, null, null, null, at.AddMinutes(1), "operator_kill_switch", "admin")));
        Assert.True(await repository.AddAsync(new Core.Revocation.Revocation(null, "task_x", null, null, null, at, "operator_kill_switch", "admin")));
        Assert.True(await repository.AddAsync(new Core.Revocation.Revocation(null, "task_x", null, null, null, at, "operator_kill_switch", "admin")));
        Assert.True(await repository.AddAsync(new Core.Revocation.Revocation(null, null, agentA, null, null, at, "operator_kill_switch", "admin")));

        var found = await repository.FindTokenAsync(jti);
        Assert.Equal((jti, "client_revoked", agentA), (found!.Jti, found.Reason, found.RevokedBy));
        Assert.Equal(at, found.RevokedAt, TimeSpan.FromMilliseconds(1));
        Assert.Equal(at.AddMinutes(5), found.ExpiresAt!.Value, TimeSpan.FromMilliseconds(1));
        Assert.Null(await repository.FindTokenAsync(UniqueId("nope")));
        await Assert.ThrowsAsync<ArgumentException>(() => repository.AddAsync(new Core.Revocation.Revocation(jti, "task_x", null, null, null, at, "r", null)));
    }

    [Fact]
    public async Task A_task_past_its_expiry_is_left_to_the_sweeper_rather_than_counted_and_recorded_as_revoked()
    {
        // A task whose expires_at has passed but the sweeper has not reached yet is not revoked and
        // gets no task.revoked record. Spec section 7: expiry is not a revocation.
        var at = DateTimeOffset.UtcNow;
        await using (var seed = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(seed, storage.Dialect);
            var grants = new EfTaskGrantRepository(seed, storage.Dialect);
            foreach (var task in new[] { LiveTask(agentA, taskId: liveId), Ended(at) })
            {
                await tasks.AddAsync(task);
                await grants.AddAsync(NewGrant(task.AgentId, task.TaskId));
            }
        }

        await using var db = storage.CreateDbContext();
        var revoked = await storage.Revocation(db).RevokeAgentTasksAsync(agentA, at, "operator_kill_switch");

        // Only the live one is counted, not the task that is over.
        Assert.Equal([liveId], revoked.Select(r => r.TaskId));

        await using var check = storage.CreateDbContext();
        var rows = await check.Tasks.AsNoTracking().Where(t => t.AgentId == agentA).ToDictionaryAsync(t => t.TaskId);
        Assert.Equal((TaskRow.StatusRevoked, "operator_kill_switch"), (rows[liveId].Status, rows[liveId].RevocationReason));

        // Untouched: still active, with nothing written about a revocation that did not happen.
        Assert.Equal((TaskRow.StatusActive, null), (rows[endedId].Status, rows[endedId].RevocationReason));
        Assert.Null(rows[endedId].RevokedAt);
    }

    [Fact]
    public async Task The_sweeper_still_expires_the_task_the_kill_switch_left_alone()
    {
        // The task that is over is left for the sweeper, so it still gets its task.expired record.
        var at = DateTimeOffset.UtcNow;
        await using (var seed = storage.CreateDbContext())
        {
            var tasks = new EfTaskRepository(seed, storage.Dialect);
            await tasks.AddAsync(Ended(at));
            await new EfTaskGrantRepository(seed, storage.Dialect).AddAsync(NewGrant(agentA, endedId));
        }

        await using (var kill = storage.CreateDbContext())
        {
            Assert.Empty(await storage.Revocation(kill).RevokeAgentTasksAsync(agentA, at, "operator_kill_switch"));
        }

        // Drained rather than swept once: the database is shared, so other tests' due tasks may come first.
        await using var sweep = storage.CreateDbContext();
        var expirySweep = storage.ExpirySweep(sweep);
        var expired = new List<string>();
        while (await expirySweep.ExpireDueAsync(at, 1000) is { Count: > 0 } batch)
        {
            expired.AddRange(batch.Select(e => e.TaskId));
        }

        Assert.Contains(endedId, expired);
        await using var check = storage.CreateDbContext();
        Assert.Equal(TaskRow.StatusExpired, (await check.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == endedId)).Status);
    }

    [Fact]
    public async Task Revoking_a_task_that_is_already_past_its_expiry_finds_it_and_revokes_nothing()
    {
        // DELETE /admin/tasks/{id} on such a task answers 200 with revoked_tasks 0, as a repeat
        // revocation does. Not 404, because the task exists.
        var at = DateTimeOffset.UtcNow;
        await using (var seed = storage.CreateDbContext())
        {
            await new EfTaskRepository(seed, storage.Dialect).AddAsync(Ended(at));
        }

        await using var db = storage.CreateDbContext();
        var outcome = await storage.Revocation(db).RevokeTreeAsync(endedId, at, "operator_kill_switch");

        Assert.True(outcome.Found);
        Assert.Empty(outcome.Revoked);
    }

    /// <summary>
    /// A task with time left on it. The shared builder dates expiry from a fixed past instant, so a
    /// task seeded from it unchanged is already over and is left to the sweeper.
    /// </summary>
    private static DelegationTask LiveTask(string agentId, string? taskId = null, string? parentTaskId = null, string? sponsor = null, string? sessionId = null) =>
        NewTask(agentId, taskId, parentTaskId, sponsor, sessionId) with { CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-2), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30) };

    /// <summary>
    /// A task of <c>agentA</c> that is over but still marked active, as every expired task is until
    /// the sweeper reaches it.
    /// </summary>
    private DelegationTask Ended(DateTimeOffset at) =>
        NewTask(agentA, taskId: endedId) with { CreatedAt = at.AddMinutes(-3), ExpiresAt = at.AddSeconds(-32) };
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresTaskRevocationTests(PostgresDatabaseFixture storage) : TaskRevocationTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteTaskRevocationTests(SqliteDatabaseFixture storage) : TaskRevocationTests(storage);
