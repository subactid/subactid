using SubactId.Core.Storage;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Repositories;

public abstract class TaskGrantRepositoryTests(IStorageFixture storage) : IAsyncLifetime
{
    private string agentId = string.Empty;
    private string otherAgentId = string.Empty;
    private string taskId = string.Empty;

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        await using var db = storage.CreateDbContext();
        agentId = UniqueId("agent");
        otherAgentId = UniqueId("other");
        var agents = new EfAgentRepository(db, storage.Dialect);
        await agents.AddAsync(NewAgent(agentId));
        await agents.AddAsync(NewAgent(otherAgentId));
        var task = NewTask(agentId);
        taskId = task.TaskId;
        await new EfTaskRepository(db, storage.Dialect).AddAsync(task);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Grant_round_trips_and_is_unusable_by_a_different_agent()
    {
        var grant = NewGrant(agentId, taskId);
        await using var db = storage.CreateDbContext();
        var repository = new EfTaskGrantRepository(db, storage.Dialect);
        await repository.AddAsync(grant);

        var found = await repository.FindAsync(agentId, grant.GrantHash);
        Assert.NotNull(found);
        Assert.Equal(grant.GrantHash.ToArray(), found.GrantHash.ToArray());
        Assert.Equal(grant with { GrantHash = default, Scopes = [] }, found with { GrantHash = default, Scopes = [] });
        Assert.Equal(grant.Scopes, found.Scopes);

        Assert.Null(await repository.FindAsync(otherAgentId, grant.GrantHash));
        Assert.Null(await repository.MarkUsedAsync(otherAgentId, grant.GrantHash, GrantScopes, GrantScopes, Now.AddMinutes(1)));
        Assert.Equal(0, await repository.RevokeByTaskAsync(otherAgentId, taskId, Now.AddMinutes(1)));
    }

    [Fact]
    public async Task Duplicate_grant_hashes_are_rejected()
    {
        var grant = NewGrant(agentId, taskId);
        await using var db = storage.CreateDbContext();
        await new EfTaskGrantRepository(db, storage.Dialect).AddAsync(grant);

        await using var second = storage.CreateDbContext();
        await Assert.ThrowsAsync<DuplicateEntityException>(() => new EfTaskGrantRepository(second, storage.Dialect).AddAsync(grant));
    }

    [Fact]
    public async Task Marking_a_grant_used_records_the_time_and_numbers_the_use()
    {
        var grant = NewGrant(agentId, taskId);
        await using var db = storage.CreateDbContext();
        var repository = new EfTaskGrantRepository(db, storage.Dialect);
        await repository.AddAsync(grant);
        var usedAt = Now.AddMinutes(2);

        Assert.Equal(1, await repository.MarkUsedAsync(agentId, grant.GrantHash, GrantScopes, GrantScopes, usedAt));
        Assert.Equal(2, await repository.MarkUsedAsync(agentId, grant.GrantHash, GrantScopes, GrantScopes, usedAt.AddMinutes(1)));

        var found = (await repository.FindAsync(agentId, grant.GrantHash))!;
        Assert.Equal((usedAt.AddMinutes(1), 2), (found.LastUsedAt, found.Renewals));
        Assert.Equal(GrantScopes, found.Scopes);
    }

    [Fact]
    public async Task Marking_a_grant_used_keeps_the_narrowed_scopes_only_while_they_are_still_the_ones_read()
    {
        var grant = NewGrant(agentId, taskId) with { Scopes = ["jira:read", "jira:comment"] };
        await using var db = storage.CreateDbContext();
        var repository = new EfTaskGrantRepository(db, storage.Dialect);
        await repository.AddAsync(grant);

        Assert.Equal(1, await repository.MarkUsedAsync(agentId, grant.GrantHash, ["jira:read", "jira:comment"], ["jira:read"], Now.AddMinutes(1)));
        Assert.Equal(["jira:read"], (await repository.FindAsync(agentId, grant.GrantHash))!.Scopes);

        // A use decided against the scopes as they were before the narrowing writes nothing.
        Assert.Null(await repository.MarkUsedAsync(agentId, grant.GrantHash, ["jira:read", "jira:comment"], ["jira:read", "jira:comment"], Now.AddMinutes(2)));
        var found = (await repository.FindAsync(agentId, grant.GrantHash))!;
        Assert.Equal(["jira:read"], found.Scopes);
        Assert.Equal((Now.AddMinutes(1), 1), (found.LastUsedAt, found.Renewals));
    }

    [Fact]
    public async Task Revoking_by_task_revokes_every_live_grant_once()
    {
        var first = NewGrant(agentId, taskId);
        var second = NewGrant(agentId, taskId);
        await using var db = storage.CreateDbContext();
        var repository = new EfTaskGrantRepository(db, storage.Dialect);
        await repository.AddAsync(first);
        await repository.AddAsync(second);
        var at = Now.AddMinutes(5);

        Assert.Equal(2, await repository.RevokeByTaskAsync(agentId, taskId, at));
        Assert.Equal(0, await repository.RevokeByTaskAsync(agentId, taskId, at.AddMinutes(1)));

        Assert.Equal(at, (await repository.FindAsync(agentId, first.GrantHash))!.RevokedAt);
        Assert.Equal(at, (await repository.FindAsync(agentId, second.GrantHash))!.RevokedAt);

        // A revoked grant cannot be marked used, so an issue racing the revocation fails inside its transaction.
        Assert.Null(await repository.MarkUsedAsync(agentId, first.GrantHash, GrantScopes, GrantScopes, at.AddMinutes(2)));
        Assert.Null((await repository.FindAsync(agentId, first.GrantHash))!.LastUsedAt);
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresTaskGrantRepositoryTests(PostgresDatabaseFixture storage) : TaskGrantRepositoryTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteTaskGrantRepositoryTests(SqliteDatabaseFixture storage) : TaskGrantRepositoryTests(storage);
