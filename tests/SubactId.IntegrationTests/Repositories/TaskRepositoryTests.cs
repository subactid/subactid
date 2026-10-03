using SubactId.Core.Delegation;
using SubactId.Core.Storage;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Repositories;

public abstract class TaskRepositoryTests(IStorageFixture storage) : IAsyncLifetime
{
    private string agentId = string.Empty;
    private string otherAgentId = string.Empty;

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        await using var db = storage.CreateDbContext();
        var agents = new EfAgentRepository(db, storage.Dialect);
        agentId = UniqueId("agent");
        otherAgentId = UniqueId("other");
        await agents.AddAsync(NewAgent(agentId));
        await agents.AddAsync(NewAgent(otherAgentId));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Task_round_trips_and_is_invisible_to_other_agents()
    {
        var task = NewTask(agentId);
        await using var db = storage.CreateDbContext();
        var repository = new EfTaskRepository(db, storage.Dialect);
        await repository.AddAsync(task);

        var found = await repository.FindAsync(agentId, task.TaskId);
        Assert.NotNull(found);
        Assert.Equal(task with { Scopes = [] }, found with { Scopes = [] });
        Assert.Equal(task.Scopes, found.Scopes);

        Assert.Null(await repository.FindAsync(otherAgentId, task.TaskId));
    }

    [Fact]
    public async Task Duplicate_task_ids_are_rejected()
    {
        var task = NewTask(agentId);
        await using var db = storage.CreateDbContext();
        await new EfTaskRepository(db, storage.Dialect).AddAsync(task);

        await using var second = storage.CreateDbContext();
        await Assert.ThrowsAsync<DuplicateEntityException>(() => new EfTaskRepository(second, storage.Dialect).AddAsync(task));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresTaskRepositoryTests(PostgresDatabaseFixture storage) : TaskRepositoryTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteTaskRepositoryTests(SqliteDatabaseFixture storage) : TaskRepositoryTests(storage);
