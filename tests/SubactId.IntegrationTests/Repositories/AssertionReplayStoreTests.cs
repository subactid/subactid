using Microsoft.EntityFrameworkCore;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Repositories;

public abstract class AssertionReplayStoreTests(IStorageFixture storage) : IAsyncLifetime
{
    private string agentId = string.Empty;

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        await using var db = storage.CreateDbContext();
        agentId = UniqueId("agent");
        await new EfAgentRepository(db, storage.Dialect).AddAsync(NewAgent(agentId));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_jti_can_be_recorded_once_per_agent()
    {
        await using var db = storage.CreateDbContext();
        var store = new EfAssertionReplayStore(db, storage.Dialect);
        var jti = Guid.NewGuid().ToString("N");

        Assert.True(await store.TryRecordAsync(agentId, jti, Now.AddMinutes(6)));
        Assert.False(await store.TryRecordAsync(agentId, jti, Now.AddMinutes(6)));
        Assert.True(await store.TryRecordAsync(agentId, Guid.NewGuid().ToString("N"), Now.AddMinutes(6)));
    }

    [Fact]
    public async Task Sixteen_simultaneous_presentations_of_one_jti_admit_exactly_one()
    {
        var jti = Guid.NewGuid().ToString("N");
        var admitted = 0;

        await Parallel.ForAsync(0, 16, async (_, ct) =>
        {
            await using var db = storage.CreateDbContext();
            if (await new EfAssertionReplayStore(db, storage.Dialect).TryRecordAsync(agentId, jti, Now.AddMinutes(6), ct))
            {
                Interlocked.Increment(ref admitted);
            }
        });

        Assert.Equal(1, admitted);
    }

    [Fact]
    public async Task Purge_removes_only_expired_records()
    {
        await using var db = storage.CreateDbContext();
        var store = new EfAssertionReplayStore(db, storage.Dialect);
        var stale = Guid.NewGuid().ToString("N");
        var live = Guid.NewGuid().ToString("N");
        await store.TryRecordAsync(agentId, stale, Now.AddMinutes(-1));
        await store.TryRecordAsync(agentId, live, Now.AddMinutes(6));

        var removed = await store.PurgeExpiredAsync(Now);

        Assert.True(removed >= 1);
        Assert.True(await store.TryRecordAsync(agentId, stale, Now.AddMinutes(6)));
        Assert.False(await store.TryRecordAsync(agentId, live, Now.AddMinutes(6)));
    }

    [Fact]
    public async Task Records_disappear_with_their_agent()
    {
        await using var db = storage.CreateDbContext();
        var jti = Guid.NewGuid().ToString("N");
        await new EfAssertionReplayStore(db, storage.Dialect).TryRecordAsync(agentId, jti, Now.AddMinutes(6));

        Assert.True(await new EfAgentRepository(db, storage.Dialect).DeleteAsync(agentId));

        Assert.False(await db.AssertionReplays.AnyAsync(r => r.AgentId == agentId));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresAssertionReplayStoreTests(PostgresDatabaseFixture storage) : AssertionReplayStoreTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteAssertionReplayStoreTests(SqliteDatabaseFixture storage) : AssertionReplayStoreTests(storage);
