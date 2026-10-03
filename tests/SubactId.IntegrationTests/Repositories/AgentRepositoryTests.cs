using SubactId.Core.Agents;
using SubactId.Core.Storage;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Repositories;

public abstract class AgentRepositoryTests(IStorageFixture storage) : IAsyncLifetime
{
    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Agent_round_trips_through_storage_unchanged()
    {
        var agent = NewAgent();
        await using (var db = storage.CreateDbContext())
        {
            await new EfAgentRepository(db, storage.Dialect).AddAsync(agent);
        }

        await using var read = storage.CreateDbContext();
        var found = await new EfAgentRepository(read, storage.Dialect).FindAsync(agent.AgentId);

        Assert.NotNull(found);
        Assert.Equal(agent with { AllowedScopes = [], AllowedAudiences = [], HighRiskAudiences = [] },
            found with { AllowedScopes = [], AllowedAudiences = [], HighRiskAudiences = [] });
        Assert.Equal(agent.AllowedScopes, found.AllowedScopes);
        Assert.Equal(agent.AllowedAudiences, found.AllowedAudiences);
        Assert.Equal(agent.HighRiskAudiences, found.HighRiskAudiences);
    }

    [Fact]
    public async Task Adding_the_same_agent_twice_is_a_duplicate()
    {
        var agent = NewAgent();
        await using var db = storage.CreateDbContext();
        var repository = new EfAgentRepository(db, storage.Dialect);
        await repository.AddAsync(agent);

        await using var second = storage.CreateDbContext();
        var exception = await Assert.ThrowsAsync<DuplicateEntityException>(() => new EfAgentRepository(second, storage.Dialect).AddAsync(agent));

        Assert.Equal("agent", exception.Entity);
        Assert.Equal(agent.AgentId, exception.Key);
    }

    [Fact]
    public async Task A_refused_duplicate_is_not_left_behind_for_a_later_save_to_retry()
    {
        var agent = NewAgent();
        await using (var db = storage.CreateDbContext())
        {
            await new EfAgentRepository(db, storage.Dialect).AddAsync(agent);
        }

        await using var second = storage.CreateDbContext();
        await Assert.ThrowsAsync<DuplicateEntityException>(() => new EfAgentRepository(second, storage.Dialect).AddAsync(agent with { DisplayName = "Impostor" }));

        Assert.Empty(second.ChangeTracker.Entries());
        Assert.Equal(0, await second.SaveChangesAsync());

        await using var read = storage.CreateDbContext();
        Assert.Equal(agent.DisplayName, (await new EfAgentRepository(read, storage.Dialect).FindAsync(agent.AgentId))!.DisplayName);
    }

    [Fact]
    public async Task Update_replaces_the_registration_and_reports_missing_agents()
    {
        var agent = NewAgent();
        await using var db = storage.CreateDbContext();
        var repository = new EfAgentRepository(db, storage.Dialect);
        await repository.AddAsync(agent);

        var changed = agent with { Enabled = false, AllowedScopes = ["jira:read"], UpdatedAt = Now.AddMinutes(1) };
        Assert.True(await repository.UpdateAsync(changed));
        Assert.False(await repository.UpdateAsync(changed with { AgentId = UniqueId("missing") }));

        await using var read = storage.CreateDbContext();
        var found = await new EfAgentRepository(read, storage.Dialect).FindAsync(agent.AgentId);
        Assert.NotNull(found);
        Assert.False(found.Enabled);
        Assert.Equal(["jira:read"], found.AllowedScopes);
        Assert.Equal(Now.AddMinutes(1), found.UpdatedAt);
    }

    [Fact]
    public async Task Delete_removes_the_agent_and_reports_missing_agents()
    {
        var agent = NewAgent();
        await using var db = storage.CreateDbContext();
        var repository = new EfAgentRepository(db, storage.Dialect);
        await repository.AddAsync(agent);

        Assert.True(await repository.DeleteAsync(agent.AgentId));
        Assert.False(await repository.DeleteAsync(agent.AgentId));
        Assert.Null(await repository.FindAsync(agent.AgentId));
    }

    [Fact]
    public async Task List_pages_through_the_registry_in_id_order_without_overlap_or_gap()
    {
        // The registry is shared with other tests, so the page walk is checked for these agents
        // and for order, not for an exact listing.
        var prefix = UniqueId("pg");
        var ids = new[] { prefix + "-c", prefix + "-a", prefix + "-e", prefix + "-b", prefix + "-d" };
        await using (var db = storage.CreateDbContext())
        {
            var repository = new EfAgentRepository(db, storage.Dialect);
            foreach (var id in ids)
            {
                await repository.AddAsync(NewAgent(id));
            }
        }

        await using var read = storage.CreateDbContext();
        var query = new EfAgentQuery(read);
        var seen = new List<string>();
        string? after = prefix;
        while (true)
        {
            var page = await query.ListAsync(after, 2);
            Assert.InRange(page.Count, 0, 2);
            seen.AddRange(page.Select(a => a.AgentId).Where(id => id.StartsWith(prefix + "-", StringComparison.Ordinal)));
            if (page.Count < 2 || !page[^1].AgentId.StartsWith(prefix + "-", StringComparison.Ordinal))
            {
                break;
            }

            after = page[^1].AgentId;
        }

        Assert.Equal(ids.Order(StringComparer.Ordinal), seen);
    }

    [Fact]
    public async Task A_second_update_waits_for_the_first_and_reads_what_it_wrote()
    {
        // The lost update behind a disable undone by a concurrent rename: both read the agent,
        // the disable commits, the rename writes enabled back. Locked, the second read waits.
        var agent = NewAgent();
        await using (var db = storage.CreateDbContext())
        {
            await new EfAgentRepository(db, storage.Dialect).AddAsync(agent);
        }

        await using var first = storage.CreateDbContext();
        await using var firstTransaction = await storage.Dialect.BeginTransactionAsync(first, CancellationToken.None);
        var firstRepository = new EfAgentRepository(first, storage.Dialect);
        var held = await firstRepository.FindForUpdateAsync(agent.AgentId);
        Assert.True(held!.Enabled);

        await using var second = storage.CreateDbContext();
        var secondRead = Task.Run(async () =>
        {
            await using var transaction = await storage.Dialect.BeginTransactionAsync(second, CancellationToken.None);
            var found = await new EfAgentRepository(second, storage.Dialect).FindForUpdateAsync(agent.AgentId);
            await transaction.CommitAsync();
            return found;
        });

        // Still waiting while the first holds the lock.
        await Task.WhenAny(secondRead, Task.Delay(TimeSpan.FromMilliseconds(500)));
        Assert.False(secondRead.IsCompleted);

        Assert.True(await firstRepository.UpdateAsync(held with { Enabled = false }));
        await firstTransaction.CommitAsync();

        var seen = await secondRead.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.NotNull(seen);
        Assert.False(seen.Enabled);
    }

    [Fact]
    public async Task Longest_max_token_ttl_is_the_largest_in_the_registry_measured_by_length()
    {
        await using var db = storage.CreateDbContext();
        var repository = new EfAgentRepository(db, storage.Dialect);

        // Storage does not enforce the registration limits, and this decides how long a retired
        // signing key stays published, so it must compare durations: "1.01:00:00" sorts before
        // "23:00:00" as text, but is two hours longer.
        await repository.AddAsync(NewAgent() with { MaxTaskTtl = TimeSpan.FromHours(23), MaxTokenTtl = TimeSpan.FromHours(23) });
        await repository.AddAsync(NewAgent() with { MaxTaskTtl = TimeSpan.FromHours(25), MaxTokenTtl = TimeSpan.FromHours(25) });

        Assert.Equal(TimeSpan.FromHours(25), await new EfAgentQuery(db).LongestMaxTokenTtlAsync());
    }

    [Fact]
    public async Task An_agents_held_key_set_round_trips_through_storage_unchanged()
    {
        var jwks = new AgentJwks(
        [
            new AgentJwk { Kid = "ec", Kty = "EC", Crv = "P-256", X = "AQAB", Y = "AQAB", Alg = "ES256", Use = "sig" },
            new AgentJwk { Kid = "rsa", Kty = "RSA", N = "AQAB", E = "AQAB", Alg = "RS256" },
        ]);
        var agent = NewAgent() with { JwksUri = null, Jwks = jwks };

        await using (var db = storage.CreateDbContext())
        {
            await new EfAgentRepository(db, storage.Dialect).AddAsync(agent);
        }

        await using var read = storage.CreateDbContext();
        var found = await new EfAgentRepository(read, storage.Dialect).FindAsync(agent.AgentId);

        Assert.NotNull(found);
        Assert.Null(found.JwksUri);
        Assert.Equal(jwks, found.Jwks);
        Assert.Equal(["ec", "rsa"], found.Jwks!.Keys.Select(k => k.Kid));
    }

    [Fact]
    public async Task Moving_an_agent_from_a_url_to_held_keys_and_back_leaves_only_one_of_them_set()
    {
        var jwks = new AgentJwks([new AgentJwk { Kid = "ec", Kty = "EC", Crv = "P-256", X = "AQAB", Y = "AQAB" }]);
        var agent = NewAgent();
        await using var db = storage.CreateDbContext();
        var repository = new EfAgentRepository(db, storage.Dialect);
        await repository.AddAsync(agent);

        Assert.True(await repository.UpdateAsync(agent with { JwksUri = null, Jwks = jwks }));
        var held = await repository.FindAsync(agent.AgentId);
        Assert.Null(held!.JwksUri);
        Assert.Equal(jwks, held.Jwks);

        Assert.True(await repository.UpdateAsync(agent with { Jwks = null }));
        var hosted = await repository.FindAsync(agent.AgentId);
        Assert.Null(hosted!.Jwks);
        Assert.NotNull(hosted.JwksUri);
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresAgentRepositoryTests(PostgresDatabaseFixture storage) : AgentRepositoryTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteAgentRepositoryTests(SqliteDatabaseFixture storage) : AgentRepositoryTests(storage);
