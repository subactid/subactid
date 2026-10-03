using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Admin;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Tasks;

/// <summary>Two server instances sweeping the same database concurrently produce no duplicate audit events.</summary>
[Collection(PostgresCollection.Name)]
public class TaskExpirySweeperReplicaTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    public Task InitializeAsync() => postgres.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Two_replicas_sweeping_together_write_exactly_one_task_expired_record_per_task()
    {
        var agentId = UniqueId("replicas");
        var now = DateTimeOffset.UtcNow;
        var ids = new List<string>();
        await using (var db = postgres.CreateDbContext())
        {
            await new EfAgentRepository(db, postgres.Dialect).AddAsync(NewAgent(agentId));
            var tasks = new EfTaskRepository(db, postgres.Dialect);
            var grants = new EfTaskGrantRepository(db, postgres.Dialect);
            for (var i = 0; i < 40; i++)
            {
                var task = NewTask(agentId) with { ExpiresAt = now.AddSeconds(-1 - i) };
                ids.Add(task.TaskId);
                await tasks.AddAsync(task);
                await grants.AddAsync(NewGrant(agentId, task.TaskId));
            }
        }

        // Two hosts, each with its own sweeper on a one-second interval and small batches, against the same database.
        await using var replicaA = new SweeperReplicaFactory(postgres);
        await using var replicaB = new SweeperReplicaFactory(postgres);
        using var clientA = replicaA.CreateClient();
        using var clientB = replicaB.CreateClient();

        var deadline = DateTimeOffset.UtcNow.AddSeconds(20);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await using var poll = postgres.CreateDbContext();
            if (await poll.Tasks.AsNoTracking().CountAsync(t => t.AgentId == agentId && t.Status == TaskRow.StatusActive) == 0)
            {
                break;
            }

            await Task.Delay(250);
        }

        await using var check = postgres.CreateDbContext();
        Assert.Equal(0, await check.Tasks.AsNoTracking().CountAsync(t => t.AgentId == agentId && t.Status == TaskRow.StatusActive));
        Assert.Equal(40, await check.Tasks.AsNoTracking().CountAsync(t => t.AgentId == agentId && t.Status == TaskRow.StatusExpired));
        Assert.Equal(40, await check.TaskGrants.AsNoTracking().CountAsync(g => g.AgentId == agentId && g.RevokedAt != null));

        var events = await check.AuditEvents.AsNoTracking().Where(e => e.AgentId == agentId && e.Event == AuditEvents.TaskExpired).Select(e => e.TaskId!).ToListAsync();
        Assert.Equal(40, events.Count);
        Assert.Equal(40, events.Distinct().Count());
        Assert.True(ids.All(events.Contains));
    }
}

/// <summary>The database-backed server with the sweeper set to run every second in batches of seven, so a forty-task backlog takes several claims per replica.</summary>
internal sealed class SweeperReplicaFactory(PostgresDatabaseFixture postgres) : DatabaseServerFactory(postgres)
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            var configured = services.Single(d => d.ServiceType == typeof(SubactId.Server.Configuration.SubactIdOptions));
            var options = (SubactId.Server.Configuration.SubactIdOptions)configured.ImplementationInstance!;
            services.Remove(configured);
            services.AddSingleton(new SubactId.Server.Configuration.SubactIdOptions
            {
                Issuer = options.Issuer,
                UpstreamIdp = options.UpstreamIdp,
                Database = options.Database,
                Tokens = options.Tokens,
                Agents = options.Agents,
                Tasks = new SubactId.Server.Configuration.TaskSweepOptions { SweepInterval = TimeSpan.FromSeconds(1), BatchSize = 7 },
                Signing = options.Signing,
                Admin = options.Admin,
                Audit = options.Audit,
            });
        });
    }
}
