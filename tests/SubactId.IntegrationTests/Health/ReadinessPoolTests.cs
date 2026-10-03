using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;
using SubactId.Core.Audit;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres;
using Xunit;

namespace SubactId.IntegrationTests.Health;

/// <summary>
/// Readiness reports whether the database is reachable, using connections of its own. It must
/// answer even when every request connection is held.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class ReadinessPoolTests(PostgresDatabaseFixture postgres)
{
    [Fact]
    public async Task Readiness_answers_while_every_request_connection_is_held()
    {
        var connectionString = new NpgsqlConnectionStringBuilder(postgres.ApplicationConnectionString) { Pooling = true, MaxPoolSize = 1, Timeout = 2 }.ConnectionString;
        await using var provider = new ServiceCollection().AddLogging().AddPostgresStorage(connectionString).BuildServiceProvider();
        var requests = provider.GetRequiredService<NpgsqlDataSource>();
        await using var held = await requests.OpenConnectionAsync();

        var database = await provider.GetRequiredService<IStorageHealthCheck>().CheckHealthAsync(new HealthCheckContext());
        var layout = await provider.GetRequiredKeyedService<IAuditLedgerPartitions>(StorageReadiness.ServiceKey).InspectAsync();

        Assert.Equal(HealthStatus.Healthy, database.Status);
        Assert.True(layout.Partitioned);

        // Check the request pool really was exhausted.
        await Assert.ThrowsAnyAsync<NpgsqlException>(async () =>
        {
            await using var another = await requests.OpenConnectionAsync();
        });
    }
}
