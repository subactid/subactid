using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using SubactId.Server.Health;
using SubactId.Storage.Postgres;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Storage;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Health;

public class HealthEndpointsTests
{
    [Fact]
    public async Task Readiness_fails_while_the_database_is_unreachable_but_liveness_still_passes()
    {
        await using var provider = BuildProvider(PostgresHealthCheckTests.UnreachableConnectionString());
        var service = provider.GetRequiredService<HealthCheckService>();

        var readiness = await service.CheckHealthAsync(HealthEndpoints.IsReadinessCheck);
        var liveness = await service.CheckHealthAsync(HealthEndpoints.IsLivenessCheck);

        Assert.Equal(HealthStatus.Unhealthy, readiness.Status);
        Assert.Equal(HealthStatus.Unhealthy, readiness.Entries[HealthEndpoints.DatabaseCheckName].Status);
        Assert.Equal(HealthStatus.Healthy, liveness.Status);
        Assert.Empty(liveness.Entries);
    }

    [Fact]
    public void The_database_check_is_registered_for_readiness()
    {
        using var provider = BuildProvider(PostgresHealthCheckTests.UnreachableConnectionString());
        var registrations = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>().Value.Registrations;

        var database = Assert.Single(registrations, r => r.Name == HealthEndpoints.DatabaseCheckName);
        Assert.True(HealthEndpoints.IsReadinessCheck(database));
        Assert.False(HealthEndpoints.IsLivenessCheck(database));
        Assert.Equal(HealthStatus.Unhealthy, database.FailureStatus);
        Assert.Equal(TimeSpan.FromSeconds(5), database.Timeout);
    }

    private static ServiceProvider BuildProvider(string connectionString)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.AddPostgresStorage(connectionString);
        services.AddSingleton(SigningKeySet.CreateEphemeral());
        // Fetched just now, so the upstream check is Healthy and the database is the only thing
        // wrong with readiness here.
        services.AddSingleton<IUpstreamKeys>(new StaticUpstreamKeys(UpstreamTestData.Snapshot(fetchedAt: DateTimeOffset.UtcNow)));
        services.AddSubactIdHealthChecks();
        return services.BuildServiceProvider();
    }
}
