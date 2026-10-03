using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SubactId.Server.Health;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Health;

public class SigningKeyHealthCheckTests
{
    [Fact]
    public async Task Reports_healthy_when_the_active_key_signs_and_verifies()
    {
        using var keys = SigningKeySet.CreateEphemeral();

        var result = await new SigningKeyHealthCheck(keys).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains(keys.Active.Kid, result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void Is_registered_as_a_readiness_check()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(SigningKeySet.CreateEphemeral());
        services.AddSingleton<IUpstreamKeys>(new StaticUpstreamKeys(UpstreamTestData.Snapshot()));
        services.AddSubactIdHealthChecks();
        using var provider = services.BuildServiceProvider();

        var registration = Assert.Single(provider.GetRequiredService<IOptions<HealthCheckServiceOptions>>().Value.Registrations, r => r.Name == "signing-key");

        Assert.True(HealthEndpoints.IsReadinessCheck(registration));
    }
}
