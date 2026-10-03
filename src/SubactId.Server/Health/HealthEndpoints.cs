using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using SubactId.Core.Audit;
using SubactId.Storage.Ef;

namespace SubactId.Server.Health;

/// <summary>
/// Liveness and readiness probes. Liveness only shows the process is serving requests.
/// Readiness runs every check tagged <see cref="ReadyTag"/> and returns 503 while any fails.
/// </summary>
public static class HealthEndpoints
{
    /// <summary>Tag that marks a health check as part of readiness.</summary>
    public const string ReadyTag = "ready";

    /// <summary>Route of the liveness probe.</summary>
    public const string LivenessPath = "/healthz";

    /// <summary>Route of the readiness probe.</summary>
    public const string ReadinessPath = "/readyz";

    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Name of the database readiness check, whichever provider is configured.</summary>
    public const string DatabaseCheckName = "database";

    /// <summary>Name of the readiness check that the ledger has a partition for this month.</summary>
    public const string AuditPartitionCheckName = "audit-partition";

    /// <summary>Registers the readiness checks: database, audit partition, signing key, upstream JWKS.</summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The health checks builder, for adding further checks.</returns>
    public static IHealthChecksBuilder AddSubactIdHealthChecks(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        return services
            .AddHealthChecks()
            .Add(new HealthCheckRegistration(DatabaseCheckName, provider => provider.GetRequiredService<IStorageHealthCheck>(), HealthStatus.Unhealthy, [ReadyTag], CheckTimeout))
            .Add(new HealthCheckRegistration(AuditPartitionCheckName, AuditPartitionCheck, HealthStatus.Unhealthy, [ReadyTag], CheckTimeout))
            .AddCheck<SigningKeyHealthCheck>("signing-key", HealthStatus.Unhealthy, [ReadyTag], CheckTimeout)
            .AddCheck<UpstreamJwksHealthCheck>("upstream-jwks", HealthStatus.Unhealthy, [ReadyTag], CheckTimeout);
    }

    /// <summary>
    /// The partition check. Uses the readiness storage (<see cref="StorageReadiness"/>) when the
    /// provider has one, so it is not queued behind requests.
    /// </summary>
    private static AuditLedgerPartitionHealthCheck AuditPartitionCheck(IServiceProvider provider) => new(
        provider.GetKeyedService<IAuditLedgerPartitions>(StorageReadiness.ServiceKey) ?? provider.GetRequiredService<IAuditLedgerPartitions>(),
        provider.GetService<TimeProvider>() ?? TimeProvider.System);

    /// <summary>Maps <see cref="LivenessPath"/> and <see cref="ReadinessPath"/>.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdHealthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Probes are never rate limited.
        endpoints.MapHealthChecks(LivenessPath, new HealthCheckOptions { Predicate = IsLivenessCheck }).DisableRateLimiting();
        endpoints.MapHealthChecks(ReadinessPath, new HealthCheckOptions { Predicate = IsReadinessCheck }).DisableRateLimiting();
    }

    /// <summary>Liveness runs no registered checks: reaching the endpoint is the signal.</summary>
    public static bool IsLivenessCheck(HealthCheckRegistration registration) => false;

    /// <summary>Readiness runs every check tagged <see cref="ReadyTag"/>.</summary>
    public static bool IsReadinessCheck(HealthCheckRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return registration.Tags.Contains(ReadyTag);
    }
}
