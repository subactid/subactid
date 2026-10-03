using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace SubactId.Storage.Ef;

/// <summary>The readiness check for the configured database. Each provider registers its own.</summary>
public interface IStorageHealthCheck : IHealthCheck;
