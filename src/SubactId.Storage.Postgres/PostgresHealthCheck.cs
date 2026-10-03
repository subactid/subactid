using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Postgres;

/// <summary>
/// Readiness probe for Postgres. Opens a connection from the readiness pool (see
/// <see cref="StorageReadiness"/>) and runs a trivial query. Descriptions never include
/// connection details.
/// </summary>
public sealed class PostgresHealthCheck(NpgsqlDataSource dataSource) : IStorageHealthCheck
{
    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            await command.ExecuteScalarAsync(cancellationToken);

            return HealthCheckResult.Healthy("Postgres is reachable.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return HealthCheckResult.Unhealthy("Postgres check timed out.");
        }
        catch (Exception exception)
        {
            return HealthCheckResult.Unhealthy("Postgres is unreachable.", exception);
        }
    }
}
