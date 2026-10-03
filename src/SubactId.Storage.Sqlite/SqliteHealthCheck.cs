using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Sqlite;

/// <summary>
/// Readiness probe for the embedded database: opens the file and runs a trivial query.
/// Descriptions never include the path.
/// </summary>
/// <param name="connectionString">The connection string built from the configured path.</param>
public sealed class SqliteHealthCheck(string connectionString) : IStorageHealthCheck
{
    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            await command.ExecuteScalarAsync(cancellationToken);

            return HealthCheckResult.Healthy("The embedded database is readable.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return HealthCheckResult.Unhealthy("The embedded database check timed out.");
        }
        catch (Exception exception)
        {
            return HealthCheckResult.Unhealthy("The embedded database is unreadable.", exception);
        }
    }
}
