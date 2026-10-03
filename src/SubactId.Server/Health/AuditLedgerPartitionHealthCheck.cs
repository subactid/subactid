using System.Globalization;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using SubactId.Core.Audit;

namespace SubactId.Server.Health;

/// <summary>
/// Readiness: the ledger has a partition for the current month.
/// <para>
/// There is no default partition, so without one every audit append, and the operation it
/// records, fails. The instance becomes ready again once a partition exists. A provider without
/// partitioning is always ready.
/// </para>
/// </summary>
public sealed class AuditLedgerPartitionHealthCheck(IAuditLedgerPartitions partitions, TimeProvider clock) : IHealthCheck
{
    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        AuditLedgerLayout layout;
        try
        {
            layout = await partitions.InspectAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // An unreachable database is reported by the database check.
            return HealthCheckResult.Unhealthy("The audit ledger's partitions could not be read.", exception);
        }

        if (!layout.Partitioned)
        {
            return HealthCheckResult.Healthy("The ledger is one table; this provider has no partitioning.");
        }

        var now = clock.GetUtcNow();
        if (layout.Covering(now) is null)
        {
            return HealthCheckResult.Unhealthy(
                $"The audit ledger has no partition for {now.ToString("yyyy-MM", CultureInfo.InvariantCulture)}, so every append would be refused. Run 'SubactId.Server migrate'.");
        }

        return HealthCheckResult.Healthy($"The audit ledger has {layout.Partitions.Count} partition(s), {layout.MonthsAhead(now)} month(s) of them ahead of this one.");
    }
}
