using System.Globalization;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Server.Health;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class AuditLedgerPartitionHealthCheckTests
{
    private static readonly DateTimeOffset September = new(2026, 9, 19, 14, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task An_instance_whose_month_has_no_partition_is_not_ready()
    {
        // Every append would be refused, and with it the request it records, so the instance is
        // taken out of service.
        var check = Check(new AuditLedgerLayout(true, [Partition("audit_events_p202608")]));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("2026-09", result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_instance_whose_month_has_a_partition_is_ready()
    {
        var check = Check(new AuditLedgerLayout(true, [Partition("audit_events_p202609"), Partition("audit_events_p202610")]));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task A_provider_without_partitioning_has_nothing_to_answer()
    {
        var check = Check(new AuditLedgerLayout(false, []));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task A_layout_that_cannot_be_read_is_not_ready()
    {
        var check = new AuditLedgerPartitionHealthCheck(new FailingPartitions(), TimeProvider.System);

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.NotNull(result.Exception);
    }

    private static AuditLedgerPartitionHealthCheck Check(AuditLedgerLayout layout) =>
        new(new StaticPartitions(layout), new FakeTimeProvider(September));

    private static AuditLedgerPartition Partition(string name)
    {
        var year = int.Parse(name[^6..^2], CultureInfo.InvariantCulture);
        var month = int.Parse(name[^2..], CultureInfo.InvariantCulture);
        return new AuditLedgerPartition(name, new DateOnly(year, month, 1), RefusesTruncate: true, PrivilegesRevoked: true);
    }

    private sealed class StaticPartitions(AuditLedgerLayout layout) : IAuditLedgerPartitions
    {
        public Task<AuditLedgerLayout> InspectAsync(CancellationToken cancellationToken = default) => Task.FromResult(layout);

        public Task<int> EnsureAsync(DateTimeOffset from, int monthsAhead, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class FailingPartitions : IAuditLedgerPartitions
    {
        public Task<AuditLedgerLayout> InspectAsync(CancellationToken cancellationToken = default) =>
            Task.FromException<AuditLedgerLayout>(new InvalidOperationException("the catalogue could not be read"));

        public Task<int> EnsureAsync(DateTimeOffset from, int monthsAhead, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }
}
