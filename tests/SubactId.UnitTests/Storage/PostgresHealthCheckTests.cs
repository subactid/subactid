using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;
using SubactId.Storage.Postgres;
using Xunit;

namespace SubactId.UnitTests.Storage;

public class PostgresHealthCheckTests
{
    private const string PasswordSentinel = "SENTINEL-DO-NOT-LEAK";

    [Fact]
    public async Task Reports_unhealthy_when_the_database_is_unreachable_without_leaking_credentials()
    {
        await using var dataSource = new NpgsqlDataSourceBuilder(UnreachableConnectionString()).Build();
        var check = new PostgresHealthCheck(dataSource);

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.NotNull(result.Description);
        Assert.DoesNotContain(PasswordSentinel, result.Description, StringComparison.Ordinal);
        Assert.NotNull(result.Exception);
        Assert.DoesNotContain(PasswordSentinel, result.Exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_unhealthy_when_cancelled()
    {
        await using var dataSource = new NpgsqlDataSourceBuilder(UnreachableConnectionString()).Build();
        var check = new PostgresHealthCheck(dataSource);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        var result = await check.CheckHealthAsync(new HealthCheckContext(), cancelled.Token);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Null(result.Exception);
    }

    /// <summary>Points at a loopback port that nothing is listening on, so connecting fails immediately.</summary>
    internal static string UnreachableConnectionString()
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        return $"Host=127.0.0.1;Port={port};Username=subactid;Password={PasswordSentinel};Database=subactid;Timeout=2;Pooling=false";
    }
}
