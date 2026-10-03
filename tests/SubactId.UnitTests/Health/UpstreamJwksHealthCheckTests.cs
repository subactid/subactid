using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Time.Testing;
using SubactId.Server.Health;
using SubactId.Server.Upstream;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Health;

/// <summary>
/// What readiness says about the identity provider. While it is unreachable the instance keeps
/// serving from the keys it holds, so readiness answers 200 and reports the upstream as degraded.
/// </summary>
public class UpstreamJwksHealthCheckTests
{
    private static UpstreamJwksHealthCheck Check(StaticUpstreamKeys keys, FakeTimeProvider clock) => new(keys, clock);

    private static FakeTimeProvider Clock() => new(UpstreamTestData.Now);

    [Fact]
    public async Task Healthy_when_the_upstream_has_usable_keys()
    {
        var result = await Check(new StaticUpstreamKeys(UpstreamTestData.Snapshot()), Clock()).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("2 upstream signing key(s)", result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unhealthy_when_the_upstream_publishes_no_usable_key_or_cannot_be_fetched()
    {
        var empty = await Check(new StaticUpstreamKeys(UpstreamTestData.Snapshot("{\"keys\":[]}")), Clock()).CheckHealthAsync(new HealthCheckContext());
        var down = await Check(new StaticUpstreamKeys(UpstreamTestData.Snapshot(), failure: new HttpRequestException("down")), Clock()).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, empty.Status);
        Assert.Equal(HealthStatus.Unhealthy, down.Status);
    }

    [Fact]
    public async Task A_warm_cache_is_answered_from_without_fetching()
    {
        // The probe does not fetch: against a frozen provider it would hang until its timeout and then
        // report from the cache anyway.
        var keys = new StaticUpstreamKeys(UpstreamTestData.Snapshot());

        var result = await Check(keys, Clock()).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal(0, keys.Gets);
    }

    [Fact]
    public async Task An_upstream_that_stopped_answering_is_degraded_rather_than_healthy_or_unhealthy()
    {
        // The provider frozen (for example with SIGSTOP) while a task is live: readiness must say the
        // provider is gone.
        var clock = Clock();
        var keys = new StaticUpstreamKeys(UpstreamTestData.Snapshot());
        var check = Check(keys, clock);

        clock.Advance(UpstreamKeyRefresher.StaleAfter + TimeSpan.FromMinutes(1));
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // Degraded, which ASP.NET still answers 200 for: this instance can validate subject
        // tokens and issue exchanges from the keys it holds, so it is not out of rotation.
        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Equal(0, keys.Gets);
    }

    [Fact]
    public async Task One_missed_refresh_is_not_an_outage()
    {
        // Three intervals, so a provider restart or a blip is not reported.
        var clock = Clock();
        var check = Check(new StaticUpstreamKeys(UpstreamTestData.Snapshot()), clock);

        clock.Advance(UpstreamKeyRefresher.RefreshInterval + TimeSpan.FromSeconds(1));

        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(new HealthCheckContext())).Status);
    }

    [Fact]
    public async Task Before_the_first_successful_fetch_the_probe_still_fetches()
    {
        // Cold start is the one case where unhealthy is right, and the only case where the probe
        // fetches: there are no keys held yet.
        var keys = new StaticUpstreamKeys(UpstreamTestData.Snapshot(), failure: new HttpRequestException("down"));

        var result = await Check(keys, Clock()).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal(1, keys.Gets);
    }

    [Fact]
    public void The_staleness_threshold_is_three_refresh_intervals()
    {
        // Pinned because the health check depends on it: a shorter interval would report a degraded
        // upstream sooner than the docs say.
        Assert.Equal(TimeSpan.FromMinutes(5), UpstreamKeyRefresher.RefreshInterval);
        Assert.Equal(UpstreamKeyRefresher.RefreshInterval * 3, UpstreamKeyRefresher.StaleAfter);
    }
}
