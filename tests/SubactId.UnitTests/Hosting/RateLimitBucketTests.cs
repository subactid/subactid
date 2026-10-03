using SubactId.Server.Configuration;
using SubactId.Server.Hosting;
using Xunit;

namespace SubactId.UnitTests.Hosting;

/// <summary>
/// The numbers the limiter is built from. The bucket holds <c>Burst</c> permits, so it must be
/// refilled often for <c>PermitsPerMinute</c> to be the sustained rate. Refilling a minute's
/// worth at once would discard everything above the burst.
/// </summary>
public class RateLimitBucketTests
{
    [Fact]
    public void A_refill_is_one_second_of_the_configured_rate()
    {
        var bucket = RateLimiting.BucketFor(new RateLimitOptions());

        Assert.Equal(TimeSpan.FromSeconds(1), bucket.ReplenishmentPeriod);
        Assert.Equal(10, bucket.TokensPerPeriod);
        Assert.Equal(RateLimitOptions.DefaultBurst, bucket.TokenLimit);
    }

    [Fact]
    public void The_configured_rate_is_reachable_within_a_minute()
    {
        // Guards against TokensPerPeriod set to the whole minute against a bucket sized for the
        // burst, which caps the sustained rate at the burst.
        var options = new RateLimitOptions();
        var bucket = RateLimiting.BucketFor(options);
        var refillsPerMinute = TimeSpan.FromMinutes(1) / bucket.ReplenishmentPeriod;

        var admittedPerMinute = Math.Min(bucket.TokensPerPeriod, bucket.TokenLimit) * refillsPerMinute;

        Assert.True(
            admittedPerMinute >= options.PermitsPerMinute,
            $"A source can be admitted {admittedPerMinute} times a minute, not the {options.PermitsPerMinute} that were configured.");
    }

    [Theory]
    [InlineData(600, 10)]
    [InlineData(60, 1)]
    [InlineData(100, 2)]
    [InlineData(1, 1)]
    public void A_rate_that_is_not_a_whole_number_of_permits_a_second_rounds_up(int permitsPerMinute, int expected)
    {
        // Rounds up, so a caller inside the configured rate is never refused.
        Assert.Equal(expected, new RateLimitOptions { PermitsPerMinute = permitsPerMinute }.PermitsPerSecond);
    }

    [Fact]
    public void A_burst_is_never_below_one_refill()
    {
        var options = new RateLimitOptions();

        Assert.True(options.Burst >= options.PermitsPerSecond, "The default bucket cannot hold one refill.");
    }

    [Fact]
    public void Nothing_is_queued_so_a_refused_caller_is_told_at_once()
    {
        // No queue: a queued caller holds a connection, which would exhaust sockets on a server shedding load.
        Assert.Equal(0, RateLimiting.BucketFor(new RateLimitOptions()).QueueLimit);
    }
}
