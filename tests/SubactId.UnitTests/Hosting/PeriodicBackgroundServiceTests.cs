using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SubactId.Server.Hosting;
using Xunit;

namespace SubactId.UnitTests.Hosting;

public class PeriodicBackgroundServiceTests
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    /// <summary>A service that counts its passes, and fails as many of the first ones as it is told to.</summary>
    private sealed class CountingService(TimeProvider clock, bool passAtStart, int failFirst = 0)
        : PeriodicBackgroundService(Interval, clock, NullLogger.Instance, passAtStart)
    {
        private int passes;
        private int failures = failFirst;

        public int Passes => Volatile.Read(ref passes);

        protected override string PassName => "Counting pass";

        protected override Task RunPassAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref passes);
            if (Interlocked.Decrement(ref failures) >= 0)
            {
                throw new InvalidOperationException("told to fail");
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// A fake clock that reports when the service has armed its timer. The loop starts on its own
    /// schedule after <c>StartAsync</c>, so advancing the clock earlier would do nothing.
    /// </summary>
    private sealed class ArmingClock : TimeProvider
    {
        private readonly FakeTimeProvider inner = new();
        private readonly TaskCompletionSource armed = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Armed => armed.Task;

        public void Advance(TimeSpan by) => inner.Advance(by);

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow();

        public override TimeZoneInfo LocalTimeZone => inner.LocalTimeZone;

        public override long TimestampFrequency => inner.TimestampFrequency;

        public override long GetTimestamp() => inner.GetTimestamp();

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = inner.CreateTimer(callback, state, dueTime, period);
            armed.TrySetResult();
            return timer;
        }
    }

    [Fact]
    public async Task The_first_pass_runs_one_interval_after_start()
    {
        var clock = new ArmingClock();
        var service = new CountingService(clock, passAtStart: false);

        await service.StartAsync(CancellationToken.None);
        await clock.Armed;
        Assert.Equal(0, service.Passes);

        clock.Advance(Interval);
        await EventuallyAsync(() => service.Passes == 1);

        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_service_that_asks_for_a_pass_at_start_gets_one_before_the_first_tick_and_ticks_as_usual_after()
    {
        var clock = new ArmingClock();
        var service = new CountingService(clock, passAtStart: true);

        await service.StartAsync(CancellationToken.None);
        await clock.Armed;
        await EventuallyAsync(() => service.Passes == 1);

        clock.Advance(Interval);
        await EventuallyAsync(() => service.Passes == 2);

        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_pass_that_fails_at_start_is_a_failed_pass_like_any_other_and_the_ticks_go_on()
    {
        var clock = new ArmingClock();
        var service = new CountingService(clock, passAtStart: true, failFirst: 1);

        await service.StartAsync(CancellationToken.None);
        await clock.Armed;
        await EventuallyAsync(() => service.Passes == 1);

        clock.Advance(Interval);
        await EventuallyAsync(() => service.Passes == 2);

        await service.StopAsync(CancellationToken.None);
    }

    /// <summary>A pass runs on the loop's own thread, so the test waits for it.</summary>
    private static async Task EventuallyAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the pass did not run within ten seconds");
            await Task.Delay(10);
        }
    }
}
