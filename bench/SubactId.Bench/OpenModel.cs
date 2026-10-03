using System.Diagnostics;

namespace SubactId.Bench;

// Open-model load: a fixed arrival rate, whether or not earlier requests have returned, so the
// offered rate does not drop as the server slows.
//
// Latency is measured from when a request was due, not when it was sent, which avoids
// coordinated omission.
internal static class OpenModel
{
    // Arrivals are dispatched in 1 ms sweeps, not one timer each. Due times are computed from the
    // run's start, so they do not drift.
    private static readonly TimeSpan SweepInterval = TimeSpan.FromMilliseconds(1);

    // How long to wait for outstanding requests after the run before counting them as abandoned.
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(120);

    public static async Task<Recorder> RunAsync(
        double ratePerSecond,
        TimeSpan warmup,
        TimeSpan measure,
        Func<CancellationToken, Task<Outcome>> operation,
        CancellationToken cancellationToken)
    {
        var recorder = new Recorder();
        var total = warmup + measure;
        var intervalTicks = Stopwatch.Frequency / ratePerSecond;
        var startedWall = DateTimeOffset.UtcNow;
        var started = Stopwatch.GetTimestamp();
        var warmupEnds = started + (long)(warmup.TotalSeconds * Stopwatch.Frequency);
        var runEnds = started + (long)(total.TotalSeconds * Stopwatch.Frequency);
        var inFlight = new InFlight();

        // Every dispatched request. Only this loop adds to it, so a plain list is enough.
        var dispatched = new List<Task>();
        long arrival = 0;

        while (true)
        {
            var now = Stopwatch.GetTimestamp();
            if (now >= runEnds)
            {
                break;
            }

            // Dispatch everything already due, so a late sweep does not lower the offered rate.
            while (true)
            {
                var due = started + (long)(arrival * intervalTicks);
                if (due > now || due >= runEnds)
                {
                    break;
                }

                arrival++;
                dispatched.Add(Dispatch(due, due >= warmupEnds, warmupEnds, runEnds, operation, recorder, inFlight, cancellationToken));
            }

            await Task.Delay(SweepInterval, cancellationToken);
        }

        recorder.Offered = arrival;
        recorder.OfferedMeasured = Math.Max(0, arrival - (long)(warmup.TotalSeconds * ratePerSecond));
        recorder.MeasuredSeconds = measure.TotalSeconds;
        recorder.MeasuredFrom = startedWall + warmup;
        recorder.MeasuredTo = startedWall + warmup + measure;
        recorder.PeakInFlight = inFlight.Peak;

        // Wait for outstanding requests so their latency is recorded, up to DrainTimeout.
        var everything = Task.WhenAll(dispatched);
        if (await Task.WhenAny(everything, Task.Delay(DrainTimeout, cancellationToken)) != everything)
        {
            recorder.Abandoned = dispatched.Count(task => !task.IsCompleted);
        }

        return recorder;
    }

    private static async Task Dispatch(
        long due,
        bool measured,
        long warmupEnds,
        long runEnds,
        Func<CancellationToken, Task<Outcome>> operation,
        Recorder recorder,
        InFlight inFlight,
        CancellationToken cancellationToken)
    {
        inFlight.Enter();
        try
        {
            var outcome = await operation(cancellationToken).ConfigureAwait(false);
            var finished = Stopwatch.GetTimestamp();
            recorder.Completed(finished >= warmupEnds && finished < runEnds, outcome.Status is >= 200 and < 300);
            if (measured)
            {
                recorder.Record((finished - due) * 1000.0 / Stopwatch.Frequency, outcome);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var finished = Stopwatch.GetTimestamp();
            recorder.Completed(finished >= warmupEnds && finished < runEnds, success: false);
            if (measured)
            {
                recorder.Record((finished - due) * 1000.0 / Stopwatch.Frequency, new Outcome(0, "exception", null, null, null));
            }
        }
        finally
        {
            inFlight.Exit();
        }
    }

    private sealed class InFlight
    {
        private int current;
        private int peak;

        public int Peak => Volatile.Read(ref peak);

        public void Enter()
        {
            var now = Interlocked.Increment(ref current);
            var seen = Volatile.Read(ref peak);
            while (now > seen && Interlocked.CompareExchange(ref peak, now, seen) != seen)
            {
                seen = Volatile.Read(ref peak);
            }
        }

        public void Exit() => Interlocked.Decrement(ref current);
    }
}
