using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;

namespace SubactId.Bench;

// Stress runs: the rate changes in stages and results are reported per second as a timeline.
//
// Like OpenModel, arrivals follow an open model and latency is measured from the due time.
internal static class Stress
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromMilliseconds(1);

    // Requests still outstanding after this are counted as abandoned.
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(120);

    // "30@100,20@800,60@100": thirty seconds at 100/s, twenty at 800/s, sixty at 100/s. A rate
    // of 0 is a pause.
    public static IReadOnlyList<Stage> ParseProfile(string text)
    {
        var stages = new List<Stage>();
        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var at = part.IndexOf('@', StringComparison.Ordinal);
            if (at <= 0
                || !double.TryParse(part[..at], NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds)
                || !double.TryParse(part[(at + 1)..], NumberStyles.Float, CultureInfo.InvariantCulture, out var rate)
                || seconds <= 0
                || rate < 0)
            {
                throw new ArgumentException($"A stage is <seconds>@<rate>, with seconds above zero and a rate of zero or more; '{part}' is not one.");
            }

            stages.Add(new Stage(seconds, rate));
        }

        if (stages.Count == 0)
        {
            throw new ArgumentException("The profile has no stages.");
        }

        return stages;
    }

    public static async Task<Timeline> RunAsync(
        IReadOnlyList<Stage> stages,
        Func<CancellationToken, Task<Outcome>> operation,
        CancellationToken cancellationToken)
    {
        var timeline = new Timeline(stages);
        var startedWall = DateTimeOffset.UtcNow;
        var started = Stopwatch.GetTimestamp();
        var frequency = (double)Stopwatch.Frequency;
        var dispatched = new List<Task>();
        var inFlight = 0;

        var stageStart = 0.0;
        foreach (var stage in stages)
        {
            var stageEnd = stageStart + stage.Seconds;
            if (stage.Rate > 0)
            {
                // Due times are computed from the stage's start, so a late sweep dispatches the backlog.
                long arrival = 0;
                while (true)
                {
                    var elapsed = (Stopwatch.GetTimestamp() - started) / frequency;
                    while (true)
                    {
                        var dueAt = stageStart + (arrival / stage.Rate);
                        if (dueAt > elapsed || dueAt >= stageEnd)
                        {
                            break;
                        }

                        arrival++;
                        var due = started + (long)(dueAt * frequency);
                        dispatched.Add(DispatchAsync(due, dueAt, started, operation, timeline, () => Interlocked.Increment(ref inFlight), () => Interlocked.Decrement(ref inFlight), cancellationToken));
                    }

                    if (elapsed >= stageEnd)
                    {
                        break;
                    }

                    await Task.Delay(SweepInterval, cancellationToken);
                    timeline.ObserveInFlight(elapsed, Volatile.Read(ref inFlight));
                }
            }
            else
            {
                while ((Stopwatch.GetTimestamp() - started) / frequency < stageEnd)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
                    timeline.ObserveInFlight((Stopwatch.GetTimestamp() - started) / frequency, Volatile.Read(ref inFlight));
                }
            }

            stageStart = stageEnd;
        }

        var everything = Task.WhenAll(dispatched);
        if (await Task.WhenAny(everything, Task.Delay(DrainTimeout, cancellationToken)) != everything)
        {
            timeline.Abandoned = dispatched.Count(task => !task.IsCompleted);
        }

        timeline.StartedAt = startedWall;
        return timeline;
    }

    private static async Task DispatchAsync(
        long due,
        double dueAt,
        long started,
        Func<CancellationToken, Task<Outcome>> operation,
        Timeline timeline,
        Action enter,
        Action exit,
        CancellationToken cancellationToken)
    {
        enter();
        Outcome outcome;
        try
        {
            outcome = await operation(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            outcome = new Outcome(0, "exception", null, null, null);
        }
        finally
        {
            exit();
        }

        var finished = Stopwatch.GetTimestamp();
        timeline.Record(dueAt, (finished - started) / (double)Stopwatch.Frequency, (finished - due) * 1000.0 / Stopwatch.Frequency, outcome);
    }
}

internal sealed record Stage(double Seconds, double Rate);

// Per-second views of a run. `byArrival` groups by due second, for latency and outcomes as
// callers saw them. `byCompletion` groups by completion second, for throughput.
internal sealed class Timeline(IReadOnlyList<Stage> stages)
{
    private readonly ConcurrentDictionary<int, Bucket> byArrival = new();
    private readonly ConcurrentDictionary<int, Bucket> byCompletion = new();
    private readonly ConcurrentDictionary<int, int> peakInFlight = new();
    private readonly ConcurrentDictionary<string, int> outcomes = new();

    public IReadOnlyList<Stage> Stages { get; } = stages;

    public DateTimeOffset StartedAt { get; set; }

    public int Abandoned { get; set; }

    public void ObserveInFlight(double elapsedSeconds, int count) =>
        peakInFlight.AddOrUpdate((int)elapsedSeconds, count, (_, seen) => Math.Max(seen, count));

    public void Record(double dueSeconds, double finishedSeconds, double latencyMs, Outcome outcome)
    {
        var key = outcome.Error is { } error
            ? $"{outcome.Status}:{error}"
            : outcome.Status.ToString(CultureInfo.InvariantCulture);
        outcomes.AddOrUpdate(key, 1, static (_, count) => count + 1);
        byArrival.GetOrAdd((int)dueSeconds, static _ => new Bucket()).Add(latencyMs, key, outcome.Status);
        byCompletion.GetOrAdd((int)finishedSeconds, static _ => new Bucket()).Add(latencyMs, key, outcome.Status);
    }

    public IReadOnlyDictionary<string, int> TokenAnswers { get; set; } = new Dictionary<string, int>();

    public StressSummary Summarize(string name)
    {
        var seconds = (int)Math.Ceiling(Stages.Sum(stage => stage.Seconds));
        var last = Math.Max(seconds, byCompletion.Keys.DefaultIfEmpty(0).Max() + 1);
        var rows = new List<SecondRow>(last);
        var offeredAt = OfferedBySecond(seconds);
        for (var second = 0; second < last; second++)
        {
            byArrival.TryGetValue(second, out var arrived);
            byCompletion.TryGetValue(second, out var completed);
            peakInFlight.TryGetValue(second, out var flight);
            rows.Add(new SecondRow(
                second,
                second < offeredAt.Length ? offeredAt[second] : 0,
                completed?.Succeeded ?? 0,
                completed?.Failed ?? 0,
                arrived?.Percentile(0.50) ?? 0,
                arrived?.Percentile(0.99) ?? 0,
                arrived?.Max ?? 0,
                flight,
                arrived?.Outcomes ?? new SortedDictionary<string, int>()));
        }

        var all = new Bucket();
        foreach (var bucket in byArrival.Values)
        {
            all.Merge(bucket);
        }

        return new StressSummary(
            name,
            StartedAt,
            [.. Stages],
            all.Count,
            all.Succeeded,
            all.Percentile(0.50),
            all.Percentile(0.99),
            all.Max,
            Abandoned,
            new SortedDictionary<string, int>(outcomes.ToDictionary(pair => pair.Key, pair => pair.Value)),
            new SortedDictionary<string, int>(TokenAnswers.ToDictionary(pair => pair.Key, pair => pair.Value)),
            rows);
    }

    private int[] OfferedBySecond(int seconds)
    {
        var offered = new double[seconds + 1];
        var start = 0.0;
        foreach (var stage in Stages)
        {
            for (var t = start; t < start + stage.Seconds; t += 1)
            {
                var slice = Math.Min(1, start + stage.Seconds - t);
                offered[Math.Min((int)t, seconds)] += stage.Rate * slice;
            }

            start += stage.Seconds;
        }

        return [.. offered.Select(value => (int)Math.Round(value))];
    }

    private sealed class Bucket
    {
        private readonly List<double> latencies = [];
        private readonly SortedDictionary<string, int> outcomes = new(StringComparer.Ordinal);

        public int Count { get; private set; }

        public int Succeeded { get; private set; }

        public int Failed => Count - Succeeded;

        public double Max { get; private set; }

        public SortedDictionary<string, int> Outcomes
        {
            get
            {
                lock (this)
                {
                    return new SortedDictionary<string, int>(outcomes, StringComparer.Ordinal);
                }
            }
        }

        public void Add(double latencyMs, string outcome, int status)
        {
            lock (this)
            {
                latencies.Add(latencyMs);
                outcomes[outcome] = outcomes.TryGetValue(outcome, out var count) ? count + 1 : 1;
                Count++;
                if (status is >= 200 and < 300)
                {
                    Succeeded++;
                }

                Max = Math.Max(Max, latencyMs);
            }
        }

        public void Merge(Bucket other)
        {
            lock (other)
            {
                lock (this)
                {
                    latencies.AddRange(other.latencies);
                    foreach (var (outcome, count) in other.outcomes)
                    {
                        outcomes[outcome] = outcomes.TryGetValue(outcome, out var seen) ? seen + count : count;
                    }

                    Count += other.Count;
                    Succeeded += other.Succeeded;
                    Max = Math.Max(Max, other.Max);
                }
            }
        }

        public double Percentile(double fraction)
        {
            lock (this)
            {
                if (latencies.Count == 0)
                {
                    return 0;
                }

                var sorted = latencies.ToArray();
                Array.Sort(sorted);
                var rank = (int)Math.Ceiling(fraction * sorted.Length) - 1;
                return sorted[Math.Clamp(rank, 0, sorted.Length - 1)];
            }
        }
    }
}

internal sealed record SecondRow(
    int Second,
    int Offered,
    int Succeeded,
    int Failed,
    double P50,
    double P99,
    double Max,
    int PeakInFlight,
    SortedDictionary<string, int> Outcomes);

internal sealed record StressSummary(
    string Name,
    DateTimeOffset StartedAt,
    Stage[] Stages,
    int Completed,
    int Succeeded,
    double P50,
    double P99,
    double Max,
    int Abandoned,
    SortedDictionary<string, int> Outcomes,
    SortedDictionary<string, int> TokenAnswers,
    List<SecondRow> Seconds);
