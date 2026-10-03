using System.Collections.Concurrent;

namespace SubactId.Bench;

// A run's results. All latencies are kept, not bucketed, so percentiles are exact.
internal sealed class Recorder
{
    private readonly ConcurrentBag<double> latencies = [];
    private readonly ConcurrentDictionary<string, int> outcomes = new();
    private int succeeded;
    private int succeededInWindow;

    public long Offered { get; set; }

    public long OfferedMeasured { get; set; }

    public double MeasuredSeconds { get; set; }

    // The measured wall-clock window, so measure.sh can match container CPU to it.
    public DateTimeOffset MeasuredFrom { get; set; }

    public DateTimeOffset MeasuredTo { get; set; }

    public int PeakInFlight { get; set; }

    public int Abandoned { get; set; }

    // Throughput counts successes completed inside the window, not arrivals, so the ceiling is
    // visible when responses fall behind.
    public void Completed(bool inWindow, bool success)
    {
        if (inWindow && success)
        {
            Interlocked.Increment(ref succeededInWindow);
        }
    }

    public void Record(double milliseconds, Outcome outcome)
    {
        latencies.Add(milliseconds);
        var key = outcome.Error is { } error
            ? $"{outcome.Status}:{error}"
            : outcome.Status.ToString(System.Globalization.CultureInfo.InvariantCulture);
        outcomes.AddOrUpdate(key, 1, static (_, count) => count + 1);
        if (outcome.Status is >= 200 and < 300)
        {
            Interlocked.Increment(ref succeeded);
        }
    }

    public RunSummary Summarize(string name, double offeredRate)
    {
        var sorted = latencies.ToArray();
        Array.Sort(sorted);
        var completed = sorted.Length;
        return new RunSummary(
            name,
            offeredRate,
            MeasuredFrom,
            MeasuredTo,
            Offered,
            completed,
            succeeded,
            // Successes per second in the measured window. Falls below the offered rate at the ceiling.
            MeasuredSeconds > 0 ? succeededInWindow / MeasuredSeconds : 0,
            Percentile(sorted, 0.50),
            Percentile(sorted, 0.90),
            Percentile(sorted, 0.99),
            sorted.Length > 0 ? sorted[^1] : 0,
            sorted.Length > 0 ? sorted.Average() : 0,
            PeakInFlight,
            Abandoned,
            new SortedDictionary<string, int>(outcomes.ToDictionary(pair => pair.Key, pair => pair.Value)));
    }

    private static double Percentile(double[] sorted, double fraction)
    {
        if (sorted.Length == 0)
        {
            return 0;
        }

        var rank = (int)Math.Ceiling(fraction * sorted.Length) - 1;
        return sorted[Math.Clamp(rank, 0, sorted.Length - 1)];
    }
}

internal sealed record RunSummary(
    string Name,
    double OfferedRate,
    DateTimeOffset MeasuredFrom,
    DateTimeOffset MeasuredTo,
    long Offered,
    int Completed,
    int Succeeded,
    double CompletedPerSecond,
    double P50,
    double P90,
    double P99,
    double Max,
    double Mean,
    int PeakInFlight,
    int Abandoned,
    SortedDictionary<string, int> Outcomes);
