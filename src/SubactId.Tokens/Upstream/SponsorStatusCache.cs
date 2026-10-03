using System.Collections.Concurrent;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Caches each sponsor's status briefly to limit admin API calls. The caller bounds the age to at
/// most one token lifetime. Unavailable answers are never cached and stale entries never served.
/// </summary>
public sealed class SponsorStatusCache(ISponsorStatusSource inner, TimeSpan ttl, TimeProvider clock) : ISponsorStatusSource
{
    private readonly ISponsorStatusSource inner = inner ?? throw new ArgumentNullException(nameof(inner));
    private readonly TimeSpan ttl = ttl > TimeSpan.Zero ? ttl : throw new ArgumentOutOfRangeException(nameof(ttl), ttl, "The cache lifetime must be positive.");
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly ConcurrentDictionary<string, (SponsorStatus Status, DateTimeOffset At)> entries = new(StringComparer.Ordinal);
    private DateTimeOffset lastSweep = DateTimeOffset.MinValue;

    /// <summary>Entry count above which stale entries are swept, at most once per lifetime.</summary>
    public const int SweepThreshold = 10_000;

    /// <summary>How long an answer is reused at most; a caller may ask for less.</summary>
    public TimeSpan Ttl => ttl;

    /// <inheritdoc />
    /// <remarks>
    /// An answer is reused only while younger than both the cache lifetime and
    /// <paramref name="maxAge"/>. With a zero <paramref name="maxAge"/> the answer is neither read
    /// from nor written to the cache.
    /// </remarks>
    public async Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var now = clock.GetUtcNow();
        if (maxAge <= TimeSpan.Zero)
        {
            return await inner.GetAsync(subject, maxAge, cancellationToken);
        }

        var reusable = maxAge < ttl ? maxAge : ttl;
        if (entries.TryGetValue(subject, out var entry) && now - entry.At < reusable)
        {
            return entry.Status;
        }

        var status = await inner.GetAsync(subject, maxAge, cancellationToken);
        if (status == SponsorStatus.Unavailable)
        {
            entries.TryRemove(subject, out _);
        }
        else
        {
            entries[subject] = (status, now);
            SweepIfLarge(now);
        }

        return status;
    }

    /// <summary>Drops stale entries when the map is large, at most once per lifetime. Clears it if still over twice the threshold.</summary>
    private void SweepIfLarge(DateTimeOffset now)
    {
        if (entries.Count <= SweepThreshold || now - lastSweep < ttl)
        {
            return;
        }

        lastSweep = now;
        foreach (var stale in entries.Where(e => now - e.Value.At >= ttl).Select(e => e.Key).ToList())
        {
            entries.TryRemove(stale, out _);
        }

        if (entries.Count > 2 * SweepThreshold)
        {
            entries.Clear();
        }
    }
}
