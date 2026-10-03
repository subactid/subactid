namespace SubactId.Tokens.ClientAuth;

/// <summary>
/// Throttles purging of expired replay records to one caller per interval. Thread-safe and
/// never blocks.
/// </summary>
public sealed class ReplayPurgeGate(TimeSpan? interval = null)
{
    private long lastPurgeTicks = long.MinValue;

    /// <summary>Minimum time between two purges.</summary>
    public TimeSpan Interval { get; } = interval ?? ClientAssertionAuthenticator.PurgeInterval;

    /// <summary>Claims the next purge if <see cref="Interval"/> has passed since the last claim.</summary>
    /// <param name="now">The current time.</param>
    /// <returns><c>true</c> for exactly one caller per interval.</returns>
    public bool TryClaim(DateTimeOffset now)
    {
        var nowTicks = now.UtcTicks;
        while (true)
        {
            var last = Interlocked.Read(ref lastPurgeTicks);
            if (last != long.MinValue && nowTicks - last < Interval.Ticks)
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref lastPurgeTicks, nowTicks, last) == last)
            {
                return true;
            }
        }
    }
}
