namespace SubactId.Server.Configuration;

/// <summary>
/// Caps how much work this instance runs at once and how long a request may wait for a turn.
/// </summary>
/// <remarks>
/// <para>
/// The rate limiter bounds each source. This bounds the instance as a whole: at most
/// <see cref="ConcurrencyLimit"/> requests run at once per kind of work, at most
/// <see cref="QueueLimit"/> wait, none waits longer than <see cref="QueueTimeout"/>, and the rest
/// get <c>503 temporarily_unavailable</c> with <c>Retry-After</c>.
/// </para>
/// <para>
/// Each kind of work (<see cref="Hosting.OverloadPartition"/>) is limited separately, so a slow
/// token endpoint cannot starve introspection, and a flood cannot delay a revocation.
/// </para>
/// </remarks>
public sealed class OverloadOptions
{
    /// <summary>Requests per core that <see cref="DefaultConcurrencyLimit"/> allows.</summary>
    public const int DefaultConcurrencyPerCore = 16;

    /// <summary>How many times <see cref="ConcurrencyLimit"/> may wait by default.</summary>
    public const int DefaultQueueFactor = 4;

    /// <summary>Default for <see cref="QueueTimeout"/>.</summary>
    public static readonly TimeSpan DefaultQueueTimeout = TimeSpan.FromSeconds(1);

    /// <summary>The longest <see cref="QueueTimeout"/> accepted.</summary>
    public static readonly TimeSpan MaxQueueTimeout = TimeSpan.FromSeconds(30);

    /// <summary>The most <see cref="ConcurrencyLimit"/> accepted.</summary>
    public const int MaxConcurrencyLimit = 100_000;

    /// <summary>The most <see cref="QueueLimit"/> accepted.</summary>
    public const int MaxQueueLimit = 1_000_000;

    /// <summary>
    /// Default for <see cref="ConcurrencyLimit"/>: <see cref="DefaultConcurrencyPerCore"/> per core the
    /// process may use (in a container, the cores its CPU limit allows).
    /// </summary>
    public static int DefaultConcurrencyLimit => Math.Min(DefaultConcurrencyPerCore * Environment.ProcessorCount, MaxConcurrencyLimit);

    /// <summary>Whether excess work is refused at all.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Requests run at once, for each kind of work (<see cref="Hosting.OverloadPartition"/>).</summary>
    public int ConcurrencyLimit { get; init; } = DefaultConcurrencyLimit;

    /// <summary>
    /// Requests that may wait for a turn, for each kind of work. Zero means a request that finds no
    /// free turn is refused at once.
    /// </summary>
    public int QueueLimit { get; init; } = Math.Min(DefaultConcurrencyLimit * DefaultQueueFactor, MaxQueueLimit);

    /// <summary>How long a request may wait for a turn before it is refused.</summary>
    public TimeSpan QueueTimeout { get; init; } = DefaultQueueTimeout;
}
