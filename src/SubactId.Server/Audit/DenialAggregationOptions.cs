namespace SubactId.Server.Audit;

/// <summary>
/// Settings for collapsing unattributable denials into summary records. See
/// <see cref="DenialAggregator"/>.
/// </summary>
public sealed class DenialAggregationOptions
{
    /// <summary>Default for <see cref="Window"/>.</summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(1);

    /// <summary>Shortest <see cref="Window"/> accepted.</summary>
    public static readonly TimeSpan MinWindow = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Longest <see cref="Window"/> accepted. Counts sit in memory for a window, so a crash loses
    /// up to one window of them.
    /// </summary>
    public static readonly TimeSpan MaxWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Whether unattributable denials are collapsed. On by default. When off, an unauthenticated
    /// caller can add one ledger row per request.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// How long a reason's window stays open before its count is written, between
    /// <see cref="MinWindow"/> and <see cref="MaxWindow"/>.
    /// </summary>
    public TimeSpan Window { get; init; } = DefaultWindow;
}
