using System.Net;

namespace SubactId.Server.Configuration;

/// <summary>
/// Per-source rate limiting for endpoints a caller reaches without a credential, where signature
/// checks and ledger writes happen before the caller is authenticated.
/// </summary>
/// <remarks>
/// A baseline only. Shedding load earlier in an ingress, load balancer or CDN is still worthwhile.
/// </remarks>
public sealed class RateLimitOptions
{
    /// <summary>Default for <see cref="PermitsPerMinute"/>.</summary>
    public const int DefaultPermitsPerMinute = 600;

    /// <summary>Default for <see cref="Burst"/>.</summary>
    public const int DefaultBurst = 120;

    /// <summary>Default for <see cref="SignalPermitsPerMinute"/>: a hundred a second, sustained.</summary>
    public const int DefaultSignalPermitsPerMinute = 6000;

    /// <summary>
    /// Default for <see cref="SignalBurst"/>. Sized for an identity provider that ends all its
    /// sessions at once, sending one logout token per session.
    /// </summary>
    public const int DefaultSignalBurst = 5000;

    /// <summary>Default for <see cref="IntrospectionPermitsPerMinute"/>: a hundred a second, sustained.</summary>
    public const int DefaultIntrospectionPermitsPerMinute = 6000;

    /// <summary>
    /// Default for <see cref="IntrospectionBurst"/>. Sized for a fleet that wakes together and
    /// introspects every agent's first tool call at once.
    /// </summary>
    public const int DefaultIntrospectionBurst = 1200;

    /// <summary>How often the bucket is refilled.</summary>
    public static readonly TimeSpan ReplenishmentPeriod = TimeSpan.FromSeconds(1);

    /// <summary>Whether requests are limited at all.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Sustained requests allowed from one source per minute. Agents behind one egress address
    /// count as one source, so raise this for a large fleet.
    /// </summary>
    public int PermitsPerMinute { get; init; } = DefaultPermitsPerMinute;

    /// <summary>
    /// Most permits the bucket holds: the burst absorbed before a caller is held to
    /// <see cref="PermitsPerMinute"/>. Must be at least <see cref="PermitsPerSecond"/>.
    /// </summary>
    public int Burst { get; init; } = DefaultBurst;

    /// <summary>Permits added to the bucket every <see cref="ReplenishmentPeriod"/>, rounded up.</summary>
    public int PermitsPerSecond => (int)Math.Ceiling(PermitsPerMinute / 60.0);

    /// <summary>
    /// Sustained signals allowed from one source per minute on the receivers an identity provider
    /// posts to (back-channel logout). Larger than <see cref="PermitsPerMinute"/> because one
    /// provider speaks for all its sessions, and a refused signal is not retried.
    /// </summary>
    public int SignalPermitsPerMinute { get; init; } = DefaultSignalPermitsPerMinute;

    /// <summary>
    /// Most signal permits the bucket holds. Bounds how many sessions a provider can end in one
    /// burst without a logout being dropped. Must be at least <see cref="SignalPermitsPerSecond"/>.
    /// </summary>
    public int SignalBurst { get; init; } = DefaultSignalBurst;

    /// <summary>Signal permits added to the bucket every <see cref="ReplenishmentPeriod"/>, rounded up.</summary>
    public int SignalPermitsPerSecond => (int)Math.Ceiling(SignalPermitsPerMinute / 60.0);

    /// <summary>
    /// Sustained introspection calls allowed from one source per minute on
    /// <c>POST /oauth2/introspect</c>. Separate from and larger than <see cref="PermitsPerMinute"/>,
    /// because the caller is a tool server checking tokens for many agents.
    /// </summary>
    public int IntrospectionPermitsPerMinute { get; init; } = DefaultIntrospectionPermitsPerMinute;

    /// <summary>
    /// Most introspection permits the bucket holds: the burst absorbed before a tool server is held
    /// to the sustained rate. Must be at least <see cref="IntrospectionPermitsPerSecond"/>.
    /// </summary>
    public int IntrospectionBurst { get; init; } = DefaultIntrospectionBurst;

    /// <summary>Introspection permits added to the bucket every <see cref="ReplenishmentPeriod"/>, rounded up.</summary>
    public int IntrospectionPermitsPerSecond => (int)Math.Ceiling(IntrospectionPermitsPerMinute / 60.0);

    /// <summary>
    /// Networks, as CIDR, whose <c>X-Forwarded-For</c> is trusted. Empty means the socket address
    /// is the source. Behind a proxy, set this to the proxy's network. Never use <c>0.0.0.0/0</c>:
    /// any caller could then pick its own source address.
    /// </summary>
    public IReadOnlyList<IPNetwork> TrustedProxies { get; init; } = [];
}
