using System.Globalization;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Primitives;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;

namespace SubactId.Server.Hosting;

/// <summary>
/// Which of the limiter's buckets a partition spends. Paths whose traffic scales with the agent
/// fleet's own work get a separate, larger bucket.
/// </summary>
public enum RateLimitBucket
{
    /// <summary>The bucket a source gets for every path not given one of its own.</summary>
    Source,

    /// <summary>The larger bucket a signal receiver gets, one per receiver per source.</summary>
    Signals,

    /// <summary>The bucket <c>POST /oauth2/introspect</c> gets, one per source.</summary>
    Introspection,
}

/// <summary>
/// Per-source rate limiting for endpoints that need no credential. Over the limit, the
/// caller gets 429 with <c>Retry-After</c>.
/// </summary>
/// <remarks>
/// Uses a token bucket refilled every second, so short bursts are absorbed. The bucket holds at
/// most <c>Burst</c> permits, so configuration rejects a burst smaller than one refill. Health and
/// readiness probes are never limited. Limits are per instance: n replicas admit n times the rate.
/// </remarks>
public static class RateLimiting
{
    /// <summary>Audit reason recorded when a request is refused by admission control.</summary>
    public const string Reason = "rate_limited";

    /// <summary>
    /// Separates a source from the path in a partition key. A source is an address or prefix and
    /// never contains it.
    /// </summary>
    private const string PartitionSeparator = "|";

    /// <summary>The introspection path, which has its own bucket per source.</summary>
    private const string IntrospectionPath = Introspection.IntrospectionEndpoints.Path;

    /// <summary>
    /// The paths identity providers and provisioning clients post to. Each has its own partition
    /// and uses the signal bucket.
    /// </summary>
    private static readonly string[] SignalPaths =
    [
        Logout.LogoutEndpoints.LogoutPath,
        Scim.ScimEndpoints.Prefix,
        Signals.SecurityEventEndpoints.EventsPath,
    ];

    /// <summary>The token bucket settings for a partition. Public so the numbers can be tested.</summary>
    /// <param name="options">The limits.</param>
    /// <param name="bucket">Which bucket the partition spends.</param>
    public static TokenBucketRateLimiterOptions BucketFor(RateLimitOptions options, RateLimitBucket bucket = RateLimitBucket.Source)
    {
        ArgumentNullException.ThrowIfNull(options);

        var (burst, perSecond) = bucket switch
        {
            RateLimitBucket.Signals => (options.SignalBurst, options.SignalPermitsPerSecond),
            RateLimitBucket.Introspection => (options.IntrospectionBurst, options.IntrospectionPermitsPerSecond),
            _ => (options.Burst, options.PermitsPerSecond),
        };

        return new TokenBucketRateLimiterOptions
        {
            TokenLimit = burst,
            TokensPerPeriod = perSecond,
            ReplenishmentPeriod = RateLimitOptions.ReplenishmentPeriod,
            // No queue: a caller over the limit is refused at once, not held on a connection.
            QueueLimit = 0,
            AutoReplenishment = true,
        };
    }

    /// <summary>Adds the limiter described by <paramref name="options"/>.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The limits.</param>
    public static IServiceCollection AddSubactIdRateLimiting(this IServiceCollection services, RateLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.Enabled)
        {
            return services;
        }

        services.AddRateLimiter(limiter =>
        {
            // Global, so every endpoint is limited unless it opts out with DisableRateLimiting.
            limiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(http =>
            {
                var partition = PartitionOf(http, options);
                return RateLimitPartition.GetTokenBucketLimiter(partition, _ => BucketFor(options, BucketOf(partition)));
            });

            limiter.OnRejected = async (context, cancellationToken) =>
            {
                var http = context.HttpContext;
                var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var after)
                    ? (int)Math.Ceiling(after.TotalSeconds)
                    : 60;

                // Refusals are audited, through the aggregator since the caller is unattributed.
                await RecordAsync(http, Reason);

                await TemporarilyUnavailable.WriteRefusalAsync(
                    http,
                    StatusCodes.Status429TooManyRequests,
                    OAuthErrorResponse.SlowDown,
                    TimeSpan.FromSeconds(retryAfter),
                    "Too many requests; retry after the interval in Retry-After.");
            };
        });

        return services;
    }

    /// <summary>Applies the limiter, and the forwarded-header handling it depends on.</summary>
    /// <param name="app">The application.</param>
    /// <param name="options">The limits.</param>
    public static IApplicationBuilder UseSubactIdRateLimiting(this IApplicationBuilder app, RateLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        return options.Enabled ? app.UseRateLimiter() : app;
    }

    /// <summary>
    /// The partition key for a request: its source, paired with the path for paths that have a
    /// bucket of their own.
    /// <para>
    /// Each signal receiver is its own partition, so a flood of signals cannot spend the agents'
    /// bucket, and a provider's bulk traffic is not held to it either. Introspection is partitioned
    /// per source, separately from the agents' bucket.
    /// </para>
    /// </summary>
    /// <param name="http">The request.</param>
    /// <param name="options">The limits, including which networks are proxies.</param>
    public static string PartitionOf(HttpContext http, RateLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(http);

        var source = SourceOf(http, options);
        if (http.Request.Path.StartsWithSegments(IntrospectionPath))
        {
            return source + PartitionSeparator + IntrospectionPath;
        }

        foreach (var path in SignalPaths)
        {
            if (http.Request.Path.StartsWithSegments(path))
            {
                return source + PartitionSeparator + path;
            }
        }

        return source;
    }

    /// <summary>Which bucket a partition key from <see cref="PartitionOf"/> spends.</summary>
    /// <param name="partition">The partition key.</param>
    public static RateLimitBucket BucketOf(string partition)
    {
        ArgumentNullException.ThrowIfNull(partition);

        var separator = partition.IndexOf(PartitionSeparator, StringComparison.Ordinal);
        if (separator < 0)
        {
            return RateLimitBucket.Source;
        }

        // A source never contains the separator, so what follows it is the path PartitionOf appended.
        var path = partition[(separator + PartitionSeparator.Length)..];
        return string.Equals(path, IntrospectionPath, StringComparison.Ordinal)
            ? RateLimitBucket.Introspection
            : RateLimitBucket.Signals;
    }

    /// <summary>
    /// The source a request is counted against. Public so the forwarded-header rule, a security
    /// property, can be tested directly.
    /// </summary>
    /// <param name="http">The request.</param>
    /// <param name="options">The limits, including which networks are proxies.</param>
    public static string SourceOf(HttpContext http, RateLimitOptions options)
    {
        var remote = http.Connection.RemoteIpAddress;
        if (remote is null)
        {
            return "unknown";
        }

        if (options.TrustedProxies.Count > 0
            && IsTrustedProxy(remote, options)
            && http.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded)
            && CallerBehind(forwarded, options) is { } observed)
        {
            // Read from the right, never the left. The left entries are caller-controlled.
            // Trusted proxies are skipped, and the first untrusted entry is the caller.
            remote = observed;
        }

        // IPv6 callers are counted per /64, since one holder controls the whole prefix.
        return remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? new IPNetwork(remote, 64).ToString()
            : remote.ToString();
    }

    /// <summary>
    /// Walks the header from its last entry backwards and returns the first address that is not a
    /// trusted proxy. If every entry is a trusted proxy, returns the outermost. An entry that is
    /// not an address ends the walk.
    /// </summary>
    /// <param name="forwarded">Every <c>X-Forwarded-For</c> value, in the order received.</param>
    /// <param name="options">The limits, including which networks are proxies.</param>
    private static IPAddress? CallerBehind(StringValues forwarded, RateLimitOptions options)
    {
        IPAddress? outermostProxy = null;
        for (var header = forwarded.Count - 1; header >= 0; header--)
        {
            if (forwarded[header] is not { } value)
            {
                continue;
            }

            var entries = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            for (var entry = entries.Length - 1; entry >= 0; entry--)
            {
                if (!IPAddress.TryParse(entries[entry], out var address))
                {
                    return outermostProxy;
                }

                if (!IsTrustedProxy(address, options))
                {
                    return address;
                }

                outermostProxy = address;
            }
        }

        return outermostProxy;
    }

    private static bool IsTrustedProxy(IPAddress address, RateLimitOptions options) =>
        options.TrustedProxies.Any(network => network.Contains(address));

    /// <summary>
    /// The audit event a refusal on <paramref name="path"/> is recorded under: the admin, SCIM,
    /// SSF or logout denial for those paths, and <c>token.denied</c> for the rest.
    /// </summary>
    /// <param name="path">The request path.</param>
    public static string DeniedEventFor(PathString path)
    {
        if (path.StartsWithSegments("/admin") || path.StartsWithSegments("/audit"))
        {
            return AuditEvents.AdminDenied;
        }

        if (path.StartsWithSegments(Scim.ScimEndpoints.Prefix))
        {
            return AuditEvents.ScimDenied;
        }

        if (path.StartsWithSegments(Signals.SecurityEventEndpoints.EventsPath))
        {
            return AuditEvents.SsfDenied;
        }

        if (path.StartsWithSegments(Logout.LogoutEndpoints.LogoutPath))
        {
            return AuditEvents.SignalDenied;
        }

        return AuditEvents.TokenDenied;
    }

    /// <summary>
    /// Records an admission-control refusal in the ledger, under the event for its path, through
    /// the denial aggregator.
    /// </summary>
    /// <remarks>
    /// With aggregation off, this writes one record per refusal. A record that cannot be written
    /// is not dropped: it is handed to the aggregator, which writes it in its next summary, and
    /// the caller still gets its refusal rather than a 500.
    /// </remarks>
    /// <param name="http">The refused request.</param>
    /// <param name="reason">Why: <see cref="Reason"/> here, <see cref="OverloadShedding.Reason"/> for a refusal at capacity.</param>
    public static async Task RecordAsync(HttpContext http, string reason)
    {
        // Required: a refusal that could not be counted anywhere would be a denial with no record.
        var aggregator = http.RequestServices.GetRequiredService<DenialAggregator>();
        var clock = http.RequestServices.GetRequiredService<TimeProvider>();
        var record = new AuditEvent(clock.GetUtcNow(), DeniedEventFor(http.Request.Path), Decision: AuditDecision.Deny, Reason: reason);
        await aggregator.RecordAsync(record, http.RequestServices.GetRequiredService<IAuditWriter>());
    }
}
