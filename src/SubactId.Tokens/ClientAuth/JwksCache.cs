using System.Net.Http;
using System.Runtime.ExceptionServices;
using SubactId.Tokens.Upstream;

namespace SubactId.Tokens.ClientAuth;

/// <summary>The keys published at one JWKS URL as of one fetch.</summary>
/// <param name="Keys">Usable keys by kid.</param>
/// <param name="FetchedAt">When the document was fetched.</param>
public sealed record JwksSnapshot(IReadOnlyDictionary<string, UpstreamKey> Keys, DateTimeOffset FetchedAt);

/// <summary>
/// Fetches and caches one JWKS document over https. Served for a TTL, refreshed at most once per
/// interval on an unknown kid, single-flight. The last good snapshot is kept if a refresh fails,
/// but only while it is younger than a stale limit: a key the agent removed is not accepted for
/// as long as its JWKS URL stays down. With no usable snapshot, a failed fetch is not retried
/// until the refresh interval has passed; callers in between get that failure.
/// </summary>
public sealed class JwksCache : IDisposable
{
    /// <summary>How long a snapshot is served before being refreshed.</summary>
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(10);

    /// <summary>Minimum time between refreshes triggered by unknown kids, and between attempts after a failure.</summary>
    public static readonly TimeSpan DefaultMinRefreshInterval = TimeSpan.FromSeconds(30);

    /// <summary>Oldest snapshot still served when refreshing it fails: six times the TTL.</summary>
    public static readonly TimeSpan DefaultMaxStale = TimeSpan.FromHours(1);

    private readonly Func<HttpClient> clientFactory;
    private readonly TimeProvider clock;
    private readonly TimeSpan ttl;
    private readonly TimeSpan minRefreshInterval;
    private readonly TimeSpan maxStale;
    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private JwksSnapshot? snapshot;
    private DateTimeOffset lastAttempt = DateTimeOffset.MinValue;
    private ExceptionDispatchInfo? lastFailure;

    /// <summary>Creates the cache. Nothing is fetched until first use.</summary>
    /// <param name="clientFactory">Provides an <see cref="HttpClient"/> per fetch.</param>
    /// <param name="jwksUri">Absolute https URL of the JWKS document.</param>
    /// <param name="clock">Time source.</param>
    /// <param name="ttl">Snapshot lifetime; defaults to <see cref="DefaultTtl"/>.</param>
    /// <param name="minRefreshInterval">Rate limit for unknown-kid refreshes and for attempts after a failure; defaults to <see cref="DefaultMinRefreshInterval"/>.</param>
    /// <param name="maxStale">Oldest snapshot served when a refresh fails; defaults to <see cref="DefaultMaxStale"/>, and is never below the TTL.</param>
    /// <exception cref="ArgumentException">The URL is not absolute https.</exception>
    public JwksCache(Func<HttpClient> clientFactory, Uri jwksUri, TimeProvider clock, TimeSpan? ttl = null, TimeSpan? minRefreshInterval = null, TimeSpan? maxStale = null)
    {
        ArgumentNullException.ThrowIfNull(clientFactory);
        ArgumentNullException.ThrowIfNull(jwksUri);
        ArgumentNullException.ThrowIfNull(clock);
        if (!jwksUri.IsAbsoluteUri || jwksUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("The JWKS URL must be absolute https.", nameof(jwksUri));
        }

        this.clientFactory = clientFactory;
        JwksUri = jwksUri;
        this.clock = clock;
        this.ttl = ttl ?? DefaultTtl;
        this.minRefreshInterval = minRefreshInterval ?? DefaultMinRefreshInterval;
        this.maxStale = TimeSpan.FromTicks(Math.Max((maxStale ?? DefaultMaxStale).Ticks, this.ttl.Ticks));
    }

    /// <summary>The document's URL.</summary>
    public Uri JwksUri { get; }

    /// <summary>The current snapshot, fetched or refreshed as needed.</summary>
    public async Task<JwksSnapshot> GetAsync(CancellationToken cancellationToken = default)
    {
        var current = snapshot;
        if (current is not null && clock.GetUtcNow() - current.FetchedAt < ttl)
        {
            return current;
        }

        return await RefreshAsync(force: false, cancellationToken);
    }

    /// <summary>A fresh snapshot because a token named an unknown kid; rate-limited.</summary>
    public Task<JwksSnapshot> RefreshForUnknownKidAsync(CancellationToken cancellationToken = default) =>
        RefreshAsync(force: true, cancellationToken);

    private async Task<JwksSnapshot> RefreshAsync(bool force, CancellationToken cancellationToken)
    {
        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            var now = clock.GetUtcNow();
            var current = snapshot;

            // Past the stale limit the snapshot is no longer an answer, even if refreshing fails.
            var usable = current is not null && now - current.FetchedAt < maxStale ? current : null;
            if (usable is not null && (now - usable.FetchedAt < (force ? minRefreshInterval : ttl) || now - lastAttempt < minRefreshInterval))
            {
                return usable;
            }

            // Nothing to serve and the last attempt failed a moment ago: the same failure, without
            // another fetch. Unauthenticated requests naming this agent cannot drive a fetch storm.
            if (usable is null && lastFailure is not null && now - lastAttempt < minRefreshInterval)
            {
                lastFailure.Throw();
            }

            lastAttempt = now;
            try
            {
                using var client = clientFactory();
                var keys = UpstreamJwksParser.Parse(await JwksHttp.ReadAsync(client, JwksUri, cancellationToken));
                var fresh = new JwksSnapshot(keys, clock.GetUtcNow());
                snapshot = fresh;
                lastFailure = null;
                return fresh;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // The caller went away. That says nothing about the document, so it is not recorded
                // as a failure to hold the next caller to.
                throw;
            }
            catch (Exception exception) when (exception is HttpRequestException or UpstreamDiscoveryException or TaskCanceledException)
            {
                lastFailure = ExceptionDispatchInfo.Capture(exception);
                if (usable is not null)
                {
                    return usable;
                }

                throw;
            }
        }
        finally
        {
            refreshLock.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Keys are not disposed here because a snapshot may still be in use. The finalizer releases them.
        refreshLock.Dispose();
    }
}
