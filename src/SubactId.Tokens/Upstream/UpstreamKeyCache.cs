using System.Net.Http;
using System.Text.Json;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Fetches and caches the upstream OIDC discovery document and JWKS for a TTL. Refreshes at most
/// once per interval on an unknown kid, and keeps the last good snapshot if a refresh fails. The
/// issuer must match the URL the document came from, and the JWKS URL must be https (RFC 8414).
/// </summary>
public sealed class UpstreamKeyCache : IUpstreamKeys, IDisposable
{
    /// <summary>The well-known suffix a discovery URL ends with.</summary>
    public const string DiscoverySuffix = "/.well-known/openid-configuration";

    /// <summary>Largest document accepted from upstream.</summary>
    public const int MaxDocumentBytes = JwksHttp.MaxDocumentBytes;

    /// <summary>How long a snapshot is served before being refreshed.</summary>
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(10);

    /// <summary>Minimum time between refreshes triggered by unknown kids.</summary>
    public static readonly TimeSpan DefaultMinRefreshInterval = TimeSpan.FromSeconds(30);

    private readonly Func<HttpClient> clientFactory;
    private readonly Uri metadataUrl;
    private readonly TimeProvider clock;
    private readonly TimeSpan ttl;
    private readonly TimeSpan minRefreshInterval;
    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private UpstreamKeySnapshot? snapshot;
    private DateTimeOffset lastAttempt = DateTimeOffset.MinValue;

    /// <summary>Creates the cache. Nothing is fetched until first use.</summary>
    /// <param name="clientFactory">Provides an <see cref="HttpClient"/> per fetch, so handler pooling and timeouts stay with the host.</param>
    /// <param name="metadataUrl">Absolute URL of the upstream discovery document.</param>
    /// <param name="clock">Time source.</param>
    /// <param name="ttl">Snapshot lifetime; defaults to <see cref="DefaultTtl"/>.</param>
    /// <param name="minRefreshInterval">Rate limit for unknown-kid refreshes; defaults to <see cref="DefaultMinRefreshInterval"/>.</param>
    public UpstreamKeyCache(Func<HttpClient> clientFactory, Uri metadataUrl, TimeProvider clock, TimeSpan? ttl = null, TimeSpan? minRefreshInterval = null)
    {
        ArgumentNullException.ThrowIfNull(clientFactory);
        ArgumentNullException.ThrowIfNull(metadataUrl);
        ArgumentNullException.ThrowIfNull(clock);
        if (!metadataUrl.IsAbsoluteUri || !metadataUrl.AbsolutePath.EndsWith(DiscoverySuffix, StringComparison.Ordinal))
        {
            throw new ArgumentException($"The metadata URL must be absolute and end with {DiscoverySuffix}.", nameof(metadataUrl));
        }

        this.clientFactory = clientFactory;
        this.metadataUrl = metadataUrl;
        this.clock = clock;
        this.ttl = ttl ?? DefaultTtl;
        this.minRefreshInterval = minRefreshInterval ?? DefaultMinRefreshInterval;
    }

    /// <summary>The issuer the discovery document must declare: the metadata URL without the well-known suffix.</summary>
    public string ExpectedIssuer => metadataUrl.GetLeftPart(UriPartial.Path)[..^DiscoverySuffix.Length].TrimEnd('/');

    /// <inheritdoc />
    public UpstreamKeySnapshot? Current => snapshot;

    /// <summary>
    /// Scheduled refresh that reports whether the upstream answered. Ignores the TTL and the
    /// unknown-kid interval. A failure keeps the last good snapshot in place.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>true</c> when the upstream answered and the snapshot was replaced.</returns>
    public async Task<bool> TryRefreshAsync(CancellationToken cancellationToken = default)
    {
        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            // Counts as an attempt, so an unknown kid right after this does not fetch again.
            lastAttempt = clock.GetUtcNow();
            snapshot = await FetchAsync(cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is HttpRequestException or UpstreamDiscoveryException or TaskCanceledException)
        {
            return false;
        }
        finally
        {
            refreshLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<UpstreamKeySnapshot> GetAsync(CancellationToken cancellationToken = default)
    {
        var current = snapshot;
        if (current is not null && clock.GetUtcNow() - current.FetchedAt < ttl)
        {
            return current;
        }

        return await RefreshAsync(force: false, cancellationToken);
    }

    /// <inheritdoc />
    public Task<UpstreamKeySnapshot> RefreshForUnknownKidAsync(CancellationToken cancellationToken = default) =>
        RefreshAsync(force: true, cancellationToken);

    private async Task<UpstreamKeySnapshot> RefreshAsync(bool force, CancellationToken cancellationToken)
    {
        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            var now = clock.GetUtcNow();
            var current = snapshot;
            if (current is not null)
            {
                // Another caller refreshed while we waited, or the rate limit says not yet.
                if (now - current.FetchedAt < (force ? minRefreshInterval : ttl) || now - lastAttempt < minRefreshInterval)
                {
                    return current;
                }
            }

            lastAttempt = now;
            try
            {
                var fresh = await FetchAsync(cancellationToken);
                snapshot = fresh;
                return fresh;
            }
            catch (Exception exception) when (current is not null && exception is HttpRequestException or UpstreamDiscoveryException or TaskCanceledException)
            {
                // Keep serving the last good snapshot; its keys are still the upstream's keys.
                return current;
            }
        }
        finally
        {
            refreshLock.Release();
        }
    }

    private async Task<UpstreamKeySnapshot> FetchAsync(CancellationToken cancellationToken)
    {
        using var client = clientFactory();
        var discovery = await JwksHttp.ReadAsync(client, metadataUrl, cancellationToken);

        string issuer;
        Uri jwksUri;
        try
        {
            using var document = JsonDocument.Parse(discovery);
            var root = document.RootElement;
            issuer = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("issuer", out var issuerElement) && issuerElement.ValueKind == JsonValueKind.String
                ? issuerElement.GetString()!
                : throw new UpstreamDiscoveryException("The upstream discovery document has no 'issuer'.", fault: UpstreamDiscoveryFault.NoIssuer);
            jwksUri = root.TryGetProperty("jwks_uri", out var jwksElement) && jwksElement.ValueKind == JsonValueKind.String
                && Uri.TryCreate(jwksElement.GetString(), UriKind.Absolute, out var parsed)
                ? parsed
                : throw new UpstreamDiscoveryException("The upstream discovery document has no absolute 'jwks_uri'.", fault: UpstreamDiscoveryFault.NoJwksUri);
        }
        catch (JsonException exception)
        {
            throw new UpstreamDiscoveryException("The upstream discovery document is not valid JSON.", exception, UpstreamDiscoveryFault.NotJson);
        }

        if (!string.Equals(issuer.TrimEnd('/'), ExpectedIssuer, StringComparison.Ordinal))
        {
            throw new UpstreamDiscoveryException("The upstream discovery document declares an issuer that does not match the URL it was fetched from.", fault: UpstreamDiscoveryFault.IssuerMismatch);
        }

        if (jwksUri.Scheme != Uri.UriSchemeHttps && !(jwksUri.Scheme == Uri.UriSchemeHttp && metadataUrl.Scheme == Uri.UriSchemeHttp))
        {
            throw new UpstreamDiscoveryException("The upstream 'jwks_uri' must use https.", fault: UpstreamDiscoveryFault.JwksNotHttps);
        }

        var keys = UpstreamJwksParser.Parse(await JwksHttp.ReadAsync(client, jwksUri, cancellationToken));
        return new UpstreamKeySnapshot(issuer, keys, clock.GetUtcNow());
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Keys are not disposed here because a snapshot may still be in use. The finalizer releases them.
        refreshLock.Dispose();
    }
}
