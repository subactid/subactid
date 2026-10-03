using System.Net;
using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Upstream;

public class UpstreamKeyCacheTests
{
    private const string MetadataUrl = "https://idp.example.test/realms/main/.well-known/openid-configuration";
    private const string JwksUrl = "https://idp.example.test/realms/main/protocol/openid-connect/certs";

    private static string Discovery(string issuer = Issuer, string jwksUri = JwksUrl) =>
        $"{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{jwksUri}\",\"token_endpoint\":\"{issuer}/protocol/openid-connect/token\"}}";

    [Fact]
    public async Task Fetches_discovery_then_jwks_and_serves_the_snapshot_from_cache_within_the_ttl()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1"), EcJwk(Ec1, "ec1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), clock);

        var first = await cache.GetAsync();
        var second = await cache.GetAsync();

        Assert.Equal(Issuer, first.Issuer);
        Assert.Equal(["ec1", "rsa1"], first.Keys.Keys.Order());
        Assert.Same(first, second);
        Assert.Equal(1, idp.Requests[MetadataUrl]);
        Assert.Equal(1, idp.Requests[JwksUrl]);
    }

    [Fact]
    public async Task Refetches_after_the_ttl()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), clock, ttl: TimeSpan.FromMinutes(10));

        await cache.GetAsync();
        clock.Advance(TimeSpan.FromMinutes(9));
        await cache.GetAsync();
        Assert.Equal(1, idp.Requests[JwksUrl]);

        clock.Advance(TimeSpan.FromMinutes(2));
        idp[JwksUrl] = Jwks(RsaJwk(Rsa2, "rsa2"));
        var refreshed = await cache.GetAsync();

        Assert.Equal(2, idp.Requests[JwksUrl]);
        Assert.Equal(["rsa2"], refreshed.Keys.Keys);
    }

    [Fact]
    public async Task Unknown_kid_refresh_picks_up_a_rotation_and_is_rate_limited()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), clock, minRefreshInterval: TimeSpan.FromSeconds(30));
        await cache.GetAsync();

        // Within the interval: served from cache, no request.
        clock.Advance(TimeSpan.FromSeconds(10));
        idp[JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1"), RsaJwk(Rsa2, "rsa2"));
        var throttled = await cache.RefreshForUnknownKidAsync();
        Assert.Equal(["rsa1"], throttled.Keys.Keys);
        Assert.Equal(1, idp.Requests[JwksUrl]);

        // After the interval: the rotated key appears without any restart.
        clock.Advance(TimeSpan.FromSeconds(25));
        var rotated = await cache.RefreshForUnknownKidAsync();
        Assert.Equal(["rsa1", "rsa2"], rotated.Keys.Keys.Order());
        Assert.Equal(2, idp.Requests[JwksUrl]);
    }

    [Fact]
    public async Task Keeps_the_last_good_snapshot_when_a_refresh_fails()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), clock, ttl: TimeSpan.FromMinutes(1));
        var good = await cache.GetAsync();

        clock.Advance(TimeSpan.FromMinutes(2));
        idp.Status[JwksUrl] = HttpStatusCode.ServiceUnavailable;
        var stale = await cache.GetAsync();

        Assert.Same(good, stale);
        Assert.Equal(2, idp.Requests[JwksUrl]);
    }

    [Fact]
    public async Task Fails_when_nothing_has_ever_been_fetched_and_the_upstream_is_down()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery() };
        idp.Status[MetadataUrl] = HttpStatusCode.BadGateway;
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));

        await Assert.ThrowsAsync<HttpRequestException>(() => cache.GetAsync());
    }

    [Theory]
    [InlineData("https://idp.example.test/realms/other", "declares an issuer that does not match")]
    [InlineData("https://evil.example/realms/main", "declares an issuer that does not match")]
    public async Task Rejects_a_discovery_document_whose_issuer_is_not_where_it_was_fetched_from(string issuer, string expected)
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(issuer: issuer), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));

        var exception = await Assert.ThrowsAsync<UpstreamDiscoveryException>(() => cache.GetAsync());

        Assert.Contains(expected, exception.Message, StringComparison.Ordinal);
        Assert.False(idp.Requests.ContainsKey(JwksUrl));
    }

    [Fact]
    public async Task Accepts_an_issuer_that_differs_only_by_a_trailing_slash()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(issuer: Issuer + "/"), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));

        var snapshot = await cache.GetAsync();

        Assert.Equal(Issuer + "/", snapshot.Issuer);
    }

    [Fact]
    public async Task Rejects_a_jwks_uri_that_downgrades_to_http_or_is_not_absolute()
    {
        var http = new FakeIdp { [MetadataUrl] = Discovery(jwksUri: "http://idp.example.test/realms/main/certs") };
        using var downgrade = new UpstreamKeyCache(http.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));
        var exception = await Assert.ThrowsAsync<UpstreamDiscoveryException>(() => downgrade.GetAsync());
        Assert.Contains("must use https", exception.Message, StringComparison.Ordinal);

        var relative = new FakeIdp { [MetadataUrl] = Discovery(jwksUri: "/certs") };
        using var notAbsolute = new UpstreamKeyCache(relative.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));
        await Assert.ThrowsAsync<UpstreamDiscoveryException>(() => notAbsolute.GetAsync());
    }

    [Fact]
    public async Task Allows_plain_http_only_when_the_metadata_url_itself_is_http()
    {
        const string devMetadata = "http://localhost:8080/realms/dev/.well-known/openid-configuration";
        const string devJwks = "http://localhost:8080/realms/dev/certs";
        var idp = new FakeIdp { [devMetadata] = Discovery(issuer: "http://localhost:8080/realms/dev", jwksUri: devJwks), [devJwks] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(devMetadata), new FakeTimeProvider(Now));

        Assert.Equal(["rsa1"], (await cache.GetAsync()).Keys.Keys);
    }

    [Fact]
    public async Task Rejects_documents_over_the_size_limit()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(), [JwksUrl] = "{\"keys\":[" + new string(' ', UpstreamKeyCache.MaxDocumentBytes) + "]}" };
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));

        var exception = await Assert.ThrowsAsync<UpstreamDiscoveryException>(() => cache.GetAsync());

        Assert.Contains("exceeds", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Concurrent_first_use_fetches_once()
    {
        var idp = new FakeIdp { [MetadataUrl] = Discovery(), [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        using var cache = new UpstreamKeyCache(idp.CreateClient, new Uri(MetadataUrl), new FakeTimeProvider(Now));

        var snapshots = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => cache.GetAsync())));

        Assert.All(snapshots, s => Assert.Same(snapshots[0], s));
        Assert.Equal(1, idp.Requests[JwksUrl]);
    }

    [Fact]
    public void The_metadata_url_must_be_a_well_known_discovery_url()
    {
        Assert.Throws<ArgumentException>(() => new UpstreamKeyCache(() => new HttpClient(), new Uri("https://idp.example.test/realms/main"), new FakeTimeProvider(Now)));
        Assert.Equal(Issuer, new UpstreamKeyCache(() => new HttpClient(), new Uri(MetadataUrl), new FakeTimeProvider(Now)).ExpectedIssuer);
    }
}
