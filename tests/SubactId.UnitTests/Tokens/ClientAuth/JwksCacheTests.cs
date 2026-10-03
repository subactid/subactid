using System.Buffers.Text;
using System.Net;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.ClientAuth.ClientAuthTestData;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.ClientAuth;

public class JwksCacheTests
{
    private const string Url = "https://jira-triage.example/jwks.json";

    [Fact]
    public async Task Fetches_once_within_the_ttl_and_again_after_it()
    {
        var server = new FakeJsonServer { [Url] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new JwksCache(server.CreateClient, new Uri(Url), clock, ttl: TimeSpan.FromMinutes(10));

        var first = await cache.GetAsync();
        clock.Advance(TimeSpan.FromMinutes(9));
        Assert.Same(first, await cache.GetAsync());
        clock.Advance(TimeSpan.FromMinutes(2));
        server[Url] = Jwks(RsaJwk(Rsa2, "rsa2"));
        var second = await cache.GetAsync();

        Assert.Equal(["rsa1"], first.Keys.Keys);
        Assert.Equal(["rsa2"], second.Keys.Keys);
        Assert.Equal(2, server.Requests[Url]);
    }

    [Fact]
    public async Task Unknown_kid_refresh_is_rate_limited_and_keeps_the_last_good_snapshot_on_failure()
    {
        var server = new FakeJsonServer { [Url] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new JwksCache(server.CreateClient, new Uri(Url), clock, minRefreshInterval: TimeSpan.FromSeconds(30));
        var initial = await cache.GetAsync();

        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Same(initial, await cache.RefreshForUnknownKidAsync());
        Assert.Equal(1, server.Requests[Url]);

        clock.Advance(TimeSpan.FromSeconds(30));
        server.Status[Url] = HttpStatusCode.InternalServerError;
        Assert.Same(initial, await cache.RefreshForUnknownKidAsync());
        Assert.Equal(2, server.Requests[Url]);

        clock.Advance(TimeSpan.FromSeconds(30));
        server.Status.Remove(Url);
        server[Url] = Jwks(RsaJwk(Rsa1, "rsa1"), RsaJwk(Rsa2, "rsa2"));
        Assert.Equal(["rsa1", "rsa2"], (await cache.RefreshForUnknownKidAsync()).Keys.Keys.Order());
    }

    [Fact]
    public async Task Fails_when_nothing_was_ever_fetched_and_rejects_oversized_documents()
    {
        var server = new FakeJsonServer();
        using var down = new JwksCache(server.CreateClient, new Uri(Url), new FakeTimeProvider(Now));
        await Assert.ThrowsAsync<HttpRequestException>(() => down.GetAsync());

        server[Url] = "{\"keys\":[" + new string(' ', UpstreamKeyCache.MaxDocumentBytes) + "]}";
        using var big = new JwksCache(server.CreateClient, new Uri(Url), new FakeTimeProvider(Now));
        await Assert.ThrowsAsync<UpstreamDiscoveryException>(() => big.GetAsync());
    }

    [Fact]
    public async Task A_snapshot_past_the_stale_limit_is_not_served_when_refreshing_fails()
    {
        // The agent removed a key, and its JWKS URL went down: the old keys are accepted for a
        // while, then not at all.
        var server = new FakeJsonServer { [Url] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        var clock = new FakeTimeProvider(Now);
        using var cache = new JwksCache(server.CreateClient, new Uri(Url), clock, ttl: TimeSpan.FromMinutes(10), maxStale: TimeSpan.FromHours(1));
        var initial = await cache.GetAsync();
        server.Status[Url] = HttpStatusCode.InternalServerError;

        clock.Advance(TimeSpan.FromMinutes(59));
        Assert.Same(initial, await cache.GetAsync());

        clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.ThrowsAsync<HttpRequestException>(() => cache.GetAsync());
    }

    [Fact]
    public async Task With_nothing_to_serve_a_failed_fetch_is_not_repeated_within_the_refresh_interval()
    {
        // Every unauthenticated request naming an agent whose keys never loaded would otherwise
        // start a fetch of its JWKS URL.
        var server = new FakeJsonServer();
        var clock = new FakeTimeProvider(Now);
        using var cache = new JwksCache(server.CreateClient, new Uri(Url), clock, minRefreshInterval: TimeSpan.FromSeconds(30));

        await Assert.ThrowsAsync<HttpRequestException>(() => cache.GetAsync());
        for (var i = 0; i < 5; i++)
        {
            clock.Advance(TimeSpan.FromSeconds(5));
            await Assert.ThrowsAsync<HttpRequestException>(() => cache.GetAsync());
            await Assert.ThrowsAsync<HttpRequestException>(() => cache.RefreshForUnknownKidAsync());
        }

        Assert.Equal(1, server.Requests.GetValueOrDefault(Url));

        clock.Advance(TimeSpan.FromSeconds(6));
        server[Url] = Jwks(RsaJwk(Rsa1, "rsa1"));
        Assert.Equal(["rsa1"], (await cache.GetAsync()).Keys.Keys);
        Assert.Equal(2, server.Requests[Url]);
    }

    [Fact]
    public async Task A_caller_that_gives_up_does_not_hold_the_next_one_to_a_failure()
    {
        var server = new FakeJsonServer { [Url] = Jwks(RsaJwk(Rsa1, "rsa1")) };
        using var cache = new JwksCache(server.CreateClient, new Uri(Url), new FakeTimeProvider(Now));
        using var gone = new CancellationTokenSource();
        await gone.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.GetAsync(gone.Token));

        Assert.Equal(["rsa1"], (await cache.GetAsync()).Keys.Keys);
    }

    [Theory]
    [InlineData("http://jira-triage.example/jwks.json")]
    [InlineData("/jwks.json")]
    public void Requires_an_absolute_https_url(string url)
    {
        Assert.Throws<ArgumentException>(() => new JwksCache(() => new HttpClient(), new Uri(url, UriKind.RelativeOrAbsolute), new FakeTimeProvider(Now)));
    }
}

public class AgentKeyCacheTests
{
    [Fact]
    public async Task Keeps_one_cache_per_agent_and_follows_a_changed_jwks_url()
    {
        var server = new FakeJsonServer
        {
            ["https://a.example/jwks.json"] = Jwks(RsaJwk(Rsa1, "a")),
            ["https://b.example/jwks.json"] = Jwks(RsaJwk(Rsa2, "b")),
            ["https://a2.example/jwks.json"] = Jwks(EcJwk(Ec1, "a2")),
        };
        using var cache = new AgentKeyCache(server.CreateClient, new FakeTimeProvider(Now));
        var a = Agent("a", jwks: new Uri("https://a.example/jwks.json"));
        var b = Agent("b", jwks: new Uri("https://b.example/jwks.json"));

        Assert.Equal(["a"], (await cache.GetAsync(a)).Keys.Keys);
        Assert.Equal(["b"], (await cache.GetAsync(b)).Keys.Keys);
        Assert.Equal(["a"], (await cache.GetAsync(a)).Keys.Keys);
        Assert.Equal(1, server.Requests["https://a.example/jwks.json"]);

        var moved = a with { JwksUri = new Uri("https://a2.example/jwks.json") };
        Assert.Equal(["a2"], (await cache.GetAsync(moved)).Keys.Keys);
        Assert.Equal(1, server.Requests["https://a2.example/jwks.json"]);
    }

    [Fact]
    public async Task Keys_from_a_replaced_jwks_url_stay_usable_by_a_verification_already_in_flight()
    {
        var server = new FakeJsonServer
        {
            ["https://a.example/jwks.json"] = Jwks(RsaJwk(Rsa1, "a")),
            ["https://a2.example/jwks.json"] = Jwks(RsaJwk(Rsa2, "a2")),
        };
        using var cache = new AgentKeyCache(server.CreateClient, new FakeTimeProvider(Now));
        var a = Agent("a", jwks: new Uri("https://a.example/jwks.json"));
        var oldKey = (await cache.GetAsync(a)).Keys["a"];
        var token = Mint("RS256", "a", Claims());
        var signingInput = Encoding.ASCII.GetBytes(token[..token.LastIndexOf('.')]);
        var signature = Base64Url.DecodeFromChars(token.AsSpan(token.LastIndexOf('.') + 1));

        // An administrator moves the agent to a new JWKS URL while a request still holds the old snapshot.
        await cache.GetAsync(a with { JwksUri = new Uri("https://a2.example/jwks.json") });

        Assert.True(oldKey.Verify("RS256", signingInput, signature));
    }

    [Fact]
    public void A_disposed_key_verifies_nothing_instead_of_throwing()
    {
        var key = UpstreamJwksParser.Parse(Jwks(RsaJwk(Rsa1, "a")))["a"];
        var token = Mint("RS256", "a", Claims());
        var signingInput = Encoding.ASCII.GetBytes(token[..token.LastIndexOf('.')]);
        var signature = Base64Url.DecodeFromChars(token.AsSpan(token.LastIndexOf('.') + 1));
        Assert.True(key.Verify("RS256", signingInput, signature));

        key.Dispose();

        Assert.False(key.Verify("RS256", signingInput, signature));
    }

    [Fact]
    public async Task An_agent_without_a_jwks_url_cannot_be_looked_up()
    {
        using var cache = new AgentKeyCache(() => new HttpClient(), new FakeTimeProvider(Now));

        await Assert.ThrowsAsync<InvalidOperationException>(() => cache.GetAsync(Agent("keyless", noJwks: true)));
    }
}
