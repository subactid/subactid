using System.Net;
using System.Net.Http;
using SubactId.Server.Http;
using SubactId.Tokens.ClientAuth;
using Xunit;

namespace SubactId.UnitTests.Http;

/// <summary>
/// The egress classifier behind the opt-in SSRF guard on agent JWKS fetches, the guard as it
/// behaves on a real connection, and the handler's standing refusal to follow a redirect.
/// </summary>
public class HardenedHttpHandlerTests
{
    [Theory]
    [InlineData("127.0.0.1")]                 // loopback
    [InlineData("127.9.9.9")]                 // loopback /8
    [InlineData("10.0.0.5")]                  // RFC 1918
    [InlineData("172.16.0.1")]                // RFC 1918
    [InlineData("172.31.255.255")]            // RFC 1918 upper edge
    [InlineData("192.168.1.1")]               // RFC 1918
    [InlineData("169.254.169.254")]           // link-local (cloud metadata)
    [InlineData("100.64.0.1")]                // shared address space
    [InlineData("100.100.100.200")]           // shared address space (a cloud metadata service)
    [InlineData("0.0.0.0")]                   // this network
    [InlineData("192.0.0.170")]               // IETF protocol assignments
    [InlineData("192.0.2.1")]                 // documentation
    [InlineData("198.51.100.7")]              // documentation
    [InlineData("203.0.113.10")]              // documentation
    [InlineData("198.18.0.1")]                // benchmarking
    [InlineData("198.19.255.255")]            // benchmarking upper edge
    [InlineData("224.0.0.1")]                 // multicast
    [InlineData("240.0.0.1")]                 // reserved
    [InlineData("255.255.255.255")]           // limited broadcast
    [InlineData("::")]                        // unspecified
    [InlineData("::1")]                       // IPv6 loopback
    [InlineData("fe80::1")]                   // IPv6 link-local
    [InlineData("fe80::1%1")]                 // IPv6 link-local with a zone
    [InlineData("fec0::1")]                   // IPv6 site-local
    [InlineData("fc00::1")]                   // IPv6 unique-local
    [InlineData("fd12:3456::1")]              // IPv6 unique-local
    [InlineData("fd00:ec2::254")]             // IPv6 unique-local (a cloud metadata service)
    [InlineData("ff02::1")]                   // IPv6 multicast
    [InlineData("100::1")]                    // discard-only
    [InlineData("2001:db8::1")]               // IPv6 documentation
    [InlineData("3fff::1")]                   // IPv6 documentation
    [InlineData("::ffff:127.0.0.1")]          // IPv4-mapped loopback
    [InlineData("::ffff:10.0.0.1")]           // IPv4-mapped RFC 1918
    [InlineData("::ffff:0:a9fe:a9fe")]        // IPv4-translated link-local
    [InlineData("::a00:5")]                   // IPv4-compatible RFC 1918
    [InlineData("64:ff9b::a9fe:a9fe")]        // NAT64 of link-local: reaches it from an IPv6-only host
    [InlineData("64:ff9b::a00:5")]            // NAT64 of RFC 1918
    [InlineData("64:ff9b:1::a00:5")]          // local-use NAT64 prefix
    [InlineData("2002:a9fe:a9fe::1")]         // 6to4 of link-local
    [InlineData("2002:7f00:1::1")]            // 6to4 of loopback
    public void Addresses_that_are_not_public_are_refused(string ip)
    {
        Assert.True(HardenedHttpHandler.IsPrivate(IPAddress.Parse(ip)), ip);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.15.0.1")]                // just below the RFC 1918 block
    [InlineData("172.32.0.1")]                // just above the RFC 1918 block
    [InlineData("100.63.255.255")]            // just below the shared address space
    [InlineData("100.128.0.1")]               // just above the shared address space
    [InlineData("198.17.255.255")]            // just below benchmarking
    [InlineData("198.20.0.1")]                // just above benchmarking
    [InlineData("223.255.255.255")]           // just below multicast
    [InlineData("2606:4700:4700::1111")]      // public IPv6
    [InlineData("::ffff:8.8.8.8")]            // IPv4-mapped public
    [InlineData("64:ff9b::808:808")]          // NAT64 of a public address
    [InlineData("2002:808:808::1")]           // 6to4 of a public address
    public void Public_addresses_are_allowed(string ip)
    {
        Assert.False(HardenedHttpHandler.IsPrivate(IPAddress.Parse(ip)), ip);
    }

    [Fact]
    public void The_handler_never_follows_redirects()
    {
        using var open = HardenedHttpHandler.Create(blockPrivateNetworks: false);
        using var guarded = HardenedHttpHandler.Create(blockPrivateNetworks: true);

        Assert.False(open.AllowAutoRedirect);
        Assert.False(guarded.AllowAutoRedirect);
    }

    [Fact]
    public void The_guard_is_wired_only_when_asked_and_then_connects_directly()
    {
        using var open = HardenedHttpHandler.Create(blockPrivateNetworks: false);
        using var guarded = HardenedHttpHandler.Create(blockPrivateNetworks: true);

        Assert.Null(open.ConnectCallback);
        Assert.True(open.UseProxy);
        Assert.NotNull(guarded.ConnectCallback);
        Assert.False(guarded.UseProxy);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")]
    [InlineData("[::1]")]
    public async Task A_guarded_fetch_of_a_loopback_destination_is_refused_before_any_connection(string host)
    {
        await using var server = new LoopbackServer(NoContent);
        using var client = new HttpClient(HardenedHttpHandler.Create(blockPrivateNetworks: true)) { Timeout = TimeSpan.FromSeconds(10) };

        var failure = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(new Uri($"http://{host}:{server.Port}/jwks.json")));

        Assert.True(DestinationRefusedException.IsIn(failure), failure.ToString());
        Assert.Equal(0, server.Connections);
    }

    [Fact]
    public async Task The_guard_judges_the_destination_and_never_goes_through_a_proxy()
    {
        await using var proxy = new LoopbackServer(NoContent);
        await using var destination = new LoopbackServer(NoContent);
        var handler = HardenedHttpHandler.Create(blockPrivateNetworks: true);
        handler.Proxy = new WebProxy(new Uri($"http://127.0.0.1:{proxy.Port}"));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        var failure = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(new Uri($"http://localhost:{destination.Port}/jwks.json")));

        // Through the proxy, the check would have judged the proxy's own address instead.
        Assert.True(DestinationRefusedException.IsIn(failure), failure.ToString());
        Assert.Contains("'localhost'", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, proxy.Connections);
        Assert.Equal(0, destination.Connections);
    }

    [Fact]
    public async Task Without_the_guard_a_private_destination_is_still_reached()
    {
        await using var server = new LoopbackServer(NoContent);
        using var client = new HttpClient(HardenedHttpHandler.Create(blockPrivateNetworks: false)) { Timeout = TimeSpan.FromSeconds(10) };

        using var response = await client.GetAsync(new Uri($"http://127.0.0.1:{server.Port}/jwks.json"));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(1, server.Connections);
    }

    [Fact]
    public async Task A_redirect_is_returned_as_it_is_and_its_target_is_never_asked()
    {
        await using var target = new LoopbackServer(NoContent);
        await using var server = new LoopbackServer($"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target.Port}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var client = new HttpClient(HardenedHttpHandler.Create(blockPrivateNetworks: false)) { Timeout = TimeSpan.FromSeconds(10) };

        using var response = await client.GetAsync(new Uri($"http://127.0.0.1:{server.Port}/jwks.json"));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(0, target.Connections);
    }

    private const string NoContent = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
}
