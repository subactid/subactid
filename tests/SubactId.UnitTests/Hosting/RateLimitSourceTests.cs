using System.Net;
using Microsoft.AspNetCore.Http;
using SubactId.Core.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;
using Xunit;

namespace SubactId.UnitTests.Hosting;

/// <summary>
/// Which address a request is counted against. Trusting the wrong forwarded entry would let a
/// caller pick its own bucket on every request.
/// </summary>
public class RateLimitSourceTests
{
    private static readonly RateLimitOptions BehindProxy = new() { TrustedProxies = [IPNetwork.Parse("10.0.0.0/8")] };

    private static HttpContext Request(string remote, params string[] forwarded)
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        if (forwarded.Length > 0)
        {
            http.Request.Headers["X-Forwarded-For"] = forwarded;
        }

        return http;
    }

    [Fact]
    public void Without_a_configured_proxy_the_socket_address_is_the_source()
    {
        // Nothing is trusted, so a header claiming otherwise changes nothing.
        Assert.Equal("203.0.113.5", RateLimiting.SourceOf(Request("203.0.113.5", "198.51.100.9"), new RateLimitOptions()));
    }

    [Fact]
    public void A_header_from_a_network_that_is_not_a_proxy_is_ignored()
    {
        Assert.Equal("203.0.113.5", RateLimiting.SourceOf(Request("203.0.113.5", "198.51.100.9"), BehindProxy));
    }

    [Fact]
    public void Behind_a_proxy_the_address_the_proxy_observed_is_the_source()
    {
        Assert.Equal("198.51.100.9", RateLimiting.SourceOf(Request("10.1.2.3", "198.51.100.9"), BehindProxy));
    }

    [Fact]
    public void A_caller_cannot_choose_its_own_bucket_by_sending_a_forwarded_header()
    {
        // The caller wrote "1.2.3.4" and the proxy appended what it saw. The left entry is
        // caller-controlled; the last is the one the proxy vouches for.
        var forged = Request("10.1.2.3", "1.2.3.4, 198.51.100.9");

        Assert.Equal("198.51.100.9", RateLimiting.SourceOf(forged, BehindProxy));
    }

    [Fact]
    public void A_forged_chain_spread_over_several_headers_is_no_better()
    {
        var forged = Request("10.1.2.3", "1.2.3.4", "5.6.7.8, 198.51.100.9");

        Assert.Equal("198.51.100.9", RateLimiting.SourceOf(forged, BehindProxy));
    }

    [Fact]
    public void Behind_two_trusted_proxies_the_caller_is_the_entry_before_the_inner_proxy()
    {
        // Caller -> load balancer -> ingress -> this server, both hops trusted. The last entry is the
        // balancer's address, and counting it would put every caller in one bucket.
        var chained = Request("10.1.2.3", "198.51.100.9, 10.0.0.7");

        Assert.Equal("198.51.100.9", RateLimiting.SourceOf(chained, BehindProxy));
    }

    [Fact]
    public void A_caller_cannot_hide_behind_a_forged_trusted_address_either()
    {
        // The caller wrote a trusted address hoping to be skipped over. The proxy still appended what
        // it saw, and that is the first entry that is not a proxy.
        var forged = Request("10.1.2.3", "10.0.0.7, 198.51.100.9");

        Assert.Equal("198.51.100.9", RateLimiting.SourceOf(forged, BehindProxy));
    }

    [Fact]
    public void When_every_entry_is_a_trusted_proxy_the_outermost_one_is_the_source()
    {
        Assert.Equal("10.0.0.5", RateLimiting.SourceOf(Request("10.1.2.3", "10.0.0.5, 10.0.0.7"), BehindProxy));
    }

    [Fact]
    public void An_unparseable_forwarded_value_falls_back_to_the_socket_address()
    {
        Assert.Equal("10.1.2.3", RateLimiting.SourceOf(Request("10.1.2.3", "not-an-address"), BehindProxy));
    }

    [Fact]
    public void An_unparseable_entry_ends_the_walk_at_the_proxies_already_seen()
    {
        // "garbage" was not written by a trusted proxy, so nothing to its left is believed. Only the
        // proxy entry after it is vouched for.
        Assert.Equal("10.0.0.7", RateLimiting.SourceOf(Request("10.1.2.3", "198.51.100.9, garbage, 10.0.0.7"), BehindProxy));
    }

    [Fact]
    public void An_ipv6_caller_is_counted_as_its_prefix_not_its_address()
    {
        // A single customer gets a whole /64, so counting individual addresses would give them a bucket each.
        var options = new RateLimitOptions();
        var first = RateLimiting.SourceOf(Request("2001:db8:1:2::1"), options);
        var second = RateLimiting.SourceOf(Request("2001:db8:1:2::dead:beef"), options);

        Assert.Equal(first, second);
        Assert.NotEqual(first, RateLimiting.SourceOf(Request("2001:db8:1:3::1"), options));
    }

    [Fact]
    public void The_logout_receiver_is_its_own_partition_and_gets_the_signal_bucket()
    {
        // Separated both ways: a flood of unverifiable logout tokens cannot spend the agents' bucket,
        // and a provider signing out every session is not held to the bucket sized for one agent.
        var options = new RateLimitOptions();
        var logout = Request("203.0.113.9");
        logout.Request.Path = SubactId.Server.Logout.LogoutEndpoints.LogoutPath;
        var token = Request("203.0.113.9");
        token.Request.Path = "/oauth2/token";

        var logoutPartition = RateLimiting.PartitionOf(logout, options);
        var tokenPartition = RateLimiting.PartitionOf(token, options);

        Assert.NotEqual(tokenPartition, logoutPartition);
        Assert.Equal(RateLimitBucket.Signals, RateLimiting.BucketOf(logoutPartition));
        Assert.Equal(RateLimitBucket.Source, RateLimiting.BucketOf(tokenPartition));

        var signals = RateLimiting.BucketFor(options, RateLimiting.BucketOf(logoutPartition));
        var agents = RateLimiting.BucketFor(options, RateLimiting.BucketOf(tokenPartition));
        Assert.Equal((options.SignalBurst, options.SignalPermitsPerSecond), (signals.TokenLimit, signals.TokensPerPeriod));
        Assert.Equal((options.Burst, options.PermitsPerSecond), (agents.TokenLimit, agents.TokensPerPeriod));
        Assert.True(signals.TokenLimit > agents.TokenLimit);
    }

    [Theory]
    [InlineData("/oauth2/token", AuditEvents.TokenDenied)]
    [InlineData("/oauth2/introspect", AuditEvents.TokenDenied)]
    [InlineData("/admin/agents", AuditEvents.AdminDenied)]
    [InlineData("/audit/events", AuditEvents.AdminDenied)]
    [InlineData("/scim/v2/Users", AuditEvents.ScimDenied)]
    [InlineData("/events", AuditEvents.SsfDenied)]
    [InlineData("/backchannel-logout", AuditEvents.SignalDenied)]
    public void A_refusal_is_recorded_under_the_event_of_the_surface_it_was_refused_on(string path, string expected)
    {
        // A provisioning client refused for its rate is a scim.denied, not a token denial, so it is
        // found under its own receiver's records.
        Assert.Equal(expected, RateLimiting.DeniedEventFor(path));
    }

    [Fact]
    public void Each_signal_receiver_has_its_own_partition_so_neither_can_spend_the_others()
    {
        // A directory sync and a realm-wide sign-out arrive from the same provider. Sharing one
        // bucket would let whichever ran first refuse the other.
        var options = new RateLimitOptions();
        var scim = Request("203.0.113.9");
        scim.Request.Path = SubactId.Server.Scim.ScimEndpoints.UsersPath;
        var logout = Request("203.0.113.9");
        logout.Request.Path = SubactId.Server.Logout.LogoutEndpoints.LogoutPath;

        var scimPartition = RateLimiting.PartitionOf(scim, options);
        var logoutPartition = RateLimiting.PartitionOf(logout, options);

        Assert.NotEqual(logoutPartition, scimPartition);
        Assert.Equal(RateLimitBucket.Signals, RateLimiting.BucketOf(scimPartition));
        Assert.Equal(RateLimitBucket.Signals, RateLimiting.BucketOf(logoutPartition));

        // And a different source is still a different bucket on the same receiver.
        var elsewhere = Request("198.51.100.4");
        elsewhere.Request.Path = SubactId.Server.Scim.ScimEndpoints.UsersPath;
        Assert.NotEqual(scimPartition, RateLimiting.PartitionOf(elsewhere, options));

        // The third receiver is its own again.
        var events = Request("203.0.113.9");
        events.Request.Path = SubactId.Server.Signals.SecurityEventEndpoints.EventsPath;
        var eventsPartition = RateLimiting.PartitionOf(events, options);
        Assert.Equal(RateLimitBucket.Signals, RateLimiting.BucketOf(eventsPartition));
        Assert.NotEqual(scimPartition, eventsPartition);
        Assert.NotEqual(logoutPartition, eventsPartition);
    }

    [Fact]
    public void Introspection_is_its_own_partition_so_a_busy_fleet_cannot_take_its_high_risk_tools_offline()
    {
        // A tool server introspecting every high-risk call often shares an egress address with the
        // agents making those calls. Sharing a bucket would refuse introspection as the fleet got busier.
        var options = new RateLimitOptions();
        var introspect = Request("203.0.113.9");
        introspect.Request.Path = SubactId.Server.Introspection.IntrospectionEndpoints.Path;
        var refresh = Request("203.0.113.9");
        refresh.Request.Path = "/oauth2/token";

        var introspectPartition = RateLimiting.PartitionOf(introspect, options);
        var refreshPartition = RateLimiting.PartitionOf(refresh, options);

        Assert.NotEqual(refreshPartition, introspectPartition);
        Assert.Equal(RateLimitBucket.Introspection, RateLimiting.BucketOf(introspectPartition));
        Assert.Equal(RateLimitBucket.Source, RateLimiting.BucketOf(refreshPartition));

        var introspection = RateLimiting.BucketFor(options, RateLimitBucket.Introspection);
        var agents = RateLimiting.BucketFor(options, RateLimitBucket.Source);
        Assert.Equal((options.IntrospectionBurst, options.IntrospectionPermitsPerSecond), (introspection.TokenLimit, introspection.TokensPerPeriod));
        Assert.True(introspection.TokenLimit > agents.TokenLimit);
        Assert.True(introspection.TokensPerPeriod > agents.TokensPerPeriod);
    }

    [Fact]
    public void Introspection_is_still_bounded_per_source_and_apart_from_the_signal_receivers()
    {
        // Its own bucket is still a limit: a flood of unverifiable tokens from one address is refused
        // and recorded.
        var options = new RateLimitOptions();
        var introspect = Request("203.0.113.9");
        introspect.Request.Path = SubactId.Server.Introspection.IntrospectionEndpoints.Path;
        var elsewhere = Request("198.51.100.4");
        elsewhere.Request.Path = SubactId.Server.Introspection.IntrospectionEndpoints.Path;

        Assert.NotEqual(RateLimiting.PartitionOf(elsewhere, options), RateLimiting.PartitionOf(introspect, options));

        // It is not the signal receivers' bucket either, so a realm-wide sign-out and a busy fleet's
        // introspection cannot spend each other's.
        var logout = Request("203.0.113.9");
        logout.Request.Path = SubactId.Server.Logout.LogoutEndpoints.LogoutPath;
        var logoutPartition = RateLimiting.PartitionOf(logout, options);
        Assert.NotEqual(logoutPartition, RateLimiting.PartitionOf(introspect, options));
        Assert.Equal(RateLimitBucket.Signals, RateLimiting.BucketOf(logoutPartition));

        // A refusal there is still a token denial in the ledger, under rate_limited.
        Assert.Equal(AuditEvents.TokenDenied, RateLimiting.DeniedEventFor(SubactId.Server.Introspection.IntrospectionEndpoints.Path));
        Assert.Equal("rate_limited", RateLimiting.Reason);
    }
}
