using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Tokens.Upstream;

/// <summary>A stand-in for Keycloak's token endpoint and admin users API that records what it was sent.</summary>
internal sealed class FakeKeycloak : HttpMessageHandler
{
    public const string TokenUrl = "https://idp.example.test/realms/main/protocol/openid-connect/token";
    public const string UsersUrl = "https://idp.example.test/admin/realms/main/users";

    public Dictionary<string, bool> Users { get; } = new(StringComparer.Ordinal) { ["f47ac10b-58cc-4372-a567-0e02b2c3d479"] = true };

    public List<Dictionary<string, string>> TokenRequests { get; } = [];

    public List<string?> UserRequestTokens { get; } = [];

    public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;

    public HttpStatusCode? UsersStatus { get; set; }

    public string? UsersBody { get; set; }

    public long TokenLifetimeSeconds { get; set; } = 300;

    public string IssuedToken { get; set; } = "service-token-1";

    public bool Throw { get; set; }

    public bool Hang { get; set; }

    public HttpClient CreateClient() => new(this, disposeHandler: false);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Throw) throw new HttpRequestException("down");
        if (Hang) await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        var url = request.RequestUri!.ToString();
        if (url == TokenUrl)
        {
            var form = (await request.Content!.ReadAsStringAsync(cancellationToken)).Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]), StringComparer.Ordinal);
            TokenRequests.Add(form);
            return TokenStatus == HttpStatusCode.OK
                ? Json($"{{\"access_token\":\"{IssuedToken}\",\"expires_in\":{TokenLifetimeSeconds},\"token_type\":\"Bearer\"}}")
                : new HttpResponseMessage(TokenStatus);
        }

        if (url.StartsWith(UsersUrl + "/", StringComparison.Ordinal))
        {
            UserRequestTokens.Add(request.Headers.Authorization?.Parameter);
            if (UsersStatus is { } forced) return UsersBody is null ? new HttpResponseMessage(forced) : Json(UsersBody, forced);
            if (request.Headers.Authorization?.Parameter != IssuedToken) return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            var subject = Uri.UnescapeDataString(url[(UsersUrl.Length + 1)..]);
            return Users.TryGetValue(subject, out var enabled) ? Json($"{{\"id\":\"{subject}\",\"enabled\":{(enabled ? "true" : "false")}}}") : new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
}

public class KeycloakSponsorStatusSourceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 9, 0, 0, TimeSpan.Zero);

    private static (KeycloakSponsorStatusSource Source, FakeKeycloak Keycloak, SigningKeySet Keys, FakeTimeProvider Clock) Build()
    {
        var keycloak = new FakeKeycloak();
        var keys = SigningKeySet.CreateEphemeral();
        var clock = new FakeTimeProvider(Now);
        return (new KeycloakSponsorStatusSource(keycloak.CreateClient, new Uri(FakeKeycloak.UsersUrl), new Uri(FakeKeycloak.TokenUrl), "subactid", keys, clock), keycloak, keys, clock);
    }

    [Fact]
    public async Task Obtains_a_service_token_with_a_private_key_jwt_signed_by_the_active_key_then_reads_enabled()
    {
        var (source, keycloak, keys, _) = Build();

        Assert.Equal(SponsorStatus.Active, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));

        var tokenRequest = Assert.Single(keycloak.TokenRequests);
        Assert.Equal("client_credentials", tokenRequest["grant_type"]);
        Assert.Equal("subactid", tokenRequest["client_id"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", tokenRequest["client_assertion_type"]);
        Assert.True(Jws.TryVerify(keys, tokenRequest["client_assertion"], out var header, out var payload));
        Assert.Equal("JWT", header!.Typ);
        using var claims = JsonDocument.Parse(payload!);
        Assert.Equal("subactid", claims.RootElement.GetProperty("iss").GetString());
        Assert.Equal("subactid", claims.RootElement.GetProperty("sub").GetString());
        Assert.Equal(FakeKeycloak.TokenUrl, claims.RootElement.GetProperty("aud").GetString());
        Assert.Equal(Now.AddSeconds(60).ToUnixTimeSeconds(), claims.RootElement.GetProperty("exp").GetInt64());
        Assert.StartsWith("kc_", claims.RootElement.GetProperty("jti").GetString(), StringComparison.Ordinal);
        Assert.Equal(["service-token-1"], keycloak.UserRequestTokens);
    }

    [Fact]
    public async Task Reports_disabled_and_missing_users()
    {
        var (source, keycloak, _, _) = Build();
        keycloak.Users[Human] = false;

        Assert.Equal(SponsorStatus.Disabled, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.NotFound, await source.GetAsync("nobody", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.NotFound, await source.GetAsync("", TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task Reuses_the_service_token_until_it_is_about_to_expire()
    {
        var (source, keycloak, _, clock) = Build();

        await source.GetAsync(Human, TimeSpan.FromMinutes(5));
        clock.Advance(TimeSpan.FromSeconds(200));
        await source.GetAsync(Human, TimeSpan.FromMinutes(5));
        Assert.Single(keycloak.TokenRequests);

        clock.Advance(TimeSpan.FromSeconds(75));
        keycloak.IssuedToken = "service-token-2";
        await source.GetAsync(Human, TimeSpan.FromMinutes(5));
        Assert.Equal(2, keycloak.TokenRequests.Count);
        Assert.Equal("service-token-2", keycloak.UserRequestTokens[^1]);
    }

    [Fact]
    public async Task A_rejected_service_token_is_replaced_once_and_the_lookup_retried()
    {
        var (source, keycloak, _, _) = Build();
        await source.GetAsync(Human, TimeSpan.FromMinutes(5));
        keycloak.IssuedToken = "service-token-2";

        Assert.Equal(SponsorStatus.Active, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));

        Assert.Equal(2, keycloak.TokenRequests.Count);
        Assert.Equal(["service-token-1", "service-token-1", "service-token-2"], keycloak.UserRequestTokens);
    }

    [Fact]
    public async Task Anything_short_of_a_clear_answer_is_unavailable_never_active()
    {
        var (source, keycloak, _, _) = Build();

        keycloak.TokenStatus = HttpStatusCode.Unauthorized;
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));
        keycloak.TokenStatus = HttpStatusCode.OK;

        keycloak.UsersStatus = HttpStatusCode.InternalServerError;
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));

        keycloak.UsersStatus = HttpStatusCode.OK;
        keycloak.UsersBody = "{\"id\":\"x\"}";
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));
        keycloak.UsersBody = "not json";
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));
        keycloak.UsersBody = "{\"enabled\":\"true\"}";
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));

        keycloak.UsersStatus = null;
        keycloak.UsersBody = null;
        keycloak.Throw = true;
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task The_subject_is_escaped_into_the_path_and_dot_segments_are_never_sent()
    {
        var (source, keycloak, _, _) = Build();
        keycloak.Users["a/b?c=d"] = true;
        keycloak.Users["."] = true;
        keycloak.Users[".."] = true;

        Assert.Equal(SponsorStatus.Active, await source.GetAsync("a/b?c=d", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.NotFound, await source.GetAsync("../users", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.NotFound, await source.GetAsync(".", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.NotFound, await source.GetAsync("..", TimeSpan.FromMinutes(5)));
        Assert.Equal(1, keycloak.UserRequestTokens.Count(t => t is not null) - 1);
    }

    [Fact]
    public async Task An_answer_about_a_different_user_or_a_body_over_the_limit_is_unavailable()
    {
        var (source, keycloak, _, _) = Build();
        keycloak.UsersStatus = HttpStatusCode.OK;
        keycloak.UsersBody = "{\"id\":\"someone-else\",\"enabled\":true}";
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));

        keycloak.UsersBody = "{\"id\":\"" + Human + "\",\"enabled\":true,\"padding\":\"" + new string('x', KeycloakSponsorStatusSource.MaxResponseBytes) + "\"}";
        Assert.Equal(SponsorStatus.Unavailable, await source.GetAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task The_callers_own_cancellation_propagates_instead_of_becoming_unavailable()
    {
        var (source, keycloak, _, _) = Build();
        keycloak.Hang = true;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.GetAsync(Human, TimeSpan.FromMinutes(5), cts.Token));
    }

    [Fact]
    public async Task Answers_the_provider_gives_are_not_the_provider_failing()
    {
        var (source, keycloak, _, _) = Build();

        Assert.Equal(new SponsorLookup(SponsorStatus.Active, ProviderFailed: false), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
        keycloak.Users[Human] = false;
        Assert.Equal(new SponsorLookup(SponsorStatus.Disabled, ProviderFailed: false), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
        Assert.Equal(new SponsorLookup(SponsorStatus.NotFound, ProviderFailed: false), await source.LookUpAsync("nobody-at-all", TimeSpan.FromMinutes(5)));
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task A_provider_in_trouble_is_the_provider_failing(HttpStatusCode status)
    {
        var (source, keycloak, _, _) = Build();
        keycloak.UsersStatus = status;

        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: true), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task No_connection_or_no_service_token_is_the_provider_failing()
    {
        var (source, keycloak, _, _) = Build();
        keycloak.Throw = true;
        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: true), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));

        var (fresh, refusing, _, _) = Build();
        refusing.TokenStatus = HttpStatusCode.InternalServerError;
        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: true), await fresh.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task A_timeout_is_the_provider_failing()
    {
        var keycloak = new FakeKeycloak { Hang = true };
        var source = new KeycloakSponsorStatusSource(
            () =>
            {
                var client = keycloak.CreateClient();
                client.Timeout = TimeSpan.FromMilliseconds(100);
                return client;
            },
            new Uri(FakeKeycloak.UsersUrl),
            new Uri(FakeKeycloak.TokenUrl),
            "subactid",
            SigningKeySet.CreateEphemeral(),
            new FakeTimeProvider(Now));

        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: true), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task A_refusal_about_one_account_is_not_the_provider_failing(HttpStatusCode status)
    {
        // For example, a service account that may not read this one person. Still a refusal for them only.
        var (source, keycloak, _, _) = Build();
        keycloak.UsersStatus = status;

        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: false), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task A_record_that_cannot_be_used_is_not_the_provider_failing()
    {
        var (source, keycloak, _, _) = Build();
        keycloak.UsersStatus = HttpStatusCode.OK;

        keycloak.UsersBody = "{\"id\":\"someone-else\",\"enabled\":true}";
        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: false), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));

        keycloak.UsersBody = "{\"id\":\"" + Human + "\",\"enabled\":true,\"padding\":\"" + new string('x', KeycloakSponsorStatusSource.MaxResponseBytes) + "\"}";
        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: false), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));

        keycloak.UsersBody = "not json";
        Assert.Equal(new SponsorLookup(SponsorStatus.Unavailable, ProviderFailed: false), await source.LookUpAsync(Human, TimeSpan.FromMinutes(5)));
    }

    [Theory]
    [InlineData("ftp://idp/users")]
    [InlineData("/relative")]
    public void Urls_must_be_absolute_http(string url)
    {
        Assert.Throws<ArgumentException>(() => new KeycloakSponsorStatusSource(() => new HttpClient(), new Uri(url, UriKind.RelativeOrAbsolute), new Uri(FakeKeycloak.TokenUrl), "subactid", SigningKeySet.CreateEphemeral(), TimeProvider.System));
    }
}

public class SponsorStatusCacheTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 9, 0, 0, TimeSpan.Zero);

    private sealed class Counting(Func<string, SponsorStatus> answer) : ISponsorStatusSource
    {
        public List<string> Calls { get; } = [];

        public Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
        {
            Calls.Add(subject);
            return Task.FromResult(answer(subject));
        }
    }

    [Fact]
    public async Task An_answer_asked_for_as_of_now_is_never_served_from_the_cache()
    {
        var status = SponsorStatus.Active;
        var inner = new Counting(_ => status);
        var clock = new FakeTimeProvider(Now);
        var cache = new SponsorStatusCache(inner, TimeSpan.FromSeconds(30), clock);
        const string human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

        Assert.Equal(SponsorStatus.Active, await cache.GetAsync(human, TimeSpan.FromMinutes(5)));
        Assert.Single(inner.Calls);

        // A reusing caller would be answered from the entry just written; this one is not.
        status = SponsorStatus.Disabled;
        Assert.Equal(SponsorStatus.Disabled, await cache.GetAsync(human, TimeSpan.Zero));
        Assert.Equal(2, inner.Calls.Count);
    }

    /// <summary>
    /// A caller who will not reuse an answer must not leave one behind for a caller who will.
    /// Otherwise a human disabled between starting a task and its first renewal survives that renewal.
    /// </summary>
    [Fact]
    public async Task An_answer_asked_for_as_of_now_is_not_left_behind_for_a_caller_who_would_reuse_it()
    {
        var status = SponsorStatus.Active;
        var inner = new Counting(_ => status);
        var clock = new FakeTimeProvider(Now);
        var cache = new SponsorStatusCache(inner, TimeSpan.FromSeconds(30), clock);
        const string human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

        Assert.Equal(SponsorStatus.Active, await cache.GetAsync(human, TimeSpan.Zero));
        Assert.Single(inner.Calls);

        status = SponsorStatus.Disabled;
        clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(SponsorStatus.Disabled, await cache.GetAsync(human, TimeSpan.FromMinutes(5)));
        Assert.Equal(2, inner.Calls.Count);
    }

    [Fact]
    public async Task Reuses_an_answer_within_the_ttl_and_asks_again_after_it()
    {
        var status = SponsorStatus.Active;
        var inner = new Counting(_ => status);
        var clock = new FakeTimeProvider(Now);
        var cache = new SponsorStatusCache(inner, TimeSpan.FromSeconds(30), clock);

        Assert.Equal(SponsorStatus.Active, await cache.GetAsync("alice", TimeSpan.FromMinutes(5)));
        status = SponsorStatus.Disabled;
        clock.Advance(TimeSpan.FromSeconds(29));
        Assert.Equal(SponsorStatus.Active, await cache.GetAsync("alice", TimeSpan.FromMinutes(5)));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(SponsorStatus.Disabled, await cache.GetAsync("alice", TimeSpan.FromMinutes(5)));
        Assert.Equal(2, inner.Calls.Count);
    }

    [Fact]
    public async Task A_caller_that_can_accept_less_age_than_the_ttl_gets_a_fresh_answer_sooner()
    {
        var status = SponsorStatus.Active;
        var inner = new Counting(_ => status);
        var clock = new FakeTimeProvider(Now);
        var cache = new SponsorStatusCache(inner, TimeSpan.FromSeconds(30), clock);

        Assert.Equal(SponsorStatus.Active, await cache.GetAsync("alice", TimeSpan.FromSeconds(10)));
        status = SponsorStatus.Disabled;
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(SponsorStatus.Disabled, await cache.GetAsync("alice", TimeSpan.FromSeconds(10)));
        Assert.Equal(SponsorStatus.Disabled, await cache.GetAsync("alice", TimeSpan.Zero));
        Assert.Equal(3, inner.Calls.Count);
    }

    [Fact]
    public async Task Subjects_are_cached_separately_and_unavailable_is_never_cached()
    {
        var unavailable = false;
        var inner = new Counting(s => unavailable ? SponsorStatus.Unavailable : s == "bob" ? SponsorStatus.Disabled : SponsorStatus.Active);
        var cache = new SponsorStatusCache(inner, TimeSpan.FromSeconds(30), new FakeTimeProvider(Now));

        Assert.Equal(SponsorStatus.Active, await cache.GetAsync("alice", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.Disabled, await cache.GetAsync("bob", TimeSpan.FromMinutes(5)));

        unavailable = true;
        Assert.Equal(SponsorStatus.Unavailable, await cache.GetAsync("carol", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.Unavailable, await cache.GetAsync("carol", TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.Active, await cache.GetAsync("alice", TimeSpan.FromMinutes(5)));
        Assert.Equal(4, inner.Calls.Count);
    }

    [Fact]
    public void The_ttl_must_be_positive()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SponsorStatusCache(new Counting(_ => SponsorStatus.Active), TimeSpan.Zero, TimeProvider.System));
    }
}
