using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SubactId.Conformance;

/// <summary>
/// The instance under test, found through the environment, and the stub everything it calls
/// out to. Missing configuration or an unreachable instance fails every test at once with the
/// reason; the suite never passes by not running.
/// </summary>
public sealed class LiveInstance : IAsyncLifetime
{
    /// <summary>Base URL of the instance under test.</summary>
    public const string UrlVariable = "SUBACTID_CONFORMANCE_URL";

    /// <summary>The instance's admin API key.</summary>
    public const string AdminKeyVariable = "SUBACTID_CONFORMANCE_ADMIN_KEY";

    /// <summary>The https base URL the instance was configured to reach the upstream identity provider and agent JWKS at; the suite listens there.</summary>
    public const string StubUrlVariable = "SUBACTID_CONFORMANCE_STUB_URL";

    /// <summary>PKCS#12 file with the certificate the stub serves; the instance must trust its issuer.</summary>
    public const string StubPfxVariable = "SUBACTID_CONFORMANCE_STUB_PFX";

    /// <summary>
    /// The client the instance's back-channel logout receiver is configured for
    /// (<c>SubactId:UpstreamIdp:BackchannelLogout:Audience</c>). Needed by the logout case only.
    /// </summary>
    public const string LogoutAudienceVariable = "SUBACTID_CONFORMANCE_LOGOUT_AUDIENCE";

    /// <summary>The credential of the instance's SCIM receiver (<c>SubactId:Scim:BearerToken</c>). Needed by the SCIM case only.</summary>
    public const string ScimTokenVariable = "SUBACTID_CONFORMANCE_SCIM_TOKEN";

    /// <summary>The stream audience of the instance's Shared Signals receiver (<c>SubactId:Ssf:Audience</c>). Needed by the Shared Signals case only.</summary>
    public const string SsfAudienceVariable = "SUBACTID_CONFORMANCE_SSF_AUDIENCE";

    /// <summary>The push credential of the instance's Shared Signals receiver (<c>SubactId:Ssf:BearerToken</c>). Needed by the Shared Signals case only.</summary>
    public const string SsfTokenVariable = "SUBACTID_CONFORMANCE_SSF_TOKEN";

    /// <summary>The trait the cases that need a receiver configured carry, so a run against an instance without them can leave them out by name.</summary>
    public const string ReceiverTrait = "Receiver";

    /// <summary>The OpenID Connect back-channel logout event.</summary>
    public const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>The <c>aud</c> the instance expects on subject tokens.</summary>
    public const string UpstreamAudience = "subactid";

    /// <summary>
    /// How far before a check's start time a denial is looked for, absorbing the clock
    /// difference between this suite and the instance.
    /// </summary>
    /// <remarks>
    /// This is also the longest suppression the suite can see through. A denial that names
    /// nobody is written through once per <c>SubactId:Audit:Aggregation:Window</c> and counted for
    /// the rest of it, so against an instance whose window is longer than this, a second run
    /// would find nothing and fail a check the server still performs. The instance is required
    /// to run with a window no longer than this; see docs/conformance.md.
    /// </remarks>
    public static readonly TimeSpan DenialLookback = TimeSpan.FromMinutes(1);

    private StubIdentityProvider stub = null!;
    private JsonElement discovery;
    private JsonElement jwks;

    /// <summary>A client for the instance without credentials.</summary>
    public HttpClient Http { get; private set; } = null!;

    /// <summary>A client for the instance with the admin API key.</summary>
    public HttpClient Admin { get; private set; } = null!;

    /// <summary>The stub identity provider.</summary>
    public StubIdentityProvider Stub => stub;

    /// <summary>The instance's issuer, as it publishes it.</summary>
    public string Issuer => discovery.GetProperty("issuer").GetString()!;

    /// <summary>The instance's token endpoint, the <c>aud</c> of every client assertion.</summary>
    public string TokenEndpoint => discovery.GetProperty("token_endpoint").GetString()!;

    /// <inheritdoc />
    public async Task InitializeAsync()
    {
        var url = new Uri(Require(UrlVariable), UriKind.Absolute);
        var adminKey = Require(AdminKeyVariable);
        var stubUrl = new Uri(Require(StubUrlVariable), UriKind.Absolute);
        if (stubUrl.Scheme != Uri.UriSchemeHttps)
        {
            // Agent JWKS are only ever fetched over https, so a plain http stub could register no agent.
            throw new InvalidOperationException($"{StubUrlVariable} must be an https URL; the instance fetches agent JWKS over https only.");
        }

        stub = await StubIdentityProvider.StartAsync(stubUrl, Require(StubPfxVariable));

        Http = new HttpClient(new WaitOutRateLimit()) { BaseAddress = url, Timeout = TimeSpan.FromMinutes(2) };
        Admin = new HttpClient(new WaitOutRateLimit()) { BaseAddress = url, Timeout = TimeSpan.FromMinutes(2) };
        Admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminKey);

        try
        {
            discovery = await Http.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration");
            jwks = await Http.GetFromJsonAsync<JsonElement>(new Uri(discovery.GetProperty("jwks_uri").GetString()!));
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new InvalidOperationException($"No Subact ID instance answers at {url}; the conformance suite needs a live one. ({exception.GetType().Name}: {exception.Message})", exception);
        }
    }

    /// <inheritdoc />
    public async Task DisposeAsync()
    {
        Http?.Dispose();
        Admin?.Dispose();
        if (stub is not null)
        {
            await stub.DisposeAsync();
        }
    }

    /// <summary>Registers a fresh agent with its own key, served by the stub. Defaults: Jira scopes and audiences, half-hour tasks, five-minute tokens, no high-risk audience.</summary>
    /// <param name="allowedScopes">Scopes the agent may ever be granted.</param>
    /// <param name="allowedAudiences">Audiences it may request tokens for.</param>
    /// <param name="maxTaskTtl">Lifetime of a whole task.</param>
    /// <param name="maxTokenTtl">Lifetime of one token.</param>
    /// <param name="maxDelegationDepth">Longest <c>act</c> chain it accepts.</param>
    /// <param name="highRiskAudiences">Audiences whose tokens must be introspected on every call.</param>
    public async Task<ConformanceAgent> RegisterAgentAsync(
        string[]? allowedScopes = null,
        string[]? allowedAudiences = null,
        string maxTaskTtl = "PT30M",
        string maxTokenTtl = "PT5M",
        int maxDelegationDepth = 2,
        string[]? highRiskAudiences = null)
    {
        var agentId = $"conformance-{Guid.NewGuid():N}"[..40];
        var key = RSA.Create(2048);
        stub.AgentKeys[agentId] = key;
        var body = new
        {
            agent_id = agentId,
            display_name = "Conformance agent",
            allowed_scopes = allowedScopes ?? ["jira:read", "jira:comment"],
            allowed_audiences = allowedAudiences ?? ["https://jira.internal", "https://confluence.internal"],
            max_task_ttl = maxTaskTtl,
            max_token_ttl = maxTokenTtl,
            max_delegation_depth = maxDelegationDepth,
            high_risk_audiences = highRiskAudiences ?? [],
            jwks_uri = $"{stub.Issuer}/agents/{agentId}/jwks.json",
        };
        using var response = await Admin.PostAsJsonAsync("/admin/agents", body);
        Assert.True(response.StatusCode == HttpStatusCode.Created, $"Registering an agent answered {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        return new ConformanceAgent(agentId, key);
    }

    /// <summary>A new human the stub's admin API knows as enabled.</summary>
    public string NewHuman()
    {
        var human = Guid.NewGuid().ToString();
        stub.Users[human] = true;
        return human;
    }

    /// <summary>A subject token from the identity provider for <paramref name="human"/> with <paramref name="scope"/>; <paramref name="overrides"/> replace claims, <paramref name="key"/> and <paramref name="kid"/> the signer.</summary>
    public string SubjectToken(string human, string scope = "openid jira:read jira:comment", RSA? key = null, string? kid = null, params (string Key, object? Value)[] overrides)
    {
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = stub.Issuer,
            ["sub"] = human,
            ["aud"] = UpstreamAudience,
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["scope"] = scope,
        };
        foreach (var (name, value) in overrides)
        {
            claims[name] = value;
        }

        return Jwt.SignRs256(key ?? stub.IdpKey, kid ?? stub.IdpKid, claims);
    }

    /// <summary>A <c>private_key_jwt</c> assertion for <paramref name="agent"/>, signed with its key unless <paramref name="key"/> says otherwise, addressed to the token endpoint unless <paramref name="audience"/> says otherwise.</summary>
    public string ClientAssertion(ConformanceAgent agent, RSA? key = null, string? jti = null, string? audience = null)
    {
        var now = DateTimeOffset.UtcNow;
        return Jwt.SignRs256(key ?? agent.Key, StubIdentityProvider.AgentKid, new Dictionary<string, object?>
        {
            ["iss"] = agent.AgentId,
            ["sub"] = agent.AgentId,
            ["aud"] = audience ?? TokenEndpoint,
            ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
        });
    }

    /// <summary>The RFC 8693 exchange.</summary>
    public Task<HttpResponseMessage> ExchangeAsync(ConformanceAgent agent, string subjectToken, string resource = "https://jira.internal", string scope = "jira:read jira:comment", string? actorToken = null) =>
        Http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = actorToken ?? ClientAssertion(agent),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["resource"] = resource,
            ["scope"] = scope,
        }));

    /// <summary>The refresh of spec section 5.</summary>
    public Task<HttpResponseMessage> RefreshAsync(ConformanceAgent agent, string grant, string resource = "https://jira.internal", string scope = "jira:read jira:comment") =>
        Http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = grant,
            ["resource"] = resource,
            ["scope"] = scope,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = ClientAssertion(agent),
        }));

    /// <summary>RFC 7662 introspection.</summary>
    public async Task<JsonElement> IntrospectAsync(string token)
    {
        using var response = await Http.PostAsync("/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    /// <summary>RFC 7009 revocation by the agent.</summary>
    public Task<HttpResponseMessage> RevokeAsync(ConformanceAgent agent, string token) =>
        Http.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = ClientAssertion(agent),
        }));

    /// <summary>
    /// Every denial the ledger holds since <paramref name="since"/>, oldest first, for <paramref name="agent"/>
    /// when given. A denial of the client assertion itself is written before the agent is attributed, so
    /// those are looked up without the agent filter.
    /// </summary>
    public async Task<IReadOnlyList<JsonElement>> DenialsAsync(ConformanceAgent? agent, DateTimeOffset since)
    {
        var from = Uri.EscapeDataString((since - DenialLookback).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
        var byAgent = agent is null ? string.Empty : $"&agent_id={Uri.EscapeDataString(agent.AgentId)}";
        var records = new List<JsonElement>();
        string? cursor = null;
        do
        {
            var page = await Admin.GetFromJsonAsync<JsonElement>($"/audit?decision=deny&from={from}&limit=1000{byAgent}{(cursor is null ? string.Empty : "&cursor=" + Uri.EscapeDataString(cursor))}");
            records.AddRange(page.GetProperty("records").EnumerateArray());
            cursor = page.GetProperty("next_cursor").GetString();
        }
        while (cursor is not null);

        return records;
    }

    /// <summary>
    /// Every record the ledger holds since <paramref name="since"/>, oldest first and unfiltered,
    /// so consecutive entries are the chain in order and their links can be followed.
    /// </summary>
    /// <param name="since">Earliest record to read.</param>
    public async Task<IReadOnlyList<JsonElement>> LedgerAsync(DateTimeOffset since)
    {
        var from = Uri.EscapeDataString((since - DenialLookback).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
        var records = new List<JsonElement>();
        string? cursor = null;
        do
        {
            var page = await Admin.GetFromJsonAsync<JsonElement>($"/audit?from={from}&limit=1000{(cursor is null ? string.Empty : "&cursor=" + Uri.EscapeDataString(cursor))}");
            records.AddRange(page.GetProperty("records").EnumerateArray());
            cursor = page.GetProperty("next_cursor").GetString();
        }
        while (cursor is not null);

        return records;
    }

    /// <summary>
    /// Refuses to act for <paramref name="sponsorKey"/> through the admin API, which also ends
    /// what is already running for them. The key is the claim the instance identifies people by,
    /// which is the subject unless it was configured otherwise; see docs/conformance.md.
    /// </summary>
    /// <param name="sponsorKey">The human, as the instance keys their tasks by them.</param>
    public async Task BlockSponsorAsync(string sponsorKey)
    {
        using var response = await Admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(sponsorKey)}/block", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>Whether the identity provider says <paramref name="human"/> is still an active user.</summary>
    /// <param name="human">The subject.</param>
    /// <param name="enabled">What the stub's admin API answers from now on.</param>
    public void SetSponsorEnabled(string human, bool enabled) => stub.Users[human] = enabled;

    /// <summary>Forgets <paramref name="human"/> entirely, as a deletion at the identity provider would.</summary>
    /// <param name="human">The subject.</param>
    public void DeleteSponsor(string human) => stub.Users.TryRemove(human, out _);

    /// <summary>A back-channel logout token from the identity provider naming <paramref name="human"/>, and <paramref name="sessionId"/> when given.</summary>
    /// <param name="human">The <c>sub</c>.</param>
    /// <param name="sessionId">The <c>sid</c>, or <c>null</c> for a logout of the person as a whole.</param>
    /// <param name="key">The signer, the identity provider's unless given.</param>
    public string LogoutToken(string human, string? sessionId = null, RSA? key = null)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = stub.Issuer,
            ["sub"] = human,
            ["aud"] = RequireReceiver(LogoutAudienceVariable, "back-channel logout"),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["events"] = new Dictionary<string, object?> { [LogoutEvent] = new Dictionary<string, object?>() },
        };
        if (sessionId is not null)
        {
            claims["sid"] = sessionId;
        }

        return Jwt.SignRs256(key ?? stub.IdpKey, stub.IdpKid, claims);
    }

    /// <summary>OpenID Connect back-channel logout.</summary>
    public Task<HttpResponseMessage> LogoutAsync(string logoutToken) =>
        Http.PostAsync("/backchannel-logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = logoutToken }));

    /// <summary>A request to the SCIM receiver as the provisioning client, with <paramref name="body"/> as SCIM JSON when given.</summary>
    /// <param name="method">The method.</param>
    /// <param name="path">The path under <c>/scim/v2</c>.</param>
    /// <param name="body">The JSON body, or <c>null</c>.</param>
    /// <param name="credential">The bearer credential, the configured one unless given.</param>
    public async Task<HttpResponseMessage> ScimAsync(HttpMethod method, string path, string? body = null, string? credential = null)
    {
        using var request = new HttpRequestMessage(method, "/scim/v2" + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential ?? RequireReceiver(ScimTokenVariable, "SCIM"));
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/scim+json");
        }

        return await Http.SendAsync(request);
    }

    /// <summary>
    /// A security event token from the stub's transmitter carrying <paramref name="eventType"/>
    /// about <paramref name="human"/>, named as an <c>iss_sub</c> subject of the identity provider.
    /// </summary>
    /// <param name="eventType">The CAEP or RISC event type.</param>
    /// <param name="human">The person.</param>
    /// <param name="jti">The token's <c>jti</c>, fresh unless given.</param>
    public string SecurityEvent(string eventType, string human, string? jti = null) =>
        Jwt.SignRs256(stub.TransmitterKey, stub.TransmitterKid, new Dictionary<string, object?>
        {
            ["iss"] = stub.TransmitterIssuer,
            ["aud"] = RequireReceiver(SsfAudienceVariable, "Shared Signals"),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
            ["events"] = new Dictionary<string, object?>
            {
                [eventType] = new Dictionary<string, object?>
                {
                    ["subject"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = stub.Issuer, ["sub"] = human },
                },
            },
        });

    /// <summary>RFC 8935 push delivery of <paramref name="securityEvent"/>, with the configured push credential unless <paramref name="credential"/> says otherwise.</summary>
    public async Task<HttpResponseMessage> PushAsync(string securityEvent, string? credential = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/events")
        {
            Content = new StringContent(securityEvent, Encoding.ASCII, "application/secevent+jwt"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential ?? RequireReceiver(SsfTokenVariable, "Shared Signals"));
        return await Http.SendAsync(request);
    }

    /// <summary>The block standing on <paramref name="sponsorKey"/>, or <c>null</c> when there is none.</summary>
    public async Task<JsonElement?> SponsorBlockAsync(string sponsorKey)
    {
        using var response = await Admin.GetAsync($"/admin/sponsors/{Uri.EscapeDataString(sponsorKey)}");
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    /// <summary>The claims of a task token, after checking it is signed by the key the instance publishes.</summary>
    public JsonElement VerifiedClaims(string token)
    {
        Assert.True(Jwt.VerifyEs256(token, jwks), "The task token does not verify against the instance's published JWKS.");
        return Jwt.Payload(token);
    }

    /// <summary>The body of a successful token response.</summary>
    public static async Task<JsonElement> TokenAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"Expected a token but the endpoint answered {(int)response.StatusCode}: {body}");
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    /// <summary>
    /// Asserts an OAuth error response with the given status and <c>error</c> code, and that the
    /// body carries none of <paramref name="secrets"/>.
    /// </summary>
    /// <param name="response">The answer.</param>
    /// <param name="status">The expected HTTP status.</param>
    /// <param name="error">The expected <c>error</c> code.</param>
    /// <param name="secrets">Credentials that were sent with the request and must not come back.</param>
    public static async Task AssertOAuthErrorAsync(HttpResponseMessage response, HttpStatusCode status, string error, params string[] secrets)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == status, $"Expected {(int)status} {error} but the endpoint answered {(int)response.StatusCode}: {body}");
        var json = JsonDocument.Parse(body).RootElement;
        Assert.Equal(error, json.GetProperty("error").GetString());
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("error_description").GetString()), "An OAuth error must carry an error_description.");
        AssertNoSecretIn(body, secrets);
    }

    /// <summary>
    /// Asserts that none of <paramref name="secrets"/> appears in <paramref name="body"/>, whole
    /// or in any run long enough to be worth having. A refusal that quotes the credential back
    /// puts it into every proxy log between here and the caller.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <param name="secrets">The credentials that were sent.</param>
    public static void AssertNoSecretIn(string body, params string[] secrets)
    {
        foreach (var secret in secrets)
        {
            if (string.IsNullOrEmpty(secret))
            {
                continue;
            }

            Assert.DoesNotContain(secret, body, StringComparison.Ordinal);

            // A token echoed in part is a token echoed: 32 characters of a signature or a grant
            // is plenty to be worth logging, and truncation is the usual way this leaks.
            for (var start = 0; start + 32 <= secret.Length; start += 32)
            {
                Assert.DoesNotContain(secret.Substring(start, 32), body, StringComparison.Ordinal);
            }
        }
    }

    /// <summary>
    /// A receiver's setting, for the case that needs that receiver. Missing, the case fails with
    /// the reason; leave the receiver cases out by trait to run against an instance without them.
    /// </summary>
    private static string RequireReceiver(string variable, string receiver) =>
        Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"{variable} is not set. This case needs the instance's {receiver} receiver configured; to run against an instance without it, leave out the cases carrying the {ReceiverTrait} trait, as docs/conformance.md describes.");

    private static string Require(string variable) =>
        Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"{variable} is not set. The conformance suite runs against a live instance: set {UrlVariable}, {AdminKeyVariable}, {StubUrlVariable} and {StubPfxVariable}.");
}

/// <summary>
/// Waits out a <c>429</c> for as long as its <c>Retry-After</c> asks, and sends the request again.
/// The suite sends a few hundred requests from one address, more than an instance's default
/// burst allows at once, and rate limiting is not what it tests. A refused request is turned away
/// before it is read, so sending it again changes nothing on the instance.
/// </summary>
internal sealed class WaitOutRateLimit() : DelegatingHandler(new HttpClientHandler())
{
    /// <summary>Most times one request is sent again before its <c>429</c> is handed back.</summary>
    private const int MaxRetries = 10;

    /// <summary>Longest single wait, whatever <c>Retry-After</c> says.</summary>
    private static readonly TimeSpan MaxWait = TimeSpan.FromSeconds(30);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Read once, so the same bytes can be sent again.
        var body = request.Content is null ? null : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var contentHeaders = request.Content?.Headers.ToList();

        for (var attempt = 0; ; attempt++)
        {
            // Not disposed when it is handed back: the response refers to it.
            var copy = new HttpRequestMessage(request.Method, request.RequestUri) { Version = request.Version };
            foreach (var header in request.Headers)
            {
                copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (body is not null)
            {
                copy.Content = new ByteArrayContent(body);
                foreach (var header in contentHeaders!)
                {
                    copy.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            var response = await base.SendAsync(copy, cancellationToken);
            if (response.StatusCode != HttpStatusCode.TooManyRequests || attempt == MaxRetries)
            {
                return response;
            }

            var wait = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(1);
            response.Dispose();
            copy.Dispose();
            await Task.Delay(wait < MaxWait ? wait : MaxWait, cancellationToken);
        }
    }
}

/// <summary>An agent the suite registered, with the key it signs with.</summary>
/// <param name="AgentId">The agent id.</param>
/// <param name="Key">Its private key; the public half is served by the stub.</param>
public sealed record ConformanceAgent(string AgentId, RSA Key);

/// <summary>All conformance tests share one instance and one stub.</summary>
[CollectionDefinition(Name)]
public sealed class LiveInstanceCollection : ICollectionFixture<LiveInstance>
{
    /// <summary>The collection name.</summary>
    public const string Name = "live-instance";
}
