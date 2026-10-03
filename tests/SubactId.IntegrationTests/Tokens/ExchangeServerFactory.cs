using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SubactId.Core.Agents;
using SubactId.IntegrationTests.Admin;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Server.Upstream;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Upstream;

namespace SubactId.IntegrationTests.Tokens;

/// <summary>
/// The database-backed server with the two outbound key fetches replaced: the upstream identity
/// provider's keys and every agent's JWKS come from keys generated once per test process, so the
/// tests can mint subject tokens and client assertions the server will accept.
/// </summary>
public class ExchangeServerFactory(PostgresDatabaseFixture postgres) : DatabaseServerFactory(postgres)
{
    public const string IdpIssuer = "https://idp.example.test";
    public const string IdpKid = "idp-key";
    public const string AgentKid = "agent-key";

    public static RSA IdpKey { get; } = RSA.Create(2048);

    public static RSA AgentKey { get; } = RSA.Create(2048);

    /// <summary>The <c>kid</c> the Shared Signals transmitter signs with.</summary>
    public const string TransmitterKid = "transmitter-key";

    /// <summary>
    /// The transmitter's signing key, separate from the identity provider's, so a test can tell that
    /// each is checked against its own keys.
    /// </summary>
    public static RSA TransmitterKey { get; } = RSA.Create(2048);

    /// <summary>The stand-in for Keycloak's token endpoint and admin users API, one per server. Flip a user's <c>Enabled</c> here to disable them.</summary>
    public FakeKeycloakAdmin Keycloak { get; } = new();

    /// <summary>The server's clock. Move it forward instead of waiting.</summary>
    public AdvancingClock Clock { get; } = new();

    /// <summary>A compact RS256 JWS over <paramref name="claims"/> signed with <paramref name="key"/>.</summary>
    public static string Mint(RSA key, string kid, Dictionary<string, object?> claims)
    {
        var header = Base64Url.EncodeToString(Encoding.UTF8.GetBytes($"{{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}"));
        var payload = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(claims));
        var signature = key.SignData(Encoding.ASCII.GetBytes($"{header}.{payload}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Base64Url.EncodeToString(signature)}";
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            services.RemoveAll<IUpstreamKeys>();
            services.AddSingleton<IUpstreamKeys>(new FixedUpstreamKeys(new UpstreamKeySnapshot(IdpIssuer, Parse(IdpKey, IdpKid), DateTimeOffset.UtcNow)));
            services.RemoveAll<IAgentKeys>();
            services.AddSingleton<IAgentKeys>(new FixedAgentKeys(new JwksSnapshot(Parse(AgentKey, AgentKid), DateTimeOffset.UtcNow)));
            services.AddHttpClient(UpstreamIdpServiceCollectionExtensions.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Keycloak);

            // The transmitter's own keys, separate from the identity provider's.
            services.RemoveAll<SecurityEventTokenValidator>();
            services.AddSingleton(provider => new SecurityEventTokenValidator(
                new FixedUpstreamKeys(new UpstreamKeySnapshot(ServerFactory.TransmitterIssuer, Parse(TransmitterKey, TransmitterKid), DateTimeOffset.UtcNow)),
                ServerFactory.StreamAudience,
                IdpIssuer,
                provider.GetService<TimeProvider>() ?? TimeProvider.System));
        });
    }

    private static IReadOnlyDictionary<string, UpstreamKey> Parse(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(false);
        return UpstreamJwksParser.Parse($"{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"{kid}\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"{Base64Url.EncodeToString(p.Modulus!)}\",\"e\":\"{Base64Url.EncodeToString(p.Exponent!)}\"}}]}}");
    }

    private sealed class FixedUpstreamKeys(UpstreamKeySnapshot snapshot) : IUpstreamKeys
    {
        public UpstreamKeySnapshot? Current => snapshot;

        public Task<UpstreamKeySnapshot> GetAsync(CancellationToken cancellationToken = default) => Task.FromResult(snapshot);

        public Task<UpstreamKeySnapshot> RefreshForUnknownKidAsync(CancellationToken cancellationToken = default) => Task.FromResult(snapshot);
    }

    private sealed class FixedAgentKeys(JwksSnapshot snapshot) : IAgentKeys
    {
        public Task<JwksSnapshot> GetAsync(Agent agent, CancellationToken cancellationToken = default) => Task.FromResult(snapshot);

        public Task<JwksSnapshot> RefreshForUnknownKidAsync(Agent agent, CancellationToken cancellationToken = default) => Task.FromResult(snapshot);
    }
}

/// <summary>
/// The system clock, moved forward by whatever a test advances it by. Timers still fire in real
/// time, so the server's background work carries on, while a test that needs time to pass, such
/// as a cache entry expiring, moves the clock instead of waiting.
/// </summary>
public sealed class AdvancingClock : TimeProvider
{
    private long offsetTicks;

    /// <summary>Moves the clock forward by <paramref name="by"/>.</summary>
    public void Advance(TimeSpan by)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(by, TimeSpan.Zero);
        Interlocked.Add(ref offsetTicks, by.Ticks);
    }

    public override DateTimeOffset GetUtcNow() => System.GetUtcNow() + TimeSpan.FromTicks(Interlocked.Read(ref offsetTicks));
}

/// <summary>
/// Keycloak as the sponsor check sees it: a token endpoint that accepts a <c>private_key_jwt</c>
/// assertion only if it verifies against the server's own published signing key, and an admin
/// users API answering <c>enabled</c> for known users and 404 for unknown ones.
/// </summary>
public sealed class FakeKeycloakAdmin : HttpMessageHandler
{
    private const string ServiceToken = "keycloak-service-token";

    /// <summary>Users by upstream subject and whether they are enabled.</summary>
    public System.Collections.Concurrent.ConcurrentDictionary<string, bool> Users { get; } = new(StringComparer.Ordinal);

    /// <summary>Client assertions received at the token endpoint that verified against the server's key.</summary>
    public int VerifiedAssertions { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        if (url == ServerFactory.SponsorTokenUrl)
        {
            var form = (await request.Content!.ReadAsStringAsync(cancellationToken)).Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]), StringComparer.Ordinal);
            using var serverKey = ECDsa.Create();
            serverKey.ImportFromPem(ServerFactory.SigningKeyPem);
            using var keys = new SubactId.Tokens.Signing.SigningKeySet([SubactId.Tokens.Signing.SigningKey.FromPrivateKey(serverKey, "test-key")], "test-key");
            if (form.GetValueOrDefault("grant_type") != "client_credentials" || form.GetValueOrDefault("client_id") != "subactid" || !SubactId.Tokens.Signing.Jws.TryVerify(keys, form.GetValueOrDefault("client_assertion"), out _, out _))
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            }

            VerifiedAssertions++;
            return Json($"{{\"access_token\":\"{ServiceToken}\",\"expires_in\":300}}");
        }

        if (url.StartsWith(ServerFactory.SponsorUsersUrl + "/", StringComparison.Ordinal))
        {
            if (request.Headers.Authorization?.Parameter != ServiceToken)
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            }

            var subject = Uri.UnescapeDataString(url[(ServerFactory.SponsorUsersUrl.Length + 1)..]);
            return Users.TryGetValue(subject, out var enabled)
                ? Json($"{{\"id\":\"{subject}\",\"enabled\":{(enabled ? "true" : "false")}}}")
                : new HttpResponseMessage(System.Net.HttpStatusCode.NotFound);
        }

        return new HttpResponseMessage(System.Net.HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) => new(System.Net.HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
