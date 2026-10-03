using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SubactId.Conformance;

/// <summary>
/// Everything the live instance reaches out to, stood in for by the suite: the upstream identity
/// provider (discovery, JWKS, the admin users API and the token endpoint the sponsor check uses),
/// the Shared Signals transmitter (discovery and JWKS, under <see cref="TransmitterPath"/>) and
/// every agent's JWKS. The instance is configured to find these at one base URL, which the
/// suite listens on; agent JWKS must be https, so the listener carries the certificate the
/// instance was told to trust.
/// </summary>
public sealed class StubIdentityProvider : IAsyncDisposable
{
    /// <summary>The <c>kid</c> every agent signs with.</summary>
    public const string AgentKid = "conformance-agent";

    /// <summary>Where under the base URL the transmitter lives. Its issuer is the base URL plus this.</summary>
    public const string TransmitterPath = "/transmitter";

    private WebApplication? app;

    private StubIdentityProvider(Uri baseUrl, RSA idpKey, RSA transmitterKey)
    {
        BaseUrl = baseUrl;
        Issuer = baseUrl.ToString().TrimEnd('/');
        IdpKey = idpKey;
        IdpKid = "conformance-idp-" + Thumbprint(idpKey);
        TransmitterKey = transmitterKey;
        TransmitterKid = "conformance-transmitter-" + Thumbprint(transmitterKey);
    }

    /// <summary>Where the stub listens; the instance's upstream and agent URLs are under it.</summary>
    public Uri BaseUrl { get; }

    /// <summary>The <c>iss</c> of subject tokens, as published in the discovery document.</summary>
    public string Issuer { get; }

    /// <summary>
    /// The <c>kid</c> the identity provider signs with, derived from the key. The instance caches
    /// the provider's keys by kid and refreshes for an unknown kid at most every so often, so the
    /// key is kept beside the certificate and reused: runs against one instance present the same
    /// key under the same kid, and a different key is a different kid, never a stale hit.
    /// </summary>
    public string IdpKid { get; }

    /// <summary>The identity provider's signing key.</summary>
    public RSA IdpKey { get; }

    /// <summary>The Shared Signals transmitter's issuer: a different issuer from the identity provider, with its own keys.</summary>
    public string TransmitterIssuer => Issuer + TransmitterPath;

    /// <summary>The <c>kid</c> the transmitter signs with, derived from its key, as <see cref="IdpKid"/> is.</summary>
    public string TransmitterKid { get; }

    /// <summary>The transmitter's signing key, kept beside the certificate for the same reason as the identity provider's.</summary>
    public RSA TransmitterKey { get; }

    /// <summary>Users the admin API knows, by subject, and whether they are enabled.</summary>
    public ConcurrentDictionary<string, bool> Users { get; } = new(StringComparer.Ordinal);

    /// <summary>Each registered agent's key, served at <c>/agents/{id}/jwks.json</c>.</summary>
    public ConcurrentDictionary<string, RSA> AgentKeys { get; } = new(StringComparer.Ordinal);

    /// <summary>Starts listening at <paramref name="baseUrl"/> with the certificate in <paramref name="pfxPath"/>; the identity provider's key lives beside it.</summary>
    public static async Task<StubIdentityProvider> StartAsync(Uri baseUrl, string pfxPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(pfxPath))!;
        var stub = new StubIdentityProvider(
            baseUrl,
            LoadOrCreateKey(Path.Combine(directory, "conformance-idp-key.pem")),
            LoadOrCreateKey(Path.Combine(directory, "conformance-transmitter-key.pem")));
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions());
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, baseUrl.Port, listen =>
            listen.UseHttps(X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password: null))));

        var app = builder.Build();
        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = stub.Issuer,
            jwks_uri = stub.Issuer + "/jwks",
            token_endpoint = stub.Issuer + "/realms/main/protocol/openid-connect/token",
        }));
        app.MapGet("/jwks", () => Results.Content(Jwt.RsaJwks(stub.IdpKey, stub.IdpKid), "application/json"));
        app.MapPost("/realms/main/protocol/openid-connect/token", () => Results.Json(new { access_token = "conformance-service-token", expires_in = 300 }));
        app.MapGet("/admin/realms/main/users/{subject}", (string subject) =>
            stub.Users.TryGetValue(subject, out var enabled) ? Results.Json(new { id = subject, enabled }) : Results.NotFound());
        app.MapGet(TransmitterPath + "/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = stub.TransmitterIssuer,
            jwks_uri = stub.TransmitterIssuer + "/jwks",
        }));
        app.MapGet(TransmitterPath + "/jwks", () => Results.Content(Jwt.RsaJwks(stub.TransmitterKey, stub.TransmitterKid), "application/json"));
        app.MapGet("/agents/{agentId}/jwks.json", (string agentId) =>
            stub.AgentKeys.TryGetValue(agentId, out var key) ? Results.Content(Jwt.RsaJwks(key, AgentKid), "application/json") : Results.NotFound());

        await app.StartAsync();
        stub.app = app;
        return stub;
    }

    private static string Thumbprint(RSA key) => Convert.ToHexStringLower(SHA256.HashData(key.ExportParameters(false).Modulus!))[..16];

    private static RSA LoadOrCreateKey(string path)
    {
        var key = RSA.Create(2048);
        if (File.Exists(path))
        {
            key.ImportFromPem(File.ReadAllText(path));
            return key;
        }

        File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());
        return key;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (app is not null)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        IdpKey.Dispose();
        TransmitterKey.Dispose();
        foreach (var key in AgentKeys.Values)
        {
            key.Dispose();
        }
    }
}
