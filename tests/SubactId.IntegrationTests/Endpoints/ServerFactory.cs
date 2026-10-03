using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SubactId.IntegrationTests.Endpoints;

/// <summary>
/// Hosts the real server in-process with a fixed issuer, a dead database and one signing key
/// generated once per test process. Tests keep the key's PEM so they can sign on their own.
/// Configuration is passed as environment variables, because the program reads it before the
/// host is built.
/// </summary>
public class ServerFactory : WebApplicationFactory<Program>
{
    /// <summary>The issuer the server is configured with; the spec's example.</summary>
    public const string Issuer = "https://subactid.internal.example.com";

    /// <summary>The admin API key the server is configured with.</summary>
    public const string AdminApiKey = "test-admin-key-0123456789abcdefghijklmnop";

    /// <summary>Where the server checks sponsors. Nothing listens there, so tests that need it stand in for it.</summary>
    public const string SponsorUsersUrl = "https://idp.example.test/admin/realms/main/users";

    /// <summary>Where the server is told to obtain its service token for the sponsor check.</summary>
    public const string SponsorTokenUrl = "https://idp.example.test/realms/main/protocol/openid-connect/token";

    /// <summary>The client the server is told the identity provider sends logout tokens for.</summary>
    public const string LogoutAudience = "workbench";

    /// <summary>The credential the server is told a provisioning client presents to the SCIM receiver.</summary>
    public const string ScimBearerToken = "test-scim-token-0123456789abcdefghijk";

    /// <summary>The Shared Signals transmitter the server is told to trust.</summary>
    public const string TransmitterIssuer = "https://transmitter.example.test";

    /// <summary>The stream audience the server is told its events carry.</summary>
    public const string StreamAudience = "https://subactid.internal.example.com/events";

    /// <summary>The credential the server is told a transmitter presents when it pushes an event.</summary>
    public const string SsfBearerToken = "test-events-token-0123456789abcdefghi";

    /// <summary>How long the server caches a sponsor's status.</summary>
    public static readonly TimeSpan SponsorCacheTtl = TimeSpan.FromSeconds(1);

    /// <summary>PKCS#8 PEM of the server's only signing key.</summary>
    public static string SigningKeyPem { get; }

    static ServerFactory()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SigningKeyPem = key.ExportPkcs8PrivateKeyPem();

        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
        Environment.SetEnvironmentVariable("SubactId__Issuer", Issuer);
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__MetadataUrl", "https://idp.example.test/.well-known/openid-configuration");
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__Audience", "subactid");
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__SponsorCheck__UsersUrl", SponsorUsersUrl);
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__SponsorCheck__TokenUrl", SponsorTokenUrl);
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__SponsorCheck__ClientId", "subactid");
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__SponsorCheck__CacheTtl", SponsorCacheTtl.ToString("c", System.Globalization.CultureInfo.InvariantCulture));
        Environment.SetEnvironmentVariable("SubactId__UpstreamIdp__BackchannelLogout__Audience", LogoutAudience);
        Environment.SetEnvironmentVariable("SubactId__Database__ConnectionString", "Host=127.0.0.1;Port=1;Username=x;Password=x;Database=x;Timeout=1");
        Environment.SetEnvironmentVariable("SubactId__Signing__Keys__0__Kid", "test-key");
        Environment.SetEnvironmentVariable("SubactId__Signing__Keys__0__Pem", SigningKeyPem);
        Environment.SetEnvironmentVariable("SubactId__Admin__ApiKey", AdminApiKey);
        Environment.SetEnvironmentVariable("SubactId__Scim__BearerToken", ScimBearerToken);
        Environment.SetEnvironmentVariable("SubactId__Ssf__Issuer", TransmitterIssuer);
        Environment.SetEnvironmentVariable("SubactId__Ssf__Audience", StreamAudience);
        Environment.SetEnvironmentVariable("SubactId__Ssf__BearerToken", SsfBearerToken);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) => builder.UseEnvironment("Production");
}
