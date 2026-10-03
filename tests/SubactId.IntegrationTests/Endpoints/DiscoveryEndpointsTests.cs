using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SubactId.IntegrationTests.Endpoints;

/// <summary>
/// Plays the role of a standard OIDC client: fetch the discovery document, follow
/// <c>jwks_uri</c>, build a public key from the JWK members alone, and verify a signature
/// with it. Nothing here uses the server's key types.
/// </summary>
public class DiscoveryEndpointsTests : IClassFixture<ServerFactory>
{
    private readonly ServerFactory factory;

    public DiscoveryEndpointsTests(ServerFactory factory) => this.factory = factory;

    [Fact]
    public async Task Discovery_document_is_the_spec_document_for_the_configured_issuer()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("public, max-age=300", response.Headers.CacheControl?.ToString());
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;
        Assert.Equal(
            ["issuer", "token_endpoint", "introspection_endpoint", "revocation_endpoint", "jwks_uri", "grant_types_supported", "token_endpoint_auth_methods_supported", "token_endpoint_auth_signing_alg_values_supported", "revocation_endpoint_auth_methods_supported", "revocation_endpoint_auth_signing_alg_values_supported", "introspection_endpoint_auth_methods_supported", "response_types_supported"],
            root.EnumerateObject().Select(p => p.Name));
        Assert.Equal(ServerFactory.Issuer, root.GetProperty("issuer").GetString());
        Assert.Equal(ServerFactory.Issuer + "/oauth2/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal(ServerFactory.Issuer + "/.well-known/jwks.json", root.GetProperty("jwks_uri").GetString());
        Assert.Equal(["urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"], root.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["private_key_jwt"], root.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["private_key_jwt"], root.GetProperty("revocation_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["ES256", "PS256", "RS256"], root.GetProperty("token_endpoint_auth_signing_alg_values_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["none"], root.GetProperty("introspection_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Empty(root.GetProperty("response_types_supported").EnumerateArray());
    }

    [Fact]
    public async Task Jwks_contains_only_public_material()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/.well-known/jwks.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("public, max-age=300", response.Headers.CacheControl?.ToString());
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("\"d\"", json, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(json);
        var key = Assert.Single(document.RootElement.GetProperty("keys").EnumerateArray());
        Assert.Equal(["kty", "crv", "use", "alg", "kid", "x", "y"], key.EnumerateObject().Select(p => p.Name));
        Assert.Equal("test-key", key.GetProperty("kid").GetString());
        Assert.Equal("ES256", key.GetProperty("alg").GetString());
    }

    [Fact]
    public async Task A_client_following_discovery_can_verify_a_signature_from_the_served_key_alone()
    {
        using var client = factory.CreateClient();
        using var discovery = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        var jwksUri = new Uri(discovery.RootElement.GetProperty("jwks_uri").GetString()!);
        Assert.Equal(new Uri(ServerFactory.Issuer), new Uri(jwksUri.GetLeftPart(UriPartial.Authority)));
        using var jwks = JsonDocument.Parse(await client.GetStringAsync(jwksUri.PathAndQuery));
        var jwk = jwks.RootElement.GetProperty("keys")[0];

        // Rebuild the public key from x and y only, the way any JOSE library does.
        using var publicKey = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64Url.DecodeFromChars(jwk.GetProperty("x").GetString()), Y = Base64Url.DecodeFromChars(jwk.GetProperty("y").GetString()) },
        });

        // Sign with the private key from the PEM the server was configured with, bypassing the server's code.
        using var privateKey = ECDsa.Create();
        privateKey.ImportFromPem(ServerFactory.SigningKeyPem);
        var data = Encoding.ASCII.GetBytes("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJodW1hbiJ9");
        var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        Assert.True(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        data[0] ^= 0x01;
        Assert.False(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks.json")]
    public async Task Documents_are_read_only(string path)
    {
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(path, new StringContent(string.Empty));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }
}
