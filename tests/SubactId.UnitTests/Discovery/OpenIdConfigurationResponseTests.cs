using System.Text.Json;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Discovery;

public class OpenIdConfigurationResponseTests
{
    private const string SpecExample = """
        {
          "issuer": "https://subactid.internal.example.com",
          "token_endpoint": "https://subactid.internal.example.com/oauth2/token",
          "introspection_endpoint": "https://subactid.internal.example.com/oauth2/introspect",
          "revocation_endpoint": "https://subactid.internal.example.com/oauth2/revoke",
          "jwks_uri": "https://subactid.internal.example.com/.well-known/jwks.json",
          "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "refresh_token"
          ],
          "token_endpoint_auth_methods_supported": ["private_key_jwt"],
          "token_endpoint_auth_signing_alg_values_supported": ["ES256", "PS256", "RS256"],
          "revocation_endpoint_auth_methods_supported": ["private_key_jwt"],
          "revocation_endpoint_auth_signing_alg_values_supported": ["ES256", "PS256", "RS256"],
          "introspection_endpoint_auth_methods_supported": ["none"],
          "response_types_supported": []
        }
        """;

    [Theory]
    [InlineData("https://subactid.internal.example.com")]
    [InlineData("https://subactid.internal.example.com/")]
    public void Matches_the_spec_example_exactly_with_or_without_a_trailing_slash(string issuer)
    {
        var document = OpenIdConfigurationResponse.For(new Uri(issuer));

        var actual = JsonSerializer.Serialize(document, SubactIdJson.CreateOptions());
        var expected = JsonSerializer.Serialize(JsonDocument.Parse(SpecExample).RootElement);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Keeps_a_path_prefix_in_every_url()
    {
        var document = OpenIdConfigurationResponse.For(new Uri("https://gateway.example/subactid/"));

        Assert.Equal("https://gateway.example/subactid", document.Issuer);
        Assert.Equal("https://gateway.example/subactid/oauth2/token", document.TokenEndpoint);
        Assert.Equal("https://gateway.example/subactid/.well-known/jwks.json", document.JwksUri);
    }
}
