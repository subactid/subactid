using System.Text.Json.Serialization;
using SubactId.Tokens;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Contracts;

/// <summary>
/// Body of <c>GET /.well-known/openid-configuration</c> (spec section 1): RFC 8414 authorization
/// server metadata, served at the OpenID Connect path. The control plane issues no ID tokens and
/// has no authorization endpoint, so the OpenID Provider fields are not claimed. Every URL is
/// derived from the configured issuer, and every list names only what is implemented.
/// </summary>
/// <param name="Issuer">The issuer, without a trailing slash.</param>
/// <param name="TokenEndpoint">Token exchange and refresh.</param>
/// <param name="IntrospectionEndpoint">RFC 7662 introspection.</param>
/// <param name="RevocationEndpoint">RFC 7009 revocation.</param>
/// <param name="JwksUri">The public signing keys.</param>
/// <param name="GrantTypesSupported">Token exchange and refresh only.</param>
/// <param name="TokenEndpointAuthMethodsSupported">Only <c>private_key_jwt</c>.</param>
/// <param name="TokenEndpointAuthSigningAlgValuesSupported">What an agent may sign its assertion with.</param>
/// <param name="RevocationEndpointAuthMethodsSupported">Only <c>private_key_jwt</c>: revocation authenticates the agent as the token endpoint does.</param>
/// <param name="RevocationEndpointAuthSigningAlgValuesSupported">As for the token endpoint.</param>
/// <param name="IntrospectionEndpointAuthMethodsSupported"><c>none</c>: holding the token is the only credential introspection asks for.</param>
/// <param name="ResponseTypesSupported">Empty: there is no authorization endpoint. Required by RFC 8414.</param>
public sealed record OpenIdConfigurationResponse(
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("token_endpoint")] string TokenEndpoint,
    [property: JsonPropertyName("introspection_endpoint")] string IntrospectionEndpoint,
    [property: JsonPropertyName("revocation_endpoint")] string RevocationEndpoint,
    [property: JsonPropertyName("jwks_uri")] string JwksUri,
    [property: JsonPropertyName("grant_types_supported")] IReadOnlyList<string> GrantTypesSupported,
    [property: JsonPropertyName("token_endpoint_auth_methods_supported")] IReadOnlyList<string> TokenEndpointAuthMethodsSupported,
    [property: JsonPropertyName("token_endpoint_auth_signing_alg_values_supported")] IReadOnlyList<string> TokenEndpointAuthSigningAlgValuesSupported,
    [property: JsonPropertyName("revocation_endpoint_auth_methods_supported")] IReadOnlyList<string> RevocationEndpointAuthMethodsSupported,
    [property: JsonPropertyName("revocation_endpoint_auth_signing_alg_values_supported")] IReadOnlyList<string> RevocationEndpointAuthSigningAlgValuesSupported,
    [property: JsonPropertyName("introspection_endpoint_auth_methods_supported")] IReadOnlyList<string> IntrospectionEndpointAuthMethodsSupported,
    [property: JsonPropertyName("response_types_supported")] IReadOnlyList<string> ResponseTypesSupported)
{
    /// <summary>Path of the discovery document.</summary>
    public const string DiscoveryPath = "/.well-known/openid-configuration";

    /// <summary>Path of the JWKS document.</summary>
    public const string JwksPath = "/.well-known/jwks.json";

    /// <summary>Path of the token endpoint.</summary>
    public const string TokenPath = "/oauth2/token";

    /// <summary>Path of the introspection endpoint.</summary>
    public const string IntrospectionPath = "/oauth2/introspect";

    /// <summary>Path of the revocation endpoint.</summary>
    public const string RevocationPath = "/oauth2/revoke";

    /// <summary>Builds the document for <paramref name="issuer"/>.</summary>
    /// <param name="issuer">The configured issuer URL. A trailing slash is dropped.</param>
    public static OpenIdConfigurationResponse For(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        var root = IssuerUrl.Canonical(issuer);
        // The algorithms an agent's assertion is verified with, in a fixed order.
        IReadOnlyList<string> assertionAlgorithms = UpstreamKey.AllowedAlgorithms.Order(StringComparer.Ordinal).ToList();
        return new OpenIdConfigurationResponse(
            root,
            root + TokenPath,
            root + IntrospectionPath,
            root + RevocationPath,
            root + JwksPath,
            ["urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"],
            // Only implemented methods are listed.
            ["private_key_jwt"],
            assertionAlgorithms,
            ["private_key_jwt"],
            assertionAlgorithms,
            ["none"],
            []);
    }
}
