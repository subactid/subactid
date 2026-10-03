using Microsoft.AspNetCore.Http.HttpResults;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Discovery;

/// <summary>
/// The unauthenticated OIDC discovery document and JWKS. Both only change on restart, so
/// clients may cache them briefly.
/// </summary>
public static class DiscoveryEndpoints
{
    /// <summary>How long clients may cache either document.</summary>
    public const int CacheSeconds = 300;

    /// <summary>Maps the discovery and JWKS endpoints.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdDiscoveryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet(OpenIdConfigurationResponse.DiscoveryPath, Discovery);
        endpoints.MapGet(OpenIdConfigurationResponse.JwksPath, Jwks);
    }

    private static JsonHttpResult<OpenIdConfigurationResponse> Discovery(SubactIdOptions options, HttpResponse response)
    {
        response.Headers.CacheControl = $"public, max-age={CacheSeconds}";
        return TypedResults.Json(OpenIdConfigurationResponse.For(options.Issuer));
    }

    private static JsonHttpResult<JwksResponse> Jwks(SigningKeySet keys, HttpResponse response)
    {
        response.Headers.CacheControl = $"public, max-age={CacheSeconds}";
        return TypedResults.Json(JwksResponse.From(keys.ToJwks()));
    }
}
