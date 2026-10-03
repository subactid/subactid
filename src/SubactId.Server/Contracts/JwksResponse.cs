using System.Text.Json.Serialization;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Contracts;

/// <summary>
/// Body of <c>GET /.well-known/jwks.json</c>: the control plane's public signing keys as an RFC
/// 7517 key set. An allowlist like every other response: a member leaves only because it is here.
/// </summary>
/// <param name="Keys">The published keys, active and retired.</param>
public sealed record JwksResponse([property: JsonPropertyName("keys")] IReadOnlyList<JwkResponse> Keys)
{
    /// <summary>Maps the signing keys' public halves.</summary>
    /// <param name="jwks">The key set the signing keys publish.</param>
    public static JwksResponse From(Jwks jwks)
    {
        ArgumentNullException.ThrowIfNull(jwks);

        return new JwksResponse(jwks.Keys.Select(k => new JwkResponse("EC", "P-256", "sig", SigningKey.Algorithm, k.Kid, k.X, k.Y)).ToList());
    }
}

/// <summary>One public P-256 signing key. There is no member for private material.</summary>
/// <param name="Kty">Key type: <c>EC</c>.</param>
/// <param name="Crv">Curve: <c>P-256</c>.</param>
/// <param name="Use">Intended use: <c>sig</c>.</param>
/// <param name="Alg">Algorithm: <c>ES256</c>.</param>
/// <param name="Kid">Key identifier.</param>
/// <param name="X">Base64url X coordinate.</param>
/// <param name="Y">Base64url Y coordinate.</param>
public sealed record JwkResponse(
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("crv")] string Crv,
    [property: JsonPropertyName("use")] string Use,
    [property: JsonPropertyName("alg")] string Alg,
    [property: JsonPropertyName("kid")] string Kid,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y);
