using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubactId.Tokens.Signing;

/// <summary>
/// The public half of a P-256 signing key as a JSON Web Key (RFC 7517). It has no field for
/// private material, so it can never serialize <c>d</c>.
/// </summary>
/// <param name="Kid">Key identifier.</param>
/// <param name="X">Base64url X coordinate.</param>
/// <param name="Y">Base64url Y coordinate.</param>
public sealed record PublicJwk(
    [property: JsonPropertyName("kid")] string Kid,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y)
{
    /// <summary>Key type: elliptic curve.</summary>
    [JsonPropertyName("kty")]
    [JsonPropertyOrder(-4)]
    public string Kty => "EC";

    /// <summary>Curve: P-256.</summary>
    [JsonPropertyName("crv")]
    [JsonPropertyOrder(-3)]
    public string Crv => "P-256";

    /// <summary>Intended use: signatures.</summary>
    [JsonPropertyName("use")]
    [JsonPropertyOrder(-2)]
    public string Use => "sig";

    /// <summary>Algorithm: ES256.</summary>
    [JsonPropertyName("alg")]
    [JsonPropertyOrder(-1)]
    public string Alg => SigningKey.Algorithm;
}

/// <summary>A JSON Web Key Set (RFC 7517 section 5) containing only public keys.</summary>
/// <param name="Keys">The published keys.</param>
public sealed record Jwks([property: JsonPropertyName("keys")] IReadOnlyList<PublicJwk> Keys)
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    /// <summary>Serializes the key set as JSON.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, Options);
}
