using System.Text.Json.Serialization;
using SubactId.Core.Agents;

namespace SubactId.Server.Contracts;

/// <summary>
/// One key of <see cref="AgentJwksResponse"/>. Has no member for private key material, so it
/// can never serialize any.
/// </summary>
/// <param name="Kid">Key identifier.</param>
/// <param name="Kty">Key type, <c>RSA</c> or <c>EC</c>.</param>
/// <param name="Alg">The algorithm the key signs with, when it declares one.</param>
/// <param name="Use">Public key use, normally <c>sig</c>.</param>
/// <param name="Crv">Curve of an EC key.</param>
/// <param name="X">Base64url X coordinate of an EC key.</param>
/// <param name="Y">Base64url Y coordinate of an EC key.</param>
/// <param name="N">Base64url modulus of an RSA key.</param>
/// <param name="E">Base64url exponent of an RSA key.</param>
public sealed record AgentJwkResponse(
    [property: JsonPropertyName("kid")] string Kid,
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("alg")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Alg,
    [property: JsonPropertyName("use")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Use,
    [property: JsonPropertyName("crv")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Crv,
    [property: JsonPropertyName("x")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? X,
    [property: JsonPropertyName("y")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Y,
    [property: JsonPropertyName("n")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? N,
    [property: JsonPropertyName("e")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? E);

/// <summary>
/// Body of <c>GET /agents/{agent_id}/jwks.json</c>: the public keys an agent authenticates with.
/// </summary>
/// <param name="Keys">The agent's public keys.</param>
public sealed record AgentJwksResponse([property: JsonPropertyName("keys")] IReadOnlyList<AgentJwkResponse> Keys)
{
    /// <summary>The path this document is served at, with <c>{agent_id}</c> as the route parameter.</summary>
    public const string Path = "/agents/{agent_id}/jwks.json";

    /// <summary>Maps a stored key set to the response.</summary>
    /// <param name="jwks">The agent's registered keys.</param>
    public static AgentJwksResponse From(AgentJwks jwks)
    {
        ArgumentNullException.ThrowIfNull(jwks);

        return new AgentJwksResponse(
            [.. jwks.Keys.Select(k => new AgentJwkResponse(k.Kid, k.Kty, k.Alg, k.Use, k.Crv, k.X, k.Y, k.N, k.E))]);
    }
}
