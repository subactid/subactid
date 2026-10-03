using System.Buffers.Text;
using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>
/// Reads the claims of a token the agent holds, for display only. Does not verify the signature,
/// and makes no security decision.
/// </summary>
internal static class Jwt
{
    /// <summary>The payload of a compact JWS, unverified.</summary>
    public static JsonElement Payload(string jws)
    {
        using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(jws.Split('.')[1]));
        return document.RootElement.Clone();
    }

    /// <summary>One string claim, or an empty string.</summary>
    public static string Claim(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
}
