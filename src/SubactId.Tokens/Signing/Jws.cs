using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubactId.Tokens.Signing;

/// <summary>Compact JWS (RFC 7515) with ES256 only. Signing uses a key set's active key; verification accepts any published key.</summary>
public static class Jws
{
    /// <summary>The <c>typ</c> header for access tokens (RFC 9068).</summary>
    public const string AccessTokenType = "at+jwt";

    /// <summary>Longest compact serialization the verifier will look at.</summary>
    public const int MaxTokenLength = JwsSegments.MaxTokenLength;

    /// <summary>Longest subject token accepted from the upstream identity provider; see <see cref="JwsSegments.MaxUpstreamTokenLength"/>.</summary>
    public const int MaxUpstreamTokenLength = JwsSegments.MaxUpstreamTokenLength;

    private static readonly JsonSerializerOptions HeaderOptions = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    /// <summary>Signs <paramref name="payload"/> with the set's active key and returns the compact serialization.</summary>
    /// <param name="keys">The key set.</param>
    /// <param name="payload">The UTF-8 payload, typically a JSON claim set.</param>
    /// <param name="typ">The <c>typ</c> header value.</param>
    public static string Sign(SigningKeySet keys, ReadOnlySpan<byte> payload, string typ = AccessTokenType)
    {
        ArgumentNullException.ThrowIfNull(keys);

        var key = keys.Active;
        var header = JsonSerializer.SerializeToUtf8Bytes(new JwsHeader(SigningKey.Algorithm, key.Kid, typ), HeaderOptions);
        var signingInput = $"{Base64Url.EncodeToString(header)}.{Base64Url.EncodeToString(payload)}";
        var signature = key.Sign(System.Text.Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Verifies a task token: <see cref="TryVerify"/>, and a <c>typ</c> of
    /// <see cref="AccessTokenType"/>. Anything else this control plane signs with the same keys,
    /// such as its client assertion to the identity provider or a health probe, is not a task
    /// token even though its signature verifies.
    /// </summary>
    /// <param name="keys">The key set.</param>
    /// <param name="token">The compact serialization.</param>
    /// <param name="payload">The verified payload bytes.</param>
    public static bool TryVerifyAccessToken(SigningKeySet keys, string? token, out byte[]? payload)
    {
        if (TryVerify(keys, token, out var header, out payload) && string.Equals(header!.Typ, AccessTokenType, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        payload = null;
        return false;
    }

    /// <summary>
    /// Verifies a compact JWS against the set's published keys. Returns <c>false</c>, never throws,
    /// for anything malformed, unsigned, signed with another algorithm, signed by an unknown key,
    /// or tampered with. Segments must be canonical base64url, a <c>crit</c> header is rejected
    /// because nothing here understands one, and tokens over <see cref="MaxTokenLength"/> are
    /// rejected before any work is done. Claims are not interpreted here.
    /// </summary>
    /// <param name="keys">The key set.</param>
    /// <param name="token">The compact serialization.</param>
    /// <param name="header">The verified header.</param>
    /// <param name="payload">The verified payload bytes.</param>
    public static bool TryVerify(SigningKeySet keys, string? token, out JwsHeader? header, out byte[]? payload)
    {
        ArgumentNullException.ThrowIfNull(keys);

        header = null;
        payload = null;
        if (!JwsSegments.TryParse(token, out var segments))
        {
            return false;
        }

        JwsHeader parsedHeader;
        byte[] signature;
        byte[] payloadBytes;
        try
        {
            parsedHeader = JsonSerializer.Deserialize<JwsHeader>(Base64Url.DecodeFromChars(segments.Header), HeaderOptions)
                ?? throw new JsonException();
            signature = Base64Url.DecodeFromChars(segments.Signature);
            payloadBytes = Base64Url.DecodeFromChars(segments.Payload);
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return false;
        }

        if (!string.Equals(parsedHeader.Alg, SigningKey.Algorithm, StringComparison.Ordinal)
            || string.IsNullOrEmpty(parsedHeader.Kid)
            || parsedHeader.Crit is not null)
        {
            return false;
        }

        var key = keys.Find(parsedHeader.Kid);
        if (key is null || !key.Verify(segments.SigningInput, signature))
        {
            return false;
        }

        header = parsedHeader;
        payload = payloadBytes;
        return true;
    }
}

/// <summary>The JOSE header this control plane writes and accepts.</summary>
/// <param name="Alg">Always <c>ES256</c>.</param>
/// <param name="Kid">The signing key identifier.</param>
/// <param name="Typ">The token type, for example <c>at+jwt</c>.</param>
/// <param name="Crit">Never written; its presence on an incoming token causes rejection (RFC 7515 section 4.1.11).</param>
public sealed record JwsHeader(
    [property: JsonPropertyName("alg")] string? Alg,
    [property: JsonPropertyName("kid")] string? Kid,
    [property: JsonPropertyName("typ")] string? Typ,
    [property: JsonPropertyName("crit")] JsonElement? Crit = null);
