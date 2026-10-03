namespace SubactId.Tokens.Signing;

/// <summary>The three segments of a compact JWS, accepted only in canonical base64url form.</summary>
/// <param name="Header">Encoded JOSE header.</param>
/// <param name="Payload">Encoded payload.</param>
/// <param name="Signature">Encoded signature.</param>
public readonly record struct JwsSegments(string Header, string Payload, string Signature)
{
    /// <summary>Longest compact serialization for Subact ID's own tokens and agent assertions. Real ones are under 2 KB.</summary>
    public const int MaxTokenLength = 8192;

    /// <summary>
    /// Longest subject token accepted from the upstream identity provider. Larger than
    /// <see cref="MaxTokenLength"/> because upstream tokens carry realm roles and groups and can
    /// be several kilobytes.
    /// </summary>
    public const int MaxUpstreamTokenLength = 16384;

    /// <summary>The bytes a signature covers: <c>header.payload</c> as ASCII.</summary>
    public byte[] SigningInput => System.Text.Encoding.ASCII.GetBytes($"{Header}.{Payload}");

    /// <summary>
    /// Splits a token into segments. Returns <c>false</c> for anything that is not exactly three
    /// non-empty segments of canonical base64url (no padding, no whitespace, no standard-alphabet
    /// characters), or that is longer than <paramref name="maxLength"/>.
    /// </summary>
    /// <param name="token">The compact serialization.</param>
    /// <param name="segments">The segments.</param>
    /// <param name="maxLength">Longest token to look at; <see cref="MaxTokenLength"/> unless the caller accepts a bigger one.</param>
    public static bool TryParse(string? token, out JwsSegments segments, int maxLength = MaxTokenLength)
    {
        segments = default;
        if (string.IsNullOrEmpty(token) || token.Length > maxLength)
        {
            return false;
        }

        var parts = token.Split('.');
        if (parts.Length != 3 || !parts.All(IsCanonicalBase64Url))
        {
            return false;
        }

        segments = new JwsSegments(parts[0], parts[1], parts[2]);
        return true;
    }

    /// <summary>Non-empty, only the base64url alphabet, and a length base64 can actually produce without padding.</summary>
    private static bool IsCanonicalBase64Url(string segment) =>
        segment.Length > 0
        && segment.Length % 4 != 1
        && segment.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
