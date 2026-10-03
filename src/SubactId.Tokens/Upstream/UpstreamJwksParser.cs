using System.Buffers.Text;
using System.Text.Json;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Reads an upstream JWKS document into <see cref="UpstreamKey"/>s. Unusable entries are skipped:
/// <c>use</c> other than <c>sig</c>, unsupported key types or curves, weak RSA keys, missing or
/// duplicate kids, and any entry with private material.
/// </summary>
public static class UpstreamJwksParser
{
    /// <summary>Parses the document. Throws only when the document itself is not a JWKS.</summary>
    /// <param name="json">The JWKS JSON.</param>
    /// <returns>Usable keys by kid.</returns>
    /// <exception cref="UpstreamDiscoveryException">The document is not JSON or has no <c>keys</c> array.</exception>
    public static IReadOnlyDictionary<string, UpstreamKey> Parse(string json)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException exception)
        {
            throw new UpstreamDiscoveryException("The upstream JWKS is not valid JSON.", exception, UpstreamDiscoveryFault.NotJson);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("keys", out var keys)
                || keys.ValueKind != JsonValueKind.Array)
            {
                throw new UpstreamDiscoveryException("The upstream JWKS has no 'keys' array.", fault: UpstreamDiscoveryFault.NoKeysArray);
            }

            var result = new Dictionary<string, UpstreamKey>(StringComparer.Ordinal);
            foreach (var entry in keys.EnumerateArray())
            {
                var key = ParseEntry(entry);
                if (key is null)
                {
                    continue;
                }

                if (!result.TryAdd(key.Kid, key))
                {
                    key.Dispose();
                }
            }

            return result;
        }
    }

    private static UpstreamKey? ParseEntry(JsonElement entry)
    {
        if (entry.ValueKind != JsonValueKind.Object || entry.TryGetProperty("d", out _))
        {
            return null;
        }

        var kid = GetString(entry, "kid");
        var kty = GetString(entry, "kty");
        var use = GetString(entry, "use");
        var alg = GetString(entry, "alg");
        if (string.IsNullOrEmpty(kid) || kty is null || (use is not null && use != "sig"))
        {
            return null;
        }

        if (alg is not null && !UpstreamKey.AllowedAlgorithms.Contains(alg))
        {
            return null;
        }

        try
        {
            return kty switch
            {
                "RSA" when GetString(entry, "n") is { } n && GetString(entry, "e") is { } e =>
                    UpstreamKey.CreateRsa(kid, alg, Base64Url.DecodeFromChars(n), Base64Url.DecodeFromChars(e)),
                "EC" when GetString(entry, "crv") == "P-256" && GetString(entry, "x") is { } x && GetString(entry, "y") is { } y =>
                    UpstreamKey.CreateP256(kid, alg, Base64Url.DecodeFromChars(x), Base64Url.DecodeFromChars(y)),
                _ => null,
            };
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string? GetString(JsonElement entry, string name) =>
        entry.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
