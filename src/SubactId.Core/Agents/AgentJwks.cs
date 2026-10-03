using System.Text.Json;
using System.Text.Json.Serialization;
using SubactId.Core.Validation;

namespace SubactId.Core.Agents;

/// <summary>
/// One public key from an agent's registered key set (RFC 7517). Only the members needed to
/// verify a signature are kept.
/// </summary>
public sealed record AgentJwk
{
    /// <summary>Key identifier, named by the <c>kid</c> header of an assertion.</summary>
    [JsonPropertyName("kid")]
    public required string Kid { get; init; }

    /// <summary>Key type: <c>RSA</c> or <c>EC</c>.</summary>
    [JsonPropertyName("kty")]
    public required string Kty { get; init; }

    /// <summary>The algorithm this key signs with, when the key declares one.</summary>
    [JsonPropertyName("alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Alg { get; init; }

    /// <summary>Public key use, normally <c>sig</c>.</summary>
    [JsonPropertyName("use")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Use { get; init; }

    /// <summary>Curve of an EC key.</summary>
    [JsonPropertyName("crv")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Crv { get; init; }

    /// <summary>Base64url X coordinate of an EC key.</summary>
    [JsonPropertyName("x")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? X { get; init; }

    /// <summary>Base64url Y coordinate of an EC key.</summary>
    [JsonPropertyName("y")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Y { get; init; }

    /// <summary>Base64url modulus of an RSA key.</summary>
    [JsonPropertyName("n")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? N { get; init; }

    /// <summary>Base64url exponent of an RSA key.</summary>
    [JsonPropertyName("e")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? E { get; init; }
}

/// <summary>
/// An agent's public keys, stored by the control plane rather than fetched from a URL. Unknown
/// members are dropped. A key with any private member is refused.
/// </summary>
/// <param name="Keys">The keys, in the order given.</param>
public sealed record AgentJwks(IReadOnlyList<AgentJwk> Keys)
{
    /// <summary>Most keys one registration may carry.</summary>
    public const int MaxKeys = 8;

    /// <summary>Longest accepted value for a single JWK member.</summary>
    public const int MaxMemberLength = 4096;

    /// <summary>
    /// Members that carry private key material (RFC 7518 sections 6.2.2, 6.3.2 and 6.4). A key
    /// containing one is refused.
    /// </summary>
    public static readonly IReadOnlySet<string> PrivateMembers =
        new HashSet<string>(StringComparer.Ordinal) { "d", "p", "q", "dp", "dq", "qi", "k", "oth" };

    private static readonly JsonSerializerOptions Canonical = new() { WriteIndented = false };

    /// <summary>Parses and validates a key set, reporting per-field errors under <paramref name="field"/>.</summary>
    /// <param name="json">The key set as JSON.</param>
    /// <param name="field">Field name to report errors against, normally <c>jwks</c>.</param>
    /// <param name="jwks">The parsed set; <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public static IReadOnlyList<ValidationError> TryParse(JsonElement json, string field, out AgentJwks? jwks)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(field);

        jwks = null;
        var errors = new List<ValidationError>();

        if (json.ValueKind != JsonValueKind.Object
            || !json.TryGetProperty("keys", out var keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            errors.Add(new(field, "must be a JSON Web Key Set: an object with a 'keys' array."));
            return errors;
        }

        var keys = new List<AgentJwk>();
        var kids = new HashSet<string>(StringComparer.Ordinal);
        var index = 0;
        foreach (var keyElement in keysElement.EnumerateArray())
        {
            var name = $"{field}.keys[{index}]";
            index++;

            if (keyElement.ValueKind != JsonValueKind.Object)
            {
                errors.Add(new(name, "must be an object."));
                continue;
            }

            var key = ReadKey(keyElement, name, errors);
            if (key is null)
            {
                continue;
            }

            if (kids.Add(key.Kid))
            {
                keys.Add(key);
            }
            else
            {
                errors.Add(new(name, $"repeats the kid '{key.Kid}'; every key must have a distinct kid."));
            }
        }

        if (keys.Count == 0 && errors.Count == 0)
        {
            errors.Add(new(field, "must contain at least one key."));
        }

        if (index > MaxKeys)
        {
            errors.Add(new(field, $"must contain at most {MaxKeys} keys."));
        }

        if (errors.Count > 0)
        {
            return errors;
        }

        jwks = new AgentJwks(keys);
        return [];
    }

    /// <summary>Parses and validates a key set given as text.</summary>
    /// <param name="json">The key set as JSON text.</param>
    /// <param name="field">Field name to report errors against.</param>
    /// <param name="jwks">The parsed set; <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public static IReadOnlyList<ValidationError> TryParse(string json, string field, out AgentJwks? jwks)
    {
        jwks = null;
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return [new ValidationError(field, "must be valid JSON.")];
        }

        using (document)
        {
            return TryParse(document.RootElement, field, out jwks);
        }
    }

    /// <summary>The key set as the JSON served at the agent's JWKS endpoint and held in storage.</summary>
    public string ToJson() => JsonSerializer.Serialize(new JwksDocument(Keys), Canonical);

    /// <summary>
    /// Two sets are equal when they hold the same keys in the same order, compared by value.
    /// </summary>
    /// <param name="other">The set to compare with.</param>
    public bool Equals(AgentJwks? other) =>
        other is not null && (ReferenceEquals(this, other) || string.Equals(ToJson(), other.ToJson(), StringComparison.Ordinal));

    /// <inheritdoc />
    public override int GetHashCode() => ToJson().GetHashCode(StringComparison.Ordinal);

    private static AgentJwk? ReadKey(JsonElement element, string name, List<ValidationError> errors)
    {
        var before = errors.Count;

        foreach (var member in element.EnumerateObject())
        {
            if (PrivateMembers.Contains(member.Name))
            {
                // Names the member but never echoes its value.
                errors.Add(new(name, $"carries the private member '{member.Name}'; a registered key set holds public keys only."));
            }
        }

        var kid = Text(element, "kid", name, errors, required: true);
        var kty = Text(element, "kty", name, errors, required: true);
        var alg = Text(element, "alg", name, errors, required: false);
        var use = Text(element, "use", name, errors, required: false);

        AgentJwk? key = null;
        switch (kty)
        {
            case "EC":
                var crv = Text(element, "crv", name, errors, required: true);
                var x = Text(element, "x", name, errors, required: true);
                var y = Text(element, "y", name, errors, required: true);
                if (errors.Count == before)
                {
                    key = new AgentJwk { Kid = kid!, Kty = kty, Alg = alg, Use = use, Crv = crv, X = x, Y = y };
                }

                break;

            case "RSA":
                var n = Text(element, "n", name, errors, required: true);
                var e = Text(element, "e", name, errors, required: true);
                if (errors.Count == before)
                {
                    key = new AgentJwk { Kid = kid!, Kty = kty, Alg = alg, Use = use, N = n, E = e };
                }

                break;

            case null:
                break;

            default:
                errors.Add(new(name, "has an unsupported 'kty'; only 'RSA' and 'EC' keys can verify an assertion."));
                break;
        }

        if (use is not null && use != "sig")
        {
            errors.Add(new(name, "must have 'use' of 'sig' when it is present; an agent key is a signing key."));
            return null;
        }

        return errors.Count == before ? key : null;
    }

    private static string? Text(JsonElement element, string member, string name, List<ValidationError> errors, bool required)
    {
        if (!element.TryGetProperty(member, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            if (required)
            {
                errors.Add(new(name, $"is missing '{member}'."));
            }

            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            errors.Add(new(name, $"has a non-string '{member}'."));
            return null;
        }

        var text = value.GetString();
        if (string.IsNullOrEmpty(text) || text.Length > MaxMemberLength)
        {
            errors.Add(new(name, $"has an empty or oversized '{member}'."));
            return null;
        }

        return text;
    }

    private sealed record JwksDocument([property: JsonPropertyName("keys")] IReadOnlyList<AgentJwk> Keys);
}
