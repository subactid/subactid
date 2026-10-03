using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SubactId.Sample.ToolServer;

/// <summary>
/// Steps 1, 2 and 6 of spec section 9: fetch and cache the control plane's keys, verify a task
/// token's signature, <c>iss</c>, <c>aud</c> and <c>exp</c>, and refuse an actor chain deeper
/// than this server allows.
/// </summary>
internal sealed class TaskTokenVerifier(HttpClient http, Uri issuer, string audience, int maxDelegationDepth, TimeProvider clock)
{
    /// <summary>Leeway applied to <c>exp</c>.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    /// <summary>How long a fetched key set is used before it is fetched again.</summary>
    public static readonly TimeSpan KeyCacheTtl = TimeSpan.FromMinutes(10);

    /// <summary>Shortest time between two fetches triggered by a token naming an unknown key.</summary>
    public static readonly TimeSpan MinRefreshInterval = TimeSpan.FromSeconds(30);

    private readonly string expectedIssuer = issuer.AbsoluteUri.TrimEnd('/');
    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private IReadOnlyDictionary<string, ECDsa> keys = new Dictionary<string, ECDsa>(StringComparer.Ordinal);
    private DateTimeOffset fetchedAt = DateTimeOffset.MinValue;
    private DateTimeOffset lastAttempt = DateTimeOffset.MinValue;

    /// <summary>Verifies <paramref name="token"/>, or explains in one word why it was refused.</summary>
    public async Task<(TaskToken? Token, string? Refusal)> VerifyAsync(string? token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token))
        {
            return (null, "no_token");
        }

        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return (null, "malformed");
        }

        JsonDocument header;
        byte[] signature;
        JsonDocument payload;
        try
        {
            header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
            signature = Base64Url.DecodeFromChars(parts[2]);
            payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return (null, "malformed");
        }

        using (header)
        using (payload)
        {
            // Task tokens are ES256 with typ at+jwt (RFC 9068). A crit header is refused.
            if (header.RootElement.TryGetProperty("crit", out _)
                || Text(header.RootElement, "alg") != "ES256" || Text(header.RootElement, "typ") != "at+jwt" || Text(header.RootElement, "kid") is not { } kid)
            {
                return (null, "unsupported_algorithm");
            }

            var key = await KeyAsync(kid, cancellationToken);
            if (key is null)
            {
                return (null, "unknown_key");
            }

            if (!key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return (null, "bad_signature");
            }

            return Claims(payload.RootElement);
        }
    }

    private (TaskToken? Token, string? Refusal) Claims(JsonElement claims)
    {
        if (Text(claims, "iss") != expectedIssuer)
        {
            return (null, "wrong_issuer");
        }

        if (Text(claims, "aud") != audience)
        {
            return (null, "wrong_audience");
        }

        if (!claims.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number
            || clock.GetUtcNow() >= DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()) + ClockSkew)
        {
            return (null, "expired");
        }

        // The human. A sub that names an agent is refused.
        if (Text(claims, "sub") is not { Length: > 0 } subject)
        {
            return (null, "no_subject");
        }

        if (subject.StartsWith("agent:", StringComparison.Ordinal))
        {
            return (null, "subject_is_agent");
        }

        // The agent, and how many hops it is from the human.
        if (!claims.TryGetProperty("act", out var act) || act.ValueKind != JsonValueKind.Object || Text(act, "sub") is not { Length: > 0 } actor)
        {
            return (null, "no_actor");
        }

        var depth = act.TryGetProperty("depth", out var depthElement) && depthElement.ValueKind == JsonValueKind.Number ? depthElement.GetInt32() : 0;
        if (depth < 1 || depth > maxDelegationDepth)
        {
            return (null, "delegation_too_deep");
        }

        var scopes = (Text(claims, "scope") ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var taskId = claims.TryGetProperty("task", out var task) && task.ValueKind == JsonValueKind.Object ? Text(task, "id") : null;
        // Written only for an audience the operator registered as high risk (spec section 4).
        var introspectRequired = claims.TryGetProperty("introspect_required", out var required) && required.ValueKind == JsonValueKind.True;
        return (new TaskToken(subject, actor, depth, new HashSet<string>(scopes, StringComparer.Ordinal), taskId, Text(claims, "jti"), introspectRequired), null);
    }

    private async Task<ECDsa?> KeyAsync(string kid, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        if (now - fetchedAt < KeyCacheTtl && keys.TryGetValue(kid, out var cached))
        {
            return cached;
        }

        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            now = clock.GetUtcNow();
            if (keys.TryGetValue(kid, out var current) && now - fetchedAt < KeyCacheTtl)
            {
                return current;
            }

            // An unknown kid may mean a key rotation. Refetch, at most once per MinRefreshInterval.
            if (now - lastAttempt < MinRefreshInterval)
            {
                return keys.GetValueOrDefault(kid);
            }

            lastAttempt = now;
            try
            {
                var fresh = await FetchKeysAsync(cancellationToken);
                keys = fresh;
                fetchedAt = clock.GetUtcNow();
            }
            catch (Exception exception) when (exception is HttpRequestException or JsonException or TaskCanceledException)
            {
                // Keep the current keys if the fetch fails.
            }

            return keys.GetValueOrDefault(kid);
        }
        finally
        {
            refreshLock.Release();
        }
    }

    private async Task<Dictionary<string, ECDsa>> FetchKeysAsync(CancellationToken cancellationToken)
    {
        using var discovery = JsonDocument.Parse(await http.GetStringAsync($"{expectedIssuer}/.well-known/openid-configuration", cancellationToken));
        var jwksUri = Text(discovery.RootElement, "jwks_uri") ?? throw new JsonException("The discovery document has no jwks_uri.");
        using var jwks = JsonDocument.Parse(await http.GetStringAsync(jwksUri, cancellationToken));

        var fresh = new Dictionary<string, ECDsa>(StringComparer.Ordinal);
        foreach (var jwk in jwks.RootElement.GetProperty("keys").EnumerateArray())
        {
            if (Text(jwk, "kty") != "EC" || Text(jwk, "crv") != "P-256" || Text(jwk, "kid") is not { } kid
                || Text(jwk, "x") is not { } x || Text(jwk, "y") is not { } y)
            {
                continue;
            }

            fresh[kid] = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Base64Url.DecodeFromChars(x), Y = Base64Url.DecodeFromChars(y) },
            });
        }

        return fresh;
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>What a verified task token says: the human, the agent acting for them, and what they may do here.</summary>
internal sealed record TaskToken(string Subject, string Agent, int Depth, IReadOnlySet<string> Scopes, string? TaskId, string? Jti, bool IntrospectRequired);
