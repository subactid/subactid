using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SubactId.Sample.Portal;

/// <summary>
/// Server-side sign-in sessions. The browser gets an opaque cookie, never the human's access
/// token, which is sent only to the agent for the exchange. Kept in memory, so a restart signs
/// everyone out.
/// </summary>
internal sealed class Sessions
{
    /// <summary>The session cookie's name. Its value is an opaque random id.</summary>
    public const string CookieName = "subactid_portal";

    private readonly ConcurrentDictionary<string, PortalSession> signedIn = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, PendingLogin> pending = new(StringComparer.Ordinal);

    /// <summary>Starts a sign-in: a state to recognise the callback by and a PKCE verifier to finish it with.</summary>
    public PendingLogin Begin()
    {
        var login = new PendingLogin(Random(), Random(), DateTimeOffset.UtcNow);
        pending[login.State] = login;

        // Drop sign-ins older than ten minutes.
        foreach (var stale in pending.Where(p => DateTimeOffset.UtcNow - p.Value.StartedAt > TimeSpan.FromMinutes(10)).ToArray())
        {
            pending.TryRemove(stale.Key, out _);
        }

        return login;
    }

    /// <summary>Claims a pending sign-in by its state, once.</summary>
    public PendingLogin? Claim(string? state) =>
        state is not null && pending.TryRemove(state, out var login) ? login : null;

    /// <summary>Records a signed-in human and returns the cookie value for them.</summary>
    public string Create(PortalSession session)
    {
        var id = Random();
        signedIn[id] = session;
        return id;
    }

    /// <summary>The session a cookie names, if it is still one.</summary>
    public PortalSession? Find(string? id) =>
        id is not null && signedIn.TryGetValue(id, out var session) ? session : null;

    /// <summary>Forgets a session.</summary>
    public void Remove(string? id)
    {
        if (id is not null)
        {
            signedIn.TryRemove(id, out _);
        }
    }

    /// <summary>The PKCE challenge for a verifier: RFC 7636 S256.</summary>
    public static string Challenge(string verifier) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private static string Random() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
}

/// <summary>A sign-in that has been sent to the identity provider and not yet come back.</summary>
/// <param name="State">Ties the callback to this browser's request.</param>
/// <param name="Verifier">The PKCE verifier, which only this process ever holds.</param>
/// <param name="StartedAt">When it was sent, so an abandoned one can be dropped.</param>
internal sealed record PendingLogin(string State, string Verifier, DateTimeOffset StartedAt);

/// <summary>
/// A signed-in human. <see cref="AccessToken"/> stays on the server and is only handed to the
/// agent to exchange.
/// </summary>
/// <param name="AccessToken">The human's access token from the identity provider.</param>
/// <param name="Username">Who they are, for the page to greet.</param>
/// <param name="Subject">Their <c>sub</c>, which is what every task token will carry.</param>
/// <param name="Scopes">The scopes the identity provider granted them.</param>
/// <param name="ExpiresAt">When their token runs out.</param>
internal sealed record PortalSession(string AccessToken, string Username, string Subject, string Scopes, DateTimeOffset ExpiresAt)
{
    /// <summary>Builds a session from a new access token, reading its claims unverified.</summary>
    public static PortalSession FromToken(string accessToken, long expiresIn)
    {
        var payload = accessToken.Split('.')[1];
        using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(payload));
        var claims = document.RootElement;
        return new PortalSession(
            accessToken,
            Text(claims, "preferred_username") ?? Text(claims, "sub") ?? "someone",
            Text(claims, "sub") ?? string.Empty,
            Text(claims, "scope") ?? string.Empty,
            DateTimeOffset.UtcNow.AddSeconds(expiresIn));
    }

    /// <summary>The claims the page prints beside the task token's, so the two can be compared.</summary>
    public object Claims()
    {
        var payload = AccessToken.Split('.')[1];
        using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(payload));
        var claims = document.RootElement;
        return new
        {
            iss = Text(claims, "iss") ?? string.Empty,
            sub = Text(claims, "sub") ?? string.Empty,
            aud = claims.TryGetProperty("aud", out var aud) && aud.ValueKind == JsonValueKind.String ? aud.GetString() : "subactid",
            scope = Text(claims, "scope") ?? string.Empty,
            preferred_username = Text(claims, "preferred_username") ?? string.Empty,
            realm_roles = claims.TryGetProperty("realm_access", out var access) && access.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array
                ? roles.EnumerateArray().Where(r => r.ValueKind == JsonValueKind.String).Select(r => r.GetString()).ToArray()
                : [],
        };
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
