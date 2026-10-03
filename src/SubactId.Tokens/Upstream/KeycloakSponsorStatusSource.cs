using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Asks Keycloak's admin API whether a user is still enabled (<c>GET {users}/{sub}</c>). Uses a
/// service-account token from <c>client_credentials</c> with <c>private_key_jwt</c> signed by the
/// active signing key, so no shared secret is configured. The service token is cached until
/// shortly before expiry. Any failure is <see cref="SponsorStatus.Unavailable"/>, never active.
/// Nothing received from the identity provider is logged.
/// </summary>
public sealed class KeycloakSponsorStatusSource(Func<HttpClient> clientFactory, Uri usersUrl, Uri tokenUrl, string clientId, SigningKeySet keys, TimeProvider clock) : ISponsorStatusProbe
{
    /// <summary>Longest admin API response read.</summary>
    public const int MaxResponseBytes = 64 * 1024;

    /// <summary>Lifetime of the client assertion this control plane signs for Keycloak.</summary>
    public static readonly TimeSpan AssertionLifetime = TimeSpan.FromSeconds(60);

    /// <summary>A service token is renewed this long before it expires.</summary>
    public static readonly TimeSpan TokenRenewalMargin = TimeSpan.FromSeconds(30);

    private readonly Func<HttpClient> clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
    private readonly Uri usersUrl = Require(usersUrl, nameof(usersUrl));
    private readonly Uri tokenUrl = Require(tokenUrl, nameof(tokenUrl));
    private readonly string clientId = string.IsNullOrWhiteSpace(clientId) ? throw new ArgumentException("A client id is required.", nameof(clientId)) : clientId;
    private readonly SigningKeySet keys = keys ?? throw new ArgumentNullException(nameof(keys));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly SemaphoreSlim tokenLock = new(1, 1);
    private (string Value, DateTimeOffset ExpiresAt)? serviceToken;

    /// <summary>The provider could not be asked, or answered as it would answer anyone.</summary>
    private static readonly SponsorLookup ProviderDown = new(SponsorStatus.Unavailable, ProviderFailed: true);

    /// <summary>The provider answered, but nothing usable about this person.</summary>
    private static readonly SponsorLookup UnusableAnswer = new(SponsorStatus.Unavailable, ProviderFailed: false);

    /// <inheritdoc />
    /// <remarks>Always asks; <paramref name="maxAge"/> is for the cache in front of this source.</remarks>
    public async Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default) =>
        (await LookUpAsync(subject, maxAge, cancellationToken)).Status;

    /// <inheritdoc />
    /// <remarks>
    /// <see cref="SponsorStatusCircuit"/> uses the distinction so one person's unusable record (a 403,
    /// or a record too large or malformed) does not open the circuit. Both are
    /// <see cref="SponsorStatus.Unavailable"/>, so a refusal.
    /// </remarks>
    public async Task<SponsorLookup> LookUpAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        // "." and ".." are unreserved, so they would survive escaping and be collapsed out of the path.
        if (string.IsNullOrEmpty(subject) || subject is "." or "..")
        {
            return new SponsorLookup(SponsorStatus.NotFound, ProviderFailed: false);
        }

        try
        {
            var lookup = await QueryAsync(subject, forceNewToken: false, cancellationToken);
            return lookup ?? await QueryAsync(subject, forceNewToken: true, cancellationToken) ?? ProviderDown;
        }
        catch (HttpRequestException exception) when (exception.HttpRequestError == HttpRequestError.ConfigurationLimitExceeded)
        {
            // This person's record is too large. The provider itself is up.
            return UnusableAnswer;
        }
        catch (JsonException)
        {
            // This person's record is not JSON. Service token parse errors are handled where it is fetched.
            return UnusableAnswer;
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // A timeout counts as a provider failure. The caller's own cancellation propagates.
            return ProviderDown;
        }
    }

    /// <summary>One lookup; <c>null</c> means the service token was refused and a fresh one should be tried once.</summary>
    private async Task<SponsorLookup?> QueryAsync(string subject, bool forceNewToken, CancellationToken cancellationToken)
    {
        string? token;
        try
        {
            token = await GetServiceTokenAsync(forceNewToken, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or InvalidOperationException || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // Without a service token no lookup is possible.
            return ProviderDown;
        }

        if (token is null)
        {
            return ProviderDown;
        }

        using var client = clientFactory();
        client.MaxResponseContentBufferSize = MaxResponseBytes;
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(usersUrl.AbsoluteUri.TrimEnd('/') + "/" + Uri.EscapeDataString(subject)));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        // Fully buffered so MaxResponseContentBufferSize bounds the read.
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);

        switch (response.StatusCode)
        {
            case HttpStatusCode.NotFound:
                return new SponsorLookup(SponsorStatus.NotFound, ProviderFailed: false);
            case HttpStatusCode.Unauthorized when !forceNewToken:
                return null;
            case HttpStatusCode.OK:
                break;
            default:
                // 5xx, 429, 408 and a 401 with a fresh token are provider-wide. Anything else is
                // about this one account.
                return (int)response.StatusCode >= 500 || response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.RequestTimeout or HttpStatusCode.Unauthorized
                    ? ProviderDown
                    : UnusableAnswer;
        }

        // The answer must be about the user asked for: an object whose id is the subject, with a boolean enabled.
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String || !string.Equals(id.GetString(), subject, StringComparison.Ordinal)
            || !root.TryGetProperty("enabled", out var enabled) || enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return UnusableAnswer;
        }

        return new SponsorLookup(enabled.GetBoolean() ? SponsorStatus.Active : SponsorStatus.Disabled, ProviderFailed: false);
    }

    private async Task<string?> GetServiceTokenAsync(bool forceNew, CancellationToken cancellationToken)
    {
        await tokenLock.WaitAsync(cancellationToken);
        try
        {
            var now = clock.GetUtcNow();
            if (!forceNew && serviceToken is { } cached && cached.ExpiresAt - TokenRenewalMargin > now)
            {
                return cached.Value;
            }

            serviceToken = null;
            var assertion = SignAssertion(now);
            using var client = clientFactory();
            client.MaxResponseContentBufferSize = MaxResponseBytes;
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ["client_assertion"] = assertion,
            });
            using var response = await client.PostAsync(tokenUrl, content, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("access_token", out var accessToken) || accessToken.ValueKind != JsonValueKind.String
                || !document.RootElement.TryGetProperty("expires_in", out var expiresIn) || !expiresIn.TryGetInt64(out var seconds) || seconds <= 0)
            {
                return null;
            }

            var value = accessToken.GetString()!;
            serviceToken = (value, now.AddSeconds(seconds));
            return value;
        }
        finally
        {
            tokenLock.Release();
        }
    }

    /// <summary>RFC 7523 client assertion for Keycloak: <c>iss</c> and <c>sub</c> are this client, <c>aud</c> is the token endpoint.</summary>
    private string SignAssertion(DateTimeOffset now)
    {
        var claims = new Dictionary<string, object>
        {
            ["iss"] = clientId,
            ["sub"] = clientId,
            ["aud"] = tokenUrl.AbsoluteUri,
            ["jti"] = OpaqueId.New("kc", now),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = (now + AssertionLifetime).ToUnixTimeSeconds(),
        };
        return Jws.Sign(keys, JsonSerializer.SerializeToUtf8Bytes(claims), typ: "JWT");
    }

    private static Uri Require(Uri url, string name)
    {
        ArgumentNullException.ThrowIfNull(url, name);
        if (!url.IsAbsoluteUri || url.Scheme is not ("https" or "http"))
        {
            throw new ArgumentException("An absolute http or https URL is required.", name);
        }

        return url;
    }
}
