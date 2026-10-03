using System.Buffers.Text;
using System.Net.Http;
using System.Text.Json;
using SubactId.Tokens.Signing;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Validates an OpenID Connect back-channel logout token (Back-Channel Logout 1.0 section 2.4)
/// against the upstream identity provider's published keys. The token must carry the
/// back-channel logout event and no <c>nonce</c>, so an ID token cannot be passed off as one.
///
/// Never throws for a bad token. The reason is for the ledger, not the response.
/// </summary>
/// <param name="keys">The upstream's published keys.</param>
/// <param name="expectedAudience">The client the identity provider registered the logout URI on.</param>
/// <param name="clock">Time source.</param>
public sealed class LogoutTokenValidator(IUpstreamKeys keys, string expectedAudience, TimeProvider clock)
{
    /// <summary>The event a logout token must carry, per Back-Channel Logout 1.0 section 2.4.</summary>
    public const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>Leeway applied to every time-based claim.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Oldest <c>iat</c> accepted. The specification sets no bound. This one limits late replay
    /// and how long replay records are kept.
    /// </summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    /// <summary>Longest identifier accepted for a subject or a session, matching the columns they are stored in.</summary>
    public const int MaxIdentifierLength = 256;

    private readonly string expectedAudience = string.IsNullOrWhiteSpace(expectedAudience)
        ? throw new ArgumentException("An expected audience is required.", nameof(expectedAudience))
        : expectedAudience;

    /// <summary>Validates <paramref name="token"/>.</summary>
    /// <param name="token">The compact JWS presented as <c>logout_token</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<LogoutValidation> ValidateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (!JwsSegments.TryParse(token, out var segments, JwsSegments.MaxUpstreamTokenLength))
        {
            return LogoutValidation.Reject(LogoutRejection.Malformed);
        }

        JwsHeader? header;
        byte[] signature;
        byte[] payload;
        try
        {
            header = JsonSerializer.Deserialize<JwsHeader>(Base64Url.DecodeFromChars(segments.Header));
            signature = Base64Url.DecodeFromChars(segments.Signature);
            payload = Base64Url.DecodeFromChars(segments.Payload);
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return LogoutValidation.Reject(LogoutRejection.Malformed);
        }

        if (header is null || header.Crit is not null || string.IsNullOrEmpty(header.Kid))
        {
            return LogoutValidation.Reject(LogoutRejection.Malformed);
        }

        if (header.Alg is null || !UpstreamKey.AllowedAlgorithms.Contains(header.Alg))
        {
            return LogoutValidation.Reject(LogoutRejection.UnsupportedAlgorithm);
        }

        UpstreamKeySnapshot snapshot;
        UpstreamKey? key;
        try
        {
            snapshot = await keys.GetAsync(cancellationToken);
            if (!snapshot.Keys.TryGetValue(header.Kid, out key))
            {
                snapshot = await keys.RefreshForUnknownKidAsync(cancellationToken);
                snapshot.Keys.TryGetValue(header.Kid, out key);
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or UpstreamDiscoveryException or TaskCanceledException)
        {
            return LogoutValidation.Reject(LogoutRejection.KeysUnavailable);
        }

        if (key is null)
        {
            return LogoutValidation.Reject(LogoutRejection.UnknownKey);
        }

        if (!key.Supports(header.Alg))
        {
            return LogoutValidation.Reject(LogoutRejection.KeyMismatch);
        }

        if (!key.Verify(header.Alg, segments.SigningInput, signature))
        {
            return LogoutValidation.Reject(LogoutRejection.InvalidSignature);
        }

        return ValidateClaims(payload, snapshot.Issuer);
    }

    private LogoutValidation ValidateClaims(byte[] payload, string trustedIssuer)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException)
        {
            return LogoutValidation.Reject(LogoutRejection.Malformed);
        }

        using (document)
        {
            var claims = document.RootElement;
            if (claims.ValueKind != JsonValueKind.Object)
            {
                return LogoutValidation.Reject(LogoutRejection.Malformed);
            }

            if (GetString(claims, "iss") is not { } issuer || !string.Equals(issuer, trustedIssuer, StringComparison.Ordinal))
            {
                return LogoutValidation.Reject(LogoutRejection.UntrustedIssuer);
            }

            if (!claims.TryGetProperty("aud", out var audience))
            {
                return LogoutValidation.Reject(LogoutRejection.AudienceMismatch);
            }

            var audienceOk = audience.ValueKind switch
            {
                JsonValueKind.String => string.Equals(audience.GetString(), expectedAudience, StringComparison.Ordinal),
                JsonValueKind.Array => audience.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && string.Equals(a.GetString(), expectedAudience, StringComparison.Ordinal)),
                _ => (bool?)null,
            };
            if (audienceOk is null)
            {
                return LogoutValidation.Reject(LogoutRejection.Malformed);
            }

            if (!audienceOk.Value)
            {
                return LogoutValidation.Reject(LogoutRejection.AudienceMismatch);
            }

            var now = clock.GetUtcNow();

            // iat is required and bounded in both directions.
            if (!claims.TryGetProperty("iat", out var iatElement))
            {
                return LogoutValidation.Reject(LogoutRejection.MissingIssuedAt);
            }

            if (!TryGetTime(iatElement, out var issuedAt))
            {
                return LogoutValidation.Reject(LogoutRejection.Malformed);
            }

            if (issuedAt > now + ClockSkew)
            {
                return LogoutValidation.Reject(LogoutRejection.NotYetValid);
            }

            if (now - issuedAt > MaxAge + ClockSkew)
            {
                return LogoutValidation.Reject(LogoutRejection.TooOld);
            }

            // exp is optional and honoured when present. The replay record is kept until the token
            // can no longer be accepted: iat plus MaxAge, or exp if sooner, plus skew.
            var acceptedUntil = issuedAt + MaxAge + ClockSkew;
            if (claims.TryGetProperty("exp", out var expElement))
            {
                if (!TryGetTime(expElement, out var expiry))
                {
                    return LogoutValidation.Reject(LogoutRejection.Malformed);
                }

                if (now >= expiry + ClockSkew)
                {
                    return LogoutValidation.Reject(LogoutRejection.Expired);
                }

                if (expiry + ClockSkew < acceptedUntil)
                {
                    acceptedUntil = expiry + ClockSkew;
                }
            }

            // The events claim marks this as a logout token, not an ID token. The member must be
            // present. Its value is not checked.
            if (!claims.TryGetProperty("events", out var events)
                || events.ValueKind != JsonValueKind.Object
                || !events.TryGetProperty(LogoutEvent, out _))
            {
                return LogoutValidation.Reject(LogoutRejection.NotALogoutEvent);
            }

            // An ID token carries a nonce; a logout token must not.
            if (claims.TryGetProperty("nonce", out _))
            {
                return LogoutValidation.Reject(LogoutRejection.NoncePresent);
            }

            // The jti is recorded and sub and sid are matched in storage, so none may carry a
            // control character. Postgres rejects a NUL in text.
            if (GetString(claims, "jti") is not { Length: > 0 and <= MaxIdentifierLength } jti)
            {
                return LogoutValidation.Reject(LogoutRejection.MissingJti);
            }

            if (jti.Any(char.IsControl))
            {
                return LogoutValidation.Reject(LogoutRejection.Malformed);
            }

            var subject = GetString(claims, "sub");
            var sessionId = GetString(claims, "sid");
            if (subject is { Length: > MaxIdentifierLength } || sessionId is { Length: > MaxIdentifierLength })
            {
                return LogoutValidation.Reject(LogoutRejection.IdentifierTooLong);
            }

            if ((subject?.Any(char.IsControl) ?? false) || (sessionId?.Any(char.IsControl) ?? false))
            {
                return LogoutValidation.Reject(LogoutRejection.Malformed);
            }

            // At least one of sub or sid is required (section 2.4).
            if (subject is not { Length: > 0 } && sessionId is not { Length: > 0 })
            {
                return LogoutValidation.Reject(LogoutRejection.NoSubjectOrSession);
            }

            return LogoutValidation.Accept(new LogoutSignal(issuer, subject, sessionId, jti, acceptedUntil, issuedAt));
        }
    }

    private static string? GetString(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>A NumericDate (RFC 7519 section 2): a JSON number of seconds since the epoch. Strings are not accepted.</summary>
    private static bool TryGetTime(JsonElement element, out DateTimeOffset time)
    {
        time = default;
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetDouble(out var seconds) || double.IsNaN(seconds) || double.IsInfinity(seconds))
        {
            return false;
        }

        if (seconds < 0 || seconds > 253_402_300_799)
        {
            return false;
        }

        time = DateTimeOffset.FromUnixTimeSeconds((long)Math.Floor(seconds));
        return true;
    }
}

/// <summary>Why a logout token was refused. Every value is a stable, machine-readable audit reason.</summary>
public enum LogoutRejection
{
    /// <summary>The token was accepted.</summary>
    None,

    /// <summary>Not a canonical compact JWS, or a header or claim has the wrong shape.</summary>
    Malformed,

    /// <summary>The <c>alg</c> header is not one this control plane accepts.</summary>
    UnsupportedAlgorithm,

    /// <summary>The upstream keys could not be fetched and nothing was cached.</summary>
    KeysUnavailable,

    /// <summary>The <c>kid</c> is not published by the upstream, even after a refresh.</summary>
    UnknownKey,

    /// <summary>The named key cannot be used with the token's algorithm.</summary>
    KeyMismatch,

    /// <summary>The signature does not verify.</summary>
    InvalidSignature,

    /// <summary>The <c>iss</c> claim is not the upstream issuer.</summary>
    UntrustedIssuer,

    /// <summary>The <c>aud</c> claim does not include the configured client.</summary>
    AudienceMismatch,

    /// <summary>No <c>iat</c> claim.</summary>
    MissingIssuedAt,

    /// <summary>The <c>iat</c> is in the future, beyond clock skew.</summary>
    NotYetValid,

    /// <summary>The <c>iat</c> is older than this control plane accepts.</summary>
    TooOld,

    /// <summary>The token has expired, beyond clock skew.</summary>
    Expired,

    /// <summary>No <c>events</c> claim carrying the back-channel logout event.</summary>
    NotALogoutEvent,

    /// <summary>A <c>nonce</c> is present, which a logout token must not carry.</summary>
    NoncePresent,

    /// <summary>
    /// No <c>jti</c>, or one that is empty or too long, so the token could not be checked for
    /// replay. One with a control character is <c>Malformed</c>.
    /// </summary>
    MissingJti,

    /// <summary>The <c>sub</c> or <c>sid</c> is longer than the column it would be matched against.</summary>
    IdentifierTooLong,

    /// <summary>Neither a <c>sub</c> nor a <c>sid</c>, so the token names nobody.</summary>
    NoSubjectOrSession,
}

/// <summary>What a valid logout token asks for.</summary>
/// <param name="Issuer">The issuer that signed it.</param>
/// <param name="Subject">The human, when the token names one.</param>
/// <param name="SessionId">The session, when the token names one.</param>
/// <param name="Jti">The token's identifier, for replay protection.</param>
/// <param name="ExpiresAt">When the replay record may be purged: the last instant the token could be accepted, including clock skew.</param>
/// <param name="IssuedAt">The token's <c>iat</c>: when the identity provider ended the session, by its own clock.</param>
public sealed record LogoutSignal(string Issuer, string? Subject, string? SessionId, string Jti, DateTimeOffset ExpiresAt, DateTimeOffset IssuedAt);

/// <summary>Outcome of logout token validation.</summary>
/// <param name="Signal">What to act on, when accepted.</param>
/// <param name="Reason">Why it was refused; <see cref="LogoutRejection.None"/> when accepted.</param>
public sealed record LogoutValidation(LogoutSignal? Signal, LogoutRejection Reason)
{
    /// <summary>Whether the token was accepted.</summary>
    public bool IsValid => Signal is not null;

    internal static LogoutValidation Accept(LogoutSignal signal) => new(signal, LogoutRejection.None);

    internal static LogoutValidation Reject(LogoutRejection reason) => new(null, reason);
}
