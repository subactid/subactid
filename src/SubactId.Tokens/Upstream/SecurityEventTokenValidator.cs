using System.Buffers.Text;
using System.Net.Http;
using System.Text.Json;
using SubactId.Tokens.Signing;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Validates a Security Event Token (RFC 8417) pushed by a Shared Signals transmitter (RFC 8935)
/// against that transmitter's published keys.
///
/// <para>
/// The transmitter is its own trust root, separate from the upstream identity provider. A SET is
/// trusted only against the configured transmitter's keys.
/// </para>
/// <para>
/// Never throws for a bad token. The caller gets a reason.
/// </para>
/// </summary>
/// <param name="keys">The transmitter's published keys.</param>
/// <param name="expectedAudience">The stream audience the transmitter is configured to send.</param>
/// <param name="subjectIssuer">The identity provider an <c>iss_sub</c> subject must name.</param>
/// <param name="clock">Time source.</param>
public sealed class SecurityEventTokenValidator(IUpstreamKeys keys, string expectedAudience, string subjectIssuer, TimeProvider clock)
{
    /// <summary>CAEP: the person's sessions were revoked. Their tasks end; they are not blocked.</summary>
    public const string SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    /// <summary>RISC: the account was disabled.</summary>
    public const string AccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

    /// <summary>RISC: the account was enabled again.</summary>
    public const string AccountEnabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

    /// <summary>RISC: the account was deleted.</summary>
    public const string AccountPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged";

    /// <summary>Leeway applied to every time-based claim.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Oldest <c>iat</c> accepted. A SET has no expiry (RFC 8417), so this bounds replay. A day,
    /// so events a transmitter queued during an outage are still accepted.
    /// </summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);

    /// <summary>Longest identifier accepted for a person, matching the column it is matched against.</summary>
    public const int MaxIdentifierLength = 256;

    private readonly string expectedAudience = string.IsNullOrWhiteSpace(expectedAudience)
        ? throw new ArgumentException("An expected audience is required.", nameof(expectedAudience))
        : expectedAudience;

    private readonly string subjectIssuer = string.IsNullOrWhiteSpace(subjectIssuer)
        ? throw new ArgumentException("A subject issuer is required.", nameof(subjectIssuer))
        : subjectIssuer.TrimEnd('/');

    /// <summary>Validates <paramref name="token"/>.</summary>
    /// <param name="token">The compact JWS posted as the request body.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<SecurityEventValidation> ValidateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (!JwsSegments.TryParse(token, out var segments, JwsSegments.MaxUpstreamTokenLength))
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
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
            return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
        }

        if (header is null || header.Crit is not null || string.IsNullOrEmpty(header.Kid))
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
        }

        if (header.Alg is null || !UpstreamKey.AllowedAlgorithms.Contains(header.Alg))
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.UnsupportedAlgorithm);
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
            return SecurityEventValidation.Reject(SecurityEventRejection.KeysUnavailable);
        }

        if (key is null)
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.UnknownKey);
        }

        if (!key.Supports(header.Alg))
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.KeyMismatch);
        }

        if (!key.Verify(header.Alg, segments.SigningInput, signature))
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.InvalidSignature);
        }

        return ValidateClaims(payload, snapshot.Issuer);
    }

    private SecurityEventValidation ValidateClaims(byte[] payload, string trustedIssuer)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException)
        {
            return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
        }

        using (document)
        {
            var claims = document.RootElement;
            if (claims.ValueKind != JsonValueKind.Object)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
            }

            if (GetString(claims, "iss") is not { } issuer || !string.Equals(issuer, trustedIssuer, StringComparison.Ordinal))
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.UntrustedIssuer);
            }

            if (!claims.TryGetProperty("aud", out var audience))
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.AudienceMismatch);
            }

            var audienceOk = audience.ValueKind switch
            {
                JsonValueKind.String => string.Equals(audience.GetString(), expectedAudience, StringComparison.Ordinal),
                JsonValueKind.Array => audience.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && string.Equals(a.GetString(), expectedAudience, StringComparison.Ordinal)),
                _ => (bool?)null,
            };
            if (audienceOk is null)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
            }

            if (!audienceOk.Value)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.AudienceMismatch);
            }

            var now = clock.GetUtcNow();

            // A SET has no expiry, so iat is required and bounded in both directions.
            if (!claims.TryGetProperty("iat", out var iatElement))
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.MissingIssuedAt);
            }

            if (!TryGetTime(iatElement, out var issuedAt))
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
            }

            if (issuedAt > now + ClockSkew)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.NotYetValid);
            }

            if (now - issuedAt > MaxAge + ClockSkew)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.TooOld);
            }

            // Recorded for replay protection, so it must be storable. Postgres rejects a NUL in text.
            if (GetString(claims, "jti") is not { Length: > 0 and <= MaxIdentifierLength } jti)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.MissingJti);
            }

            if (jti.Any(char.IsControl))
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.Malformed);
            }

            if (!claims.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Object)
            {
                return SecurityEventValidation.Reject(SecurityEventRejection.NotASecurityEvent);
            }

            // The subject may be at the top level or inside the event. If both are present they
            // must name the same person, or the token is refused.
            var subject = ReadSubject(claims, "sub_id");

            var acted = new List<SecurityEventAction>();
            foreach (var member in events.EnumerateObject())
            {
                if (Action(member.Name) is not { } action)
                {
                    continue;
                }

                var own = member.Value.ValueKind == JsonValueKind.Object ? ReadSubject(member.Value, "subject") : null;
                if (subject is { Length: > 0 } && own is { Length: > 0 } && !string.Equals(subject, own, StringComparison.Ordinal))
                {
                    return SecurityEventValidation.Reject(SecurityEventRejection.AmbiguousSubject);
                }

                var eventSubject = subject ?? own;
                if (eventSubject is null)
                {
                    return SecurityEventValidation.Reject(SecurityEventRejection.NoUsableSubject);
                }

                if (eventSubject.Length == 0)
                {
                    return SecurityEventValidation.Reject(SecurityEventRejection.UnsupportedSubjectFormat);
                }

                acted.Add(new SecurityEventAction(member.Name, action, eventSubject));
            }

            // A token with only unhandled events is still valid, and the caller treats it as
            // delivered so the transmitter does not retry.
            return SecurityEventValidation.Accept(new SecurityEventSignal(issuer, jti, acted, issuedAt + MaxAge + ClockSkew, issuedAt));
        }
    }

    /// <summary>What an event type asks this control plane to do, or <c>null</c> when it asks for nothing it can do.</summary>
    private static SecurityEventKind? Action(string eventType) => eventType switch
    {
        SessionRevoked => SecurityEventKind.SessionsRevoked,
        AccountDisabled => SecurityEventKind.AccountDisabled,
        AccountEnabled => SecurityEventKind.AccountEnabled,
        AccountPurged => SecurityEventKind.AccountPurged,
        _ => null,
    };

    /// <summary>
    /// The person a subject identifier (RFC 9493) names, as tasks are keyed. An empty string means
    /// the identifier is present but in an unsupported format, which is refused, not treated as absent.
    /// </summary>
    private string? ReadSubject(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var identifier) || identifier.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var format = GetString(identifier, "format");
        if (string.Equals(format, "iss_sub", StringComparison.Ordinal))
        {
            // The subject's issuer, not the token's. It must be the upstream identity provider.
            if (GetString(identifier, "iss")?.TrimEnd('/') is not { } iss || !string.Equals(iss, subjectIssuer, StringComparison.Ordinal))
            {
                return string.Empty;
            }

            return GetString(identifier, "sub") is { Length: > 0 and <= MaxIdentifierLength } sub && !sub.Any(char.IsControl) ? sub : string.Empty;
        }

        if (string.Equals(format, "opaque", StringComparison.Ordinal))
        {
            return GetString(identifier, "id") is { Length: > 0 and <= MaxIdentifierLength } id && !id.Any(char.IsControl) ? id : string.Empty;
        }

        return string.Empty;
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

/// <summary>What an event asks this control plane to do about a person.</summary>
public enum SecurityEventKind
{
    /// <summary>End their live tasks without blocking them.</summary>
    SessionsRevoked,

    /// <summary>Refuse to act for them, as disabled, and end their live tasks.</summary>
    AccountDisabled,

    /// <summary>Refuse to act for them, as gone, and end their live tasks.</summary>
    AccountPurged,

    /// <summary>Act for them again, if this receiver is what stopped it.</summary>
    AccountEnabled,
}

/// <summary>One event of a security event token, and who it is about.</summary>
/// <param name="EventType">The event type URI, for the record.</param>
/// <param name="Kind">What it asks for.</param>
/// <param name="SponsorKey">The person, as tasks are keyed by them.</param>
public sealed record SecurityEventAction(string EventType, SecurityEventKind Kind, string SponsorKey);

/// <summary>A validated security event token.</summary>
/// <param name="Issuer">The transmitter that signed it.</param>
/// <param name="Jti">Its identifier, for replay protection.</param>
/// <param name="Actions">The events this control plane acts on, in the order they were read; empty when it acts on none of them.</param>
/// <param name="ExpiresAt">When the replay record may be purged: the last instant the token could have been accepted.</param>
/// <param name="IssuedAt">The token's <c>iat</c>: when the transmitter issued it, by its own clock. Events are ordered by it.</param>
public sealed record SecurityEventSignal(string Issuer, string Jti, IReadOnlyList<SecurityEventAction> Actions, DateTimeOffset ExpiresAt, DateTimeOffset IssuedAt);

/// <summary>Why a security event token was refused. Every value is a stable, machine-readable audit reason.</summary>
public enum SecurityEventRejection
{
    /// <summary>The token was accepted.</summary>
    None,

    /// <summary>Not a canonical compact JWS, or a header or claim has the wrong shape.</summary>
    Malformed,

    /// <summary>The <c>alg</c> header is not one this control plane accepts.</summary>
    UnsupportedAlgorithm,

    /// <summary>The transmitter's keys could not be fetched and nothing was cached.</summary>
    KeysUnavailable,

    /// <summary>The <c>kid</c> is not published by the transmitter, even after a refresh.</summary>
    UnknownKey,

    /// <summary>The named key cannot be used with the token's algorithm.</summary>
    KeyMismatch,

    /// <summary>The signature does not verify.</summary>
    InvalidSignature,

    /// <summary>The <c>iss</c> claim is not the configured transmitter.</summary>
    UntrustedIssuer,

    /// <summary>The <c>aud</c> claim does not include the configured stream audience.</summary>
    AudienceMismatch,

    /// <summary>No <c>iat</c> claim.</summary>
    MissingIssuedAt,

    /// <summary>The <c>iat</c> is in the future, beyond clock skew.</summary>
    NotYetValid,

    /// <summary>The <c>iat</c> is older than this control plane accepts.</summary>
    TooOld,

    /// <summary>
    /// No <c>jti</c>, or one that is empty or too long, so the token could not be checked for
    /// replay. One with a control character is <c>Malformed</c>.
    /// </summary>
    MissingJti,

    /// <summary>No <c>events</c> claim, so the token is not a security event token.</summary>
    NotASecurityEvent,

    /// <summary>An event this receiver acts on names nobody at all.</summary>
    NoUsableSubject,

    /// <summary>The subject identifier is in a format this receiver does not read, or names another issuer's user.</summary>
    UnsupportedSubjectFormat,

    /// <summary>The token names one person at the top level and another inside an event.</summary>
    AmbiguousSubject,
}

/// <summary>Outcome of security event token validation.</summary>
/// <param name="Signal">What to act on, when accepted.</param>
/// <param name="Reason">Why it was refused; <see cref="SecurityEventRejection.None"/> when accepted.</param>
public sealed record SecurityEventValidation(SecurityEventSignal? Signal, SecurityEventRejection Reason)
{
    /// <summary>Whether the token was accepted.</summary>
    public bool IsValid => Signal is not null;

    internal static SecurityEventValidation Accept(SecurityEventSignal signal) => new(signal, SecurityEventRejection.None);

    internal static SecurityEventValidation Reject(SecurityEventRejection reason) => new(null, reason);
}
