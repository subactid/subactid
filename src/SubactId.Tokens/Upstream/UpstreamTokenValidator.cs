using System.Buffers.Text;
using System.Net.Http;
using System.Text.Json;
using SubactId.Tokens.Signing;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// Validates a subject token issued by the upstream identity provider: canonical compact JWS,
/// an allowed algorithm that fits the named key, a signature by a published key (refreshing
/// once for an unknown kid), the <c>iss</c>, <c>aud</c>, <c>exp</c>, <c>nbf</c>, <c>iat</c> and
/// <c>sub</c> claims with 60 seconds of clock skew, and the <c>typ</c> header when the operator
/// names the types accepted. Never throws for a bad token.
/// </summary>
public sealed class UpstreamTokenValidator(IUpstreamKeys keys, string expectedAudience, TimeProvider clock, IReadOnlyList<string>? acceptedTokenTypes = null)
{
    /// <summary>Leeway applied to every time-based claim.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    /// <summary>Longest <c>sub</c> accepted. It is stored as the sponsor of every task and audit record.</summary>
    public const int MaxSubjectLength = 256;

    private readonly string expectedAudience = string.IsNullOrWhiteSpace(expectedAudience)
        ? throw new ArgumentException("An expected audience is required.", nameof(expectedAudience))
        : expectedAudience;

    /// <summary>
    /// The <c>typ</c> header values a subject token may carry, or empty to accept any. When set,
    /// a token whose header <c>typ</c> is absent or not on the list is refused. Off by default:
    /// the spec (section 3) does not require a <c>typ</c>, so this only tightens an operator that
    /// asks for it, for example to <c>at+jwt</c>, so that only an RFC 9068 access token is accepted
    /// from an identity provider that marks its access tokens that way. Held without the
    /// <c>application/</c> prefix, so either spelling of a type matches (RFC 7515 section 4.1.9).
    /// </summary>
    private readonly HashSet<string> acceptedTokenTypes = new((acceptedTokenTypes ?? []).Select(MediaSubtype), StringComparer.OrdinalIgnoreCase);

    /// <summary>Validates <paramref name="token"/>.</summary>
    /// <param name="token">The compact JWS presented as <c>subject_token</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<UpstreamValidation> ValidateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (!JwsSegments.TryParse(token, out var segments, JwsSegments.MaxUpstreamTokenLength))
        {
            return UpstreamValidation.Reject(UpstreamRejection.Malformed);
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
            return UpstreamValidation.Reject(UpstreamRejection.Malformed);
        }

        if (header is null || header.Crit is not null || string.IsNullOrEmpty(header.Kid))
        {
            return UpstreamValidation.Reject(UpstreamRejection.Malformed);
        }

        if (header.Alg is null || !UpstreamKey.AllowedAlgorithms.Contains(header.Alg))
        {
            return UpstreamValidation.Reject(UpstreamRejection.UnsupportedAlgorithm);
        }

        // Optional, off by default. When an operator pins the accepted header types, a token whose
        // typ is absent or not on the list is refused before any key work.
        if (acceptedTokenTypes.Count > 0)
        {
            var typ = header.Typ;
            if (typ is null || !acceptedTokenTypes.Contains(MediaSubtype(typ)))
            {
                return UpstreamValidation.Reject(UpstreamRejection.UnacceptedType);
            }
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
            return UpstreamValidation.Reject(UpstreamRejection.KeysUnavailable);
        }

        if (key is null)
        {
            return UpstreamValidation.Reject(UpstreamRejection.UnknownKey);
        }

        if (!key.Supports(header.Alg))
        {
            return UpstreamValidation.Reject(UpstreamRejection.KeyMismatch);
        }

        if (!key.Verify(header.Alg, segments.SigningInput, signature))
        {
            return UpstreamValidation.Reject(UpstreamRejection.InvalidSignature);
        }

        return ValidateClaims(payload, snapshot.Issuer);
    }

    private UpstreamValidation ValidateClaims(byte[] payload, string trustedIssuer)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException)
        {
            return UpstreamValidation.Reject(UpstreamRejection.Malformed);
        }

        using (document)
        {
            var claims = document.RootElement;
            if (claims.ValueKind != JsonValueKind.Object)
            {
                return UpstreamValidation.Reject(UpstreamRejection.Malformed);
            }

            if (GetString(claims, "iss") is not { } issuer || !string.Equals(issuer, trustedIssuer, StringComparison.Ordinal))
            {
                return UpstreamValidation.Reject(UpstreamRejection.UntrustedIssuer);
            }

            var now = clock.GetUtcNow();

            if (!claims.TryGetProperty("exp", out var expElement))
            {
                return UpstreamValidation.Reject(UpstreamRejection.MissingExpiry);
            }

            if (!TryGetTime(expElement, out var expiresAt))
            {
                return UpstreamValidation.Reject(UpstreamRejection.Malformed);
            }

            if (now >= expiresAt + ClockSkew)
            {
                return UpstreamValidation.Reject(UpstreamRejection.Expired);
            }

            if (claims.TryGetProperty("nbf", out var nbfElement))
            {
                if (!TryGetTime(nbfElement, out var notBefore))
                {
                    return UpstreamValidation.Reject(UpstreamRejection.Malformed);
                }

                if (now + ClockSkew < notBefore)
                {
                    return UpstreamValidation.Reject(UpstreamRejection.NotYetValid);
                }
            }

            DateTimeOffset? issuedAt = null;
            if (claims.TryGetProperty("iat", out var iatElement))
            {
                if (!TryGetTime(iatElement, out var iat))
                {
                    return UpstreamValidation.Reject(UpstreamRejection.Malformed);
                }

                if (iat > now + ClockSkew)
                {
                    return UpstreamValidation.Reject(UpstreamRejection.NotYetValid);
                }

                issuedAt = iat;
            }

            if (!claims.TryGetProperty("aud", out var audElement))
            {
                return UpstreamValidation.Reject(UpstreamRejection.AudienceMismatch);
            }

            var audienceOk = audElement.ValueKind switch
            {
                JsonValueKind.String => string.Equals(audElement.GetString(), expectedAudience, StringComparison.Ordinal),
                JsonValueKind.Array => audElement.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && string.Equals(a.GetString(), expectedAudience, StringComparison.Ordinal)),
                _ => (bool?)null,
            };
            if (audienceOk is null)
            {
                return UpstreamValidation.Reject(UpstreamRejection.Malformed);
            }

            if (!audienceOk.Value)
            {
                return UpstreamValidation.Reject(UpstreamRejection.AudienceMismatch);
            }

            if (GetString(claims, "sub") is not { Length: > 0 } subject)
            {
                return UpstreamValidation.Reject(UpstreamRejection.MissingSubject);
            }

            if (subject.Length > MaxSubjectLength)
            {
                return UpstreamValidation.Reject(UpstreamRejection.SubTooLong);
            }

            // Control characters are refused. The subject goes into every audit record, and
            // Postgres rejects a NUL in text.
            if (subject.Any(char.IsControl))
            {
                return UpstreamValidation.Reject(UpstreamRejection.SubMalformed);
            }

            var scopes = GetString(claims, "scope") is { } scope
                ? scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : [];

            return UpstreamValidation.Accept(new UpstreamPrincipal(subject, issuer, scopes, expiresAt, claims.Clone(), issuedAt));
        }
    }

    private static string? GetString(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>
    /// A <c>typ</c> value without its <c>application/</c> prefix. RFC 7515 section 4.1.9 reads a
    /// <c>typ</c> with no <c>/</c> as if <c>application/</c> were prepended, so <c>at+jwt</c> and
    /// <c>application/at+jwt</c> are one type, and RFC 9068 section 4 accepts either.
    /// </summary>
    private static string MediaSubtype(string typ)
    {
        const string Application = "application/";
        return typ.StartsWith(Application, StringComparison.OrdinalIgnoreCase) && !typ.AsSpan(Application.Length).Contains('/')
            ? typ[Application.Length..]
            : typ;
    }

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

/// <summary>Why an upstream token was rejected. Every value is a stable, machine-readable audit reason.</summary>
public enum UpstreamRejection
{
    /// <summary>The token was accepted.</summary>
    None,

    /// <summary>Not a canonical compact JWS, or a header or claim has the wrong shape.</summary>
    Malformed,

    /// <summary>The <c>alg</c> header is not RS256, PS256 or ES256.</summary>
    UnsupportedAlgorithm,

    /// <summary>The <c>typ</c> header is not one the operator's configured allowlist accepts.</summary>
    UnacceptedType,

    /// <summary>The upstream discovery or JWKS could not be fetched and nothing was cached.</summary>
    KeysUnavailable,

    /// <summary>The <c>kid</c> is not published by the upstream, even after a refresh.</summary>
    UnknownKey,

    /// <summary>The named key cannot be used with the token's algorithm.</summary>
    KeyMismatch,

    /// <summary>The signature does not verify.</summary>
    InvalidSignature,

    /// <summary>The <c>iss</c> claim is not the upstream issuer.</summary>
    UntrustedIssuer,

    /// <summary>No <c>exp</c> claim.</summary>
    MissingExpiry,

    /// <summary>The token has expired, beyond clock skew.</summary>
    Expired,

    /// <summary>The token's <c>nbf</c> or <c>iat</c> is in the future, beyond clock skew.</summary>
    NotYetValid,

    /// <summary>The <c>aud</c> claim does not include this control plane.</summary>
    AudienceMismatch,

    /// <summary>No non-empty <c>sub</c> claim.</summary>
    MissingSubject,

    /// <summary>
    /// The <c>sub</c> claim is longer than <see cref="UpstreamTokenValidator.MaxSubjectLength"/>.
    /// Named for the claim, so its audit reason is <c>subject_sub_too_long</c>.
    /// </summary>
    SubTooLong,

    /// <summary>
    /// The <c>sub</c> claim contains a control character. Named for the claim, so its audit reason
    /// is <c>subject_sub_malformed</c>.
    /// </summary>
    SubMalformed,
}

/// <summary>Outcome of upstream token validation.</summary>
/// <param name="Principal">The validated human, when accepted.</param>
/// <param name="Reason">Why the token was rejected; <see cref="UpstreamRejection.None"/> when accepted.</param>
public sealed record UpstreamValidation(UpstreamPrincipal? Principal, UpstreamRejection Reason)
{
    /// <summary>Whether the token was accepted.</summary>
    public bool IsValid => Principal is not null;

    internal static UpstreamValidation Accept(UpstreamPrincipal principal) => new(principal, UpstreamRejection.None);

    internal static UpstreamValidation Reject(UpstreamRejection reason) => new(null, reason);
}

/// <summary>The human a validated upstream token identifies. This becomes the <c>sub</c> of every task token.</summary>
/// <param name="Subject">The upstream <c>sub</c> claim.</param>
/// <param name="Issuer">The upstream issuer.</param>
/// <param name="Scopes">The upstream <c>scope</c> claim split on spaces; empty when absent.</param>
/// <param name="ExpiresAt">The upstream <c>exp</c>.</param>
/// <param name="Claims">Every claim, for policy decisions that need more than the above.</param>
/// <param name="IssuedAt">The upstream <c>iat</c>, when the token carries one. A logout is matched against it.</param>
public sealed record UpstreamPrincipal(string Subject, string Issuer, IReadOnlyList<string> Scopes, DateTimeOffset ExpiresAt, JsonElement Claims, DateTimeOffset? IssuedAt)
{
    /// <summary>
    /// The value of <paramref name="name"/> if it is a non-empty string no longer than a subject,
    /// otherwise <c>null</c>. Other JSON types are not coerced.
    /// </summary>
    /// <param name="name">The claim name.</param>
    public string? FindStringClaim(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (Claims.ValueKind != JsonValueKind.Object
            || !Claims.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString() is { Length: > 0 and <= UpstreamTokenValidator.MaxSubjectLength } text ? text : null;
    }
}
