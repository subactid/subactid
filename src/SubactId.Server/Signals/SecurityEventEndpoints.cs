using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Primitives;
using SubactId.Core.Audit;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Signals;

/// <summary>
/// The Shared Signals push receiver of RFC 8935, mapped only when a transmitter is configured.
/// Takes one security event token per request and answers <c>202</c> when it is accepted.
/// </summary>
public static class SecurityEventEndpoints
{
    /// <summary>Path of the receiver.</summary>
    public const string EventsPath = "/events";

    /// <summary>The media type a security event token is pushed as (RFC 8935 section 2.1).</summary>
    public const string MediaType = "application/secevent+jwt";

    /// <summary>Largest request body read, in bytes. Enough for one JWS.</summary>
    public const long MaxRequestBodyBytes = 64 * 1024;

    /// <summary>Registers the receiver's services, when it is configured.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The receiver's settings, or <c>null</c> when it is not configured.</param>
    /// <param name="subjectIssuer">The identity provider whose users this control plane knows, for an <c>iss_sub</c> subject.</param>
    public static IServiceCollection AddSubactIdSecurityEvents(this IServiceCollection services, SsfOptions? options, string subjectIssuer)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (options is null)
        {
            return services;
        }

        // A separate key cache from the identity provider's, so neither issuer can sign for the other.
        services.AddKeyedSingleton(nameof(SsfOptions), (provider, _) => new UpstreamKeyCache(
            () => provider.GetRequiredService<IHttpClientFactory>().CreateClient(Upstream.UpstreamIdpServiceCollectionExtensions.HttpClientName),
            options.MetadataUrl,
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddSingleton(provider => new SecurityEventTokenValidator(
            provider.GetRequiredKeyedService<UpstreamKeyCache>(nameof(SsfOptions)),
            options.Audience,
            subjectIssuer,
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddScoped<SecurityEventService>();
        services.TryAddScoped<SponsorSignalWriter>();
        return services;
    }

    /// <summary>Maps the receiver, when it is configured.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="options">The receiver's settings, or <c>null</c> when it is not configured.</param>
    public static void MapSubactIdSecurityEventEndpoints(this IEndpointRouteBuilder endpoints, SsfOptions? options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        if (options is null)
        {
            return;
        }

        endpoints.MapPost(EventsPath, async (HttpRequest request, SecurityEventService events, CancellationToken cancellationToken) =>
        {
            var http = request.HttpContext;
            if (await SecurityEventBearerFilter.AuthenticateAsync(http) is { } refusal)
            {
                return refusal;
            }

            if (!IsAcceptedMediaType(request.ContentType))
            {
                await events.RefuseUnreadableAsync();
                return Results.Json(
                    new SecurityEventErrorResponse("invalid_request", "The body must be a security event token sent as " + MediaType + "."),
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var token = await ReadAsync(request, cancellationToken);
            return Answer(await events.ReceiveAsync(token, cancellationToken));
        });
    }

    /// <summary>
    /// The response for <paramref name="rejection"/>: <c>202</c> with no body when accepted, an
    /// RFC 8935 error when the token is invalid, and a retryable <c>503</c> when the transmitter's
    /// keys could not be fetched.
    /// </summary>
    /// <param name="rejection">Why the token was refused, or <c>null</c> when it was accepted.</param>
    public static IResult Answer(SecurityEventRejection? rejection)
    {
        if (rejection is null)
        {
            return Results.StatusCode(StatusCodes.Status202Accepted);
        }

        if (rejection == SecurityEventRejection.KeysUnavailable)
        {
            return Results.Json(
                new SecurityEventErrorResponse("invalid_key", "The transmitter's keys could not be fetched; retry later."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        var (err, description) = Describe(rejection.Value);
        return Results.Json(new SecurityEventErrorResponse(err, description), statusCode: StatusCodes.Status400BadRequest);
    }

    /// <summary>The RFC 8935 error code and a sentence for <paramref name="rejection"/>.</summary>
    private static (string Err, string Description) Describe(SecurityEventRejection rejection) => rejection switch
    {
        SecurityEventRejection.UnsupportedAlgorithm or SecurityEventRejection.UnknownKey or SecurityEventRejection.KeyMismatch or SecurityEventRejection.InvalidSignature =>
            ("invalid_key", "The event is not signed by a key this receiver trusts."),
        SecurityEventRejection.UntrustedIssuer => ("invalid_issuer", "The event was not issued by the configured transmitter."),
        SecurityEventRejection.AudienceMismatch => ("invalid_audience", "The event is not addressed to this receiver."),
        SecurityEventRejection.NoUsableSubject or SecurityEventRejection.UnsupportedSubjectFormat =>
            ("invalid_request", "The event does not name a subject in a format this receiver reads."),
        SecurityEventRejection.AmbiguousSubject =>
            ("invalid_request", "The event names one subject at the top level and another inside the event."),

        // Age problems are named explicitly so a transmitter can see why old events were refused.
        SecurityEventRejection.MissingIssuedAt => ("invalid_request", "The event has no iat."),
        SecurityEventRejection.NotYetValid => ("invalid_request", "The event's iat is in the future."),
        SecurityEventRejection.TooOld => ("invalid_request", "The event's iat is older than this receiver accepts, so it was not acted on."),
        SecurityEventRejection.MissingJti => ("invalid_request", "The event has no jti, so it cannot be checked for replay."),
        SecurityEventRejection.NotASecurityEvent => ("invalid_request", "The token has no events claim."),
        _ => ("invalid_request", "The event is not a valid security event token."),
    };

    /// <summary>Whether <paramref name="contentType"/> is <c>application/secevent+jwt</c>. No other type is read.</summary>
    /// <param name="contentType">The request's <c>Content-Type</c>.</param>
    public static bool IsAcceptedMediaType(string? contentType) =>
        Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(contentType, out var parsed)
        && string.Equals(parsed.MediaType.Value, MediaType, StringComparison.OrdinalIgnoreCase);

    /// <summary>Reads the compact JWS from the body, bounded, or <c>null</c> when it cannot be read.</summary>
    private static async Task<string?> ReadAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
        {
            limit.MaxRequestBodySize = MaxRequestBodyBytes;
        }

        try
        {
            using var reader = new StreamReader(request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            return await reader.ReadToEndAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is BadHttpRequestException or IOException or InvalidOperationException)
        {
            // Includes an oversized body. The validator refuses null like any other invalid token.
            return null;
        }
    }
}

/// <summary>
/// Authenticates a transmitter with the configured push credential. Checked before the token's
/// signature, since it is cheaper.
/// </summary>
public static class SecurityEventBearerFilter
{
    /// <summary>
    /// The refusal to answer <paramref name="http"/> with, or <c>null</c> when it carries a
    /// configured credential.
    /// </summary>
    /// <param name="http">The request.</param>
    public static async Task<IResult?> AuthenticateAsync(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        var options = http.RequestServices.GetRequiredService<SubactIdOptions>();
        if (options.Ssf is not { } ssf)
        {
            return Results.NotFound();
        }

        if (Check(http.Request.Headers.Authorization, ssf) is { } reason)
        {
            var clock = http.RequestServices.GetRequiredService<TimeProvider>();
            var record = new AuditEvent(clock.GetUtcNow(), AuditEvents.SsfDenied, Decision: AuditDecision.Deny, Reason: reason);
            await http.RequestServices.GetRequiredService<DenialAggregator>()
                .RecordAsync(record, http.RequestServices.GetRequiredService<IAuditWriter>());

            http.Response.Headers.WWWAuthenticate = "Bearer realm=\"subactid-events\"";

            // Do not say which check failed to an unauthenticated caller, nor anything else (spec section 6).
            return Results.Json(
                new SecurityEventErrorResponse("authentication_failed"),
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return null;
    }

    /// <summary>Returns the audit reason for rejecting <paramref name="authorization"/>, or <c>null</c> when it carries either configured credential.</summary>
    /// <param name="authorization">The <c>Authorization</c> header values.</param>
    /// <param name="ssf">The receiver's settings, holding the credentials in force.</param>
    public static string? Check(StringValues authorization, SsfOptions ssf)
    {
        ArgumentNullException.ThrowIfNull(ssf);

        // The scheme is case-insensitive (RFC 7235 section 2.1); the credential is not.
        if (authorization.Count != 1 || authorization[0] is not { } header || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AdminApiKeyFilter.MissingApiKey;
        }

        var presented = header["Bearer ".Length..].Trim();
        if (presented.Length == 0)
        {
            return AdminApiKeyFilter.MissingApiKey;
        }

        var presentedDigest = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        var matched = Matches(presentedDigest, ssf.BearerToken);

        // Both are always compared, so timing does not reveal which one matched.
        matched |= Matches(presentedDigest, ssf.PreviousBearerToken);
        return matched ? null : AdminApiKeyFilter.InvalidApiKey;
    }

    private static bool Matches(byte[] presentedDigest, string? configured)
    {
        if (configured is null)
        {
            return false;
        }

        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            presentedDigest,
            System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(configured)));
    }
}
