using Microsoft.AspNetCore.Http.Features;
using Microsoft.Net.Http.Headers;
using SubactId.Server.Contracts;

namespace SubactId.Server.Tokens;

/// <summary>Shared form handling for the OAuth endpoints: no-store responses and a consistent form read.</summary>
public static class FormEndpoints
{
    /// <summary>The only request media type accepted (RFC 6749 section 4.5).</summary>
    public const string FormMediaType = "application/x-www-form-urlencoded";

    /// <summary>
    /// Largest form body read on the token, introspection, revocation and back-channel logout
    /// endpoints: 64 KiB. The largest legitimate one is an exchange, whose subject token is at most
    /// 16 KiB and actor token at most 8 KiB, with its other values bounded too, so this is well
    /// above anything real and far below the host's own limit.
    /// </summary>
    public const long MaxBodyBytes = 64 * 1024;

    /// <summary>
    /// Marks the response uncacheable and reads the form body. Only the RFC 6749 media type is
    /// accepted. Returns the form, or the denial to answer with.
    /// </summary>
    /// <param name="http">The request.</param>
    /// <param name="denials">Where a refusal is recorded.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<(IFormCollection? Form, IResult? Error)> ReadFormAsync(HttpContext http, TokenAudit denials, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(denials);

        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Pragma = "no-cache";

        if (!MediaTypeHeaderValue.TryParse(http.Request.ContentType, out var contentType) || !contentType.MediaType.Equals(FormMediaType, StringComparison.OrdinalIgnoreCase))
        {
            return (null, (await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, $"The body must be {FormMediaType}.", OAuthErrorResponse.InvalidRequest)).Error!.ToResult());
        }

        if (await TryReadAsync(http.Request, cancellationToken) is { } form)
        {
            return (form, null);
        }

        return (null, (await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, "The form body is too large or malformed.", OAuthErrorResponse.InvalidRequest)).Error!.ToResult());
    }

    /// <summary>
    /// Holds the body of <paramref name="http"/> to <see cref="MaxBodyBytes"/>, before anything
    /// reads it. The host then refuses a longer body as it arrives, chunked or not. Returns
    /// <c>false</c> when the declared length is already over the limit, so nothing need be read.
    /// </summary>
    /// <param name="http">The request.</param>
    public static bool LimitBody(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
        {
            limit.MaxRequestBodySize = MaxBodyBytes;
        }

        return http.Request.ContentLength is not > MaxBodyBytes;
    }

    /// <summary>
    /// Reads the form body, held to <see cref="MaxBodyBytes"/>. Returns <c>null</c> for a body over
    /// that limit or over the form reader's own, or one that is not a well-formed form.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<IFormCollection?> TryReadAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!LimitBody(request.HttpContext))
        {
            return null;
        }

        try
        {
            return await request.ReadFormAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is InvalidDataException or BadHttpRequestException)
        {
            // A BadHttpRequestException is the host refusing a body over the limit (413) or one
            // that ended early.
            return null;
        }
    }
}
