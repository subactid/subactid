using System.Globalization;
using SubactId.Server.Contracts;
using SubactId.Server.Logging;
using SubactId.Server.Scim;

namespace SubactId.Server.Hosting;

/// <summary>
/// Writes the server's retryable refusals: <c>503</c> with the <c>temporarily_unavailable</c>
/// OAuth error, and <c>429</c> with <c>slow_down</c> (spec section 8), each with <c>Retry-After</c>
/// and <c>no-store</c>. The same on every path except <c>/scim</c>, which uses the RFC 7644 error
/// shape.
/// </summary>
public static class TemporarilyUnavailable
{
    /// <summary>Answers <paramref name="context"/> with a retryable 503, unless an answer has already started.</summary>
    /// <param name="context">The request.</param>
    /// <param name="retryAfter">How long the caller should wait before trying again.</param>
    /// <param name="description">The <c>error_description</c>; names nothing about the server's internals.</param>
    /// <returns>Whether the answer was written. A response that had already started is aborted instead.</returns>
    public static Task<bool> WriteAsync(HttpContext context, TimeSpan retryAfter, string description) =>
        WriteRefusalAsync(context, StatusCodes.Status503ServiceUnavailable, OAuthErrorResponse.TemporarilyUnavailable, retryAfter, description);

    /// <summary>
    /// Answers <paramref name="context"/> with a retryable admission refusal: <paramref name="status"/>,
    /// <c>Retry-After</c> and <c>no-store</c>, and <paramref name="error"/> as an OAuth error body,
    /// or the RFC 7644 error shape on <c>/scim</c>. Unless an answer has already started.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <param name="status">The HTTP status, <c>503</c> or <c>429</c>.</param>
    /// <param name="error">The OAuth error code.</param>
    /// <param name="retryAfter">How long the caller should wait before trying again.</param>
    /// <param name="description">The <c>error_description</c>; names nothing about the server's internals.</param>
    /// <returns>Whether the answer was written. A response that had already started is aborted instead.</returns>
    public static async Task<bool> WriteRefusalAsync(HttpContext context, int status, string error, TimeSpan retryAfter, string description)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!ResponseReset.TryClear(context))
        {
            return false;
        }

        context.Response.StatusCode = status;
        context.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        // Never cached. This can be written before the endpoints that set no-store themselves run.
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";

        if (context.Request.Path.StartsWithSegments(ScimEndpoints.Prefix))
        {
            await ScimResults.Error(status, null, description).ExecuteAsync(context);
            return true;
        }

        await context.Response.WriteAsJsonAsync(new OAuthErrorResponse(error, description), CancellationToken.None);
        return true;
    }
}

/// <summary>Resets a response while keeping its correlation id.</summary>
internal static class ResponseReset
{
    /// <summary>
    /// Clears the response so a different answer can be written, then restores the correlation id
    /// header. If the response has already started, aborts the connection and returns <c>false</c>.
    /// </summary>
    /// <param name="context">The request.</param>
    public static bool TryClear(HttpContext context)
    {
        if (context.Response.HasStarted)
        {
            context.Abort();
            return false;
        }

        var correlationId = context.Response.Headers[CorrelationIdMiddleware.HeaderName];
        context.Response.Clear();
        if (correlationId.Count > 0)
        {
            context.Response.Headers[CorrelationIdMiddleware.HeaderName] = correlationId;
        }

        return true;
    }
}
