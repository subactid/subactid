using Serilog.Context;

namespace SubactId.Server.Logging;

/// <summary>
/// Gives every request a correlation id, echoes it in the response, and attaches it to the
/// request's log events. A caller-supplied id is used only if it is short and made of safe
/// characters, so clients cannot inject text into the logs.
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    /// <summary>Request and response header carrying the correlation id.</summary>
    public const string HeaderName = "X-Correlation-Id";

    /// <summary>Name of the log property attached to each event.</summary>
    public const string LogPropertyName = "CorrelationId";

    private const int MaxLength = 64;

    /// <summary>Processes the request.</summary>
    /// <param name="context">The HTTP context.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var correlationId = ResolveCorrelationId(context.Request);
        context.TraceIdentifier = correlationId;
        context.Response.Headers[HeaderName] = correlationId;

        using (LogContext.PushProperty(LogPropertyName, correlationId))
        {
            await next(context);
        }
    }

    /// <summary>Returns the caller's id when it is acceptable, otherwise a freshly generated one.</summary>
    /// <param name="request">The incoming request.</param>
    public static string ResolveCorrelationId(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Headers.TryGetValue(HeaderName, out var values)
            && values.Count == 1
            && values[0] is { } supplied
            && IsAcceptable(supplied))
        {
            return supplied;
        }

        return Guid.NewGuid().ToString("N");
    }

    private static bool IsAcceptable(string value) =>
        value.Length is > 0 and <= MaxLength
        && value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
}
