using System.Text.Json;
using System.Text.RegularExpressions;
using SubactId.Core.Validation;
using SubactId.Server.Contracts;
using SubactId.Storage.Ef;

namespace SubactId.Server.Hosting;

/// <summary>
/// Turns an unhandled fault into a problem document and logs it with the correlation id.
/// </summary>
/// <remarks>
/// <para>
/// The response body says nothing about the fault. Details go to the log only.
/// </para>
/// <para>
/// A request body the host refused keeps the host's 4xx status. A JSON body refused because one
/// member's value had the wrong type or format, or because the request has no such member, is
/// answered with a per-field error naming it. An
/// unreachable or overloaded database, as decided by <see cref="IStorageFaults"/>, is answered as
/// <c>503 temporarily_unavailable</c> with <c>Retry-After</c>. Anything else is a 500.
/// </para>
/// </remarks>
/// <param name="next">The rest of the pipeline.</param>
/// <param name="logger">Where the fault is written.</param>
public sealed partial class UnhandledFaultMiddleware(RequestDelegate next, ILogger<UnhandledFaultMiddleware> logger)
{
    /// <summary>
    /// How long a caller is told to wait when the database is unreachable. Long enough to cover
    /// a restart or failover.
    /// </summary>
    public static readonly TimeSpan StorageRetryAfter = TimeSpan.FromSeconds(5);

    /// <summary>Longest member name reported back in a per-field error.</summary>
    private const int MaxMemberLength = 64;

    /// <summary>Runs the rest of the pipeline, turning anything it throws into a problem document.</summary>
    /// <param name="context">The request.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            await next(context);
        }
        catch (BadHttpRequestException bad)
        {
            // Log the path only, never the query string, which can carry a token. The exception
            // details are logged, not returned.
            logger.LogWarning(bad, "Unreadable request body on {Method} {Path}.", Logged(context.Request.Method), Logged(context.Request.Path.Value));

            // A JSON body with a value of the wrong type or format for one member, or a member the
            // request does not have, is rejected per field, like any other invalid value (spec
            // section 2). The two are told apart only by the serializer's message, which is not
            // stable text, so one error covers both.
            if (MistypedMember(bad) is { } member)
            {
                if (ResponseReset.TryClear(context))
                {
                    NoStore(context);
                    await ValidationProblems.ToResult([new ValidationError(member, "is not a field of this request, or has the wrong type or format.")]).ExecuteAsync(context);
                }

                return;
            }

            // Keep the host's status only if it is a 4xx.
            var status = bad.StatusCode is >= 400 and <= 499 ? bad.StatusCode : StatusCodes.Status400BadRequest;
            await WriteProblemAsync(context, status, "The request body could not be read.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException && IsStorageUnavailable(context, exception))
        {
            logger.LogWarning(exception, "The database could not be reached answering {Method} {Path}.", Logged(context.Request.Method), Logged(context.Request.Path.Value));
            await TemporarilyUnavailable.WriteAsync(context, StorageRetryAfter, "The control plane's database is unavailable or too busy to answer. Retry after the interval in Retry-After.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "Unhandled fault answering {Method} {Path}.", Logged(context.Request.Method), Logged(context.Request.Path.Value));
            await WriteProblemAsync(context, StatusCodes.Status500InternalServerError, "The request could not be handled.");
        }
    }

    /// <summary>
    /// The top-level member of a JSON body whose value could not be converted, for example
    /// <c>max_task_ttl</c> for <c>"max_task_ttl": "30m"</c>. <c>null</c> when the body failed for
    /// any other reason, including JSON that is not well-formed, which names no member reliably.
    /// </summary>
    /// <param name="bad">The host's refusal to bind the body.</param>
    private static string? MistypedMember(BadHttpRequestException bad)
    {
        // A value that did not convert is a JsonException of its own, or wraps the conversion's
        // own failure. A syntax error wraps the reader's JsonException, and its path is only
        // where the reader stopped.
        if (bad.InnerException is not JsonException { Path: { } path } json || json.InnerException is JsonException || !path.StartsWith("$.", StringComparison.Ordinal))
        {
            return null;
        }

        var member = path[2..];
        var end = member.IndexOfAny(['.', '[']);
        member = end >= 0 ? member[..end] : member;
        return member.Length is > 0 and <= MaxMemberLength ? member : null;
    }

    /// <summary>
    /// A request value as the log carries it. Every control character, line breaks included, is
    /// replaced, so a crafted method or path cannot forge a log line or drive a terminal.
    /// </summary>
    /// <param name="value">The method or path as the client sent it.</param>
    private static string? Logged(string? value) => value is null ? null : ControlCharacters().Replace(value, "?");

    // \p{Cc} is what char.IsControl matches: the C0 and C1 controls, CR and LF among them.
    [GeneratedRegex(@"\p{Cc}", RegexOptions.CultureInvariant)]
    private static partial Regex ControlCharacters();

    private static bool IsStorageUnavailable(HttpContext context, Exception exception) =>
        context.RequestServices?.GetService<IStorageFaults>() is { } faults && faults.IsUnavailable(exception);

    /// <summary>
    /// Never cached. Clearing the response dropped what the endpoint had set, and the token,
    /// introspection, revocation and logout endpoints promise no-store on every answer.
    /// </summary>
    private static void NoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }

    private static async Task WriteProblemAsync(HttpContext context, int status, string title)
    {
        // A response that has already started is aborted instead.
        if (ResponseReset.TryClear(context))
        {
            NoStore(context);
            await Results.Problem(statusCode: status, title: title).ExecuteAsync(context);
        }
    }
}

/// <summary>Adds <see cref="UnhandledFaultMiddleware"/> to the pipeline.</summary>
public static class UnhandledFaultMiddlewareExtensions
{
    /// <summary>Answers an unhandled fault with a problem document that reveals no internals.</summary>
    /// <param name="app">The application.</param>
    public static IApplicationBuilder UseSubactIdUnhandledFaults(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseMiddleware<UnhandledFaultMiddleware>();
    }
}
