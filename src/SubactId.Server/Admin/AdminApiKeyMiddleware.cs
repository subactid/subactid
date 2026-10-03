using SubactId.Server.Audit;

namespace SubactId.Server.Admin;

/// <summary>
/// Checks the admin API key on every request under <c>/admin</c> and <c>/audit</c> before routing,
/// so no request body is read for a caller without a valid key. Every refusal is a 401 with an
/// <c>admin.denied</c> audit record.
/// </summary>
/// <param name="next">The rest of the pipeline.</param>
public sealed class AdminApiKeyMiddleware(RequestDelegate next)
{
    /// <summary>Answers the refusal, or passes the request on.</summary>
    /// <param name="context">The request.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (await AdminApiKeyFilter.AuthenticateAsync(context) is { } refusal)
        {
            await refusal.ExecuteAsync(context);
            return;
        }

        await next(context);
    }
}

/// <summary>Adds <see cref="AdminApiKeyMiddleware"/> to the pipeline for the operator-facing paths.</summary>
public static class AdminApiKeyMiddlewareExtensions
{
    /// <summary>Checks the admin key on <c>/admin</c> and <c>/audit</c> requests before their body is read.</summary>
    /// <param name="app">The application.</param>
    public static IApplicationBuilder UseSubactIdAdminApiKey(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseWhen(IsOperatorRequest, branch => branch.UseMiddleware<AdminApiKeyMiddleware>());
    }

    /// <summary>Whether <paramref name="http"/> is for a path under <c>/admin</c> or <c>/audit</c>, by segment.</summary>
    /// <param name="http">The request.</param>
    public static bool IsOperatorRequest(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        return http.Request.Path.StartsWithSegments(AdminEndpoints.Prefix) || http.Request.Path.StartsWithSegments(AuditEndpoints.Path);
    }
}
