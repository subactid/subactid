using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using SubactId.Core.Audit;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;

namespace SubactId.Server.Scim;

/// <summary>
/// Authenticates a provisioning client with the configured SCIM credential, presented as
/// <c>Authorization: Bearer &lt;token&gt;</c>. Compared in constant time over SHA-256 digests.
/// Every failure writes a <c>scim.denied</c> record.
///
/// <para>
/// A current and a previous value are both accepted, so the credential can be rotated without
/// an outage.
/// </para>
/// <para>
/// This credential is not the admin key and grants none of its authority. It reaches only the
/// SCIM routes.
/// </para>
/// <para>
/// Checked twice: in <see cref="ScimBearerMiddleware"/> before routing reads the body, and again
/// as an endpoint filter in case a route is mapped without the middleware.
/// </para>
/// </summary>
public sealed class ScimBearerFilter : IEndpointFilter
{
    /// <summary>Largest request body the receiver reads, in bytes. Enough for one user.</summary>
    public const long MaxRequestBodyBytes = 64 * 1024;

    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        return await AuthenticateAsync(context.HttpContext) ?? await next(context);
    }

    /// <summary>
    /// The refusal to answer <paramref name="http"/> with, or <c>null</c> when it carries a
    /// configured credential. Without a configured SCIM credential the answer is 404, as for any
    /// unknown path.
    /// </summary>
    /// <param name="http">The request.</param>
    public static async Task<IResult?> AuthenticateAsync(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        var options = http.RequestServices.GetRequiredService<SubactIdOptions>();
        if (options.Scim is not { } scim)
        {
            return ScimResults.Error(StatusCodes.Status404NotFound, null, "No such resource.");
        }

        // Let the host refuse an oversized body before it is read.
        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
        {
            limit.MaxRequestBodySize = MaxRequestBodyBytes;
        }

        if (Check(http.Request.Headers.Authorization, scim) is { } reason)
        {
            var clock = http.RequestServices.GetRequiredService<TimeProvider>();
            var record = new AuditEvent(clock.GetUtcNow(), AuditEvents.ScimDenied, Decision: AuditDecision.Deny, Reason: reason);
            await http.RequestServices.GetRequiredService<DenialAggregator>()
                .RecordAsync(record, http.RequestServices.GetRequiredService<IAuditWriter>());

            http.Response.Headers.WWWAuthenticate = "Bearer realm=\"subactid-scim\"";
            return ScimResults.Error(StatusCodes.Status401Unauthorized, null, "Authentication failed.");
        }

        return null;
    }

    /// <summary>
    /// Returns the audit reason for rejecting <paramref name="authorization"/>, or <c>null</c>
    /// when it carries either configured credential.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> header values.</param>
    /// <param name="scim">The receiver's settings, holding the credentials in force.</param>
    public static string? Check(StringValues authorization, ScimOptions scim)
    {
        ArgumentNullException.ThrowIfNull(scim);

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

        var presentedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        var matched = Matches(presentedDigest, scim.BearerToken);

        // Both are always compared, so timing does not reveal which one matched.
        matched |= Matches(presentedDigest, scim.PreviousBearerToken);
        return matched ? null : AdminApiKeyFilter.InvalidApiKey;
    }

    private static bool Matches(byte[] presentedDigest, string? configured)
    {
        if (configured is null)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(presentedDigest, SHA256.HashData(Encoding.UTF8.GetBytes(configured)));
    }
}

/// <summary>
/// Checks the SCIM credential on every request under <c>/scim</c> before routing, since endpoint
/// parameters, including a JSON body, are bound before any endpoint filter runs.
/// </summary>
/// <param name="next">The rest of the pipeline.</param>
public sealed class ScimBearerMiddleware(RequestDelegate next)
{
    /// <summary>Answers the refusal, or lets the request through to the endpoint and its own filter.</summary>
    /// <param name="context">The request.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (await ScimBearerFilter.AuthenticateAsync(context) is { } refusal)
        {
            await refusal.ExecuteAsync(context);
            return;
        }

        await next(context);
    }
}

/// <summary>Adds <see cref="ScimBearerMiddleware"/> to the pipeline for the SCIM routes.</summary>
public static class ScimBearerMiddlewareExtensions
{
    /// <summary>
    /// Checks the SCIM credential on <c>/scim</c> requests before anything about them is read.
    /// Registered only when the receiver is configured, so unconfigured deployments answer 404.
    /// </summary>
    /// <param name="app">The application.</param>
    /// <param name="options">The receiver's settings, or <c>null</c> when it is not configured.</param>
    public static IApplicationBuilder UseSubactIdScimBearer(this IApplicationBuilder app, ScimOptions? options)
    {
        ArgumentNullException.ThrowIfNull(app);

        return options is null ? app : app.UseWhen(IsScimRequest, branch => branch.UseMiddleware<ScimBearerMiddleware>());
    }

    /// <summary>Whether <paramref name="http"/> is for the SCIM receiver: a path under <c>/scim</c>, by segment.</summary>
    /// <param name="http">The request.</param>
    public static bool IsScimRequest(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        return http.Request.Path.StartsWithSegments(ScimEndpoints.Prefix);
    }
}
