using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Primitives;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;

namespace SubactId.Server.Admin;

/// <summary>
/// Authenticates admin requests with the configured API key, presented as
/// <c>Authorization: Bearer &lt;key&gt;</c>. Compared in constant time over SHA-256 digests.
/// Every failure writes an <c>admin.denied</c> audit record. With no key configured, the admin
/// API answers 503.
/// <para>
/// <see cref="AdminApiKeyMiddleware"/> runs the same check before routing. This filter repeats
/// it so an admin endpoint mapped without the middleware is still protected.
/// </para>
/// </summary>
public sealed class AdminApiKeyFilter : IEndpointFilter
{
    /// <summary>Audit reason when no usable bearer credential was presented.</summary>
    public const string MissingApiKey = "missing_api_key";

    /// <summary>Audit reason when the presented key does not match.</summary>
    public const string InvalidApiKey = "invalid_api_key";

    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        return await AuthenticateAsync(context.HttpContext) ?? await next(context);
    }

    /// <summary>
    /// The refusal for <paramref name="http"/>, or <c>null</c> when it carries the configured key.
    /// 503 when no key is configured, otherwise 401 after writing an <c>admin.denied</c> record.
    /// </summary>
    /// <param name="http">The request.</param>
    public static async Task<IResult?> AuthenticateAsync(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        var options = http.RequestServices.GetRequiredService<SubactIdOptions>();
        if (options.Admin.ApiKey is not { } configured)
        {
            return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "The admin API is not configured.");
        }

        if (Check(http.Request.Headers.Authorization, configured) is { } reason)
        {
            var clock = http.RequestServices.GetRequiredService<TimeProvider>();
            var record = new AuditEvent(clock.GetUtcNow(), AuditEvents.AdminDenied, Decision: AuditDecision.Deny, Reason: reason);
            await http.RequestServices.GetRequiredService<DenialAggregator>()
                .RecordAsync(record, http.RequestServices.GetRequiredService<IAuditWriter>());

            http.Response.Headers.WWWAuthenticate = "Bearer realm=\"subactid-admin\"";
            return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Admin authentication failed.");
        }

        return null;
    }

    /// <summary>Returns the audit reason for rejecting <paramref name="authorization"/>, or <c>null</c> when it carries the configured key.</summary>
    /// <param name="authorization">The <c>Authorization</c> header values.</param>
    /// <param name="configured">The configured key.</param>
    public static string? Check(StringValues authorization, string configured)
    {
        ArgumentException.ThrowIfNullOrEmpty(configured);

        // The scheme is case-insensitive (RFC 7235 section 2.1). The key is not.
        if (authorization.Count != 1 || authorization[0] is not { } header || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return MissingApiKey;
        }

        var presented = header["Bearer ".Length..].Trim();
        if (presented.Length == 0)
        {
            return MissingApiKey;
        }

        var presentedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        var configuredDigest = SHA256.HashData(Encoding.UTF8.GetBytes(configured));
        return CryptographicOperations.FixedTimeEquals(presentedDigest, configuredDigest) ? null : InvalidApiKey;
    }
}
