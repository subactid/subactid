using SubactId.Server.Contracts;
using SubactId.Server.Tokens;

namespace SubactId.Server.Revocation;

/// <summary><c>POST /oauth2/revoke</c>, RFC 7009. Responses are never cacheable.</summary>
public static class RevocationEndpoints
{
    /// <summary>Route of the revocation endpoint.</summary>
    public const string Path = "/oauth2/revoke";

    /// <summary>Registers the revocation service.</summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSubactIdRevocation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<RevocationService>();
        return services;
    }

    /// <summary>Maps the revocation endpoint.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdRevocationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(Path, RevokeAsync);
    }

    private static async Task<IResult> RevokeAsync(HttpContext http, RevocationService service, TokenAudit denials, CancellationToken cancellationToken)
    {
        var (form, error) = await FormEndpoints.ReadFormAsync(http, denials, cancellationToken);
        if (form is null)
        {
            return error!;
        }

        var request = RevokeTokenRequest.FromForm(form, out var formErrors);
        var refusal = await service.RevokeForClientAsync(request, formErrors, cancellationToken);
        return refusal is null ? Results.Ok() : refusal.ToResult();
    }
}
