using SubactId.Server.Contracts;
using SubactId.Server.Tokens;

namespace SubactId.Server.Introspection;

/// <summary><c>POST /oauth2/introspect</c>, RFC 7662. Responses are never cacheable.</summary>
public static class IntrospectionEndpoints
{
    /// <summary>Route of the introspection endpoint.</summary>
    public const string Path = "/oauth2/introspect";

    /// <summary>Registers the introspection service.</summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSubactIdIntrospection(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<IntrospectionService>();
        return services;
    }

    /// <summary>Maps the introspection endpoint.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdIntrospectionEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(Path, IntrospectAsync);
    }

    private static async Task<IResult> IntrospectAsync(HttpContext http, IntrospectionService service, TokenAudit denials, CancellationToken cancellationToken)
    {
        var (form, error) = await FormEndpoints.ReadFormAsync(http, denials, cancellationToken);
        if (form is null)
        {
            return error!;
        }

        var request = IntrospectTokenRequest.FromForm(form, out var formErrors);
        var outcome = await service.IntrospectAsync(request, formErrors, cancellationToken);
        return outcome.Response is { } response ? Results.Json(response, statusCode: StatusCodes.Status200OK) : outcome.Error!.ToResult();
    }
}
