using SubactId.Server.Contracts;
using SubactId.Server.Revocation;
using SubactId.Tokens.Grants;

namespace SubactId.Server.Tokens;

/// <summary><c>POST /oauth2/token</c>: the token-exchange grant of spec section 3 and the refresh grant of section 5. Responses are never cacheable.</summary>
public static class TokenEndpoints
{
    /// <summary>Route of the token endpoint.</summary>
    public const string Path = "/oauth2/token";

    /// <summary>Registers the exchange and refresh services.</summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSubactIdTokenEndpoint(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<TokenAudit>();
        services.AddSingleton<SignOutRetentionCheck>();
        services.AddScoped<TokenExchangeService>();
        services.AddScoped<TaskGrantRedeemer>();
        services.AddScoped<TokenRefreshService>();
        return services;
    }

    /// <summary>Maps the token endpoint.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdTokenEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(Path, TokenAsync);
    }

    private static async Task<IResult> TokenAsync(HttpContext http, TokenExchangeService exchange, TokenRefreshService refresh, TokenAudit denials, CancellationToken cancellationToken)
    {
        var (form, error) = await FormEndpoints.ReadFormAsync(http, denials, cancellationToken);
        if (form is null)
        {
            return error!;
        }

        var grantType = form["grant_type"];
        if (grantType.Count > 1)
        {
            return ToResult(await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, "grant_type must not be repeated.", OAuthErrorResponse.InvalidRequest));
        }

        if (grantType.Count == 1 && grantType[0] == ExchangeTokenRequest.TokenExchangeGrantType)
        {
            var request = ExchangeTokenRequest.FromForm(form, out var formErrors);
            return ToResult(await exchange.ExchangeAsync(request, formErrors, cancellationToken));
        }

        if (grantType.Count == 1 && grantType[0] == RefreshTokenRequest.RefreshTokenGrantType)
        {
            var request = RefreshTokenRequest.FromForm(form, out var formErrors);
            return ToResult(await refresh.RefreshAsync(request, formErrors, cancellationToken));
        }

        return grantType.Count == 0 || string.IsNullOrEmpty(grantType[0])
            ? ToResult(await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, "grant_type is required.", OAuthErrorResponse.InvalidRequest))
            : ToResult(await denials.DenyAsync(OAuthErrorResponse.UnsupportedGrantType, $"Only {ExchangeTokenRequest.TokenExchangeGrantType} and {RefreshTokenRequest.RefreshTokenGrantType} are supported.", OAuthErrorResponse.UnsupportedGrantType));
    }

    private static IResult ToResult(TokenOutcome outcome) =>
        outcome.Response is { } response ? Results.Json(response, statusCode: StatusCodes.Status200OK) : outcome.Error!.ToResult();
}
