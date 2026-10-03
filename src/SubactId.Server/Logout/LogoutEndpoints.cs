using Microsoft.Extensions.DependencyInjection;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Tokens;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Logout;

/// <summary>
/// The back-channel logout receiver, mapped only when an audience is configured.
/// </summary>
public static class LogoutEndpoints
{
    /// <summary>Path of the back-channel logout receiver.</summary>
    public const string LogoutPath = "/backchannel-logout";

    /// <summary>The form field carrying the logout token, per Back-Channel Logout 1.0 section 2.5.</summary>
    public const string LogoutTokenField = "logout_token";

    /// <summary>Registers the receiver, when it is configured.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">Validated upstream settings.</param>
    public static IServiceCollection AddSubactIdLogout(this IServiceCollection services, UpstreamIdpOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        if (options.BackchannelLogout is not { } logout)
        {
            return services;
        }

        services.AddSingleton(provider => new LogoutTokenValidator(
            provider.GetRequiredService<IUpstreamKeys>(),
            logout.Audience,
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddScoped<LogoutService>();
        return services;
    }

    /// <summary>Maps the receiver, when it is configured.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="options">Validated upstream settings.</param>
    public static void MapSubactIdLogoutEndpoints(this IEndpointRouteBuilder endpoints, UpstreamIdpOptions options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(options);

        if (options.BackchannelLogout is null)
        {
            return;
        }

        endpoints.MapPost(LogoutPath, async (HttpRequest request, LogoutService logout, CancellationToken cancellationToken) =>
        {
            // Back-Channel Logout 1.0 section 2.8: never cached, whatever the outcome.
            request.HttpContext.Response.Headers.CacheControl = "no-store";

            // A body that is not a form, or a form over the limits (FormEndpoints.MaxBodyBytes among
            // them), carries no token. It is refused and recorded like any other logout that does
            // not validate.
            if (!request.HasFormContentType)
            {
                return Answer(await logout.RefuseUnreadableAsync());
            }

            if (await FormEndpoints.TryReadAsync(request, cancellationToken) is not { } form)
            {
                return Answer(await logout.RefuseUnreadableAsync());
            }

            return Answer(await logout.ReceiveAsync(form[LogoutTokenField], cancellationToken));
        });
    }

    /// <summary>
    /// The response for <paramref name="rejection"/>: an empty <c>200</c> when accepted, a
    /// retryable <c>503</c> when the provider's keys could not be fetched, and <c>400</c> otherwise.
    /// </summary>
    /// <param name="rejection">Why the token was refused, or <c>null</c> when it was accepted.</param>
    public static IResult Answer(LogoutRejection? rejection) => rejection switch
    {
        null => Results.Ok(),
        LogoutRejection.KeysUnavailable => new OAuthErrorResponse(OAuthErrorResponse.TemporarilyUnavailable, "The identity provider's keys could not be fetched; retry later.").ToResult(),
        _ => Refused(),
    };

    /// <summary>
    /// The single 400 refusal (section 2.8) for any invalid token. Which check failed is recorded
    /// in the ledger, not returned.
    /// </summary>
    private static IResult Refused() => Results.BadRequest(
        new OAuthErrorResponse(OAuthErrorResponse.InvalidRequest, "The logout token is missing or not valid."));
}
