using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SubactId.Core.Scim;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;

namespace SubactId.Server.Scim;

/// <summary>
/// The SCIM 2.0 (RFC 7644) Users receiver, mapped only when a credential is configured. Supports
/// the Users resource only: no Groups, bulk, sorting or entity tags, and one filter shape.
/// <c>ServiceProviderConfig</c> reports this.
/// </summary>
public static class ScimEndpoints
{
    /// <summary>Route prefix of everything this receiver serves.</summary>
    public const string Prefix = "/scim";

    /// <summary>Route prefix of the version this receiver speaks.</summary>
    public const string VersionPrefix = "/scim/v2";

    /// <summary>Path of the Users collection.</summary>
    public const string UsersPath = VersionPrefix + "/Users";

    /// <summary>Path of the configuration document.</summary>
    public const string ServiceProviderConfigPath = VersionPrefix + "/ServiceProviderConfig";

    /// <summary>Registers the receiver's services, when it is configured.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The receiver's settings, or <c>null</c> when it is not configured.</param>
    public static IServiceCollection AddSubactIdScim(this IServiceCollection services, ScimOptions? options)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (options is null)
        {
            return services;
        }

        services.AddSingleton(options);
        services.AddScoped<ScimUserService>();

        // Shared with the other signal receivers. Whichever is configured registers it.
        services.TryAddScoped<Signals.SponsorSignalWriter>();
        return services;
    }

    /// <summary>Maps the receiver, when it is configured.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="options">The receiver's settings, or <c>null</c> when it is not configured.</param>
    public static void MapSubactIdScimEndpoints(this IEndpointRouteBuilder endpoints, ScimOptions? options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        if (options is null)
        {
            return;
        }

        var scim = endpoints.MapGroup(VersionPrefix).AddEndpointFilter<ScimBearerFilter>();

        scim.MapGet("/ServiceProviderConfig", (HttpContext http) =>
            ScimResults.Json(ScimConfiguration.Describe(ScimResults.Location(http, ServiceProviderConfigPath)), StatusCodes.Status200OK));

        var users = scim.MapGroup("/Users");

        users.MapGet("", async (HttpContext http, [AsParameters] ListScimUsersRequest request, ScimUserService service, CancellationToken cancellationToken) =>
        {
            if (!request.TryToFilter(out var filter))
            {
                return ScimResults.Error(StatusCodes.Status400BadRequest, ScimResults.InvalidFilter, "The filter is not one this receiver supports.");
            }

            var page = await service.ListAsync(filter!, cancellationToken);
            var resources = page.Users.Select(u => ScimUserResponse.From(u, ScimResults.UserLocation(http, u.Id))).ToList();
            return ScimResults.Json(ScimListResponse.From(page, filter!.StartIndex, resources), StatusCodes.Status200OK);
        });

        users.MapGet("/{id}", async (HttpContext http, string id, ScimUserService service, CancellationToken cancellationToken) =>
        {
            var (user, failure) = await service.GetAsync(id, cancellationToken);
            return user is null ? ScimResults.Failed(failure) : ScimResults.Resource(http, user, StatusCodes.Status200OK);
        });

        users.MapPost("", async (HttpContext http, ScimUserService service, CancellationToken cancellationToken) =>
        {
            if (await ScimResults.ReadAsync<ScimUserRequest>(http, cancellationToken) is not { } read)
            {
                return ScimResults.Unreadable(http);
            }

            var (user, failure) = await service.CreateAsync(read, cancellationToken);
            if (user is null)
            {
                return ScimResults.Failed(failure);
            }

            http.Response.Headers.Location = ScimResults.UserLocation(http, user.Id);
            return ScimResults.Resource(http, user, StatusCodes.Status201Created);
        });

        users.MapPut("/{id}", async (HttpContext http, string id, ScimUserService service, CancellationToken cancellationToken) =>
        {
            if (await ScimResults.ReadAsync<ScimUserRequest>(http, cancellationToken) is not { } read)
            {
                return ScimResults.Unreadable(http);
            }

            var (user, failure) = await service.ReplaceAsync(id, read, cancellationToken);
            return user is null ? ScimResults.Failed(failure) : ScimResults.Resource(http, user, StatusCodes.Status200OK);
        });

        users.MapPatch("/{id}", async (HttpContext http, string id, ScimUserService service, CancellationToken cancellationToken) =>
        {
            if (await ScimResults.ReadAsync<ScimPatchRequest>(http, cancellationToken) is not { } read)
            {
                return ScimResults.Unreadable(http);
            }

            var (user, failure) = await service.PatchAsync(id, read, cancellationToken);
            return user is null ? ScimResults.Failed(failure) : ScimResults.Resource(http, user, StatusCodes.Status200OK);
        });

        users.MapDelete("/{id}", async (string id, ScimUserService service, CancellationToken cancellationToken) =>
            await service.DeleteAsync(id, cancellationToken) is { } failure ? ScimResults.Failed(failure) : Results.NoContent());
    }
}

/// <summary>What this receiver supports, as the configuration document reports it.</summary>
public static class ScimConfiguration
{
    /// <summary>The document, addressed at <paramref name="location"/>.</summary>
    /// <param name="location">The document's own absolute URI.</param>
    public static ScimServiceProviderConfigResponse Describe(string location) => new(
        [ScimSchemas.ServiceProviderConfig],
        new ScimSupported(true),
        new ScimBulkSupported(false, 0, 0),
        new ScimFilterSupported(true, ListScimUsersRequest.MaxCount),
        // No password change: this control plane never handles passwords.
        new ScimSupported(false),
        new ScimSupported(false),
        new ScimSupported(false),
        [new ScimAuthenticationScheme("oauthbearertoken", "OAuth Bearer Token", "A bearer token issued to this provisioning client.", true)],
        new ScimDocumentMeta("ServiceProviderConfig", location));
}
