using System.Net.Http.Headers;
using SubactId.Core.Sponsors;
using SubactId.Server.Configuration;
using SubactId.Server.Http;
using SubactId.Server.Tokens;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Upstream;

/// <summary>Registers upstream token validation.</summary>
public static class UpstreamIdpServiceCollectionExtensions
{
    /// <summary>Name of the HTTP client used to fetch upstream discovery and JWKS.</summary>
    public const string HttpClientName = "upstream-idp";

    /// <summary>
    /// Registers a single <see cref="UpstreamKeyCache"/> for the configured identity provider, the
    /// <see cref="UpstreamKeyRefresher"/> that keeps it warm, the
    /// <see cref="UpstreamTokenValidator"/> that uses it, and the <see cref="SponsorGate"/> used
    /// by both token grants. The HTTP client times out after 10 seconds.
    ///
    /// An <see cref="ISponsorStatusSource"/> is registered only under
    /// <see cref="SponsorCheckMode.Poll"/>. Under <see cref="SponsorCheckMode.Signals"/> nothing
    /// calls the identity provider for sponsor status.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">Validated upstream settings.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddUpstreamIdp(this IServiceCollection services, UpstreamIdpOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddHttpClient(HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
            // Discovery, JWKS and the sponsor-check admin API are fetched here. The identity
            // provider is operator-configured and may be internal, so private destinations are not
            // refused; redirects still are, so the configured URL is the host that answers.
            .ConfigurePrimaryHttpMessageHandler(() => HardenedHttpHandler.Create(blockPrivateNetworks: false));
        services.AddSingleton(provider => new UpstreamKeyCache(
            () => provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
            options.MetadataUrl,
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddSingleton<IUpstreamKeys>(provider => provider.GetRequiredService<UpstreamKeyCache>());

        // Refreshes the cache on a timer. Built by hand so a TimeProvider stays optional.
        services.AddHostedService(provider => new UpstreamKeyRefresher(
            provider.GetRequiredService<UpstreamKeyCache>(),
            provider.GetService<TimeProvider>() ?? TimeProvider.System,
            provider.GetRequiredService<ILogger<UpstreamKeyRefresher>>()));
        services.AddSingleton(provider => new UpstreamTokenValidator(
            provider.GetRequiredService<IUpstreamKeys>(),
            options.Audience,
            provider.GetService<TimeProvider>() ?? TimeProvider.System,
            options.SubjectTokenTypes));
        if (options.SponsorCheckMode == SponsorCheckMode.Poll)
        {
            // Poll mode without its settings fails here, at startup.
            var sponsorCheck = options.SponsorCheck ?? throw new ArgumentException("Poll mode requires the sponsor check settings.", nameof(options));
            services.AddSingleton<ISponsorStatusSource>(provider =>
            {
                var clock = provider.GetService<TimeProvider>() ?? TimeProvider.System;
                var source = new KeycloakSponsorStatusSource(
                    () => provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
                    sponsorCheck.UsersUrl,
                    sponsorCheck.TokenUrl,
                    sponsorCheck.ClientId,
                    provider.GetRequiredService<SigningKeySet>(),
                    clock);
                // The circuit sits under the cache, so cached answers are still served while it is open.
                return new SponsorStatusCache(new SponsorStatusCircuit(source, clock), sponsorCheck.CacheTtl, clock);
            });
        }

        services.AddScoped(provider => new SponsorGate(
            provider.GetRequiredService<ISponsorRepository>(),
            provider.GetService<ISponsorStatusSource>()));

        return services;
    }
}
