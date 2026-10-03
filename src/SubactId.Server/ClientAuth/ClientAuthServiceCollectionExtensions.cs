using System.Net.Http.Headers;
using SubactId.Core.Agents;
using SubactId.Server.Http;
using SubactId.Tokens.ClientAuth;

namespace SubactId.Server.ClientAuth;

/// <summary>Registers <c>private_key_jwt</c> client authentication.</summary>
public static class ClientAuthServiceCollectionExtensions
{
    /// <summary>Name of the HTTP client used to fetch agents' JWKS documents.</summary>
    public const string HttpClientName = "agent-jwks";

    /// <summary>
    /// Registers one process-wide <see cref="AgentKeyCache"/> and <see cref="ReplayPurgeGate"/>, and a
    /// scoped <see cref="ClientAssertionAuthenticator"/> bound to this control plane's issuer.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="issuer">This control plane's issuer URL.</param>
    /// <param name="blockPrivateNetworks">Whether a fetch of an agent's <c>jwks_uri</c> that resolves only to addresses that are not public is refused.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddClientAuthentication(this IServiceCollection services, Uri issuer, bool blockPrivateNetworks = false)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(issuer);

        services.AddHttpClient(HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
            // An agent's jwks_uri is fetched here. Never follow a redirect, and refuse a private
            // destination when the operator has asked for it.
            .ConfigurePrimaryHttpMessageHandler(() => HardenedHttpHandler.Create(blockPrivateNetworks));
        services.AddSingleton(provider => new AgentKeyCache(
            () => provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddSingleton<IAgentKeys>(provider => provider.GetRequiredService<AgentKeyCache>());
        services.AddSingleton<ReplayPurgeGate>();
        services.AddScoped(provider => new ClientAssertionAuthenticator(
            provider.GetRequiredService<IAgentRepository>(),
            provider.GetRequiredService<IAgentKeys>(),
            provider.GetRequiredService<IAssertionReplayStore>(),
            issuer,
            provider.GetService<TimeProvider>() ?? TimeProvider.System,
            provider.GetRequiredService<ReplayPurgeGate>()));

        return services;
    }
}
