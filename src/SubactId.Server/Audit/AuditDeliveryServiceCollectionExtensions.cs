using System.Net.Http.Headers;
using SubactId.Core.Audit;
using SubactId.Server.Configuration;

namespace SubactId.Server.Audit;

/// <summary>Registers delivery of audit records to an external sink.</summary>
public static class AuditDeliveryServiceCollectionExtensions
{
    /// <summary>
    /// Registers the HTTP sink and the outbox drain when a sink URL is configured. Without one,
    /// nothing is registered and nothing is queued. The client times out after 10 seconds.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">Validated audit settings.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddSubactIdAuditDelivery(this IServiceCollection services, AuditOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.DeliveryEnabled)
        {
            return services;
        }

        services.AddHttpClient(HttpAuditSink.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        });
        services.AddSingleton<IAuditSink>(provider => new HttpAuditSink(provider.GetRequiredService<IHttpClientFactory>(), options));
        services.AddSingleton(provider => new AuditOutboxDrain(
            provider.GetRequiredService<IServiceScopeFactory>(),
            options,
            provider.GetService<TimeProvider>() ?? TimeProvider.System,
            provider.GetRequiredService<ILogger<AuditOutboxDrain>>()));
        services.AddHostedService(provider => provider.GetRequiredService<AuditOutboxDrain>());

        return services;
    }
}
