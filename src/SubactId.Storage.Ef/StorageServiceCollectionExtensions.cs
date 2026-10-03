using Microsoft.Extensions.DependencyInjection;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Core.Scim;
using SubactId.Core.Signals;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Storage.Ef.Repositories;

namespace SubactId.Storage.Ef;

/// <summary>Registers the repositories that are the same whichever database is behind them.</summary>
public static class StorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers every provider-neutral repository over <see cref="SubactIdDbContext"/>. A provider
    /// registers its own context, its <see cref="IStorageDialect"/>, the outbox claim, the expiry
    /// sweep and the revocation walk.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="deliverAudit">Whether audit records are queued in the outbox for an external sink.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddSharedStorage(this IServiceCollection services, bool deliverAudit)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton(new AuditOutboxSettings(deliverAudit));
        services.AddScoped<IAgentRepository, EfAgentRepository>();
        services.AddScoped<IAgentQuery, EfAgentQuery>();
        services.AddScoped<IRevocationFence, EfRevocationFence>();
        services.AddScoped<IAssertionReplayStore, EfAssertionReplayStore>();
        services.AddScoped<ITaskRepository, EfTaskRepository>();
        services.AddScoped<ISponsorRepository, EfSponsorRepository>();
        services.AddScoped<ISignalReplayStore, EfSignalReplayStore>();
        services.AddScoped<IScimUserRepository, EfScimUserRepository>();
        services.AddScoped<ITaskGrantRepository, EfTaskGrantRepository>();
        services.AddScoped<ITaskRetention, EfTaskRetention>();
        services.AddScoped<IUnitOfWork, EfUnitOfWork>();
        services.AddScoped<IAuditWriter, EfAuditWriter>();
        services.AddScoped<IRevocationRepository, EfRevocationRepository>();
        services.AddScoped<IAuditLedgerReader, EfAuditLedgerReader>();
        services.AddScoped<IAuditQuery, EfAuditQuery>();
        services.AddScoped<IAuditCheckpointQuery, EfAuditCheckpointQuery>();
        services.AddScoped<IAuditCheckpointRepository, EfAuditCheckpointRepository>();
        services.AddScoped<IAuditArchiveRepository, EfAuditArchiveRepository>();

        return services;
    }
}
