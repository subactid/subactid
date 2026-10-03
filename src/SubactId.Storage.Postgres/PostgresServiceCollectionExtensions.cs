using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres.Repositories;

namespace SubactId.Storage.Postgres;

/// <summary>Registers the Postgres storage services.</summary>
public static class PostgresServiceCollectionExtensions
{
    /// <summary>
    /// Registers one pooled <see cref="NpgsqlDataSource"/>, an <see cref="SubactIdDbContext"/> over it,
    /// the shared repositories and the Postgres-specific ones. Migrations are never applied here.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="connectionString">The Postgres connection string. Treated as a secret.</param>
    /// <param name="deliverAudit">Whether audit records are queued in the outbox for an external sink.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddPostgresStorage(this IServiceCollection services, string connectionString, bool deliverAudit = false)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        connectionString = PostgresConnectionString.WithDefaults(connectionString);
        services.AddSingleton<IStorageDialect, PostgresDialect>();
        services.AddSingleton(_ => new NpgsqlDataSourceBuilder(connectionString).Build());
        services.AddDbContext<SubactIdDbContext>((provider, options) =>
            options.UseNpgsql(provider.GetRequiredService<NpgsqlDataSource>(), npgsql => npgsql.MigrationsAssembly(MigrationsAssembly)));

        services.AddSharedStorage(deliverAudit);
        services.AddScoped<ITaskExpirySweep, PostgresTaskExpirySweep>();
        services.AddScoped<ITaskRevocation, PostgresTaskRevocation>();
        services.AddScoped<IAuditOutboxQueue, PostgresAuditOutboxQueue>();
        services.AddSingleton<IAuditLedgerPartitions, PostgresAuditLedgerPartitions>();
        services.AddSingleton<IAuditLedgerArchive, PostgresAuditLedgerArchive>();
        services.AddSingleton<IStorageFaults, PostgresFaults>();

        // Readiness has its own pool, so a busy request pool cannot fail the probe (see StorageReadiness).
        services.AddKeyedSingleton<NpgsqlDataSource>(StorageReadiness.ServiceKey, (_, _) => ReadinessDataSource(connectionString));
        services.AddKeyedSingleton<IAuditLedgerPartitions>(
            StorageReadiness.ServiceKey,
            (provider, key) => new PostgresAuditLedgerPartitions(provider.GetRequiredKeyedService<NpgsqlDataSource>(key)));
        services.AddSingleton<IStorageHealthCheck>(
            provider => new PostgresHealthCheck(provider.GetRequiredKeyedService<NpgsqlDataSource>(StorageReadiness.ServiceKey)));

        return services;
    }

    /// <summary>A pool of <see cref="StorageReadiness.PoolSize"/> connections for readiness alone, with the same credentials as the request pool.</summary>
    /// <param name="connectionString">The configured connection string.</param>
    internal static NpgsqlDataSource ReadinessDataSource(string connectionString)
    {
        var builder = new NpgsqlDataSourceBuilder(PostgresConnectionString.WithDefaults(connectionString));
        builder.ConnectionStringBuilder.MaxPoolSize = StorageReadiness.PoolSize;
        builder.ConnectionStringBuilder.MinPoolSize = 0;
        return builder.Build();
    }

    /// <summary>The assembly holding this provider's migrations. The model lives in the shared project.</summary>
    internal const string MigrationsAssembly = "SubactId.Storage.Postgres";
}
