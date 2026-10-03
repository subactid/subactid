using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef;
using SubactId.Storage.Sqlite.Repositories;

namespace SubactId.Storage.Sqlite;

/// <summary>Registers the embedded SQLite storage services.</summary>
public static class SqliteServiceCollectionExtensions
{
    /// <summary>
    /// Registers an <see cref="SubactIdDbContext"/> on the database file at <paramref name="path"/>,
    /// the shared repositories, and the SQLite-specific ones. Never applies migrations. Only one
    /// process writes the database at a time.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="path">Path to the database file.</param>
    /// <param name="deliverAudit">Whether audit records are queued in the outbox for an external sink.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddSqliteStorage(this IServiceCollection services, string path, bool deliverAudit = false)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var connectionString = SqliteDatabase.ConnectionString(path);
        services.AddSingleton<IStorageDialect, SqliteDialect>();
        services.AddDbContext<SubactIdDbContext>(options =>
            options.UseSqlite(connectionString, sqlite => sqlite.MigrationsAssembly(MigrationsAssembly)));

        services.AddSharedStorage(deliverAudit);
        services.AddScoped<ITaskExpirySweep, SqliteTaskExpirySweep>();
        services.AddScoped<ITaskRevocation, SqliteTaskRevocation>();
        services.AddScoped<IAuditOutboxQueue, SqliteAuditOutboxQueue>();
        services.AddSingleton<IAuditLedgerPartitions, SqliteAuditLedgerPartitions>();
        services.AddSingleton<IStorageHealthCheck>(new SqliteHealthCheck(connectionString));

        // No connection pool to starve, so readiness uses the same services as requests.
        services.AddKeyedSingleton<IAuditLedgerPartitions>(StorageReadiness.ServiceKey, (provider, _) => provider.GetRequiredService<IAuditLedgerPartitions>());
        services.AddSingleton<IStorageFaults, SqliteFaults>();

        return services;
    }

    /// <summary>The assembly that holds this provider's migrations.</summary>
    internal const string MigrationsAssembly = "SubactId.Storage.Sqlite";
}
