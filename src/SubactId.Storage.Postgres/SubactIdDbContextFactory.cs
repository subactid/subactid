using Microsoft.EntityFrameworkCore;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Postgres;

/// <summary>Creates a context from a connection string, for the operator commands that run outside the host.</summary>
public static class SubactIdDbContextFactory
{
    /// <summary>A context on <paramref name="connectionString"/>. The string is a secret and is never logged.</summary>
    /// <param name="connectionString">The Postgres connection string.</param>
    public static SubactIdDbContext Create(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        return new SubactIdDbContext(
            new DbContextOptionsBuilder<SubactIdDbContext>()
                .UseNpgsql(PostgresConnectionString.WithDefaults(connectionString), npgsql => npgsql.MigrationsAssembly(PostgresServiceCollectionExtensions.MigrationsAssembly))
                .Options,
            new PostgresDialect());
    }
}
