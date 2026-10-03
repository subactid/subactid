using Npgsql;

namespace SubactId.Storage.Postgres;

/// <summary>
/// Creates a data source from a connection string, for operator commands that run outside the host.
/// </summary>
public static class SubactIdDataSourceFactory
{
    /// <summary>A data source on <paramref name="connectionString"/>. The string is a secret and is never logged.</summary>
    /// <param name="connectionString">The Postgres connection string.</param>
    public static NpgsqlDataSource Create(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        return new NpgsqlDataSourceBuilder(PostgresConnectionString.WithDefaults(connectionString)).Build();
    }
}
