using Microsoft.EntityFrameworkCore;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Sqlite;

/// <summary>Creates a context on a SQLite file, for the operator commands that run outside the host.</summary>
public static class SubactIdSqliteDbContextFactory
{
    /// <summary>A context on the database file at <paramref name="path"/>.</summary>
    /// <param name="path">Path to the database file.</param>
    public static SubactIdDbContext Create(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        return new SubactIdDbContext(
            new DbContextOptionsBuilder<SubactIdDbContext>()
                .UseSqlite(SqliteDatabase.ConnectionString(path), sqlite => sqlite.MigrationsAssembly(SqliteServiceCollectionExtensions.MigrationsAssembly))
                .Options,
            new SqliteDialect());
    }
}
