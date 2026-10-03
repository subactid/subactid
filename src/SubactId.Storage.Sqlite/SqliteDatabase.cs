using Microsoft.Data.Sqlite;

namespace SubactId.Storage.Sqlite;

/// <summary>Builds the SQLite connection string, so every connection is opened the same way.</summary>
public static class SqliteDatabase
{
    /// <summary>
    /// A connection string for the database file at <paramref name="path"/>, with foreign keys
    /// enforced. SQLite leaves them off by default, and Subact ID relies on them.
    /// </summary>
    /// <param name="path">Path to the database file. It is created when the database is migrated.</param>
    public static string ConnectionString(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        return new SqliteConnectionStringBuilder
        {
            DataSource = path,
            ForeignKeys = true,
        }.ConnectionString;
    }
}
