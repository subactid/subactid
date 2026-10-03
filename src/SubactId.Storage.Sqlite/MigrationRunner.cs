using Microsoft.EntityFrameworkCore;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Sqlite;

/// <summary>Applies pending SQLite migrations. Run only by an explicit operator command.</summary>
public static class MigrationRunner
{
    /// <summary>
    /// Creates the database file at <paramref name="path"/> if needed, switches it to write-ahead
    /// logging, and applies every pending migration. WAL mode is stored in the file, so it is set once here.
    /// </summary>
    /// <param name="path">Path to the database file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The migrations applied by this call and the full list now applied.</returns>
    public static async Task<MigrationReport> ApplyAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (Path.GetDirectoryName(Path.GetFullPath(path)) is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
        }

        await using var db = SubactIdSqliteDbContextFactory.Create(path);
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode = WAL", cancellationToken);
        return await Ef.MigrationRunner.ApplyAsync(db, cancellationToken);
    }
}
