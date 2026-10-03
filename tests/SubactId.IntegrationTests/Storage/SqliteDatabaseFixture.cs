using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef;
using SubactId.Storage.Sqlite;
using SubactId.Storage.Sqlite.Repositories;
using Xunit;

namespace SubactId.IntegrationTests.Storage;

/// <summary>
/// A migrated SQLite database in its own directory, deleted with the fixture. Needs no server
/// and no container.
/// </summary>
public sealed class SqliteDatabaseFixture : IStorageFixture, IAsyncLifetime
{
    private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"subactid-sqlite-{Guid.NewGuid():N}");
    private readonly SemaphoreSlim migrationLock = new(1, 1);
    private bool migrated;

    /// <summary>Path of the database file under test.</summary>
    public string DatabasePath => System.IO.Path.Combine(directory, "subactid.db");

    /// <inheritdoc />
    public IStorageDialect Dialect { get; } = new SqliteDialect();

    /// <inheritdoc />
    public Task InitializeAsync()
    {
        Directory.CreateDirectory(directory);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task EnsureMigratedAsync()
    {
        await migrationLock.WaitAsync();
        try
        {
            if (!migrated)
            {
                await SubactId.Storage.Sqlite.MigrationRunner.ApplyAsync(DatabasePath);
                migrated = true;
            }
        }
        finally
        {
            migrationLock.Release();
        }
    }

    /// <inheritdoc />
    public SubactIdDbContext CreateDbContext() => SubactIdSqliteDbContextFactory.Create(DatabasePath);

    /// <inheritdoc />
    public ITaskExpirySweep ExpirySweep(SubactIdDbContext db) => new SqliteTaskExpirySweep(db);

    /// <inheritdoc />
    public ITaskRevocation Revocation(SubactIdDbContext db) => new SqliteTaskRevocation(db);

    /// <inheritdoc />
    public IAuditOutboxQueue OutboxQueue(SubactIdDbContext db) => new SqliteAuditOutboxQueue(db);

    /// <inheritdoc />
    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        migrationLock.Dispose();
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
            // A file the runtime still holds is left for the operating system to clean up.
        }

        return Task.CompletedTask;
    }
}

/// <summary>Shares one embedded database across the tests that run against it.</summary>
[CollectionDefinition(Name)]
public sealed class SqliteCollection : ICollectionFixture<SqliteDatabaseFixture>
{
    /// <summary>Collection name.</summary>
    public const string Name = "sqlite";
}
