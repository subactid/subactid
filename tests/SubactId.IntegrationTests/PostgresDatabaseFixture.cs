using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.IntegrationTests.Repositories;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using Testcontainers.PostgreSql;
using Xunit;

namespace SubactId.IntegrationTests;

/// <summary>
/// A clean Postgres database owned by a dedicated, non-superuser application role.
/// By default a container of <see cref="DefaultImage"/> is started, or of the image named by
/// <see cref="ImageVariable"/>. Set <see cref="OverrideVariable"/> to an admin
/// connection string (a role with CREATEDB and CREATEROLE) to use an existing server
/// instead; a fresh database and role are still created and dropped per run.
/// </summary>
public sealed class PostgresDatabaseFixture : IStorageFixture, IAsyncLifetime
{
    /// <summary>Environment variable holding an admin connection string to an existing Postgres.</summary>
    public const string OverrideVariable = "SUBACTID_TEST_POSTGRES";

    /// <summary>Environment variable naming the image to start instead of <see cref="DefaultImage"/>, such as the oldest supported version.</summary>
    public const string ImageVariable = "SUBACTID_TEST_POSTGRES_IMAGE";

    /// <summary>The image started when neither variable is set: the version CI and the quickstart run.</summary>
    public const string DefaultImage = "postgres:18";

    private PostgreSqlContainer? container;
    private string adminConnectionString = string.Empty;
    private string databaseName = string.Empty;
    private readonly SemaphoreSlim migrationLock = new(1, 1);
    private bool migrated;

    /// <inheritdoc />
    public IStorageDialect Dialect { get; } = new PostgresDialect();

    /// <inheritdoc />
    public SubactIdDbContext CreateDbContext() => SubactIdDbContextFactory.Create(ApplicationConnectionString);

    /// <inheritdoc />
    public ITaskExpirySweep ExpirySweep(SubactIdDbContext db) => new PostgresTaskExpirySweep(db);

    /// <inheritdoc />
    public ITaskRevocation Revocation(SubactIdDbContext db) => new PostgresTaskRevocation(db);

    /// <inheritdoc />
    public IAuditOutboxQueue OutboxQueue(SubactIdDbContext db) => new PostgresAuditOutboxQueue(db);

    /// <summary>Name of the non-superuser role that owns the schema and that the application would run as.</summary>
    public string ApplicationRole { get; private set; } = string.Empty;

    /// <summary>Connection string for <see cref="ApplicationRole"/> to the test database.</summary>
    public string ApplicationConnectionString { get; private set; } = string.Empty;

    /// <inheritdoc />
    public async Task InitializeAsync()
    {
        var overrideConnectionString = Environment.GetEnvironmentVariable(OverrideVariable);
        if (string.IsNullOrWhiteSpace(overrideConnectionString))
        {
            var image = Environment.GetEnvironmentVariable(ImageVariable);
            container = new PostgreSqlBuilder(string.IsNullOrWhiteSpace(image) ? DefaultImage : image).Build();
            await container.StartAsync();
            adminConnectionString = container.GetConnectionString();
        }
        else
        {
            adminConnectionString = overrideConnectionString;
        }

        var suffix = Guid.NewGuid().ToString("N")[..8];
        ApplicationRole = $"subactid_app_{suffix}";
        databaseName = $"subactid_test_{suffix}";
        var password = Guid.NewGuid().ToString("N");

        await using (var admin = new NpgsqlConnection(adminConnectionString))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, $"CREATE ROLE {ApplicationRole} LOGIN PASSWORD '{password}'");
            await ExecuteAsync(admin, $"CREATE DATABASE {databaseName}");
            await ExecuteAsync(admin, $"GRANT CONNECT ON DATABASE {databaseName} TO {ApplicationRole}");
        }

        var adminInTestDatabase = new NpgsqlConnectionStringBuilder(adminConnectionString) { Database = databaseName }.ConnectionString;
        await using (var admin = new NpgsqlConnection(adminInTestDatabase))
        {
            await admin.OpenAsync();
            await ExecuteAsync(admin, $"GRANT USAGE, CREATE ON SCHEMA public TO {ApplicationRole}");
        }

        ApplicationConnectionString = new NpgsqlConnectionStringBuilder(adminConnectionString)
        {
            Database = databaseName,
            Username = ApplicationRole,
            Password = password,
            Pooling = false,
        }.ConnectionString;
    }

    /// <summary>Applies the migrations as <see cref="ApplicationRole"/> once per fixture and returns the report of that first run.</summary>
    public async Task EnsureMigratedAsync()
    {
        await migrationLock.WaitAsync();
        try
        {
            if (!migrated)
            {
                await SubactId.Storage.Postgres.MigrationRunner.ApplyAsync(ApplicationConnectionString);
                await EnsureAuditPartitionsAsync();
                migrated = true;
            }
        }
        finally
        {
            migrationLock.Release();
        }
    }

    /// <summary>
    /// A provider over this database's storage, for the background passes that resolve their own
    /// scope rather than taking a context. Disposed by the caller.
    /// </summary>
    public ServiceProvider Services()
    {
        var services = new ServiceCollection();
        services.AddPostgresStorage(ApplicationConnectionString);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Partitions for every month the suite writes into. The ledger has no catch-all partition, and
    /// the suite uses both the wall clock and the fixed <see cref="RepositoryTestData.Now"/>, so this
    /// covers a month either side of both and a year ahead.
    /// </summary>
    private async Task EnsureAuditPartitionsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var first = (RepositoryTestData.Now < now ? RepositoryTestData.Now : now).AddMonths(-1);
        var last = (RepositoryTestData.Now > now ? RepositoryTestData.Now : now).AddMonths(13);

        await using var dataSource = SubactIdDataSourceFactory.Create(ApplicationConnectionString);
        await new PostgresAuditLedgerPartitions(dataSource)
            .EnsureAsync(first, ((last.Year - first.Year) * 12) + last.Month - first.Month);
    }

    /// <summary>Opens a connection as <see cref="ApplicationRole"/>.</summary>
    public async Task<NpgsqlConnection> OpenApplicationConnectionAsync()
    {
        var connection = new NpgsqlConnection(ApplicationConnectionString);
        await connection.OpenAsync();
        return connection;
    }

    /// <inheritdoc />
    public async Task DisposeAsync()
    {
        if (container is not null)
        {
            await container.DisposeAsync();
        }
        else
        {
            await using var admin = new NpgsqlConnection(adminConnectionString);
            await admin.OpenAsync();
            await ExecuteAsync(admin, $"DROP DATABASE IF EXISTS {databaseName} WITH (FORCE)");
            await ExecuteAsync(admin, $"DROP ROLE IF EXISTS {ApplicationRole}");
        }

        migrationLock.Dispose();
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}

/// <summary>Shares one database across the migration tests.</summary>
[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresDatabaseFixture>
{
    /// <summary>Collection name.</summary>
    public const string Name = "postgres";
}
