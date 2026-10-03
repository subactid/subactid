using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using PostgresMigrations = SubactId.Storage.Postgres.MigrationRunner;
using SqliteMigrations = SubactId.Storage.Sqlite.MigrationRunner;

namespace SubactId.Server.Commands;

/// <summary>
/// <c>SubactId.Server migrate</c>: applies pending schema migrations and exits. The only code path
/// that changes the schema. The server never migrates at startup.
/// </summary>
internal static class MigrateCommand
{
    /// <summary>The command word on the command line.</summary>
    public const string Name = "migrate";

    /// <summary>Runs the command.</summary>
    /// <param name="options">Validated configuration.</param>
    /// <returns>Process exit code: 0 on success, 1 on failure.</returns>
    public static async Task<int> RunAsync(SubactIdOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        try
        {
            var report = options.Database.Provider == StorageProvider.Sqlite
                ? await SqliteMigrations.ApplyAsync(options.Database.Path!)
                : await PostgresMigrations.ApplyAsync(options.Database.MigrationConnectionString ?? options.Database.ConnectionString!);

            if (report.AppliedNow.Count == 0)
            {
                Console.WriteLine("Database schema is already up to date.");
            }
            else
            {
                Console.WriteLine($"Applied {report.AppliedNow.Count} migration(s):");
                foreach (var migration in report.AppliedNow)
                {
                    Console.WriteLine($"  - {migration}");
                }
            }

            Console.WriteLine($"Schema version: {report.AllApplied[^1]}");

            // Every run creates the ledger partitions ahead of this month, per
            // SubactId:Audit:Partitions:MonthsAhead, for deployments where the server role cannot.
            await TopUpAuditPartitionsAsync(options);
            return 0;
        }
        catch (Exception exception)
        {
            // Exception messages from Npgsql and EF Core name hosts and objects, never credentials.
            Console.Error.WriteLine($"Migration failed: {exception.GetType().Name}: {exception.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Ensures ledger partitions exist for this month and the next
    /// <c>SubactId:Audit:Partitions:MonthsAhead</c> months. Does nothing on SQLite.
    /// </summary>
    /// <param name="options">Validated configuration.</param>
    private static async Task TopUpAuditPartitionsAsync(SubactIdOptions options)
    {
        if (options.Database.Provider == StorageProvider.Sqlite)
        {
            return;
        }

        await using var dataSource = SubactIdDataSourceFactory.Create(options.Database.MigrationConnectionString ?? options.Database.ConnectionString!);
        var partitions = new PostgresAuditLedgerPartitions(dataSource);
        var created = await partitions.EnsureAsync(DateTimeOffset.UtcNow, options.Audit.PartitionMonthsAhead);

        Console.WriteLine(created == 0
            ? $"Audit ledger partitions: already {options.Audit.PartitionMonthsAhead} month(s) ahead."
            : $"Audit ledger partitions: created {created}, now {options.Audit.PartitionMonthsAhead} month(s) ahead.");
    }
}
