using SubactId.Storage.Ef;

namespace SubactId.Storage.Postgres;

/// <summary>Applies pending Postgres migrations. Only run by an explicit operator command.</summary>
public static class MigrationRunner
{
    /// <summary>Applies every pending migration to the database behind <paramref name="connectionString"/>.</summary>
    /// <param name="connectionString">Connection string for a role allowed to change the schema. Treated as a secret.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The migrations applied by this call and the full list now applied.</returns>
    public static async Task<MigrationReport> ApplyAsync(string connectionString, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        await using var db = SubactIdDbContextFactory.Create(connectionString);
        return await Ef.MigrationRunner.ApplyAsync(db, cancellationToken);
    }
}
