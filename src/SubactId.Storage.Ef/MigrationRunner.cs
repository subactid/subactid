using Microsoft.EntityFrameworkCore;

namespace SubactId.Storage.Ef;

/// <summary>Applies pending migrations. Only run by an explicit operator command.</summary>
public static class MigrationRunner
{
    /// <summary>Applies every pending migration on <paramref name="db"/>, whichever provider it is.</summary>
    /// <param name="db">A context built for the database to migrate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The migrations applied by this call and the full list now applied.</returns>
    public static async Task<MigrationReport> ApplyAsync(SubactIdDbContext db, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);

        var pending = (await db.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();
        if (pending.Count > 0)
        {
            await db.Database.MigrateAsync(cancellationToken);
        }

        var applied = (await db.Database.GetAppliedMigrationsAsync(cancellationToken)).ToList();
        return new MigrationReport(pending, applied);
    }
}

/// <summary>Outcome of a migration run.</summary>
/// <param name="AppliedNow">Migrations applied by this run, in order.</param>
/// <param name="AllApplied">Every migration the database now has, in order.</param>
public sealed record MigrationReport(IReadOnlyList<string> AppliedNow, IReadOnlyList<string> AllApplied);
