using Microsoft.EntityFrameworkCore;
using SubactId.Core.Storage;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>Translates the database's unique-violation into the domain's <see cref="DuplicateEntityException"/>.</summary>
internal static class UniqueViolation
{
    public static async Task SaveOrThrowDuplicateAsync(DbContext db, IStorageDialect dialect, string entity, string key, CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (exception.InnerException is { } inner && dialect.IsUniqueViolation(inner))
        {
            // The refused changes stay tracked otherwise, and a later save in the same scope would
            // try them again. None of them was written.
            foreach (var entry in db.ChangeTracker.Entries().Where(e => e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted).ToList())
            {
                entry.State = EntityState.Detached;
            }

            throw new DuplicateEntityException(entity, key);
        }
    }
}
