using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// The archived months, one row each. Months are archived in order, so the greatest month is
/// the floor of the online ledger for both records and checkpoints.
/// </summary>
public sealed class EfAuditArchiveRepository(SubactIdDbContext db) : IAuditArchiveRepository
{
    /// <inheritdoc />
    public async Task<AuditArchive?> LastAsync(CancellationToken cancellationToken = default)
    {
        var row = await db.AuditArchives.AsNoTracking()
            .OrderByDescending(a => a.Month)
            .FirstOrDefaultAsync(cancellationToken);

        return row?.ToDomain();
    }

    /// <inheritdoc />
    public async Task<AuditArchive?> FindAsync(DateTimeOffset month, CancellationToken cancellationToken = default)
    {
        var at = month.ToUniversalTime();
        var row = await db.AuditArchives.AsNoTracking().FirstOrDefaultAsync(a => a.Month == at, cancellationToken);
        return row?.ToDomain();
    }

    /// <inheritdoc />
    public async Task AppendAsync(AuditArchive archive, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archive);

        db.AuditArchives.Add(archive.ToRow());
        await db.SaveChangesAsync(cancellationToken);
    }
}
