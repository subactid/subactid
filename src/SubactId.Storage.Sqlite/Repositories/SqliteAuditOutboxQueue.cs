using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;

namespace SubactId.Storage.Sqlite.Repositories;

/// <summary>
/// SQLite's outbox claim. No row locking is needed: the drain's unit of work holds the database
/// write lock, so no second drain can claim the same batch.
/// </summary>
/// <param name="db">The context.</param>
public sealed class SqliteAuditOutboxQueue(SubactIdDbContext db) : EfAuditOutboxQueue(db)
{
    /// <inheritdoc />
    public override async Task<IReadOnlyList<AuditOutboxEntry>> ClaimDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(batchSize, 0);

        var at = now.ToUniversalTime();
        var rows = await Db.AuditOutbox.AsNoTracking()
            .Where(o => o.NextAttemptAt <= at)
            .OrderBy(o => o.Id)
            .Take(batchSize)
            .Select(o => new { o.Id, o.AuditSeq, o.Attempts })
            .ToListAsync(cancellationToken);
        return rows.Select(r => new AuditOutboxEntry(r.Id, r.AuditSeq, r.Attempts)).ToList();
    }
}
