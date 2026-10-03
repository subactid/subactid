using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;

namespace SubactId.Storage.Postgres.Repositories;

/// <summary>Postgres's outbox claim. The batch is locked with <c>SKIP LOCKED</c> for the caller's transaction, so concurrent drains never take the same entry.</summary>
/// <param name="db">The context.</param>
public sealed class PostgresAuditOutboxQueue(SubactIdDbContext db) : EfAuditOutboxQueue(db)
{
    /// <inheritdoc />
    public override async Task<IReadOnlyList<AuditOutboxEntry>> ClaimDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(batchSize, 0);

        var at = now.ToUniversalTime();
        var rows = await Db.Database.SqlQuery<ClaimedEntry>($"""
            SELECT id AS "Id", audit_seq AS "AuditSeq", attempts AS "Attempts" FROM audit_outbox
            WHERE next_attempt_at <= {at}
            ORDER BY id
            LIMIT {batchSize}
            FOR UPDATE SKIP LOCKED
            """).ToListAsync(cancellationToken);
        return rows.Select(r => new AuditOutboxEntry(r.Id, r.AuditSeq, r.Attempts)).ToList();
    }

    private sealed class ClaimedEntry
    {
        public long Id { get; init; }

        public long AuditSeq { get; init; }

        public int Attempts { get; init; }
    }
}
