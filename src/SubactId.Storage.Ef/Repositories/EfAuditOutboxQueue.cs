using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// The outbox, except the claim, which each provider supplies.
/// </summary>
/// <param name="db">The context.</param>
public abstract class EfAuditOutboxQueue(SubactIdDbContext db) : IAuditOutboxQueue
{
    /// <summary>Longest error text stored.</summary>
    public const int MaxErrorLength = 1024;

    /// <summary>The context these statements run on.</summary>
    protected SubactIdDbContext Db { get; } = db;

    /// <inheritdoc />
    public abstract Task<IReadOnlyList<AuditOutboxEntry>> ClaimDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public async Task RemoveDeliveredAsync(IReadOnlyList<long> ids, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ids);

        // The delete commits with the claim, so a crash before commit leaves the entry and the
        // delivery is repeated (at-least-once, per the spec).
        var wanted = ids.ToArray();
        await Db.AuditOutbox
            .Where(o => wanted.Contains(o.Id))
            .ExecuteDeleteAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task MarkFailedAsync(IReadOnlyList<long> ids, DateTimeOffset now, string error, DateTimeOffset nextAttemptAt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ids);
        ArgumentException.ThrowIfNullOrEmpty(error);

        var wanted = ids.ToArray();
        var text = error.Length > MaxErrorLength ? error[..MaxErrorLength] : error;
        var next = nextAttemptAt.ToUniversalTime();
        await Db.AuditOutbox
            .Where(o => wanted.Contains(o.Id))
            .ExecuteUpdateAsync(setters => setters.SetProperty(o => o.Attempts, o => o.Attempts + 1).SetProperty(o => o.LastError, text).SetProperty(o => o.NextAttemptAt, next), cancellationToken);
    }
}
