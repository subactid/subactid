using Microsoft.EntityFrameworkCore;
using SubactId.Core.Sponsors;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// Blocked humans, keyed by the configured key claim's value. The check is a single primary-key
/// lookup, since it runs on every exchange and refresh.
/// </summary>
public sealed class EfSponsorRepository(SubactIdDbContext db, IStorageDialect dialect) : ISponsorRepository
{
    /// <inheritdoc />
    public async Task<SponsorBlock?> FindAsync(string sponsorKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);

        var row = await db.SponsorBlocks.AsNoTracking()
            .SingleOrDefaultAsync(s => s.SponsorKey == sponsorKey, cancellationToken);
        return row?.ToDomain();
    }

    /// <inheritdoc />
    public async Task<SponsorBlockWrite> BlockAsync(SponsorBlock block, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(block);

        var source = RowMapping.ToColumn(block.Source);
        var kind = RowMapping.ToColumn(block.Kind);
        var blockedAt = block.BlockedAt.ToUniversalTime();

        // A lift can land between the statements below, so the write is tried again from the top.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            // Inserted only if the human has no block, so a concurrent writer never meets a
            // duplicate and another source's block is never overwritten. Hand-written because EF
            // has no insert-if-absent. The values are bound, never interpolated.
            var inserted = await db.Database.ExecuteSqlAsync(
                $"""
                INSERT INTO sponsor_blocks (sponsor_key, source, kind, blocked_at, placed_by_deletion)
                VALUES ({block.SponsorKey}, {source}, {kind}, {dialect.Timestamp(blockedAt)}, {block.PlacedByDeletion})
                ON CONFLICT (sponsor_key) DO NOTHING
                """,
                cancellationToken);
            if (inserted == 1)
            {
                return new SponsorBlockWrite(block, Written: true);
            }

            // The same source may change the kind, for example disabled to deleted, which also
            // records when it changed. Another source's block is left exactly as it stands.
            var changed = await db.SponsorBlocks
                .Where(s => s.SponsorKey == block.SponsorKey && s.Source == source && s.Kind != kind)
                .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.Kind, kind).SetProperty(s => s.BlockedAt, blockedAt), cancellationToken);

            // A deletion marks this source's block whatever its kind, so that only a new record
            // lifts it. Never cleared here.
            if (block.PlacedByDeletion)
            {
                await db.SponsorBlocks
                    .Where(s => s.SponsorKey == block.SponsorKey && s.Source == source && !s.PlacedByDeletion)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.PlacedByDeletion, true), cancellationToken);
            }

            if (await FindAsync(block.SponsorKey, cancellationToken) is { } standing)
            {
                return new SponsorBlockWrite(standing, Written: changed > 0);
            }
        }

        throw new InvalidOperationException("The block on this human kept changing under the write.");
    }

    /// <inheritdoc />
    public async Task<bool> UnblockAsync(string sponsorKey, SponsorBlockSource source, bool unlessPlacedByDeletion = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);

        // The mark is read in the statement that lifts, so a deletion that marked the block since
        // the caller read it is not undone.
        var owner = RowMapping.ToColumn(source);
        var removed = await db.SponsorBlocks
            .Where(s => s.SponsorKey == sponsorKey && s.Source == owner && (!unlessPlacedByDeletion || !s.PlacedByDeletion))
            .ExecuteDeleteAsync(cancellationToken);
        return removed > 0;
    }

    /// <inheritdoc />
    public async Task ForgetDeletionAsync(string sponsorKey, SponsorBlockSource source, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);

        var owner = RowMapping.ToColumn(source);
        await db.SponsorBlocks
            .Where(s => s.SponsorKey == sponsorKey && s.Source == owner && s.PlacedByDeletion)
            .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.PlacedByDeletion, false), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> AdvanceSignalWatermarkAsync(string sponsorKey, DateTimeOffset eventAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);

        // Inserted, or moved forward, in one statement, which compares against the row as it stands
        // and holds it until the unit of work ends. An event no older than the latest one writes
        // the row (the same value, for a tie); an older one fails the WHERE and writes nothing.
        // Hand-written because EF has no conditional upsert. The values are bound.
        var at = dialect.Timestamp(eventAt.ToUniversalTime());
        var written = await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO ssf_signal_watermarks (sponsor_key, event_at)
            VALUES ({sponsorKey}, {at})
            ON CONFLICT (sponsor_key) DO UPDATE SET event_at = excluded.event_at
            WHERE ssf_signal_watermarks.event_at <= excluded.event_at
            """,
            cancellationToken);
        return written == 1;
    }
}
