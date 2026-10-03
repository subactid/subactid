namespace SubactId.Core.Sponsors;

/// <summary>
/// Persistence for blocked humans. Read on every exchange and refresh, so a lookup is one keyed read.
/// </summary>
public interface ISponsorRepository
{
    /// <summary>Returns the block on <paramref name="sponsorKey"/>, or <c>null</c> when there is none.</summary>
    /// <param name="sponsorKey">The human, as the configured key claim named them.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SponsorBlock?> FindAsync(string sponsorKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records <paramref name="block"/> when the human has no block. A block the same source placed
    /// with the same kind is left as it was, <c>blocked_at</c> included. One the same source placed
    /// with a different kind takes the new kind and the new <c>blocked_at</c>. A block another
    /// source placed is never replaced or taken over. Safe against a concurrent write for the same
    /// human. A block with <see cref="SponsorBlock.PlacedByDeletion"/> set also marks a block the
    /// same source already holds, whether or not anything else changes; the mark alone is not
    /// reported as a change.
    /// </summary>
    /// <param name="block">The block to record.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The block standing afterwards, and whether this write changed it.</returns>
    Task<SponsorBlockWrite> BlockAsync(SponsorBlock block, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lifts the block on <paramref name="sponsorKey"/> if <paramref name="source"/> is the one
    /// that placed it and, when <paramref name="unlessPlacedByDeletion"/> is set, no deletion
    /// placed it. Returns <c>false</c> when there is no block, another source owns it, or a
    /// deletion placed it and that was asked to stop it. Decided in the same statement that lifts it.
    /// </summary>
    /// <param name="sponsorKey">The human.</param>
    /// <param name="source">The source asking, which must own the block.</param>
    /// <param name="unlessPlacedByDeletion">Whether a block with <see cref="SponsorBlock.PlacedByDeletion"/> set stays.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> UnblockAsync(string sponsorKey, SponsorBlockSource source, bool unlessPlacedByDeletion = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears <see cref="SponsorBlock.PlacedByDeletion"/> on the block <paramref name="source"/>
    /// holds on <paramref name="sponsorKey"/>, if any. The block itself stays.
    /// </summary>
    /// <param name="sponsorKey">The human.</param>
    /// <param name="source">The source whose block it is.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task ForgetDeletionAsync(string sponsorKey, SponsorBlockSource source, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records that a Shared Signals event about <paramref name="sponsorKey"/>'s account, issued
    /// at <paramref name="eventAt"/>, is being applied, unless one issued later already was.
    /// Returns <c>false</c>, and changes nothing, when the latest event applied for the person was
    /// issued after <paramref name="eventAt"/>. An event with the same <c>iat</c> as the latest one
    /// is applied after it, in the order the two arrived. Kept whether or not a block stands, and after a block is lifted,
    /// so that an event delivered late is not applied over a newer one. Decided in one statement,
    /// which holds the person's row until the unit of work ends.
    /// </summary>
    /// <param name="sponsorKey">The human.</param>
    /// <param name="eventAt">The event's <c>iat</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether the event is in order and may be applied.</returns>
    Task<bool> AdvanceSignalWatermarkAsync(string sponsorKey, DateTimeOffset eventAt, CancellationToken cancellationToken = default);
}
