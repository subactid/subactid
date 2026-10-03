using SubactId.Core.Audit;
using SubactId.Core.Revocation;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Core.Validation;
using SubactId.Server.Audit;
using SubactId.Server.Revocation;

namespace SubactId.Server.Admin;

/// <summary>Why a sponsor operation could not be completed.</summary>
public enum SponsorAdminFailure
{
    /// <summary>The key is not well-formed.</summary>
    InvalidKey,

    /// <summary>There is no block on that human.</summary>
    NotBlocked,

    /// <summary>Another source placed the block, and only that source may lift it.</summary>
    NotOwned,

    /// <summary>
    /// Another source already blocks that human. Its block stands and is not taken over, but the
    /// person's live tasks are still ended.
    /// </summary>
    BlockedElsewhere,
}

/// <summary>
/// Operator management of the humans this control plane will not act for. Blocking a person and
/// revoking their live tasks happen in one transaction.
///
/// Lifting a block does not undo revocations. It only lets the person start new tasks.
///
/// An exchange racing a block cannot slip past it. The exchange re-reads the block inside the
/// same fenced transaction that stores its task: a block already committed refuses the task, and
/// one placed after waits for the task to be stored and then revokes it.
/// </summary>
public sealed class SponsorAdminService(
    ISponsorRepository sponsors,
    ITaskRevocation tasks,
    IRevocationRepository revocations,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    RenewalSummary summaries,
    TimeProvider clock)
{
    /// <summary>Reason recorded on a task revoked because the human it acts for was blocked.</summary>
    public const string SponsorBlocked = "sponsor_blocked";

    /// <summary>
    /// Reason recorded on the refused <c>sponsor.blocked</c> when another source already blocks the
    /// human, so the operator's block is not placed.
    /// </summary>
    public const string SponsorBlockedElsewhere = "sponsor_blocked_elsewhere";

    /// <summary>
    /// Reason recorded on the refused <c>sponsor.unblocked</c> when the block was placed by another
    /// source, so the operator may not lift it.
    /// </summary>
    public const string SponsorBlockNotOwned = "sponsor_block_not_owned";

    /// <summary>Longest sponsor key accepted, matching the task storage column.</summary>
    public const int MaxSponsorKeyLength = SponsorKey.MaxLength;

    /// <summary>The block on <paramref name="sponsorKey"/>, or a failure saying there is none.</summary>
    /// <param name="sponsorKey">The human, as the configured key claim names them.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(SponsorBlock? Block, SponsorAdminFailure? Failure)> GetAsync(string? sponsorKey, CancellationToken cancellationToken = default)
    {
        if (!IsKey(sponsorKey))
        {
            return (null, SponsorAdminFailure.InvalidKey);
        }

        var block = await sponsors.FindAsync(sponsorKey!, cancellationToken);
        return block is null ? (null, SponsorAdminFailure.NotBlocked) : (block, null);
    }

    /// <summary>
    /// Records an operator's block and revokes everything live for that person, in one
    /// transaction. Idempotent: a repeat keeps the block as it was placed and writes no second
    /// <c>sponsor.blocked</c>, though it still ends anything live. A block another source placed is
    /// never taken over. It is reported as <c>BlockedElsewhere</c>, with the block that stands, and
    /// recorded as a denied <c>sponsor.blocked</c>. The person's live tasks are still ended, and
    /// recorded, exactly as an operator's block ends them: the kill switch always works.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim names them.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(SponsorBlock? Block, int RevokedTasks, SponsorAdminFailure? Failure)> BlockAsync(string? sponsorKey, CancellationToken cancellationToken = default)
    {
        if (!IsKey(sponsorKey))
        {
            return (null, 0, SponsorAdminFailure.InvalidKey);
        }

        var now = clock.GetUtcNow();

        // Operator blocks are always Disabled. Deleted is only set by a source that knows the
        // account is gone.
        var block = new SponsorBlock(sponsorKey!, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, now);
        return await unitOfWork.RunAsync(
            async ct =>
            {
                // The person first, then the block row, as every block writer takes them.
                await tasks.HoldSponsorsAsync([block.SponsorKey], ct);
                var write = await sponsors.BlockAsync(block, ct);
                var elsewhere = write.Standing.Source != SponsorBlockSource.Admin;

                var ended = await tasks.RevokeSponsorTasksAsync(block.SponsorKey, now, SponsorBlocked, ct);
                var records = new List<AuditEvent>(ended.Count + 1);
                if (elsewhere)
                {
                    // The block itself is refused: another source's stands unchanged.
                    records.Add(new(now, AuditEvents.SponsorBlocked, null, null, block.SponsorKey, Decision: AuditDecision.Deny, Reason: SponsorBlockedElsewhere));
                }
                else if (write.Written)
                {
                    // The operator's action succeeded, so it is an Allow.
                    records.Add(new(now, AuditEvents.SponsorBlocked, null, null, block.SponsorKey, Decision: AuditDecision.Allow, Reason: SponsorBlocked));
                }

                records.AddRange(ended.SelectMany(t => summaries.Ending(RevocationService.Record(t, now, t.IsRoot ? SponsorBlocked : ITaskRevocation.ParentRevoked), t.Renewals)));
                if (ended.Count > 0)
                {
                    await revocations.AddAsync(new Core.Revocation.Revocation(null, null, null, block.SponsorKey, null, now, SponsorBlocked, RevocationService.Admin), ct);
                }

                if (records.Count > 0)
                {
                    await audit.AppendAsync(records, ct);
                }

                if (elsewhere)
                {
                    return (write.Standing, ended.Count, (SponsorAdminFailure?)SponsorAdminFailure.BlockedElsewhere);
                }

                return (write.Standing, ended.Count, null);
            },
            cancellationToken);
    }

    /// <summary>
    /// Lifts a block an operator placed. A block from another source is left in place, reported
    /// as <c>NotOwned</c>, and recorded as a denied <c>sponsor.unblocked</c>.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim names them.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<SponsorAdminFailure?> UnblockAsync(string? sponsorKey, CancellationToken cancellationToken = default)
    {
        if (!IsKey(sponsorKey))
        {
            return SponsorAdminFailure.InvalidKey;
        }

        var notOwned = false;
        SponsorAdminFailure? failure;
        try
        {
            failure = await unitOfWork.RunAsync(
                async ct =>
                {
                    // The person first, then the block row, as every block writer takes them.
                    await tasks.HoldSponsorsAsync([sponsorKey!], ct);
                    var existing = await sponsors.FindAsync(sponsorKey!, ct);
                    if (existing is null)
                    {
                        return SponsorAdminFailure.NotBlocked;
                    }

                    if (existing.Source != SponsorBlockSource.Admin)
                    {
                        notOwned = true;
                        return (SponsorAdminFailure?)SponsorAdminFailure.NotOwned;
                    }

                    await sponsors.UnblockAsync(sponsorKey!, SponsorBlockSource.Admin, cancellationToken: ct);
                    await audit.AppendAsync(new AuditEvent(clock.GetUtcNow(), AuditEvents.SponsorUnblocked, null, null, sponsorKey, Decision: AuditDecision.Allow, Reason: "operator_unblocked"), ct);
                    return null;
                },
                cancellationToken);
        }
        catch (OperationCanceledException) when (notOwned)
        {
            // The refusal was decided before the caller went away. Nothing was lifted, so it stands.
            failure = SponsorAdminFailure.NotOwned;
        }

        if (failure is SponsorAdminFailure.NotOwned)
        {
            // Not cancellable by the caller: a denial is always recorded.
            await audit.AppendAsync(new AuditEvent(clock.GetUtcNow(), AuditEvents.SponsorUnblocked, null, null, sponsorKey, Decision: AuditDecision.Deny, Reason: SponsorBlockNotOwned), CancellationToken.None);
        }

        return failure;
    }

    /// <summary>
    /// Revokes everything live for a person without blocking them, so they may start a new task at
    /// once. A person with nothing running is not an error.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim names them.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(int RevokedTasks, SponsorAdminFailure? Failure)> RevokeTasksAsync(string? sponsorKey, CancellationToken cancellationToken = default)
    {
        if (!IsKey(sponsorKey))
        {
            return (0, SponsorAdminFailure.InvalidKey);
        }

        var revoked = await unitOfWork.RunAsync(
            async ct =>
            {
                var now = clock.GetUtcNow();
                var ended = await tasks.RevokeSponsorTasksAsync(sponsorKey!, now, RevocationService.OperatorKillSwitch, ct);
                if (ended.Count > 0)
                {
                    await revocations.AddAsync(new Core.Revocation.Revocation(null, null, null, sponsorKey, null, now, RevocationService.OperatorKillSwitch, RevocationService.Admin), ct);
                    await audit.AppendAsync(
                        ended.SelectMany(t => summaries.Ending(RevocationService.Record(t, now, t.IsRoot ? RevocationService.OperatorKillSwitch : ITaskRevocation.ParentRevoked), t.Renewals)).ToList(),
                        ct);
                }

                return ended.Count;
            },
            cancellationToken);

        return (revoked, null);
    }

    /// <summary>
    /// The same rule the exchange applies before it stores a key.
    /// </summary>
    private static bool IsKey(string? value) => SponsorKey.IsWellFormed(value);
}
