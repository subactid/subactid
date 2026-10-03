using SubactId.Core.Audit;
using SubactId.Core.Revocation;
using SubactId.Core.Sponsors;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Revocation;

namespace SubactId.Server.Signals;

/// <summary>
/// Applies inbound signals about a person, shared by all signal receivers. A signal can block a
/// person, end their running tasks, or lift a block the same source placed.
///
/// <para>
/// A block placed by another source is never replaced, lifted or taken over.
/// </para>
/// <para>
/// Audit records are written when something changed, and each method returns whether it did. A
/// signal refused because another source's block stands is recorded too, as the admin API records
/// it, unless the caller says the signal only restates what it said before.
/// </para>
/// <para>
/// A signal that carries the time it was issued is ordered by it: one issued before the latest
/// signal already applied for the person is not applied, and the refusal is recorded with
/// <see cref="SignalOutOfOrder"/>. Two with the same time are applied in the order they arrive.
/// </para>
/// <para>
/// No method opens a transaction. The caller runs them inside its own unit of work.
/// </para>
/// <para>
/// Every method holds the person (see <see cref="HoldAsync"/>) before it reads or writes anything
/// else about them: the order is the person, then an ordered signal's watermark, then the block
/// row, then the tasks and the audit ledger. A caller that writes something about the person
/// first, or acts for more than one person in a unit of work, holds them all itself, together,
/// before its first write.
/// </para>
/// </summary>
public sealed class SponsorSignalWriter(
    ISponsorRepository sponsors,
    ITaskRevocation tasks,
    IRevocationRepository revocations,
    IAuditWriter audit,
    RenewalSummary summaries)
{
    /// <summary>
    /// Reason recorded, on a refused <c>sponsor.blocked</c> or <c>sponsor.unblocked</c>, when a
    /// signal was issued before the latest one already applied for the person, so it is not applied.
    /// </summary>
    public const string SignalOutOfOrder = "signal_out_of_order";

    /// <summary>
    /// Holds each of <paramref name="sponsorKeys"/>, together and in a fixed order, for the rest of
    /// the unit of work, as every method here holds the person it acts for. Called before the unit
    /// of work writes anything about them. See <see cref="ITaskRevocation.HoldSponsorsAsync"/>.
    /// </summary>
    /// <param name="sponsorKeys">The people the unit of work will act for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task HoldAsync(IReadOnlyCollection<string> sponsorKeys, CancellationToken cancellationToken = default) =>
        tasks.HoldSponsorsAsync(sponsorKeys, cancellationToken);

    /// <summary>
    /// Refuses to act for <paramref name="sponsorKey"/> and ends what is running for them.
    /// </summary>
    /// <param name="sponsorKey">The human, as tasks are keyed by them.</param>
    /// <param name="source">What is blocking them. Only it may lift the block later.</param>
    /// <param name="kind">Whether the person is disabled or gone.</param>
    /// <param name="reason">Machine-readable reason, recorded on the signal and on every task.</param>
    /// <param name="revokedBy">Who asked, for the revocation record.</param>
    /// <param name="now">The time to record.</param>
    /// <param name="restated">
    /// Whether the signal only repeats what this source said before, as a directory sync does. A
    /// restated signal refused by another source's block records nothing.
    /// </param>
    /// <param name="eventAt">
    /// When the signal was issued, for a source whose signals carry their own time. A signal issued
    /// before the latest one applied for the person neither blocks nor ends anything, and the
    /// refusal is recorded.
    /// </param>
    /// <param name="byDeletion">
    /// Whether the record the source held for the person was deleted. The block is marked, and is
    /// then lifted only by <see cref="UnblockAsync"/> after <see cref="ForgetDeletionAsync"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether anything changed.</returns>
    public async Task<bool> BlockAsync(
        string sponsorKey,
        SponsorBlockSource source,
        SponsorBlockKind kind,
        string reason,
        string revokedBy,
        DateTimeOffset now,
        bool restated = false,
        DateTimeOffset? eventAt = null,
        bool byDeletion = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        await tasks.HoldSponsorsAsync([sponsorKey], cancellationToken);
        if (eventAt is { } issued && !await InOrderAsync(sponsorKey, issued, AuditEvents.SponsorBlocked, now, cancellationToken))
        {
            return false;
        }

        // Another source's block is left as it is. The person is already refused, and this
        // source's block is not placed, which is a refusal and recorded as one.
        var write = await sponsors.BlockAsync(new SponsorBlock(sponsorKey, source, kind, now, byDeletion), cancellationToken);
        if (write.Standing.Source != source && !restated)
        {
            await audit.AppendAsync(
                new AuditEvent(now, AuditEvents.SponsorBlocked, null, null, sponsorKey, Decision: AuditDecision.Deny, Reason: SponsorAdminService.SponsorBlockedElsewhere),
                cancellationToken);
        }

        return await RecordAsync(sponsorKey, reason, revokedBy, write.Written, signsOutBefore: null, now, cancellationToken);
    }

    /// <summary>
    /// Ends the running tasks of <paramref name="sponsorKey"/> without blocking them. Used when a
    /// session ends, as opposed to an account being closed.
    /// </summary>
    /// <param name="sponsorKey">The human, as tasks are keyed by them.</param>
    /// <param name="reason">Machine-readable reason, recorded on the signal and on every task.</param>
    /// <param name="revokedBy">Who asked, for the revocation record.</param>
    /// <param name="now">The time to record.</param>
    /// <param name="signsOutBefore">
    /// When set, the signal also signs the person out: their subject tokens issued before this
    /// instant may not start a task. It is then recorded whether or not anything was running.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether anything was ended or recorded.</returns>
    public Task<bool> RevokeAsync(string sponsorKey, string reason, string revokedBy, DateTimeOffset now, DateTimeOffset? signsOutBefore = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        return RecordAsync(sponsorKey, reason, revokedBy, blockWritten: false, signsOutBefore, now, cancellationToken);
    }

    /// <summary>
    /// Lifts a block, only if <paramref name="source"/> placed it. Revoked tasks stay revoked.
    /// </summary>
    /// <param name="sponsorKey">The human, as tasks are keyed by them.</param>
    /// <param name="source">The source asking, which must own the block.</param>
    /// <param name="reason">Machine-readable reason for the record.</param>
    /// <param name="now">The time to record.</param>
    /// <param name="restated">
    /// Whether the signal only repeats what this source said before. A restated signal refused by
    /// another source's block records nothing.
    /// </param>
    /// <param name="eventAt">
    /// When the signal was issued, for a source whose signals carry their own time. A signal issued
    /// before the latest one applied for the person lifts nothing, and the refusal is recorded.
    /// </param>
    /// <param name="stillStands">
    /// Asked once a block <paramref name="source"/> placed is found: whether something else this
    /// source knows of still keeps the block in place. When it answers <c>true</c>, the block stays
    /// and nothing is recorded, since nothing changed. The answer is only as good as what it reads,
    /// so every write of that source holds the person before it writes anything the answer reads,
    /// as this method holds them before it asks. A write under way when it is asked has then
    /// either committed and is read, or has not started and waits for this unit of work, then
    /// applies its own block.
    /// </param>
    /// <param name="keepsDeletion">
    /// Whether a block a deletion placed (see <see cref="BlockAsync"/>) stays. It does, and nothing
    /// is recorded, as for <paramref name="stillStands"/>. Checked again in the statement that lifts.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether a block was lifted.</returns>
    public async Task<bool> UnblockAsync(
        string sponsorKey,
        SponsorBlockSource source,
        string reason,
        DateTimeOffset now,
        bool restated = false,
        Func<CancellationToken, Task<bool>>? stillStands = null,
        DateTimeOffset? eventAt = null,
        bool keepsDeletion = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        await tasks.HoldSponsorsAsync([sponsorKey], cancellationToken);
        if (eventAt is { } issued && !await InOrderAsync(sponsorKey, issued, AuditEvents.SponsorUnblocked, now, cancellationToken))
        {
            return false;
        }

        if (await sponsors.FindAsync(sponsorKey, cancellationToken) is not { } existing)
        {
            return false;
        }

        if (existing.Source != source)
        {
            // Only the source that placed a block may lift it. The refusal is recorded.
            if (!restated)
            {
                await audit.AppendAsync(
                    new AuditEvent(now, AuditEvents.SponsorUnblocked, null, null, sponsorKey, Decision: AuditDecision.Deny, Reason: SponsorAdminService.SponsorBlockNotOwned),
                    cancellationToken);
            }

            return false;
        }

        if (keepsDeletion && existing.PlacedByDeletion)
        {
            return false;
        }

        if (stillStands is not null && await stillStands(cancellationToken))
        {
            return false;
        }

        if (!await sponsors.UnblockAsync(sponsorKey, source, keepsDeletion, cancellationToken))
        {
            return false;
        }

        await audit.AppendAsync(
            new AuditEvent(now, AuditEvents.SponsorSignal, null, null, sponsorKey, Decision: AuditDecision.Allow, Reason: reason),
            cancellationToken);
        return true;
    }

    /// <summary>
    /// Takes the deletion mark off the block <paramref name="source"/> holds on
    /// <paramref name="sponsorKey"/>, if any, because a new record now stands for the person. The
    /// block stays; whether it is lifted is for <see cref="UnblockAsync"/> to decide.
    /// </summary>
    /// <param name="sponsorKey">The human.</param>
    /// <param name="source">The source whose block it is.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task ForgetDeletionAsync(string sponsorKey, SponsorBlockSource source, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);

        return sponsors.ForgetDeletionAsync(sponsorKey, source, cancellationToken);
    }

    /// <summary>
    /// Whether a signal issued at <paramref name="issued"/> is in order for the person, recording it
    /// as the latest when it is. One that is not is refused and recorded as <paramref name="refused"/>
    /// with <see cref="SignalOutOfOrder"/>. The order is decided in the statement that records it,
    /// which keeps the person's watermark row until the unit of work ends, so the next signal for
    /// the same person waits for this one and is then compared against it.
    /// </summary>
    /// <remarks>
    /// Taken only by ordered signals, after the person is held and before the block row, the order
    /// every block writer takes those in.
    /// </remarks>
    private async Task<bool> InOrderAsync(string sponsorKey, DateTimeOffset issued, string refused, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (await sponsors.AdvanceSignalWatermarkAsync(sponsorKey, issued, cancellationToken))
        {
            return true;
        }

        await audit.AppendAsync(
            new AuditEvent(now, refused, null, null, sponsorKey, Decision: AuditDecision.Deny, Reason: SignalOutOfOrder),
            cancellationToken);
        return false;
    }

    /// <summary>Ends the person's live tasks and writes the audit records, if anything changed.</summary>
    private async Task<bool> RecordAsync(string sponsorKey, string reason, string revokedBy, bool blockWritten, DateTimeOffset? signsOutBefore, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var ended = await tasks.RevokeSponsorTasksAsync(sponsorKey, now, reason, cancellationToken);
        if (!blockWritten && ended.Count == 0 && signsOutBefore is null)
        {
            return false;
        }

        var records = new List<AuditEvent>(ended.Count + 1)
        {
            new(now, AuditEvents.SponsorSignal, null, null, sponsorKey, Decision: AuditDecision.Allow, Reason: reason),
        };
        records.AddRange(ended.SelectMany(t => summaries.Ending(RevocationService.Record(t, now, t.IsRoot ? reason : ITaskRevocation.ParentRevoked), t.Renewals)));
        if (ended.Count > 0 || signsOutBefore is not null)
        {
            // Written after the walk above took the person's lock, so an exchange under way reads
            // a sign-out here or finishes first and is ended by the walk.
            await revocations.AddAsync(new Core.Revocation.Revocation(null, null, null, sponsorKey, null, now, reason, revokedBy, IssuedBefore: signsOutBefore), cancellationToken);
        }

        await audit.AppendAsync(records, cancellationToken);
        return true;
    }
}
