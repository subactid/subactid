using SubactId.Core.Audit;

namespace SubactId.Server.Audit;

/// <summary>What verifying an export found.</summary>
/// <param name="Seal">How far the checkpoints in it held, and the first fault if they did not.</param>
/// <param name="Records">Records the export carried inside those checkpoints.</param>
/// <param name="Complete">Whether every record in the export is inside one of its checkpoints.</param>
public sealed record AuditArchiveReport(AuditCheckpointReport Seal, long Records, bool Complete)
{
    /// <summary>Whether the export is exactly what its checkpoints sealed.</summary>
    public bool IsIntact => Seal.IsIntact && Complete;
}

/// <summary>
/// Verifies an export on its own. Each checkpoint is checked against the published key set and
/// the checkpoint before it, and each root against the tree rebuilt from the export's records.
/// Nothing is read from the database.
/// </summary>
public static class AuditArchiveVerification
{
    /// <summary>
    /// Walks <paramref name="archive"/> and reports how far it held. Records are streamed, so
    /// memory use is one checkpoint's leaves.
    /// </summary>
    /// <param name="archive">The export, positioned at its records section.</param>
    /// <param name="signatures">Where a checkpoint's signature is checked.</param>
    /// <param name="sealedBefore">The checkpoint the export's first one must follow, if known. <c>null</c> uses the export's own start.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<AuditArchiveReport> VerifyAsync(
        AuditArchiveReader archive,
        IAuditCheckpointSignatures signatures,
        AuditCheckpoint? sealedBefore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(signatures);

        var verifier = new AuditCheckpointVerifier(signatures, Floor(archive, sealedBefore));
        var records = 0L;
        var next = await archive.ReadRecordAsync(cancellationToken);
        foreach (var checkpoint in archive.Checkpoints)
        {
            // Read the checkpoint's whole range so an inserted record fails the leaf count.
            // A record below the range stays unread and fails the range check.
            var leaves = new List<AuditLedgerRecord>();
            while (next is { } record && record.Seq <= checkpoint.LastSeq)
            {
                leaves.Add(record);
                records++;
                next = await archive.ReadRecordAsync(cancellationToken);
            }

            if (!verifier.Feed(checkpoint, leaves))
            {
                return new AuditArchiveReport(verifier.Report, records, true);
            }
        }

        // A record that no checkpoint seals was added to the file, so the export is incomplete.
        return new AuditArchiveReport(verifier.Report, records, next is null);
    }

    /// <summary>
    /// Where the walk of an export begins. Only the ledger's first export starts at checkpoint 1.
    /// A later export continues from the one before it, which only that export or the ledger can confirm.
    /// </summary>
    private static AuditCheckpointFloor? Floor(AuditArchiveReader archive, AuditCheckpoint? sealedBefore)
    {
        if (sealedBefore is not null)
        {
            return new AuditCheckpointFloor(sealedBefore.CheckpointId + 1, sealedBefore);
        }

        return archive.Header.FirstCheckpointId <= 1 ? null : new AuditCheckpointFloor(archive.Header.FirstCheckpointId);
    }
}
