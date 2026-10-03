namespace SubactId.Core.Audit;

/// <summary>What is wrong with the seal at a checkpoint.</summary>
public enum AuditCheckpointFault
{
    /// <summary>Everything fed so far holds.</summary>
    None,

    /// <summary>The signature does not verify, or the key it names is not one this control plane publishes.</summary>
    BadSignature,

    /// <summary>
    /// The <c>prev_checkpoint_hash</c> or the range does not follow from the previous checkpoint.
    /// A checkpoint was removed, inserted or replaced.
    /// </summary>
    BrokenChain,

    /// <summary>The records in the checkpoint's range no longer build the root it signed: one was edited, removed or inserted.</summary>
    TamperedRecords,

    /// <summary>A checkpoint recorded earlier is gone or no longer signs the same root: the tail was cut or rewritten.</summary>
    Truncated,
}

/// <summary>
/// A checkpoint verified earlier and stored outside the database. Confirming against it detects
/// a truncated ledger.
/// </summary>
/// <param name="CheckpointId">The checkpoint's id.</param>
/// <param name="RootHash">The root it signed.</param>
public sealed record AuditCheckpointMark(long CheckpointId, ReadOnlyMemory<byte> RootHash);

/// <summary>
/// Where a walk begins when the oldest months have been archived (spec section 7.5). Their
/// checkpoints remain in the table, but their records are gone.
/// </summary>
/// <param name="CheckpointId">The first checkpoint the walk must find: one past the last archived one.</param>
/// <param name="Archived">
/// The last archived checkpoint, used to check the link and sequence continuity at the boundary.
/// When <c>null</c>, the first checkpoint's link and start are accepted as given.
/// </param>
public sealed record AuditCheckpointFloor(long CheckpointId, AuditCheckpoint? Archived = null);

/// <summary>The result of walking the checkpoints: how far the seal held, and the first fault if it did not.</summary>
/// <param name="Verified">Checkpoints that verified, in order, before the fault or the end.</param>
/// <param name="SealedRecords">Records those checkpoints sealed between them.</param>
/// <param name="LastCheckpointId">The last verified checkpoint's id; 0 when none verified.</param>
/// <param name="LastSeq">The end of the sealed range; 0 when none verified.</param>
/// <param name="Fault">The first fault found.</param>
/// <param name="FaultCheckpointId">The checkpoint the fault was found at.</param>
public sealed record AuditCheckpointReport(
    long Verified,
    long SealedRecords,
    long LastCheckpointId,
    long LastSeq,
    AuditCheckpointFault Fault,
    long? FaultCheckpointId)
{
    /// <summary>Whether every checkpoint fed so far held.</summary>
    public bool IsIntact => Fault == AuditCheckpointFault.None;
}

/// <summary>
/// Walks the checkpoints in id order and checks each one's signature, its link to the previous
/// checkpoint, and, when records are supplied, its root against the rebuilt tree.
/// <para>
/// Pure apart from the delegated signature check. Checkpoints after a fault are not examined.
/// </para>
/// </summary>
/// <param name="signatures">Where a checkpoint's signature is checked.</param>
/// <param name="floor">Where the walk begins when the ledger has been archived; <c>null</c> when nothing was archived.</param>
public sealed class AuditCheckpointVerifier(IAuditCheckpointSignatures signatures, AuditCheckpointFloor? floor = null)
{
    private readonly Dictionary<long, byte[]> seen = [];
    private readonly HashSet<long> watched = [];
    private long verified;
    private long sealedRecords;
    private AuditCheckpoint? previous;

    /// <summary>What the next checkpoint must link to: the last verified one, or the floor's archived one.</summary>
    private AuditCheckpoint? link = floor?.Archived;

    private AuditCheckpointFault fault;
    private long? faultCheckpointId;

    /// <summary>The report so far.</summary>
    public AuditCheckpointReport Report => new(
        verified,
        sealedRecords,
        previous?.CheckpointId ?? 0,
        previous?.LastSeq ?? 0,
        fault,
        faultCheckpointId);

    /// <summary>The last verified checkpoint, or <c>null</c> before any. Keep it for a later run.</summary>
    public AuditCheckpointMark? Mark => previous is { } last ? new AuditCheckpointMark(last.CheckpointId, last.RootHash) : null;

    /// <summary>Remembers the root seen at <paramref name="checkpointId"/> so <see cref="Confirm"/> can check a mark there.</summary>
    /// <param name="checkpointId">A checkpoint a mark will be confirmed at.</param>
    public void Watch(long checkpointId) => watched.Add(checkpointId);

    /// <summary>
    /// Records a checkpoint below the floor so a mark at it can still be confirmed after its month
    /// was archived. Only the signature is checked. The link and records are checked in the export.
    /// </summary>
    /// <param name="checkpoint">A checkpoint with an id below the floor's, read from the ledger.</param>
    /// <returns><c>false</c> at a fault, as <see cref="Feed"/> does; nothing after it is examined.</returns>
    public bool Note(AuditCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        if (floor is null || checkpoint.CheckpointId >= floor.CheckpointId)
        {
            throw new ArgumentException("Only a checkpoint below the floor is noted; one at or above it is walked.", nameof(checkpoint));
        }

        if (previous is not null)
        {
            throw new InvalidOperationException("A checkpoint below the floor is noted before the walk begins, not during it.");
        }

        if (fault != AuditCheckpointFault.None)
        {
            return false;
        }

        if (!signatures.Verify(checkpoint.Kid, AuditCheckpointHash.SignedBytes(checkpoint), checkpoint.Signature.Span))
        {
            return Fail(AuditCheckpointFault.BadSignature, checkpoint.CheckpointId);
        }

        seen[checkpoint.CheckpointId] = checkpoint.RootHash.ToArray();
        return true;
    }

    /// <summary>
    /// Checks that a checkpoint recorded earlier was seen in this walk with the same root.
    /// Otherwise the tail was cut or rewritten.
    /// </summary>
    /// <param name="expected">The checkpoint recorded earlier.</param>
    public bool Confirm(AuditCheckpointMark expected)
    {
        ArgumentNullException.ThrowIfNull(expected);

        if (fault != AuditCheckpointFault.None)
        {
            return false;
        }

        var root = seen.GetValueOrDefault(expected.CheckpointId);
        if (root is null || !root.AsSpan().SequenceEqual(expected.RootHash.Span))
        {
            return Fail(AuditCheckpointFault.Truncated, expected.CheckpointId);
        }

        return true;
    }

    /// <summary>
    /// Checks <paramref name="checkpoint"/> against the seal so far. Returns <c>false</c> at the
    /// first fault; later checkpoints are ignored.
    /// </summary>
    /// <param name="checkpoint">The next checkpoint in id order.</param>
    /// <param name="records">
    /// Every record in <c>[FirstSeq, LastSeq]</c>, in sequence order, to recompute the root from.
    /// <c>null</c> checks only the signature and chain. The whole range must be read, or a record
    /// inserted into a gap is missed.
    /// </param>
    public bool Feed(AuditCheckpoint checkpoint, IReadOnlyList<AuditLedgerRecord>? records = null)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        if (fault != AuditCheckpointFault.None)
        {
            return false;
        }

        if (previous is { } last && checkpoint.CheckpointId <= last.CheckpointId)
        {
            throw new ArgumentException($"Checkpoints must be fed in id order; {checkpoint.CheckpointId} came after {last.CheckpointId}.", nameof(checkpoint));
        }

        if (previous is null && floor is { } start && checkpoint.CheckpointId != start.CheckpointId)
        {
            // The first online checkpoint must directly follow the archived ones.
            return Fail(AuditCheckpointFault.BrokenChain, checkpoint.CheckpointId);
        }

        var signed = AuditCheckpointHash.SignedBytes(checkpoint);
        if (!signatures.Verify(checkpoint.Kid, signed, checkpoint.Signature.Span))
        {
            return Fail(AuditCheckpointFault.BadSignature, checkpoint.CheckpointId);
        }

        if (!LinksToPrevious(checkpoint) || !CoversOnFromPrevious(checkpoint))
        {
            return Fail(AuditCheckpointFault.BrokenChain, checkpoint.CheckpointId);
        }

        if (records is not null && !SealsExactly(checkpoint, records))
        {
            return Fail(AuditCheckpointFault.TamperedRecords, checkpoint.CheckpointId);
        }

        verified++;
        sealedRecords += checkpoint.TreeSize;
        previous = checkpoint;
        link = checkpoint;
        if (watched.Contains(checkpoint.CheckpointId))
        {
            seen[checkpoint.CheckpointId] = checkpoint.RootHash.ToArray();
        }

        return true;
    }

    /// <summary>Whether <paramref name="checkpoint"/> names the hash of the checkpoint before it, and nothing before the first one.</summary>
    private bool LinksToPrevious(AuditCheckpoint checkpoint)
    {
        var stored = checkpoint.PrevCheckpointHash is { } linked ? linked.Span : ReadOnlySpan<byte>.Empty;
        if (link is { } last)
        {
            return stored.SequenceEqual(AuditCheckpointHash.LinkHash(last));
        }

        // No link target: either the ledger's first checkpoint, which links to nothing, or a floor
        // without its archived checkpoint, whose link is checked against the export instead.
        return (previous is null && floor is not null) || stored.IsEmpty;
    }

    /// <summary>
    /// Whether the range is valid and starts right after the previous one, with no gap or overlap.
    /// </summary>
    private bool CoversOnFromPrevious(AuditCheckpoint checkpoint)
    {
        if (checkpoint.TreeSize < 1 || checkpoint.FirstSeq < 1 || checkpoint.FirstSeq > checkpoint.LastSeq)
        {
            return false;
        }

        if (link is { } last)
        {
            return checkpoint.FirstSeq == last.LastSeq + 1;
        }

        // At a floor without its archived checkpoint, the start is accepted. See LinksToPrevious.
        return (previous is null && floor is not null) || checkpoint.FirstSeq == 1;
    }

    /// <summary>
    /// Whether <paramref name="records"/> match what the checkpoint sealed: the same count, every
    /// sequence number inside the range, and the same root.
    /// </summary>
    private static bool SealsExactly(AuditCheckpoint checkpoint, IReadOnlyList<AuditLedgerRecord> records)
    {
        if (records.Count != checkpoint.TreeSize)
        {
            return false;
        }

        var leaves = new byte[records.Count][];
        for (var i = 0; i < records.Count; i++)
        {
            var record = records[i];
            if (record.Seq < checkpoint.FirstSeq || record.Seq > checkpoint.LastSeq || (i > 0 && record.Seq <= records[i - 1].Seq))
            {
                return false;
            }

            leaves[i] = AuditCheckpointHash.Leaf(record.Event);
        }

        return MerkleTree.Root(leaves).AsSpan().SequenceEqual(checkpoint.RootHash.Span);
    }

    private bool Fail(AuditCheckpointFault kind, long checkpointId)
    {
        fault = kind;
        faultCheckpointId = checkpointId;
        return false;
    }
}
