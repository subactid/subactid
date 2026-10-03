namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// One signed checkpoint of the audit ledger (spec section 7): the Merkle root over a contiguous
/// range of sequence numbers, linked to the previous checkpoint. Append-only like the ledger: the
/// table refuses <c>UPDATE</c>, <c>DELETE</c> and <c>TRUNCATE</c>.
/// <para>
/// No foreign key to the ledger, because a range can include numbers from rolled-back appends.
/// </para>
/// </summary>
public sealed class AuditCheckpointRow
{
    /// <summary>
    /// The checkpoint's identity, ascending in closing order. Allocated by the sealing pass, since
    /// it is part of the signed bytes.
    /// </summary>
    public long CheckpointId { get; set; }

    /// <summary>Start of the covered range: one past where the previous checkpoint ended, or 1.</summary>
    public long FirstSeq { get; set; }

    /// <summary>End of the covered range. The next checkpoint starts one past it.</summary>
    public long LastSeq { get; set; }

    /// <summary>Records in the range when it was sealed, which is the tree's leaf count.</summary>
    public long TreeSize { get; set; }

    /// <summary>The Merkle root over those records, in sequence order.</summary>
    public required byte[] RootHash { get; set; }

    /// <summary>SHA-256 of the previous checkpoint's signed bytes. Null only for the first checkpoint.</summary>
    public byte[]? PrevCheckpointHash { get; set; }

    /// <summary>When the checkpoint was closed.</summary>
    public DateTimeOffset ClosedAt { get; set; }

    /// <summary>The signing key this checkpoint was signed with.</summary>
    public required string Kid { get; set; }

    /// <summary>The signature over the checkpoint's canonical JSON without this field.</summary>
    public required byte[] Signature { get; set; }
}
