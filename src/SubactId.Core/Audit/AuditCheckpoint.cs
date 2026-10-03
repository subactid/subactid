using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace SubactId.Core.Audit;

/// <summary>
/// A signed seal over a contiguous range of the ledger (spec section 7). It covers
/// <c>[FirstSeq, LastSeq]</c>, starting right after the previous checkpoint. The records in the
/// range, in sequence order, are the leaves of a Merkle tree whose root is signed here. Each
/// checkpoint links to the previous one by the hash of its signed bytes. Records written after
/// the last checkpoint are not yet sealed.
/// <para>
/// The range can contain gaps left by rolled-back appends. <see cref="TreeSize"/> is the number
/// of records actually present, so a record inserted into a gap later is detected.
/// </para>
/// </summary>
/// <param name="CheckpointId">Identity of the checkpoint, ascending in the order they were closed.</param>
/// <param name="FirstSeq">Start of the range this checkpoint covers: one past where the previous one ended, or 1.</param>
/// <param name="LastSeq">End of the range this checkpoint covers; the next one starts one past it.</param>
/// <param name="TreeSize">Leaves in the tree, which is how many records the range held when it was sealed.</param>
/// <param name="RootHash">The Merkle root over those leaves.</param>
/// <param name="PrevCheckpointHash">SHA-256 of the previous checkpoint's signed bytes; <c>null</c> for the first one.</param>
/// <param name="ClosedAt">When the checkpoint was closed.</param>
/// <param name="Kid">The signing key this was signed with.</param>
/// <param name="Signature">The signature over <see cref="AuditCheckpointHash.SignedBytes"/>.</param>
public sealed record AuditCheckpoint(
    long CheckpointId,
    long FirstSeq,
    long LastSeq,
    long TreeSize,
    ReadOnlyMemory<byte> RootHash,
    ReadOnlyMemory<byte>? PrevCheckpointHash,
    DateTimeOffset ClosedAt,
    string Kid,
    ReadOnlyMemory<byte> Signature);

/// <summary>
/// The bytes a checkpoint is signed over and chained by: its canonical JSON without
/// <c>signature</c>. Keys in lexicographic order, no whitespace, explicit nulls, hashes as
/// lowercase hex, and the timestamp in <see cref="AuditHash.TimestampFormat"/>.
/// </summary>
public static class AuditCheckpointHash
{
    /// <summary>Length of a checkpoint link hash in bytes.</summary>
    public const int Length = 32;

    /// <summary>
    /// A record's leaf in its checkpoint's tree: the RFC 6962 leaf hash of its canonical JSON.
    /// Shared by the sealing pass, the verifier and the proof endpoint.
    /// </summary>
    /// <param name="record">The record as written.</param>
    public static byte[] Leaf(AuditEvent record) => MerkleTree.Leaf(AuditHash.CanonicalJson(record));

    /// <summary>The canonical JSON of <paramref name="checkpoint"/> without its signature, as UTF-8.</summary>
    /// <param name="checkpoint">The checkpoint.</param>
    public static byte[] SignedBytes(AuditCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("checkpoint_id", checkpoint.CheckpointId);
            writer.WriteString("closed_at", checkpoint.ClosedAt.ToUniversalTime().ToString(AuditHash.TimestampFormat, CultureInfo.InvariantCulture));
            writer.WriteNumber("first_seq", checkpoint.FirstSeq);
            writer.WriteString("kid", checkpoint.Kid);
            writer.WriteNumber("last_seq", checkpoint.LastSeq);
            if (checkpoint.PrevCheckpointHash is { } previous)
            {
                writer.WriteString("prev_checkpoint_hash", Convert.ToHexStringLower(previous.Span));
            }
            else
            {
                writer.WriteNull("prev_checkpoint_hash");
            }

            writer.WriteString("root_hash", Convert.ToHexStringLower(checkpoint.RootHash.Span));
            writer.WriteNumber("tree_size", checkpoint.TreeSize);
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// The hash the next checkpoint links to: SHA-256 of the signed bytes, not the signature, so
    /// the chain survives key rotation.
    /// </summary>
    /// <param name="checkpoint">The checkpoint.</param>
    public static byte[] LinkHash(AuditCheckpoint checkpoint) => SHA256.HashData(SignedBytes(checkpoint));
}

/// <summary>
/// Checks a checkpoint's signature. Implemented where the signing keys live.
/// </summary>
public interface IAuditCheckpointSignatures
{
    /// <summary>Whether <paramref name="signature"/> is a signature over <paramref name="signedBytes"/> by the published key <paramref name="kid"/>.</summary>
    /// <param name="kid">The key the checkpoint names.</param>
    /// <param name="signedBytes">The canonical bytes that were signed.</param>
    /// <param name="signature">The signature stored with the checkpoint.</param>
    bool Verify(string kid, ReadOnlySpan<byte> signedBytes, ReadOnlySpan<byte> signature);
}

/// <summary>Read-only, ordered access to the checkpoints. One projected query per page.</summary>
public interface IAuditCheckpointQuery
{
    /// <summary>Up to <paramref name="limit"/> checkpoints with an id above <paramref name="afterId"/>, in id order.</summary>
    Task<IReadOnlyList<AuditCheckpoint>> ReadAsync(long afterId, int limit, CancellationToken cancellationToken = default);

    /// <summary>The checkpoint whose range covers <paramref name="seq"/>, or <c>null</c> when that record is not sealed yet.</summary>
    Task<AuditCheckpoint?> SealingAsync(long seq, CancellationToken cancellationToken = default);

    /// <summary>The checkpoint that covers each of <paramref name="seqs"/>, keyed by sequence number. Unsealed records are absent.</summary>
    Task<IReadOnlyDictionary<long, long>> SealingAsync(IReadOnlyList<long> seqs, CancellationToken cancellationToken = default);
}

/// <summary>Writes checkpoints, and reads what the sealing pass needs to write the next one.</summary>
public interface IAuditCheckpointRepository
{
    /// <summary>
    /// The last checkpoint written, or <c>null</c> when there is none. Read inside the sealing
    /// transaction.
    /// </summary>
    Task<AuditCheckpoint?> LastAsync(CancellationToken cancellationToken = default);

    /// <summary>Appends <paramref name="checkpoint"/>. Checkpoints are never updated.</summary>
    Task AppendAsync(AuditCheckpoint checkpoint, CancellationToken cancellationToken = default);

    /// <summary>
    /// The highest sequence number at or below which every record is committed. Read under the
    /// exclusive seal fence in a transaction of its own.
    /// </summary>
    Task<long> FenceHighWaterMarkAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Claims the right to seal for the rest of the current transaction. Returns <c>false</c>
    /// without waiting when another instance holds it.
    /// </summary>
    Task<bool> TryClaimSealAsync(CancellationToken cancellationToken = default);
}
