using System.Text.Json.Serialization;
using SubactId.Core.Audit;

namespace SubactId.Server.Contracts;

/// <summary>
/// One signed checkpoint as published by <c>GET /audit/checkpoints</c> (spec section 7), with
/// hashes and signature as lowercase hex.
/// <para>
/// The field names are the keys of the signed canonical JSON, minus <c>signature</c>. Renaming
/// one breaks outside verification.
/// </para>
/// </summary>
public sealed class AuditCheckpointPayload
{
    /// <summary>The checkpoint's id, ascending in the order they were closed.</summary>
    public required long CheckpointId { get; init; }

    /// <summary>Start of the range it covers: one past where the previous checkpoint ended, or 1.</summary>
    public required long FirstSeq { get; init; }

    /// <summary>End of the range it covers.</summary>
    public required long LastSeq { get; init; }

    /// <summary>Records the range held when it was sealed, which is the tree's leaf count.</summary>
    public required long TreeSize { get; init; }

    /// <summary>The Merkle root over those records, as lowercase hex.</summary>
    public required string RootHash { get; init; }

    /// <summary>SHA-256 of the previous checkpoint's signed bytes as lowercase hex. <c>null</c> for the first checkpoint.</summary>
    public required string? PrevCheckpointHash { get; init; }

    /// <summary>When the checkpoint was closed, written exactly as it was signed.</summary>
    [JsonConverter(typeof(AuditTimestampConverter))]
    public required DateTimeOffset ClosedAt { get; init; }

    /// <summary>The key it was signed with, as published in JWKS.</summary>
    public required string Kid { get; init; }

    /// <summary>The ES256 signature over the canonical JSON of the fields above, as lowercase hex.</summary>
    public required string Signature { get; init; }

    /// <summary>The payload for a checkpoint.</summary>
    /// <param name="checkpoint">The checkpoint as stored.</param>
    public static AuditCheckpointPayload From(AuditCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        return new AuditCheckpointPayload
        {
            CheckpointId = checkpoint.CheckpointId,
            FirstSeq = checkpoint.FirstSeq,
            LastSeq = checkpoint.LastSeq,
            TreeSize = checkpoint.TreeSize,
            RootHash = Convert.ToHexStringLower(checkpoint.RootHash.Span),
            PrevCheckpointHash = checkpoint.PrevCheckpointHash is { } previous ? Convert.ToHexStringLower(previous.Span) : null,
            ClosedAt = checkpoint.ClosedAt,
            Kid = checkpoint.Kid,
            Signature = Convert.ToHexStringLower(checkpoint.Signature.Span),
        };
    }
}

/// <summary>One page of <c>GET /audit/checkpoints</c>: the checkpoints in id order, and where the next page starts.</summary>
/// <param name="Checkpoints">The checkpoints of this page, oldest first.</param>
/// <param name="NextAfter">Pass as <c>after</c> for the next page. <c>null</c> on the last page.</param>
public sealed record AuditCheckpointsResponse(
    [property: JsonPropertyName("checkpoints")] IReadOnlyList<AuditCheckpointPayload> Checkpoints,
    [property: JsonPropertyName("next_after")] long? NextAfter)
{
    /// <summary>
    /// Builds the page from up to one checkpoint more than the page size. The extra one only
    /// signals a next page and is not returned.
    /// </summary>
    /// <param name="checkpoints">Up to <paramref name="limit"/> + 1 checkpoints.</param>
    /// <param name="limit">The page size asked for.</param>
    public static AuditCheckpointsResponse From(IReadOnlyList<AuditCheckpoint> checkpoints, int limit)
    {
        ArgumentNullException.ThrowIfNull(checkpoints);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        var page = checkpoints.Take(limit).ToList();
        var next = checkpoints.Count > limit ? page[^1].CheckpointId : (long?)null;
        return new AuditCheckpointsResponse(page.Select(AuditCheckpointPayload.From).ToList(), next);
    }
}

/// <summary>
/// The answer of <c>GET /audit/records/{seq}/proof</c>: an inclusion proof for one record. A
/// verifier recomputes the record's leaf, folds the path over it, and compares the result with
/// <c>root_hash</c> after checking the checkpoint's signature against JWKS.
/// </summary>
public sealed class AuditProofResponse
{
    /// <summary>The record being proved.</summary>
    public required long Seq { get; init; }

    /// <summary>The checkpoint that seals it, exactly as <c>GET /audit/checkpoints</c> publishes it.</summary>
    public required AuditCheckpointPayload Checkpoint { get; init; }

    /// <summary>The record's position among the checkpoint's leaves, counted from zero in sequence order.</summary>
    public required long LeafIndex { get; init; }

    /// <summary>The audit path as lowercase hex, closest sibling first. Empty when the checkpoint sealed one record.</summary>
    public required IReadOnlyList<string> AuditPath { get; init; }
}
