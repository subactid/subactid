using SubactId.Core.Audit;
using SubactId.Core.Validation;
using SubactId.Server.Admin;
using SubactId.Server.Contracts;

namespace SubactId.Server.Audit;

/// <summary>
/// The read side of spec section 7: <c>GET /audit</c> (the ledger, filtered),
/// <c>GET /audit/checkpoints</c> (the signed seals) and <c>GET /audit/records/{seq}/proof</c>
/// (the path from one record to a checkpoint's root). All three require the admin API key.
/// </summary>
public static class AuditEndpoints
{
    /// <summary>Route of the audit query.</summary>
    public const string Path = "/audit";

    /// <summary>Route of the checkpoint listing.</summary>
    public const string CheckpointsPath = "/audit/checkpoints";

    /// <summary>Route of a record's inclusion proof.</summary>
    public const string ProofPath = "/audit/records/{seq}/proof";

    /// <summary>Maps the audit query, the checkpoint listing and the proof behind <see cref="AdminApiKeyFilter"/>.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdAuditEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet(Path, async (
            [AsParameters] QueryAuditRequest request,
            IAuditQuery audit,
            IAuditCheckpointQuery checkpoints,
            IAuditArchiveRepository archives,
            CancellationToken cancellationToken) =>
        {
            var errors = request.TryToQuery(out var query);
            if (errors.Count > 0)
            {
                return ValidationProblems.ToResult(errors);
            }

            // Fetch one extra record to know whether there is a next page.
            var records = await audit.QueryAsync(query! with { Limit = query.Limit + 1 }, cancellationToken);
            var page = records.Take(query.Limit).ToList();

            // One lookup for the whole page. Records not yet sealed are absent from the result.
            var sealing = await checkpoints.SealingAsync(page.Select(r => r.Seq).ToList(), cancellationToken);

            // Included on every page so an empty page can be told apart from an archived range.
            var archived = await archives.LastAsync(cancellationToken);
            return Results.Ok(AuditQueryResponse.From(records, query.Limit, sealing, archived));
        }).AddEndpointFilter<AdminApiKeyFilter>();

        endpoints.MapGet(CheckpointsPath, async (
            [AsParameters] QueryAuditCheckpointsRequest request,
            IAuditCheckpointQuery checkpoints,
            CancellationToken cancellationToken) =>
        {
            var errors = request.TryToQuery(out var after, out var limit);
            if (errors.Count > 0)
            {
                return ValidationProblems.ToResult(errors);
            }

            var page = await checkpoints.ReadAsync(after, limit + 1, cancellationToken);
            return Results.Ok(AuditCheckpointsResponse.From(page, limit));
        }).AddEndpointFilter<AdminApiKeyFilter>();

        endpoints.MapGet(ProofPath, async (
            long seq,
            IAuditCheckpointQuery checkpoints,
            IAuditLedgerReader ledger,
            IAuditArchiveRepository archives,
            CancellationToken cancellationToken) =>
        {
            if (seq < 1)
            {
                return ValidationProblems.ToResult([new ValidationError("seq", "must be a positive whole number.")]);
            }

            var checkpoint = await checkpoints.SealingAsync(seq, cancellationToken);
            if (checkpoint is null)
            {
                // No such record, or not sealed yet. The audit query tells the two apart.
                return Results.NotFound();
            }

            // The checkpoint's records are archived, so the proof can only come from the export.
            if (await archives.LastAsync(cancellationToken) is { } archived && checkpoint.CheckpointId <= archived.LastCheckpointId)
            {
                return Results.Problem(
                    title: "The checkpoint that seals this record has been archived.",
                    detail: $"Checkpoint {checkpoint.CheckpointId} seals records the ledger no longer holds; nothing before {AuditArchive.MonthName(archived.ArchivedBefore)} is online. The proof is in the export, which 'SubactId.Server audit-verify --archive' reads.",
                    statusCode: StatusCodes.Status410Gone);
            }

            return await ProofAsync(seq, checkpoint, ledger, cancellationToken);
        }).AddEndpointFilter<AdminApiKeyFilter>();
    }

    /// <summary>
    /// Rebuilds the checkpoint's tree from the whole range it sealed and returns the path from
    /// <paramref name="seq"/> to its root.
    /// </summary>
    private static async Task<IResult> ProofAsync(long seq, AuditCheckpoint checkpoint, IAuditLedgerReader ledger, CancellationToken cancellationToken)
    {
        // Read one more than the tree size so a record inserted into the range is detected.
        var records = await ledger.ReadRangeAsync(checkpoint.FirstSeq - 1, checkpoint.LastSeq, checked((int)checkpoint.TreeSize) + 1, cancellationToken);
        var index = -1;
        var leaves = new byte[records.Count][];
        for (var i = 0; i < records.Count; i++)
        {
            leaves[i] = AuditCheckpointHash.Leaf(records[i].Event);
            if (records[i].Seq == seq)
            {
                index = i;
            }
        }

        if (records.Count != checkpoint.TreeSize || !MerkleTree.Root(leaves).AsSpan().SequenceEqual(checkpoint.RootHash.Span))
        {
            // The range no longer matches what was sealed, so no valid proof exists. The root is
            // compared as well as the count, since a swapped record keeps the count.
            // audit-verify reports which record changed.
            return Results.Problem(
                title: "The ledger no longer matches its checkpoint.",
                detail: $"Checkpoint {checkpoint.CheckpointId} sealed {checkpoint.TreeSize} record(s) in [{checkpoint.FirstSeq}, {checkpoint.LastSeq}] and the records found do not rebuild the root it signed. Run audit-verify.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        if (index < 0)
        {
            // The range is intact but has no record at this number: an append took the number
            // and rolled back. That is "no such record", not a fault.
            return Results.NotFound();
        }

        return Results.Ok(new AuditProofResponse
        {
            Seq = seq,
            Checkpoint = AuditCheckpointPayload.From(checkpoint),
            LeafIndex = index,
            AuditPath = MerkleTree.Path(leaves, index).Select(step => Convert.ToHexStringLower(step)).ToList(),
        });
    }
}
