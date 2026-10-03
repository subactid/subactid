using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Audit;

/// <summary>
/// Seals the ledger on a timer. Each pass builds a Merkle tree over the records no checkpoint
/// covers yet, in sequence order, signs the root with the active signing key and links the
/// checkpoint to the previous one. Ledger rows are never updated.
/// <para>
/// The high-water mark is read under the seal fence, held exclusively in its own transaction.
/// The fence is granted only after every in-flight append commits, so no record can later appear
/// below a signed root. The pass itself runs under a separate claim so two instances never seal
/// the same range. An instance that cannot take the claim skips the pass.
/// </para>
/// <para>
/// Every replica runs one. A failed pass is logged and retried at the next tick. Only counts are
/// logged. The first pass runs one interval after start.
/// </para>
/// </summary>
public sealed class AuditCheckpointSealer(
    IServiceScopeFactory scopes,
    SubactIdOptions options,
    SigningKeySet signingKeys,
    TimeProvider clock,
    ILogger<AuditCheckpointSealer> logger)
    : PeriodicBackgroundService(options.Audit.CheckpointInterval, clock, logger)
{
    /// <summary>
    /// Most records sealed by one checkpoint. Each checkpoint's leaves are held in memory, so a
    /// larger range is sealed as several checkpoints.
    /// </summary>
    public const int MaxRecordsPerCheckpoint = 50_000;

    /// <summary>The cap this sealer uses. Defaults to <see cref="MaxRecordsPerCheckpoint"/>. Set only by tests.</summary>
    public int MaxRecords { get; init; } = MaxRecordsPerCheckpoint;

    /// <inheritdoc />
    protected override string PassName => "Audit checkpoint seal";

    /// <inheritdoc />
    protected override async Task RunPassAsync(CancellationToken cancellationToken)
    {
        var (checkpoints, records) = await SealAsync(cancellationToken);
        if (checkpoints > 0)
        {
            Logger.LogInformation("Sealed {Records} audit record(s) in {Checkpoints} checkpoint(s).", records, checkpoints);
        }
    }

    /// <summary>
    /// One pass: reads the high-water mark once, then seals up to it, a checkpoint at a time,
    /// until there is nothing left below the mark.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>How many checkpoints were written and how many records they sealed.</returns>
    public async Task<(int Checkpoints, long Records)> SealAsync(CancellationToken cancellationToken = default)
    {
        var mark = await HighWaterMarkAsync(cancellationToken);
        var checkpoints = 0;
        var records = 0L;
        while (true)
        {
            var sealedNow = await SealChunkAsync(mark, cancellationToken);
            if (sealedNow == 0)
            {
                return (checkpoints, records);
            }

            checkpoints++;
            records += sealedNow;
        }
    }

    /// <summary>
    /// The highest sequence number below which no new record can appear. Read under the fence in
    /// its own transaction, once per pass.
    /// </summary>
    private async Task<long> HighWaterMarkAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var checkpoints = scope.ServiceProvider.GetRequiredService<IAuditCheckpointRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        return await unitOfWork.RunAsync(checkpoints.FenceHighWaterMarkAsync, cancellationToken);
    }

    /// <summary>
    /// Writes one checkpoint in one transaction. Returns how many records it sealed, or 0 when
    /// there was nothing to seal or another instance holds the claim.
    /// </summary>
    private async Task<int> SealChunkAsync(long mark, CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var checkpoints = scope.ServiceProvider.GetRequiredService<IAuditCheckpointRepository>();
        var ledger = scope.ServiceProvider.GetRequiredService<IAuditLedgerReader>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        return await unitOfWork.RunAsync(
            async ct =>
            {
                if (!await checkpoints.TryClaimSealAsync(ct))
                {
                    return 0;
                }

                // Read inside the claim, never cached, so this checkpoint extends the latest seal.
                var previous = await checkpoints.LastAsync(ct);
                var firstSeq = (previous?.LastSeq ?? 0) + 1;
                if (firstSeq > mark)
                {
                    return 0;
                }

                // Read one more than the cap to know whether the range exceeds it.
                var found = await ledger.ReadRangeAsync(firstSeq - 1, mark, MaxRecords + 1, ct);
                if (found.Count == 0)
                {
                    // Every number in the range belongs to a rolled-back append. The range stays
                    // open until a later checkpoint covers it.
                    return 0;
                }

                var records = found.Count > MaxRecords ? found.Take(MaxRecords).ToList() : found;
                var lastSeq = records.Count < found.Count ? records[^1].Seq : mark;
                await checkpoints.AppendAsync(Sign(previous, firstSeq, lastSeq, records), ct);
                return records.Count;
            },
            cancellationToken);
    }

    /// <summary>The checkpoint over <paramref name="records"/>, linked to <paramref name="previous"/> and signed.</summary>
    private AuditCheckpoint Sign(AuditCheckpoint? previous, long firstSeq, long lastSeq, IReadOnlyList<AuditLedgerRecord> records)
    {
        var leaves = records.Select(record => AuditCheckpointHash.Leaf(record.Event)).ToList();
        var unsigned = new AuditCheckpoint(
            (previous?.CheckpointId ?? 0) + 1,
            firstSeq,
            lastSeq,
            records.Count,
            MerkleTree.Root(leaves),
            previous is null ? null : (ReadOnlyMemory<byte>?)AuditCheckpointHash.LinkHash(previous),
            // Truncated to milliseconds so the published timestamp matches the signed one.
            Millisecond(Clock.GetUtcNow()),
            signingKeys.Active.Kid,
            ReadOnlyMemory<byte>.Empty);

        return unsigned with { Signature = signingKeys.Active.Sign(AuditCheckpointHash.SignedBytes(unsigned)) };
    }

    /// <summary>The instant in UTC, truncated to the millisecond precision of the signed bytes.</summary>
    private static DateTimeOffset Millisecond(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return utc.AddTicks(-(utc.Ticks % TimeSpan.TicksPerMillisecond));
    }
}
