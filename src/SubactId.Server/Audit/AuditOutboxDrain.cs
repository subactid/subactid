using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;

namespace SubactId.Server.Audit;

/// <summary>
/// Delivers queued ledger records to the sink on a timer, one batch per transaction.
/// <para>
/// A batch is claimed with an exclusive, skip-locked read, so replicas can drain the same outbox
/// without delivering an entry twice. If the process dies mid-delivery, the claim is released and
/// the entry is retried. A delivered batch is deleted in the same transaction.
/// </para>
/// <para>
/// A failed delivery sets each entry's next attempt with exponential backoff, capped at
/// <see cref="MaxBackoff"/>, and ends the pass. Only counts are logged, never record contents.
/// The first pass runs one interval after start.
/// </para>
/// </summary>
public sealed class AuditOutboxDrain(IServiceScopeFactory scopes, AuditOptions options, TimeProvider clock, ILogger<AuditOutboxDrain> logger)
    : PeriodicBackgroundService(options.DrainInterval, clock, logger)
{
    /// <summary>Longest wait between attempts on one entry.</summary>
    public static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);

    /// <summary>Wait after the given number of failed attempts. Doubles from one second, capped at <see cref="MaxBackoff"/>.</summary>
    /// <param name="attempts">Attempts so far, including the one that just failed.</param>
    public static TimeSpan Backoff(int attempts)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(attempts, 1);

        var seconds = attempts >= 10 ? MaxBackoff.TotalSeconds : Math.Pow(2, attempts - 1);
        return TimeSpan.FromSeconds(Math.Min(seconds, MaxBackoff.TotalSeconds));
    }

    /// <inheritdoc />
    protected override string PassName => "Audit outbox drain";

    /// <inheritdoc />
    protected override async Task RunPassAsync(CancellationToken cancellationToken)
    {
        var delivered = await DrainAsync(cancellationToken);
        if (delivered > 0)
        {
            Logger.LogInformation("Delivered {Count} audit record(s) to the sink.", delivered);
        }
    }

    /// <summary>One pass: batches until one comes back short or the sink fails. Returns how many records were delivered.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> DrainAsync(CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (true)
        {
            var (delivered, failed) = await DrainBatchAsync(cancellationToken);
            total += delivered;
            if (failed || delivered < options.DrainBatchSize)
            {
                return total;
            }
        }
    }

    private async Task<(int Delivered, bool Failed)> DrainBatchAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<IAuditOutboxQueue>();
        var ledger = scope.ServiceProvider.GetRequiredService<IAuditLedgerReader>();
        var checkpoints = scope.ServiceProvider.GetRequiredService<IAuditCheckpointQuery>();
        var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        return await unitOfWork.RunAsync(
            async ct =>
            {
                var entries = await queue.ClaimDueAsync(Clock.GetUtcNow(), options.DrainBatchSize, ct);
                if (entries.Count == 0)
                {
                    return (0, false);
                }

                var ids = entries.Select(e => e.Id).ToList();
                var records = await ledger.ReadBySeqAsync(entries.Select(e => e.AuditSeq).ToList(), ct);
                try
                {
                    if (records.Count != entries.Count)
                    {
                        throw new AuditSinkException("A queued ledger record could not be read.");
                    }

                    // A record not yet sealed goes out with a null checkpoint. A redelivery after
                    // sealing carries the checkpoint that covers it.
                    var sealing = await checkpoints.SealingAsync(records.Select(r => r.Seq).ToList(), ct);
                    await sink.DeliverAsync(records, sealing, ct);
                }
                catch (Exception exception) when (!ct.IsCancellationRequested)
                {
                    // Backoff is measured from the failure, not from the claim.
                    var failedAt = Clock.GetUtcNow();
                    var error = Describe(exception);
                    foreach (var group in entries.GroupBy(e => e.Attempts))
                    {
                        await queue.MarkFailedAsync(group.Select(e => e.Id).ToList(), failedAt, error, failedAt + Backoff(group.Key + 1), ct);
                    }

                    Logger.LogWarning("Delivery of {Count} audit record(s) to the sink failed ({Error}); next attempt in {Backoff}.", entries.Count, error, Backoff(entries.Min(e => e.Attempts) + 1));
                    return (0, true);
                }

                await queue.RemoveDeliveredAsync(ids, ct);
                return (entries.Count, false);
            },
            cancellationToken);
    }

    /// <summary>The exception's type and message. No stack trace or inner exceptions are stored.</summary>
    private static string Describe(Exception exception) => $"{exception.GetType().Name}: {exception.Message}";
}
