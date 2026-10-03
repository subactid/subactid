using SubactId.Core.Audit;
using SubactId.Server.Hosting;

namespace SubactId.Server.Audit;

/// <summary>
/// Writes each window's accumulated denial counts as one batch per pass. Each pass is a single
/// chained append, so the audit chain lock is taken once per window.
/// </summary>
/// <remarks>
/// A failed write hands the window's summaries back to the aggregator, so their counts are written
/// by the next pass instead of being lost. Only a process that stops without a final flush loses
/// a window's counts.
/// </remarks>
/// <param name="aggregator">The counts.</param>
/// <param name="scopes">Scope factory, for the scoped writer.</param>
/// <param name="options">The window.</param>
/// <param name="clock">The clock the timer runs on.</param>
/// <param name="logger">Where failed passes are reported.</param>
public sealed class DenialAggregationFlusher(
    DenialAggregator aggregator,
    IServiceScopeFactory scopes,
    DenialAggregationOptions options,
    TimeProvider clock,
    ILogger<DenialAggregationFlusher> logger)
    : PeriodicBackgroundService(options.Window, clock, logger)
{
    /// <inheritdoc />
    protected override string PassName => "Denial aggregation flush";

    /// <inheritdoc />
    protected override Task RunPassAsync(CancellationToken cancellationToken) => FlushAsync(cancellationToken);

    /// <summary>Writes the current window's counts, if any. Returns how many summary records were written.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> FlushAsync(CancellationToken cancellationToken = default)
    {
        var summaries = aggregator.Drain();
        if (summaries.Count == 0)
        {
            return 0;
        }

        try
        {
            using var scope = scopes.CreateScope();
            var audit = scope.ServiceProvider.GetRequiredService<IAuditWriter>();
            await audit.AppendAsync(summaries, cancellationToken);
            return summaries.Count;
        }
        catch
        {
            // Nothing of a failed batch was committed, so every count goes back for the next pass.
            foreach (var summary in summaries)
            {
                aggregator.CarryOver(summary);
            }

            throw;
        }
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);

        // A graceful stop writes the last window's counts.
        try
        {
            await FlushAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Logger.LogError(exception, "The final denial aggregation flush failed; the last window's counts could not be written before the process stopped.");
        }
    }
}
