using SubactId.Core.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;

namespace SubactId.Server.Audit;

/// <summary>
/// Keeps <c>SubactId:Audit:Partitions:MonthsAhead</c> months of ledger partitions ahead of the
/// current one, on a timer and once at start.
/// <para>
/// There is no default partition, so a record whose month has no partition is refused and the
/// action it records fails. Partitions are therefore created ahead of time, never on demand.
/// </para>
/// <para>
/// Every replica runs one. Creating a partition is idempotent, so no lock is needed. A failed
/// pass is logged and retried at the next tick. Where the server role may not change the schema,
/// <c>migrate</c> extends the runway instead.
/// </para>
/// </summary>
public sealed class AuditPartitionSweeper(IAuditLedgerPartitions partitions, SubactIdOptions options, TimeProvider clock, ILogger<AuditPartitionSweeper> logger)
    : PeriodicBackgroundService(TopUpInterval, clock, logger, passAtStart: true)
{
    /// <summary>How often the runway is topped up. Not configurable.</summary>
    public static readonly TimeSpan TopUpInterval = TimeSpan.FromHours(1);

    /// <inheritdoc />
    protected override string PassName => "Audit ledger partition top-up";

    /// <inheritdoc />
    protected override async Task RunPassAsync(CancellationToken cancellationToken)
    {
        var monthsAhead = options.Audit.PartitionMonthsAhead;
        var created = await partitions.EnsureAsync(Clock.GetUtcNow(), monthsAhead, cancellationToken);
        if (created > 0)
        {
            Logger.LogInformation("Created {Count} audit ledger partition(s); the ledger now has {Months} month(s) of runway.", created, monthsAhead);
        }
    }
}
