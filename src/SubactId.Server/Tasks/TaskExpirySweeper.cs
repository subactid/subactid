using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;

namespace SubactId.Server.Tasks;

/// <summary>
/// Marks expired tasks terminal and revokes their grants on a timer, one small batch per
/// transaction. Each task gets a <c>task.expired</c> record in the same transaction, preceded by
/// a renewal summary when it renewed more than once. Every replica runs one, and the storage
/// claim is exclusive, so no task is recorded twice. A failed pass is logged and retried at the
/// next tick. Only counts are logged. The first sweep runs one interval after start.
/// <para>
/// The same pass then removes tasks terminal for longer than the retention period, with their
/// grants. Removal writes no audit record.
/// </para>
/// </summary>
public sealed class TaskExpirySweeper(IServiceScopeFactory scopes, SubactIdOptions options, RenewalSummary summaries, TimeProvider clock, ILogger<TaskExpirySweeper> logger)
    : PeriodicBackgroundService(options.Tasks.SweepInterval, clock, logger)
{
    /// <summary>Audit reason written on every <c>task.expired</c> record.</summary>
    public const string Reason = "task_ttl_elapsed";

    /// <inheritdoc />
    protected override string PassName => "Task expiry sweep";

    /// <inheritdoc />
    protected override async Task RunPassAsync(CancellationToken cancellationToken)
    {
        var expired = await SweepAsync(cancellationToken);
        if (expired > 0)
        {
            Logger.LogInformation("Expired {Count} task(s).", expired);
        }

        var purged = await PurgeAsync(cancellationToken);
        if (purged > 0)
        {
            Logger.LogInformation("Removed {Count} task(s) past the retention period.", purged);
        }
    }

    /// <summary>One sweep: batches until a pass comes back short. Returns how many tasks were expired.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> SweepAsync(CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (true)
        {
            var count = await SweepBatchAsync(cancellationToken);
            total += count;
            if (count < options.Tasks.BatchSize)
            {
                return total;
            }
        }
    }

    /// <summary>
    /// One purge: removes tasks whose expiry is more than the retention period ago, in batches
    /// until one comes back short. Returns how many tasks were removed.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> PurgeAsync(CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (true)
        {
            var count = await PurgeBatchAsync(cancellationToken);
            total += count;
            if (count < options.Tasks.BatchSize)
            {
                return total;
            }
        }
    }

    private async Task<int> SweepBatchAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var sweep = scope.ServiceProvider.GetRequiredService<ITaskExpirySweep>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditWriter>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var now = Clock.GetUtcNow();

        return await unitOfWork.RunAsync(
            async ct =>
            {
                var expired = await sweep.ExpireDueAsync(now, options.Tasks.BatchSize, ct);
                var records = expired
                    .SelectMany(task => summaries.Ending(new AuditEvent(now, AuditEvents.TaskExpired, task.TaskId, task.AgentId, task.Sponsor, task.Audience, string.Join(' ', task.Scopes), DelegationDepth: task.DelegationDepth, Reason: Reason), task.Renewals))
                    .ToList();
                await audit.AppendAsync(records, ct);
                return expired.Count;
            },
            cancellationToken);
    }

    private async Task<int> PurgeBatchAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var retention = scope.ServiceProvider.GetRequiredService<ITaskRetention>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var before = Clock.GetUtcNow() - options.Tasks.Retention;

        return await unitOfWork.RunAsync(ct => retention.PurgeTerminalAsync(before, options.Tasks.BatchSize, ct), cancellationToken);
    }
}
