using SubactId.Core.Revocation;
using SubactId.Core.Storage;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;

namespace SubactId.Server.Revocation;

/// <summary>
/// Removes sign-outs once <c>SubactId:Revocations:SignOutRetention</c> has passed since they were
/// recorded, on a timer, in batches of <see cref="BatchSize"/>, one transaction each, until a batch
/// comes back short. A sign-out is the record of a back-channel logout or a Shared Signals
/// <c>session-revoked</c> that refuses the subject tokens it signed out; once every such token
/// has expired it refuses nothing. No other revocation is removed.
/// <para>
/// Every replica runs one. Removing a record twice removes it once, so no lock is needed. A failed
/// pass is logged and retried at the next tick. Removal writes no audit record: the ledger keeps the
/// logout's own. Only counts are logged. The first pass runs one interval after start.
/// </para>
/// </summary>
public sealed class SignOutPruner(IServiceScopeFactory scopes, SubactIdOptions options, TimeProvider clock, ILogger<SignOutPruner> logger)
    : PeriodicBackgroundService(PruneInterval, clock, logger)
{
    /// <summary>
    /// Time between passes. Not configurable: a record is kept at most this much past its
    /// retention, and keeping one longer refuses nothing that should be let through.
    /// </summary>
    public static readonly TimeSpan PruneInterval = TimeSpan.FromHours(1);

    /// <summary>Most sign-outs removed in one transaction.</summary>
    public const int BatchSize = 1000;

    /// <inheritdoc />
    protected override string PassName => "Sign-out prune";

    /// <inheritdoc />
    protected override async Task RunPassAsync(CancellationToken cancellationToken)
    {
        var pruned = await PruneAsync(cancellationToken);
        if (pruned > 0)
        {
            Logger.LogInformation("Removed {Count} sign-out record(s) past the retention period.", pruned);
        }
    }

    /// <summary>One pass: batches until one comes back short. Returns how many sign-outs were removed.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> PruneAsync(CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (true)
        {
            var count = await PruneBatchAsync(cancellationToken);
            total += count;
            if (count < BatchSize)
            {
                return total;
            }
        }
    }

    private async Task<int> PruneBatchAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var revocations = scope.ServiceProvider.GetRequiredService<IRevocationRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var before = Clock.GetUtcNow() - options.Revocations.SignOutRetention;

        return await unitOfWork.RunAsync(ct => revocations.PruneSignOutsAsync(before, BatchSize, ct), cancellationToken);
    }
}
