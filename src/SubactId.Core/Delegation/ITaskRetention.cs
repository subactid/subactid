namespace SubactId.Core.Delegation;

/// <summary>
/// Retention purge across all agents: removes long-expired tasks and their grants. The audit
/// ledger, not the task row, is the lasting record. Runs inside the caller's unit of work.
/// </summary>
public interface ITaskRetention
{
    /// <summary>
    /// Removes up to <paramref name="batchSize"/> tasks that are no longer active and whose
    /// <c>expires_at</c> is at or before <paramref name="before"/>, together with their grants. A task
    /// that another task was delegated from is kept until that task is gone. Returns how many tasks
    /// were removed.
    /// </summary>
    /// <param name="before">Tasks that expired at or before this instant are removed.</param>
    /// <param name="batchSize">Most tasks to remove in one call.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int> PurgeTerminalAsync(DateTimeOffset before, int batchSize, CancellationToken cancellationToken = default);
}
