namespace SubactId.Core.Delegation;

/// <summary>A task the sweeper just expired, with the fields its audit record needs.</summary>
/// <param name="TaskId">The task.</param>
/// <param name="AgentId">The agent it was issued to.</param>
/// <param name="Sponsor">The human it acted for.</param>
/// <param name="Audience">Its audience.</param>
/// <param name="Scopes">Its scopes.</param>
/// <param name="DelegationDepth">Its delegation depth.</param>
/// <param name="ExpiresAt">When it expired.</param>
/// <param name="Renewals">How many times its grant was used to refresh, read when the grant was revoked.</param>
public sealed record ExpiredTask(string TaskId, string AgentId, string Sponsor, string Audience, IReadOnlyList<string> Scopes, int DelegationDepth, DateTimeOffset ExpiresAt, int Renewals = 0);

/// <summary>
/// Expiry sweep across all agents: claims active tasks past their expiry, marks them expired and
/// revokes their grants. Claims are exclusive, so concurrent sweepers never process the same task.
/// </summary>
public interface ITaskExpirySweep
{
    /// <summary>
    /// Marks up to <paramref name="batchSize"/> active tasks with <c>expires_at</c> at or before
    /// <paramref name="now"/> as expired, revokes their live grants, and returns them. Runs inside
    /// the caller's unit of work, so the audit records the caller writes commit with the change.
    /// </summary>
    /// <param name="now">The current time.</param>
    /// <param name="batchSize">Most tasks to claim in one call.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<ExpiredTask>> ExpireDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default);
}
