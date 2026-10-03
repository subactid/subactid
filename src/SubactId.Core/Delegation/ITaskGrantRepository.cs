using SubactId.Core.Storage;

namespace SubactId.Core.Delegation;

/// <summary>
/// Persistence for task grants. Every query takes the agent id, so a grant presented by
/// an agent other than the one it was issued to is simply not found.
/// </summary>
public interface ITaskGrantRepository
{
    /// <summary>Stores a new grant.</summary>
    /// <exception cref="DuplicateEntityException">A grant with the same hash already exists.</exception>
    Task AddAsync(TaskGrant grant, CancellationToken cancellationToken = default);

    /// <summary>Returns the grant with the given hash if it is bound to <paramref name="agentId"/>, otherwise <c>null</c>.</summary>
    Task<TaskGrant?> FindAsync(string agentId, ReadOnlyMemory<byte> grantHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a use of the grant, sets its scopes to <paramref name="scopes"/>, and returns the new
    /// use count. Returns <c>null</c> if no live grant is bound to the agent (unknown, another
    /// agent's, or revoked), or if the grant's scopes are no longer <paramref name="heldScopes"/>
    /// because a concurrent use changed them. Called inside the transaction that issues the token.
    /// The count is taken under the row lock, so concurrent uses get distinct numbers, and a use
    /// decided against scopes that have since narrowed cannot write them back.
    /// </summary>
    /// <param name="agentId">The agent the grant must be bound to.</param>
    /// <param name="grantHash">SHA-256 of the grant value.</param>
    /// <param name="heldScopes">The grant's scopes as read when the use was decided.</param>
    /// <param name="scopes">The scopes the grant keeps from now on. The caller never passes one outside <paramref name="heldScopes"/>.</param>
    /// <param name="usedAt">When the grant was used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int?> MarkUsedAsync(string agentId, ReadOnlyMemory<byte> grantHash, IReadOnlyList<string> heldScopes, IReadOnlyList<string> scopes, DateTimeOffset usedAt, CancellationToken cancellationToken = default);

    /// <summary>Revokes every live grant of the agent's task. Returns the number of grants revoked.</summary>
    Task<int> RevokeByTaskAsync(string agentId, string taskId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
