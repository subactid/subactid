using SubactId.Core.Agents;
using SubactId.Core.Delegation;
using SubactId.Tokens.Issuance;

namespace SubactId.Tokens.Grants;

/// <summary>Why a presented task grant was not accepted. Every value is a stable audit reason.</summary>
public enum TaskGrantRejection
{
    /// <summary>The grant was accepted.</summary>
    None,

    /// <summary>No live grant with that value is bound to this agent: unknown, malformed, or issued to another agent. These share one reason.</summary>
    NotFound,

    /// <summary>The grant was revoked.</summary>
    Revoked,

    /// <summary>The grant has passed its expiry.</summary>
    Expired,

    /// <summary>The task the grant belongs to was revoked.</summary>
    TaskRevoked,

    /// <summary>The task the grant belongs to has expired.</summary>
    TaskExpired,
}

/// <summary>
/// Outcome of redeeming a grant. When rejected, carries the reason and, if the grant was found,
/// the grant and task so the denial can be attributed.
/// </summary>
/// <param name="Grant">The grant, when it was found for this agent.</param>
/// <param name="Task">The grant's task, when it was found.</param>
/// <param name="Reason">Why it was rejected; <see cref="TaskGrantRejection.None"/> when accepted.</param>
public sealed record TaskGrantRedemption(TaskGrant? Grant, DelegationTask? Task, TaskGrantRejection Reason)
{
    /// <summary>Whether the grant may be used.</summary>
    public bool IsAccepted => Reason == TaskGrantRejection.None;

    /// <summary>The task the grant belongs to, whenever the grant was found.</summary>
    public string? TaskId => Task?.TaskId ?? Grant?.TaskId;

    internal static TaskGrantRedemption Accept(TaskGrant grant, DelegationTask task) => new(grant, task, TaskGrantRejection.None);

    internal static TaskGrantRedemption Reject(TaskGrantRejection reason, TaskGrant? grant = null, DelegationTask? task = null) => new(grant, task, reason);
}

/// <summary>
/// Resolves a presented grant value to a live grant and task for the presenting agent. The lookup
/// is by hash and scoped to the agent, so another agent's grant is not found. Never throws for a bad value.
/// </summary>
public sealed class TaskGrantRedeemer(ITaskGrantRepository grants, ITaskRepository tasks)
{
    /// <summary>
    /// Redeems <paramref name="presented"/> for <paramref name="agent"/> at <paramref name="now"/>.
    /// Read only. The caller records the use with <see cref="ITaskGrantRepository.MarkUsedAsync"/>
    /// in the issuing transaction and must treat <c>false</c> as a denial, since that catches a
    /// concurrent revocation.
    /// </summary>
    /// <param name="agent">The authenticated agent presenting the grant.</param>
    /// <param name="presented">The <c>refresh_token</c> value as sent.</param>
    /// <param name="now">The current time.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<TaskGrantRedemption> RedeemAsync(Agent agent, string? presented, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agent);

        if (!TaskGrantSecret.IsWellFormed(presented))
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.NotFound);
        }

        var grant = await grants.FindAsync(agent.AgentId, TaskGrantSecret.Hash(presented), cancellationToken);
        if (grant is null || !string.Equals(grant.AgentId, agent.AgentId, StringComparison.Ordinal))
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.NotFound);
        }

        // Spec section 5 order: grant exists, task not revoked, task not expired, then the grant itself.
        // A grant revoked or expired with its task reports the task's reason.
        var task = await tasks.FindAsync(agent.AgentId, grant.TaskId, cancellationToken);
        if (task is null)
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.NotFound, grant);
        }

        if (task.Status == DelegationTaskStatus.Revoked)
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.TaskRevoked, grant, task);
        }

        if (task.Status == DelegationTaskStatus.Expired || now >= task.ExpiresAt)
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.TaskExpired, grant, task);
        }

        if (grant.RevokedAt is not null)
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.Revoked, grant, task);
        }

        if (now >= grant.ExpiresAt)
        {
            return TaskGrantRedemption.Reject(TaskGrantRejection.Expired, grant, task);
        }

        return TaskGrantRedemption.Accept(grant, task);
    }
}
