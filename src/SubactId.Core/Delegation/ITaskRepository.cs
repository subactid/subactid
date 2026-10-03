using SubactId.Core.Storage;

namespace SubactId.Core.Delegation;

/// <summary>
/// Persistence for tasks, scoped to the owning agent. Every query takes the agent id, so one
/// agent never sees or changes another's tasks. Cross-agent operations use separate privileged interfaces.
/// </summary>
public interface ITaskRepository
{
    /// <summary>Stores a new task.</summary>
    /// <exception cref="DuplicateEntityException">A task with the same id already exists.</exception>
    Task AddAsync(DelegationTask task, CancellationToken cancellationToken = default);

    /// <summary>Returns the task if it exists and belongs to <paramref name="agentId"/>, otherwise <c>null</c>.</summary>
    Task<DelegationTask?> FindAsync(string agentId, string taskId, CancellationToken cancellationToken = default);
}
