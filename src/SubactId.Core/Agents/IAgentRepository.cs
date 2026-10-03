using SubactId.Core.Storage;

namespace SubactId.Core.Agents;

/// <summary>Persistence for agent registrations.</summary>
public interface IAgentRepository
{
    /// <summary>Returns the agent with the given id, or <c>null</c>.</summary>
    Task<Agent?> FindAsync(string agentId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the agent with the given id, or <c>null</c>, locked against other updates until the
    /// unit of work it runs in commits. For a read-modify-write: a concurrent one waits, then reads
    /// what this one wrote, so neither change is lost. Only inside a unit of work.
    /// </summary>
    Task<Agent?> FindForUpdateAsync(string agentId, CancellationToken cancellationToken = default);

    /// <summary>Stores a new agent.</summary>
    /// <exception cref="DuplicateEntityException">An agent with the same id already exists.</exception>
    Task AddAsync(Agent agent, CancellationToken cancellationToken = default);

    /// <summary>Replaces an existing agent's registration. Returns <c>false</c> if no such agent exists.</summary>
    Task<bool> UpdateAsync(Agent agent, CancellationToken cancellationToken = default);

    /// <summary>Removes an agent. Returns <c>false</c> if no such agent exists.</summary>
    Task<bool> DeleteAsync(string agentId, CancellationToken cancellationToken = default);
}
