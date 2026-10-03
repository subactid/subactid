using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Core.Validation;
using SubactId.Server.Contracts;

namespace SubactId.Server.Admin;

/// <summary>Why an admin operation could not be completed.</summary>
public enum AdminFailure
{
    /// <summary>No agent with that id.</summary>
    NotFound,

    /// <summary>An agent with that id already exists.</summary>
    AlreadyExists,

    /// <summary>The agent still has tasks. Revoke them first.</summary>
    InUse,
}

/// <summary>Outcome of an admin operation: exactly one of an agent, validation errors, or a failure.</summary>
/// <param name="Agent">The resulting agent, on success.</param>
/// <param name="ValidationErrors">Per-field errors, when the request was invalid.</param>
/// <param name="Failure">The failure, when the operation could not be completed.</param>
public sealed record AdminResult(Agent? Agent, IReadOnlyList<ValidationError> ValidationErrors, AdminFailure? Failure)
{
    internal static AdminResult Ok(Agent agent) => new(agent, [], null);

    internal static AdminResult Invalid(IReadOnlyList<ValidationError> errors) => new(null, errors, null);

    internal static AdminResult Failed(AdminFailure failure) => new(null, [], failure);
}

/// <summary>
/// Agent registry operations. Every mutation runs in one transaction with its audit record.
/// Nothing is cached, so a change such as disabling an agent applies to the next request.
/// </summary>
public sealed class AgentAdminService(
    IAgentRepository agents,
    IAgentQuery agentQuery,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    AgentRegistrationLimits limits,
    TimeProvider clock)
{
    /// <summary>Reason recorded on the refused <c>agent.registered</c> when the id is already taken.</summary>
    public const string AgentAlreadyExists = "agent_already_exists";

    /// <summary>Reason recorded on the refused <c>agent.deleted</c> when the agent still has tasks stored.</summary>
    public const string AgentHasTasks = "agent_has_tasks";

    /// <summary>
    /// Registers a new agent. A taken id is refused and recorded as a denied
    /// <c>agent.registered</c>.
    /// </summary>
    public async Task<AdminResult> RegisterAsync(RegisterAgentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var errors = request.TryToAgent(limits, clock.GetUtcNow(), out var agent);
        if (errors.Count > 0)
        {
            return AdminResult.Invalid(errors);
        }

        AdminResult? refused = null;
        AdminResult result;
        try
        {
            result = await unitOfWork.RunAsync(
                async ct =>
                {
                    try
                    {
                        await agents.AddAsync(agent!, ct);
                    }
                    catch (DuplicateEntityException)
                    {
                        refused = AdminResult.Failed(AdminFailure.AlreadyExists);
                        return refused;
                    }

                    await audit.AppendAsync(new AuditEvent(clock.GetUtcNow(), AuditEvents.AgentRegistered, AgentId: agent!.AgentId, Decision: AuditDecision.Allow), ct);
                    return AdminResult.Ok(agent);
                },
                cancellationToken);
        }
        catch (OperationCanceledException) when (refused is not null)
        {
            // The refusal was decided before the caller went away. Nothing was written, so it stands.
            result = refused;
        }

        if (result.Failure is AdminFailure.AlreadyExists)
        {
            // In a transaction of its own: the database may have aborted the one the insert ran in.
            // Not cancellable by the caller: a denial is always recorded.
            await audit.AppendAsync(new AuditEvent(clock.GetUtcNow(), AuditEvents.AgentRegistered, AgentId: agent!.AgentId, Decision: AuditDecision.Deny, Reason: AgentAlreadyExists), CancellationToken.None);
        }

        return result;
    }

    /// <summary>Returns the agent, or <see cref="AdminFailure.NotFound"/>.</summary>
    public async Task<AdminResult> GetAsync(string agentId, CancellationToken cancellationToken = default)
    {
        var agent = await agents.FindAsync(agentId, cancellationToken);
        return agent is null ? AdminResult.Failed(AdminFailure.NotFound) : AdminResult.Ok(agent);
    }

    /// <summary>Up to <paramref name="limit"/> agents after <paramref name="afterId"/>, ordered by id.</summary>
    public Task<IReadOnlyList<Agent>> ListAsync(string? afterId, int limit, CancellationToken cancellationToken = default) =>
        agentQuery.ListAsync(afterId, limit, cancellationToken);

    /// <summary>Applies a partial update.</summary>
    public Task<AdminResult> UpdateAsync(string agentId, UpdateAgentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        return unitOfWork.RunAsync(
            async ct =>
            {
                // Locked until commit: two updates of one agent run one after the other, each on
                // what the other left, so a rename racing a disable cannot write enabled back.
                var existing = await agents.FindForUpdateAsync(agentId, ct);
                if (existing is null)
                {
                    return AdminResult.Failed(AdminFailure.NotFound);
                }

                var errors = request.TryApplyTo(existing, limits, clock.GetUtcNow(), out var updated);
                if (errors.Count > 0)
                {
                    return AdminResult.Invalid(errors);
                }

                if (!await agents.UpdateAsync(updated!, ct))
                {
                    return AdminResult.Failed(AdminFailure.NotFound);
                }

                var changed = request.ChangedFields();
                await audit.AppendAsync(
                    new AuditEvent(clock.GetUtcNow(), AuditEvents.AgentUpdated, AgentId: agentId, Decision: AuditDecision.Allow, Reason: changed.Count == 0 ? "no_change" : "changed:" + string.Join(",", changed)),
                    ct);
                return AdminResult.Ok(updated!);
            },
            cancellationToken);
    }

    /// <summary>
    /// Removes an agent that has no tasks. An agent that still has some is refused and recorded as
    /// a denied <c>agent.deleted</c>.
    /// </summary>
    public async Task<AdminFailure?> DeleteAsync(string agentId, CancellationToken cancellationToken = default)
    {
        var inUse = false;
        AdminFailure? failure;
        try
        {
            failure = await unitOfWork.RunAsync<AdminFailure?>(
                async ct =>
                {
                    try
                    {
                        if (!await agents.DeleteAsync(agentId, ct))
                        {
                            return AdminFailure.NotFound;
                        }
                    }
                    catch (DependentEntitiesException)
                    {
                        inUse = true;
                        return AdminFailure.InUse;
                    }

                    await audit.AppendAsync(new AuditEvent(clock.GetUtcNow(), AuditEvents.AgentDeleted, AgentId: agentId, Decision: AuditDecision.Allow), ct);
                    return null;
                },
                cancellationToken);
        }
        catch (OperationCanceledException) when (inUse)
        {
            // The refusal was decided before the caller went away. Nothing was deleted, so it stands.
            failure = AdminFailure.InUse;
        }

        if (failure is AdminFailure.InUse)
        {
            // In a transaction of its own: the database aborted the one the delete ran in.
            // Not cancellable by the caller: a denial is always recorded.
            await audit.AppendAsync(new AuditEvent(clock.GetUtcNow(), AuditEvents.AgentDeleted, AgentId: agentId, Decision: AuditDecision.Deny, Reason: AgentHasTasks), CancellationToken.None);
        }

        return failure;
    }
}
