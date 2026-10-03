using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Core.Storage;
using SubactId.Core.Validation;
using SubactId.Server.Audit;
using SubactId.Server.Contracts;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Revocation;

/// <summary>Outcome of an admin revocation: not found, or how many live tasks it ended.</summary>
/// <param name="Found">Whether the task or agent exists.</param>
/// <param name="RevokedTasks">Tasks that were live and are now revoked, descendants included.</param>
public sealed record AdminRevocation(bool Found, int RevokedTasks);

/// <summary>
/// Revocation, spec section 6. A task is revoked with every task delegated from it and their
/// grants, in one transaction with a <c>task.revoked</c> record per task. Revoking again is a
/// no-op. An agent may revoke its own task grant, which revokes the task, or one of its own task
/// tokens by <c>jti</c>. Locally validated tokens stay valid until they expire.
/// </summary>
public sealed class RevocationService(
    IAgentRepository agents,
    ITaskGrantRepository grants,
    ITaskRevocation tasks,
    IRevocationRepository revocations,
    ClientAssertionAuthenticator actors,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    TokenAudit denials,
    RenewalSummary summaries,
    SigningKeySet keys,
    TimeProvider clock)
{
    /// <summary>Reason recorded when an operator revokes.</summary>
    public const string OperatorKillSwitch = "operator_kill_switch";

    /// <summary>Reason recorded when an agent revokes its own task or token.</summary>
    public const string ClientRevoked = "client_revoked";

    /// <summary>Audit reason when an agent tries to revoke a grant or token that is not its own or does not exist. The response is still an empty 200.</summary>
    public const string NotOwner = "revocation_not_owner";

    /// <summary>The <c>revoked_by</c> value for operator revocations.</summary>
    public const string Admin = "admin";

    /// <summary><c>DELETE /admin/tasks/{id}</c>: the task and everything delegated from it.</summary>
    public Task<AdminRevocation> RevokeTaskAsync(string taskId, CancellationToken cancellationToken = default) =>
        unitOfWork.RunAsync(
            async ct =>
            {
                var now = clock.GetUtcNow();
                var outcome = await tasks.RevokeTreeAsync(taskId, now, OperatorKillSwitch, ct);
                if (!outcome.Found)
                {
                    return new AdminRevocation(false, 0);
                }

                if (outcome.Revoked.Count > 0)
                {
                    await revocations.AddAsync(new Core.Revocation.Revocation(null, taskId, null, null, null, now, OperatorKillSwitch, Admin), ct);
                    await audit.AppendAsync(Records(outcome.Revoked, taskId, now, OperatorKillSwitch), ct);
                }

                return new AdminRevocation(true, outcome.Revoked.Count);
            },
            cancellationToken);

    /// <summary><c>DELETE /admin/agents/{id}/tasks</c>: every live task of the agent, with their descendants.</summary>
    public Task<AdminRevocation> RevokeAgentTasksAsync(string agentId, CancellationToken cancellationToken = default) =>
        unitOfWork.RunAsync(
            async ct =>
            {
                if (await agents.FindAsync(agentId, ct) is null)
                {
                    return new AdminRevocation(false, 0);
                }

                var now = clock.GetUtcNow();
                var revoked = await tasks.RevokeAgentTasksAsync(agentId, now, OperatorKillSwitch, ct);
                if (revoked.Count > 0)
                {
                    await revocations.AddAsync(new Core.Revocation.Revocation(null, null, agentId, null, null, now, OperatorKillSwitch, Admin), ct);
                    await audit.AppendAsync(revoked.SelectMany(t => summaries.Ending(Record(t, now, t.IsRoot ? OperatorKillSwitch : ITaskRevocation.ParentRevoked), t.Renewals)).ToList(), ct);
                }

                return new AdminRevocation(true, revoked.Count);
            },
            cancellationToken);

    /// <summary>
    /// <c>POST /oauth2/revoke</c>. After the agent authenticates, its own task grant revokes that
    /// task's tree and its own task token is revoked by <c>jti</c>, whether or not the agent is
    /// still enabled. Anything else, including another agent's token, gets the same empty 200
    /// (RFC 7009 section 2.2) but is audited as a denial.
    /// </summary>
    /// <param name="request">The parsed form.</param>
    /// <param name="formErrors">Problems found while reading the form.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>null</c> for the empty 200, otherwise the error to answer with.</returns>
    public async Task<OAuthErrorResponse?> RevokeForClientAsync(RevokeTokenRequest request, IReadOnlyList<ValidationError> formErrors, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(formErrors);

        var errors = formErrors.Concat(request.Validate()).ToList();
        if (errors.Count > 0)
        {
            var fields = string.Join(", ", errors.Select(e => $"{e.Field} {e.Message}"));
            return (await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, $"The request is invalid: {fields}", OAuthErrorResponse.InvalidRequest)).Error;
        }

        // The token_type_hint is not consulted: a grant and a task token are told apart by their
        // form, and an unrecognised hint is ignored (RFC 7009 section 2.1). A disabled agent may
        // still revoke its own grants and tokens, since revoking only takes access away.
        var actor = await actors.AuthenticateToRevokeAsync(request.ClientAssertion, request.ClientId, cancellationToken);
        if (actor.Agent is not { } agent)
        {
            return (await denials.DenyActorAsync(actor)).Error;
        }

        var now = clock.GetUtcNow();
        var handled = TaskGrantSecret.IsWellFormed(request.Token)
            ? await RevokeGrantAsync(agent, request.Token, now, cancellationToken)
            : Jws.TryVerifyAccessToken(keys, request.Token, out var payload) && await RevokeTokenAsync(agent, payload!, now, cancellationToken);
        if (!handled)
        {
            await audit.AppendAsync(new AuditEvent(now, AuditEvents.TokenDenied, AgentId: agent.AgentId, Decision: AuditDecision.Deny, Reason: NotOwner), CancellationToken.None);
        }

        return null;
    }

    /// <summary>Revokes the task under a grant of this agent. <c>false</c> when no such grant is bound to it.</summary>
    private async Task<bool> RevokeGrantAsync(Agent agent, string grantValue, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var grant = await grants.FindAsync(agent.AgentId, TaskGrantSecret.Hash(grantValue), cancellationToken);
        if (grant is null)
        {
            return false;
        }

        await unitOfWork.RunAsync(
            async ct =>
            {
                var outcome = await tasks.RevokeTreeAsync(grant.TaskId, now, ClientRevoked, ct);
                if (outcome.Revoked.Count > 0)
                {
                    await revocations.AddAsync(new Core.Revocation.Revocation(null, grant.TaskId, null, null, null, now, ClientRevoked, agent.AgentId), ct);
                    await audit.AppendAsync(Records(outcome.Revoked, grant.TaskId, now, ClientRevoked), ct);
                }

                return true;
            },
            cancellationToken);
        return true;
    }

    /// <summary>Revokes a verified task token by <c>jti</c> if it was issued to this agent. <c>false</c> when it is not this agent's or not a task token.</summary>
    private async Task<bool> RevokeTokenAsync(Agent agent, byte[] payload, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!TaskTokenReader.TryRead(payload, out var token) || !string.Equals(token.AgentId, agent.AgentId, StringComparison.Ordinal))
        {
            return false;
        }

        await unitOfWork.RunAsync(
            async ct =>
            {
                if (await revocations.AddAsync(new Core.Revocation.Revocation(token.Jti, null, null, null, null, now, ClientRevoked, agent.AgentId, token.ExpiresAt), ct))
                {
                    await audit.AppendAsync(new AuditEvent(now, AuditEvents.TokenRevoked, token.TaskId, agent.AgentId, token.Subject, token.Audience, token.Scope, token.Jti, token.Depth, Reason: ClientRevoked), ct);
                }

                return true;
            },
            cancellationToken);
        return true;
    }

    private List<AuditEvent> Records(IReadOnlyList<RevokedTask> revoked, string rootTaskId, DateTimeOffset now, string reason) =>
        revoked.SelectMany(t => summaries.Ending(Record(t, now, t.IsRoot ? reason : ITaskRevocation.ParentRevoked), t.Renewals)).ToList();

    internal static AuditEvent Record(RevokedTask task, DateTimeOffset now, string reason) =>
        new(now, AuditEvents.TaskRevoked, task.TaskId, task.AgentId, task.Sponsor, task.Audience, string.Join(' ', task.Scopes), DelegationDepth: task.DelegationDepth, Reason: reason);
}
