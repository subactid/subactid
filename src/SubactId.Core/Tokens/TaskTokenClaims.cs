using SubactId.Core.Agents;
using SubactId.Core.Delegation;

namespace SubactId.Core.Tokens;

/// <summary>The <c>task</c> claim: which task the token belongs to, when it ends, and for whom.</summary>
/// <param name="Id">The task id.</param>
/// <param name="ExpiresAt">When the task expires; no token under it outlives this.</param>
/// <param name="Sponsor">The human the task acts for; always equal to the token's <c>sub</c>.</param>
public sealed record TaskClaim(string Id, DateTimeOffset ExpiresAt, string Sponsor);

/// <summary>
/// The claim set of a task token (spec section 4). <see cref="Subject"/> is always the human.
/// The agent appears only in <see cref="Actor"/>. Built only by <see cref="Issue"/>, which sets
/// the lifetime and delegation chain and re-checks the agent and task state.
/// </summary>
/// <param name="Issuer">This control plane.</param>
/// <param name="Subject">The human, taken from the task's sponsor.</param>
/// <param name="Audience">The tool server the token is for.</param>
/// <param name="ExpiresAt">Token expiry; never after the task's.</param>
/// <param name="IssuedAt">When the token was issued.</param>
/// <param name="Jti">Token identifier.</param>
/// <param name="Scopes">Granted scopes, in order, never wider than the task's.</param>
/// <param name="Actor">The <c>act</c> chain.</param>
/// <param name="Task">The <c>task</c> block.</param>
/// <param name="IntrospectRequired">
/// Whether the agent's registration marks the audience as high risk. A tool server that sees it
/// must introspect on every call.
/// </param>
public sealed record TaskTokenClaims(
    Uri Issuer,
    string Subject,
    string Audience,
    DateTimeOffset ExpiresAt,
    DateTimeOffset IssuedAt,
    string Jti,
    IReadOnlyList<string> Scopes,
    ActorClaim Actor,
    TaskClaim Task,
    bool IntrospectRequired = false)
{
    /// <summary>
    /// The shortest lifetime worth issuing a token with. A task with less time left than this is refused.
    /// </summary>
    public static readonly TimeSpan MinimumLifetime = TimeSpan.FromSeconds(5);

    /// <summary>The acting agent as a client identifier: always the outermost actor's subject.</summary>
    public string ClientId => Actor.Subject;

    /// <summary>
    /// Builds the claims for a token issued under <paramref name="task"/> to <paramref name="agent"/>.
    /// Lifetime is the smallest of the requested lifetime, the agent's <c>max_token_ttl</c> and
    /// the time the task has left. Pure function.
    /// </summary>
    /// <param name="issuer">This control plane's issuer URL.</param>
    /// <param name="task">The task the token belongs to. Must be active with time left.</param>
    /// <param name="agent">The agent the token is issued to; must be the task's agent.</param>
    /// <param name="scopes">The effective scopes from the policy engine; must be non-empty and within the task's.</param>
    /// <param name="instance">The agent's instance identifier, if it gave one.</param>
    /// <param name="delegatedFrom">The parent token's <c>act</c> claim on a delegation hop; <c>null</c> on a first hop.</param>
    /// <param name="requestedTtl">The lifetime asked for, or the server default.</param>
    /// <param name="now">The issue time.</param>
    /// <param name="jti">The token identifier to write.</param>
    /// <exception cref="ArgumentException">An input contradicts another or names an agent as the human.</exception>
    /// <exception cref="InvalidOperationException">The agent is disabled, or the task is not active or has no time left.</exception>
    public static TaskTokenClaims Issue(
        Uri issuer,
        DelegationTask task,
        Agent agent,
        IReadOnlyList<string> scopes,
        string? instance,
        ActorClaim? delegatedFrom,
        TimeSpan requestedTtl,
        DateTimeOffset now,
        string jti)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(task);
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentException.ThrowIfNullOrEmpty(jti);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(requestedTtl, TimeSpan.Zero);
        if (agent.MaxTokenTtl <= TimeSpan.Zero)
        {
            throw new ArgumentException($"Agent '{agent.AgentId}' has no positive max_token_ttl.", nameof(agent));
        }

        if (string.IsNullOrEmpty(task.Sponsor) || ActorClaim.IsAgentSubject(task.Sponsor))
        {
            throw new ArgumentException("The task's sponsor must be a human subject; an agent identifier can never be 'sub'.", nameof(task));
        }

        if (!string.Equals(task.AgentId, agent.AgentId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Task '{task.TaskId}' belongs to agent '{task.AgentId}', not '{agent.AgentId}'.", nameof(agent));
        }

        if (scopes.Count == 0 || scopes.Any(s => string.IsNullOrEmpty(s) || !task.Scopes.Contains(s, StringComparer.Ordinal)))
        {
            throw new ArgumentException("Token scopes must be non-empty and within the task's scopes.", nameof(scopes));
        }

        var actor = ActorClaim.ForAgent(agent.AgentId, instance, delegatedFrom);
        if (actor.Depth != task.DelegationDepth)
        {
            throw new ArgumentException($"The delegation chain has depth {actor.Depth} but the task records {task.DelegationDepth}.", nameof(delegatedFrom));
        }

        if (actor.Depth > agent.MaxDelegationDepth)
        {
            throw new ArgumentException($"Depth {actor.Depth} exceeds agent '{agent.AgentId}' max_delegation_depth {agent.MaxDelegationDepth}.", nameof(delegatedFrom));
        }

        if (!agent.Enabled)
        {
            throw new InvalidOperationException($"Agent '{agent.AgentId}' is disabled; no token may be issued to it.");
        }

        if (task.Status != DelegationTaskStatus.Active)
        {
            throw new InvalidOperationException($"Task '{task.TaskId}' is {task.Status}; no token may be issued under it.");
        }

        var remaining = task.ExpiresAt - now;
        if (remaining <= TimeSpan.Zero)
        {
            throw new InvalidOperationException($"Task '{task.TaskId}' has expired; no token may be issued under it.");
        }

        var ttl = Min(requestedTtl, agent.MaxTokenTtl, remaining);
        return new(
            issuer,
            task.Sponsor,
            task.Audience,
            now + ttl,
            now,
            jti,
            scopes.Distinct(StringComparer.Ordinal).ToList().AsReadOnly(),
            actor,
            new TaskClaim(task.TaskId, task.ExpiresAt, task.Sponsor),
            agent.HighRiskAudiences.Contains(task.Audience, StringComparer.Ordinal));
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b, TimeSpan c) => TimeSpan.FromTicks(Math.Min(a.Ticks, Math.Min(b.Ticks, c.Ticks)));
}
