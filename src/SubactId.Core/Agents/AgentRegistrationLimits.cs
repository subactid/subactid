namespace SubactId.Core.Agents;

/// <summary>
/// Server-wide bounds for agent registrations, and default lifetimes for registrations that name
/// none. Delegation depth bounds are fixed by the spec. The rest is configurable.
/// </summary>
/// <param name="MinTaskTtl">Smallest allowed <c>max_task_ttl</c>.</param>
/// <param name="MaxTaskTtl">Largest allowed <c>max_task_ttl</c>.</param>
/// <param name="MinTokenTtl">Smallest allowed <c>max_token_ttl</c>.</param>
/// <param name="MaxTokenTtl">Largest allowed <c>max_token_ttl</c>.</param>
/// <param name="DefaultTaskTtl">The <c>max_task_ttl</c> of a registration that names none.</param>
/// <param name="DefaultTokenTtl">The <c>max_token_ttl</c> of a registration that names none.</param>
public sealed record AgentRegistrationLimits(
    TimeSpan MinTaskTtl,
    TimeSpan MaxTaskTtl,
    TimeSpan MinTokenTtl,
    TimeSpan MaxTokenTtl,
    TimeSpan DefaultTaskTtl,
    TimeSpan DefaultTokenTtl)
{
    /// <summary>Smallest allowed <c>max_delegation_depth</c>.</summary>
    public const int MinDelegationDepth = 1;

    /// <summary>Largest allowed <c>max_delegation_depth</c>.</summary>
    public const int MaxDelegationDepth = 5;

    /// <summary>Task lifetime 1 minute to 1 day (default 30 minutes). Token lifetime 30 seconds to 1 hour (default 5 minutes).</summary>
    public static AgentRegistrationLimits Default { get; } = new(
        MinTaskTtl: TimeSpan.FromMinutes(1),
        MaxTaskTtl: TimeSpan.FromDays(1),
        MinTokenTtl: TimeSpan.FromSeconds(30),
        MaxTokenTtl: TimeSpan.FromHours(1),
        DefaultTaskTtl: TimeSpan.FromMinutes(30),
        DefaultTokenTtl: TimeSpan.FromMinutes(5));

    /// <summary>
    /// <paramref name="agent"/> with its lifetimes held to these bounds' maximums, for issuing. A
    /// registration is checked against the bounds when it is made, but bounds lowered since then
    /// apply to every agent from its next exchange or refresh, not only to new registrations.
    /// </summary>
    /// <param name="agent">The agent as registered.</param>
    public Agent Bound(Agent agent)
    {
        ArgumentNullException.ThrowIfNull(agent);

        return agent.MaxTaskTtl <= MaxTaskTtl && agent.MaxTokenTtl <= MaxTokenTtl
            ? agent
            : agent with
            {
                MaxTaskTtl = agent.MaxTaskTtl <= MaxTaskTtl ? agent.MaxTaskTtl : MaxTaskTtl,
                MaxTokenTtl = agent.MaxTokenTtl <= MaxTokenTtl ? agent.MaxTokenTtl : MaxTokenTtl,
            };
    }

    /// <summary>Every inconsistency in these bounds, as operator-readable sentences. Empty means they are consistent.</summary>
    /// <remarks>
    /// The defaults are checked against the bounds, but not against each other. The configuration
    /// loader reports a default token lifetime longer than the default task lifetime.
    /// </remarks>
    public IReadOnlyList<string> Contradictions()
    {
        var problems = new List<string>();
        if (MinTaskTtl > MaxTaskTtl)
        {
            problems.Add("the smallest task lifetime is longer than the largest");
        }

        if (MinTokenTtl > MaxTokenTtl)
        {
            problems.Add("the smallest token lifetime is longer than the largest");
        }

        // A token never outlives its task, so the shortest allowed task must fit the shortest allowed token.
        if (MinTokenTtl > MinTaskTtl)
        {
            problems.Add("the smallest token lifetime is longer than the smallest task lifetime, which no registration at that task lifetime could satisfy");
        }

        if (DefaultTaskTtl < MinTaskTtl || DefaultTaskTtl > MaxTaskTtl)
        {
            problems.Add("the default task lifetime is outside the allowed task lifetimes");
        }

        if (DefaultTokenTtl < MinTokenTtl || DefaultTokenTtl > MaxTokenTtl)
        {
            problems.Add("the default token lifetime is outside the allowed token lifetimes");
        }

        return problems;
    }
}
