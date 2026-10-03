namespace SubactId.Core.Tokens;

/// <summary>
/// The <c>act</c> claim of a task token (spec section 4, RFC 8693 section 4.1). The outermost actor
/// is the current one and has the greatest depth. Previous actors are nested inside.
/// </summary>
/// <param name="Subject">The actor identifier, always <c>agent:</c> followed by the agent id.</param>
/// <param name="Instance">Which running instance of the agent, if it said.</param>
/// <param name="Depth">Position in the delegation chain; 1 for an agent acting directly for a human.</param>
/// <param name="Actor">The actor this one was delegated from, if any. Its depth is exactly one less.</param>
public sealed record ActorClaim(string Subject, string? Instance, int Depth, ActorClaim? Actor)
{
    /// <summary>Prefix that marks an actor identifier; nothing carrying it may ever be a <c>sub</c>.</summary>
    public const string AgentSubjectPrefix = "agent:";

    /// <summary>The <c>act</c> claim for <paramref name="agentId"/> acting at the hop after <paramref name="delegatedFrom"/>.</summary>
    /// <param name="agentId">The acting agent's id.</param>
    /// <param name="instance">Its instance identifier, if any; blank counts as none.</param>
    /// <param name="delegatedFrom">The parent token's <c>act</c> claim on a delegation hop; <c>null</c> on a first hop.</param>
    public static ActorClaim ForAgent(string agentId, string? instance, ActorClaim? delegatedFrom)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);

        return new(AgentSubjectPrefix + agentId, string.IsNullOrWhiteSpace(instance) ? null : instance, delegatedFrom is null ? 1 : delegatedFrom.Depth + 1, delegatedFrom);
    }

    /// <summary>Whether <paramref name="subject"/> names an agent rather than a human.</summary>
    /// <param name="subject">A candidate <c>sub</c> value.</param>
    public static bool IsAgentSubject(string subject) =>
        subject is not null && subject.StartsWith(AgentSubjectPrefix, StringComparison.OrdinalIgnoreCase);
}
