using SubactId.Core.Agents;

namespace SubactId.Core.Policy;

/// <summary>
/// The authorization decision of spec section 3, as a pure function with no I/O:
/// <c>(user_scopes, agent, requested_scopes, audience, depth) -> Allow(effective_scopes) | Deny(reason)</c>.
/// </summary>
/// <remarks>
/// <para>
/// Effective scopes are the intersection of the human's, the agent's allowed and the requested
/// scopes. An empty intersection is a denial. No scope is defaulted. On a delegation hop the
/// caller passes the parent token's scopes as the user scopes.
/// </para>
/// <para>
/// Only the receiving agent's <c>max_delegation_depth</c> is checked here. The exchange endpoint
/// checks whether the delegating agent may delegate. This function narrows silently, but spec
/// section 5 requires a widening refresh to fail with <c>invalid_scope</c>, so refresh refuses any
/// scope outside the grant first and calls this only with a request that is already within it.
/// </para>
/// </remarks>
public static class PolicyEngine
{
    /// <summary>Decides whether a token may be issued and with which scopes.</summary>
    /// <param name="userScopes">Scopes the subject token carries: the human's on the first hop, the parent task token's on a delegation hop.</param>
    /// <param name="agent">The agent the token would be issued to.</param>
    /// <param name="requestedScopes">Scopes the agent asked for.</param>
    /// <param name="audience">The audience (<c>resource</c>) the agent asked for.</param>
    /// <param name="depth">The delegation depth the new token would have; 1 for a token created from a user token.</param>
    /// <returns>The decision. Never throws for any combination of client-supplied values.</returns>
    public static PolicyDecision Evaluate(IReadOnlyList<string> userScopes, Agent agent, IReadOnlyList<string> requestedScopes, string? audience, int depth)
    {
        ArgumentNullException.ThrowIfNull(userScopes);
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(requestedScopes);

        if (!agent.Enabled)
        {
            return PolicyDecision.Deny(PolicyDenialReason.AgentDisabled);
        }

        if (depth < 1)
        {
            return PolicyDecision.Deny(PolicyDenialReason.InvalidDelegationDepth);
        }

        if (depth > agent.MaxDelegationDepth)
        {
            return PolicyDecision.Deny(PolicyDenialReason.DelegationDepthExceeded);
        }

        if (string.IsNullOrWhiteSpace(audience))
        {
            return PolicyDecision.Deny(PolicyDenialReason.AudienceMissing);
        }

        if (!agent.AllowedAudiences.Contains(audience, StringComparer.Ordinal))
        {
            return PolicyDecision.Deny(PolicyDenialReason.AudienceNotAllowed);
        }

        var effective = Intersect(userScopes, agent.AllowedScopes, requestedScopes);
        return effective.Count == 0
            ? PolicyDecision.Deny(PolicyDenialReason.EmptyScopeIntersection)
            : PolicyDecision.Allow(effective);
    }

    /// <summary>Case-sensitive intersection in requested order. Empty and duplicate scopes are dropped. The result is read-only.</summary>
    private static IReadOnlyList<string> Intersect(IReadOnlyList<string> userScopes, IReadOnlyList<string> agentScopes, IReadOnlyList<string> requestedScopes)
    {
        var held = new HashSet<string>(userScopes.Where(s => !string.IsNullOrEmpty(s)), StringComparer.Ordinal);
        held.IntersectWith(agentScopes);

        var effective = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scope in requestedScopes)
        {
            if (!string.IsNullOrEmpty(scope) && held.Contains(scope) && seen.Add(scope))
            {
                effective.Add(scope);
            }
        }

        return effective.AsReadOnly();
    }
}
