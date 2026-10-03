namespace SubactId.Core.Policy;

/// <summary>Why the policy engine denied a request. Each value maps to one OAuth error code and one audit reason.</summary>
public enum PolicyDenialReason
{
    /// <summary>The request was allowed.</summary>
    None,

    /// <summary>The agent is disabled; nothing is issued to it.</summary>
    AgentDisabled,

    /// <summary>The delegation depth is not a positive number.</summary>
    InvalidDelegationDepth,

    /// <summary>The delegation depth exceeds the agent's <c>max_delegation_depth</c>.</summary>
    DelegationDepthExceeded,

    /// <summary>No audience was requested.</summary>
    AudienceMissing,

    /// <summary>The audience is not one of the agent's <c>allowed_audiences</c>.</summary>
    AudienceNotAllowed,

    /// <summary>The intersection of user, agent and requested scopes is empty.</summary>
    EmptyScopeIntersection,
}

/// <summary>Maps a <see cref="PolicyDenialReason"/> to the wire and ledger vocabularies of spec section 8.</summary>
public static class PolicyDenialReasons
{
    /// <summary>The OAuth <c>error</c> code the token endpoint answers with.</summary>
    /// <param name="reason">A denial reason other than <see cref="PolicyDenialReason.None"/>.</param>
    public static string ToErrorCode(this PolicyDenialReason reason) => reason switch
    {
        PolicyDenialReason.AgentDisabled => "access_denied",
        PolicyDenialReason.InvalidDelegationDepth => "access_denied",
        PolicyDenialReason.DelegationDepthExceeded => "access_denied",
        PolicyDenialReason.AudienceMissing => "invalid_target",
        PolicyDenialReason.AudienceNotAllowed => "invalid_target",
        PolicyDenialReason.EmptyScopeIntersection => "invalid_scope",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Not a denial."),
    };

    /// <summary>The machine-readable <c>reason</c> written to the audit ledger.</summary>
    /// <param name="reason">A denial reason other than <see cref="PolicyDenialReason.None"/>.</param>
    public static string ToAuditReason(this PolicyDenialReason reason) => reason switch
    {
        PolicyDenialReason.AgentDisabled => "agent_disabled",
        PolicyDenialReason.InvalidDelegationDepth => "invalid_delegation_depth",
        PolicyDenialReason.DelegationDepthExceeded => "delegation_depth_exceeded",
        PolicyDenialReason.AudienceMissing => "audience_missing",
        PolicyDenialReason.AudienceNotAllowed => "audience_not_allowed",
        PolicyDenialReason.EmptyScopeIntersection => "scope_intersection_empty",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Not a denial."),
    };
}

/// <summary>
/// The outcome of <see cref="PolicyEngine.Evaluate"/>: either <c>Allow</c> with the effective
/// scopes, or <c>Deny</c> with a reason. An allowed decision always carries at least one scope,
/// and only the engine can construct one.
/// </summary>
public sealed class PolicyDecision
{
    private PolicyDecision(IReadOnlyList<string> effectiveScopes, PolicyDenialReason reason)
    {
        EffectiveScopes = effectiveScopes;
        Reason = reason;
    }

    /// <summary>Whether the request may proceed.</summary>
    public bool IsAllowed => Reason == PolicyDenialReason.None;

    /// <summary>The scopes the token may carry: the intersection, in requested order, without duplicates. Empty when denied.</summary>
    public IReadOnlyList<string> EffectiveScopes { get; }

    /// <summary>Why the request was denied; <see cref="PolicyDenialReason.None"/> when allowed.</summary>
    public PolicyDenialReason Reason { get; }

    internal static PolicyDecision Allow(IReadOnlyList<string> effectiveScopes) => new(effectiveScopes, PolicyDenialReason.None);

    internal static PolicyDecision Deny(PolicyDenialReason reason) => new([], reason);
}
