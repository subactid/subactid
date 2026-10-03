namespace SubactId.Core.Agents;

/// <summary>
/// A registered agent (spec section 2), as stored after the admin API accepted it.
/// </summary>
/// <param name="AgentId">Stable identifier, for example <c>jira-triage</c>.</param>
/// <param name="DisplayName">Human-readable name.</param>
/// <param name="SponsorRequired">When <c>true</c>, no token is issued without a human subject token.</param>
/// <param name="AllowedScopes">Scopes the agent may ever be granted.</param>
/// <param name="AllowedAudiences">Audiences the agent may request tokens for.</param>
/// <param name="MaxTaskTtl">Upper bound on the lifetime of a whole task.</param>
/// <param name="MaxTokenTtl">Upper bound on the lifetime of a single token.</param>
/// <param name="MaxDelegationDepth">Maximum nesting of the <c>act</c> chain.</param>
/// <param name="HighRiskAudiences">Audiences that require per-call introspection.</param>
/// <param name="JwksUri">Where the agent publishes the public keys it authenticates with.</param>
/// <param name="Jwks">The agent's public keys, held here instead of fetched from a URL. Exactly one of this and <paramref name="JwksUri"/> is set.</param>
/// <param name="Enabled">A disabled agent is refused every new exchange immediately.</param>
/// <param name="CreatedAt">When the agent was registered.</param>
/// <param name="UpdatedAt">When the registration was last changed.</param>
public sealed record Agent(
    string AgentId,
    string DisplayName,
    bool SponsorRequired,
    IReadOnlyList<string> AllowedScopes,
    IReadOnlyList<string> AllowedAudiences,
    TimeSpan MaxTaskTtl,
    TimeSpan MaxTokenTtl,
    int MaxDelegationDepth,
    IReadOnlyList<string> HighRiskAudiences,
    Uri? JwksUri,
    AgentJwks? Jwks,
    bool Enabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
