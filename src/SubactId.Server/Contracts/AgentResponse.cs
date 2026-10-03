using System.Text.Json;
using System.Text.Json.Serialization;
using SubactId.Core.Agents;

namespace SubactId.Server.Contracts;

/// <summary>An agent registration as returned by the admin API: the registration payload plus its state.</summary>
/// <param name="AgentId">Stable identifier.</param>
/// <param name="DisplayName">Human-readable name.</param>
/// <param name="SponsorRequired">Whether a human subject token is required.</param>
/// <param name="AllowedScopes">Scopes the agent may ever be granted.</param>
/// <param name="AllowedAudiences">Audiences the agent may request tokens for.</param>
/// <param name="MaxTaskTtl">Upper bound on a task's lifetime.</param>
/// <param name="MaxTokenTtl">Upper bound on a token's lifetime.</param>
/// <param name="MaxDelegationDepth">Maximum nesting of the <c>act</c> chain.</param>
/// <param name="HighRiskAudiences">Audiences that require per-call introspection.</param>
/// <param name="JwksUri">Where the agent publishes its public keys; <c>null</c> when they are held inline.</param>
/// <param name="Jwks">The agent's public keys when the control plane holds them, public members only; <c>null</c> when it has a <c>jwks_uri</c>. Both are always present, exactly one non-null.</param>
/// <param name="Enabled">Whether new exchanges are accepted.</param>
/// <param name="CreatedAt">Registration time.</param>
/// <param name="UpdatedAt">Last change.</param>
public sealed record AgentResponse(
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("sponsor_required")] bool SponsorRequired,
    [property: JsonPropertyName("allowed_scopes")] IReadOnlyList<string> AllowedScopes,
    [property: JsonPropertyName("allowed_audiences")] IReadOnlyList<string> AllowedAudiences,
    [property: JsonPropertyName("max_task_ttl")] TimeSpan MaxTaskTtl,
    [property: JsonPropertyName("max_token_ttl")] TimeSpan MaxTokenTtl,
    [property: JsonPropertyName("max_delegation_depth")] int MaxDelegationDepth,
    [property: JsonPropertyName("high_risk_audiences")] IReadOnlyList<string> HighRiskAudiences,
    [property: JsonPropertyName("jwks_uri")] string? JwksUri,
    [property: JsonPropertyName("jwks")] JsonElement? Jwks,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("updated_at")] DateTimeOffset UpdatedAt)
{
    /// <summary>
    /// Reads a response back into a domain agent, for clients of this API.
    /// </summary>
    /// <exception cref="System.Text.Json.JsonException">The <c>jwks</c> member is not a key set this server would have issued.</exception>
    public Agent ToAgent()
    {
        AgentJwks? jwks = null;
        if (Jwks is { } inline && AgentJwks.TryParse(inline, "jwks", out jwks).Count > 0)
        {
            throw new System.Text.Json.JsonException("The agent's key set could not be read.");
        }

        return new Agent(
            AgentId,
            DisplayName,
            SponsorRequired,
            AllowedScopes,
            AllowedAudiences,
            MaxTaskTtl,
            MaxTokenTtl,
            MaxDelegationDepth,
            HighRiskAudiences,
            JwksUri is null ? null : new Uri(JwksUri, UriKind.Absolute),
            jwks,
            Enabled,
            CreatedAt,
            UpdatedAt);
    }

    /// <summary>Maps a domain agent to the response.</summary>
    /// <param name="agent">The agent.</param>
    public static AgentResponse From(Agent agent)
    {
        ArgumentNullException.ThrowIfNull(agent);

        return new AgentResponse(
            agent.AgentId,
            agent.DisplayName,
            agent.SponsorRequired,
            agent.AllowedScopes,
            agent.AllowedAudiences,
            agent.MaxTaskTtl,
            agent.MaxTokenTtl,
            agent.MaxDelegationDepth,
            agent.HighRiskAudiences,
            agent.JwksUri?.ToString(),
            // Re-serialized from the stored members, not echoed from what was posted.
            agent.Jwks is null ? null : JsonSerializer.Deserialize<JsonElement>(agent.Jwks.ToJson()),
            agent.Enabled,
            agent.CreatedAt,
            agent.UpdatedAt);
    }
}

/// <summary>One page of <c>GET /admin/agents</c>: the agents in id order, and where the next page starts.</summary>
/// <param name="Agents">The agents of this page.</param>
/// <param name="NextAfter">Pass as <c>after</c> for the next page. <c>null</c> on the last page.</param>
public sealed record AgentsResponse(
    [property: JsonPropertyName("agents")] IReadOnlyList<AgentResponse> Agents,
    [property: JsonPropertyName("next_after")] string? NextAfter)
{
    /// <summary>
    /// Builds the page from up to one agent more than the page size. The extra one only signals a
    /// next page and is not returned.
    /// </summary>
    /// <param name="agents">Up to <paramref name="limit"/> + 1 agents.</param>
    /// <param name="limit">The page size asked for.</param>
    public static AgentsResponse From(IReadOnlyList<Agent> agents, int limit)
    {
        ArgumentNullException.ThrowIfNull(agents);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        var page = agents.Take(limit).ToList();
        var next = agents.Count > limit ? page[^1].AgentId : null;
        return new AgentsResponse(page.Select(AgentResponse.From).ToList(), next);
    }
}
