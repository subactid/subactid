namespace SubactId.Storage.Ef.Schema;

/// <summary>Persisted agent registration (spec section 2).</summary>
public sealed class AgentRow
{
    /// <summary>Stable identifier, for example <c>jira-triage</c>.</summary>
    public required string AgentId { get; set; }

    /// <summary>Human-readable name.</summary>
    public required string DisplayName { get; set; }

    /// <summary>When <c>true</c>, no token is issued without a human subject token.</summary>
    public bool SponsorRequired { get; set; } = true;

    /// <summary>Scopes the agent may ever be granted.</summary>
    public required string[] AllowedScopes { get; set; }

    /// <summary>Audiences the agent may request tokens for.</summary>
    public required string[] AllowedAudiences { get; set; }

    /// <summary>Upper bound on the lifetime of a whole task.</summary>
    public TimeSpan MaxTaskTtl { get; set; }

    /// <summary>Upper bound on the lifetime of a single token.</summary>
    public TimeSpan MaxTokenTtl { get; set; }

    /// <summary>Maximum nesting of the <c>act</c> chain.</summary>
    public int MaxDelegationDepth { get; set; }

    /// <summary>Audiences that require per-call introspection instead of local validation.</summary>
    public string[] HighRiskAudiences { get; set; } = [];

    /// <summary>Where the agent publishes the public keys it authenticates with.</summary>
    public string? JwksUri { get; set; }

    /// <summary>The agent's public keys as a JSON Web Key Set, when stored here instead of fetched.</summary>
    public string? Jwks { get; set; }

    /// <summary>A disabled agent is refused every new exchange immediately.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>When the agent was registered.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>When the registration was last changed.</summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
