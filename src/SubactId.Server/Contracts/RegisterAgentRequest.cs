using System.Text.Json;
using System.Text.Json.Serialization;
using SubactId.Core.Agents;
using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// Body of <c>POST /admin/agents</c>, the registration payload of spec section 2. Every field is
/// nullable so a missing one becomes a per-field error.
/// </summary>
/// <param name="AgentId">Stable identifier, for example <c>jira-triage</c>.</param>
/// <param name="DisplayName">Human-readable name.</param>
/// <param name="SponsorRequired">Whether a human subject token is required. Defaults to <c>true</c>.</param>
/// <param name="AllowedScopes">Scopes the agent may ever be granted.</param>
/// <param name="AllowedAudiences">Audiences the agent may request tokens for.</param>
/// <param name="MaxTaskTtl">Lifetime of a whole task, as an ISO 8601 duration. Optional. Defaults to the server's.</param>
/// <param name="MaxTokenTtl">Lifetime of a single token, as an ISO 8601 duration, never past the task's end. Optional. Defaults to the server's.</param>
/// <param name="MaxDelegationDepth">Maximum nesting of the <c>act</c> chain.</param>
/// <param name="HighRiskAudiences">Audiences that require per-call introspection. Defaults to none.</param>
/// <param name="JwksUri">Where the agent publishes the public keys it authenticates with.</param>
/// <param name="Jwks">The agent's public keys inline, as an RFC 7517 key set. Exactly one of this and <paramref name="JwksUri"/> is set.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record RegisterAgentRequest(
    string? AgentId,
    string? DisplayName,
    bool? SponsorRequired,
    IReadOnlyList<string>? AllowedScopes,
    IReadOnlyList<string>? AllowedAudiences,
    TimeSpan? MaxTaskTtl,
    TimeSpan? MaxTokenTtl,
    int? MaxDelegationDepth,
    IReadOnlyList<string>? HighRiskAudiences,
    string? JwksUri,
    JsonElement? Jwks)
{
    /// <summary>
    /// Validates the request and, when it is valid, produces the <see cref="Agent"/> to store.
    /// Missing required fields are reported before the domain rules run.
    /// </summary>
    /// <param name="limits">Server-wide lifetime bounds.</param>
    /// <param name="now">Registration time, used for the created and updated timestamps.</param>
    /// <param name="agent">The agent to store. <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public IReadOnlyList<ValidationError> TryToAgent(AgentRegistrationLimits limits, DateTimeOffset now, out Agent? agent)
    {
        ArgumentNullException.ThrowIfNull(limits);

        agent = null;
        var errors = new List<ValidationError>();

        Require(AgentId, "agent_id", errors);
        Require(DisplayName, "display_name", errors);
        Require(AllowedScopes, "allowed_scopes", errors);
        Require(AllowedAudiences, "allowed_audiences", errors);
        Require(MaxDelegationDepth, "max_delegation_depth", errors);

        if (JwksUri is not null && !Uri.TryCreate(JwksUri, UriKind.Absolute, out _))
        {
            errors.Add(new("jwks_uri", "must be an absolute https URL."));
        }

        AgentJwks? jwks = null;
        if (Jwks is { } inline)
        {
            errors.AddRange(AgentJwksBinding.TryRead(inline, out jwks));
        }

        if (errors.Count > 0)
        {
            return errors;
        }

        var candidate = new Agent(
            AgentId!,
            DisplayName!,
            SponsorRequired ?? true,
            AllowedScopes!,
            AllowedAudiences!,
            // Omitted lifetimes take the server defaults, still checked against the server bounds.
            // A default token lifetime is cut to the task lifetime, never extended past it.
            MaxTaskTtl ?? limits.DefaultTaskTtl,
            MaxTokenTtl ?? Shorter(limits.DefaultTokenTtl, MaxTaskTtl ?? limits.DefaultTaskTtl),
            MaxDelegationDepth!.Value,
            HighRiskAudiences ?? [],
            JwksUri is null ? null : new Uri(JwksUri, UriKind.Absolute),
            jwks,
            Enabled: true,
            CreatedAt: now,
            UpdatedAt: now);

        var domainErrors = AgentValidator.Validate(candidate, limits);
        if (domainErrors.Count > 0)
        {
            return domainErrors;
        }

        agent = candidate;
        return [];
    }

    private static TimeSpan Shorter(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private static void Require<T>(T? value, string field, List<ValidationError> errors)
    {
        if (value is null)
        {
            errors.Add(new(field, "is required."));
        }
    }
}
