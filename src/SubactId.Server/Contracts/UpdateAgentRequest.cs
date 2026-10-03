using System.Text.Json;
using System.Text.Json.Serialization;
using SubactId.Core.Agents;
using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// Body of <c>PATCH /admin/agents/{id}</c>: any subset of the registration fields plus
/// <c>enabled</c>. Only present fields change. The merged registration is validated as a whole,
/// like a new one. <c>agent_id</c> cannot be changed; it may be sent only as the id already in the
/// path, so a whole registration can be sent back as an update.
/// </summary>
/// <param name="DisplayName">New display name.</param>
/// <param name="SponsorRequired">New sponsor requirement.</param>
/// <param name="AllowedScopes">Replacement scope list.</param>
/// <param name="AllowedAudiences">Replacement audience list.</param>
/// <param name="MaxTaskTtl">New task lifetime bound.</param>
/// <param name="MaxTokenTtl">New token lifetime bound.</param>
/// <param name="MaxDelegationDepth">New delegation depth bound.</param>
/// <param name="HighRiskAudiences">Replacement high-risk audience list.</param>
/// <param name="JwksUri">New JWKS URL. Setting it moves the agent off inline keys.</param>
/// <param name="Jwks">Replacement inline key set. Setting it moves the agent off a JWKS URL.</param>
/// <param name="Enabled">Enable or disable the agent. Disabling blocks new exchanges on the next request.</param>
/// <param name="AgentId">Accepted only as the id already in the path, so a whole registration can be sent back as an update. Never changes.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateAgentRequest(
    string? DisplayName,
    bool? SponsorRequired,
    IReadOnlyList<string>? AllowedScopes,
    IReadOnlyList<string>? AllowedAudiences,
    TimeSpan? MaxTaskTtl,
    TimeSpan? MaxTokenTtl,
    int? MaxDelegationDepth,
    IReadOnlyList<string>? HighRiskAudiences,
    string? JwksUri,
    JsonElement? Jwks,
    bool? Enabled,
    string? AgentId = null)
{
    /// <summary>The spec field names this request changes, in payload order.</summary>
    public IReadOnlyList<string> ChangedFields()
    {
        var fields = new List<string>(10);
        if (DisplayName is not null) fields.Add("display_name");
        if (SponsorRequired is not null) fields.Add("sponsor_required");
        if (AllowedScopes is not null) fields.Add("allowed_scopes");
        if (AllowedAudiences is not null) fields.Add("allowed_audiences");
        if (MaxTaskTtl is not null) fields.Add("max_task_ttl");
        if (MaxTokenTtl is not null) fields.Add("max_token_ttl");
        if (MaxDelegationDepth is not null) fields.Add("max_delegation_depth");
        if (HighRiskAudiences is not null) fields.Add("high_risk_audiences");
        if (JwksUri is not null) fields.Add("jwks_uri");
        if (Jwks is not null) fields.Add("jwks");
        if (Enabled is not null) fields.Add("enabled");
        return fields;
    }

    /// <summary>Applies the present fields to <paramref name="existing"/> and validates the result.</summary>
    /// <param name="existing">The current registration.</param>
    /// <param name="limits">Server-wide lifetime bounds.</param>
    /// <param name="now">Update time.</param>
    /// <param name="updated">The merged registration. <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public IReadOnlyList<ValidationError> TryApplyTo(Agent existing, AgentRegistrationLimits limits, DateTimeOffset now, out Agent? updated)
    {
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(limits);

        updated = null;

        // Errors are collected, one or more per field, rather than returned at the first: a
        // field this step cannot read is left as it was for the whole-registration check below,
        // so that check still reports every other field.
        var errors = new List<ValidationError>();
        if (AgentId is not null && !string.Equals(AgentId, existing.AgentId, StringComparison.Ordinal))
        {
            errors.Add(new ValidationError("agent_id", "cannot be changed; it must be the agent in the path, or left out."));
        }

        Uri? jwksUri = null;
        if (JwksUri is not null && !Uri.TryCreate(JwksUri, UriKind.Absolute, out jwksUri))
        {
            errors.Add(new ValidationError("jwks_uri", "must be an absolute https URL."));
        }

        var bothKeySources = JwksUri is not null && Jwks is not null;
        if (bothKeySources)
        {
            errors.Add(new ValidationError("jwks", "must not be set together with jwks_uri; an agent's keys come from one place."));
        }

        AgentJwks? jwks = existing.Jwks;
        var jwksRead = false;
        if (Jwks is { } inline)
        {
            var jwksErrors = AgentJwksBinding.TryRead(inline, out var read);
            errors.AddRange(jwksErrors);
            if (jwksErrors.Count == 0)
            {
                jwks = read;
                jwksRead = true;
            }
        }

        // Setting one key source clears the other. An agent's keys come from one place. A source
        // that could not be read, or two at once, leaves the keys as they were.
        var (newJwksUri, newJwks) = bothKeySources
            ? (existing.JwksUri, existing.Jwks)
            : jwksRead ? (null, jwks)
            : jwksUri is not null ? (jwksUri, (AgentJwks?)null)
            : (existing.JwksUri, existing.Jwks);

        var candidate = existing with
        {
            DisplayName = DisplayName ?? existing.DisplayName,
            SponsorRequired = SponsorRequired ?? existing.SponsorRequired,
            AllowedScopes = AllowedScopes ?? existing.AllowedScopes,
            AllowedAudiences = AllowedAudiences ?? existing.AllowedAudiences,
            MaxTaskTtl = MaxTaskTtl ?? existing.MaxTaskTtl,
            MaxTokenTtl = MaxTokenTtl ?? existing.MaxTokenTtl,
            MaxDelegationDepth = MaxDelegationDepth ?? existing.MaxDelegationDepth,
            HighRiskAudiences = HighRiskAudiences ?? existing.HighRiskAudiences,
            JwksUri = newJwksUri,
            Jwks = newJwks,
            Enabled = Enabled ?? existing.Enabled,
            UpdatedAt = now,
        };

        errors.AddRange(AgentValidator.Validate(candidate, limits));
        if (errors.Count > 0)
        {
            return errors;
        }

        updated = candidate;
        return [];
    }
}
