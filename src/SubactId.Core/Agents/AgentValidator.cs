using System.Text.RegularExpressions;
using SubactId.Core.Validation;

namespace SubactId.Core.Agents;

/// <summary>
/// Validates an <see cref="Agent"/> registration. Errors use spec field names and can be returned
/// to an administrator as is.
/// </summary>
public static partial class AgentValidator
{
    /// <summary>Longest allowed <c>agent_id</c>.</summary>
    public const int MaxAgentIdLength = 128;

    /// <summary>Longest allowed <c>display_name</c>.</summary>
    public const int MaxDisplayNameLength = 256;

    /// <summary>Longest allowed scope, audience or JWKS URI.</summary>
    public const int MaxValueLength = Syntax.MaxValueLength;

    /// <summary>Returns every problem with <paramref name="candidate"/>; empty means valid.</summary>
    /// <param name="candidate">The registration to check.</param>
    /// <param name="limits">Server-wide lifetime bounds.</param>
    public static IReadOnlyList<ValidationError> Validate(Agent candidate, AgentRegistrationLimits limits)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(limits);

        var errors = new List<ValidationError>();

        if (string.IsNullOrEmpty(candidate.AgentId) || candidate.AgentId.Length > MaxAgentIdLength || !AgentId().IsMatch(candidate.AgentId))
        {
            errors.Add(new("agent_id", $"must be 1 to {MaxAgentIdLength} characters of lowercase letters, digits, '-', '_' or '.', starting with a letter or digit."));
        }

        if (string.IsNullOrWhiteSpace(candidate.DisplayName) || candidate.DisplayName.Length > MaxDisplayNameLength)
        {
            errors.Add(new("display_name", $"must be 1 to {MaxDisplayNameLength} characters."));
        }

        // Every exchange requires a human subject token, so `false` is not supported.
        if (!candidate.SponsorRequired)
        {
            errors.Add(new("sponsor_required", "must be true: issuing without a human subject token is not supported yet."));
        }

        ValidateScopes(candidate.AllowedScopes, errors);
        ValidateAudiences("allowed_audiences", candidate.AllowedAudiences, required: true, errors);
        ValidateAudiences("high_risk_audiences", candidate.HighRiskAudiences, required: false, errors);

        if (candidate.MaxTaskTtl < limits.MinTaskTtl || candidate.MaxTaskTtl > limits.MaxTaskTtl)
        {
            errors.Add(new("max_task_ttl", $"must be between {limits.MinTaskTtl} and {limits.MaxTaskTtl}."));
        }

        if (candidate.MaxTokenTtl < limits.MinTokenTtl || candidate.MaxTokenTtl > limits.MaxTokenTtl)
        {
            errors.Add(new("max_token_ttl", $"must be between {limits.MinTokenTtl} and {limits.MaxTokenTtl}."));
        }
        else if (candidate.MaxTokenTtl > candidate.MaxTaskTtl)
        {
            errors.Add(new("max_token_ttl", "must not exceed max_task_ttl."));
        }

        if (candidate.MaxDelegationDepth is < AgentRegistrationLimits.MinDelegationDepth or > AgentRegistrationLimits.MaxDelegationDepth)
        {
            errors.Add(new("max_delegation_depth", $"must be between {AgentRegistrationLimits.MinDelegationDepth} and {AgentRegistrationLimits.MaxDelegationDepth}."));
        }

        if (candidate.JwksUri is { } jwks && (!jwks.IsAbsoluteUri || jwks.Scheme != Uri.UriSchemeHttps || jwks.OriginalString.Length > MaxValueLength))
        {
            errors.Add(new("jwks_uri", "must be an absolute https URL."));
        }

        // Keys come from exactly one source: jwks or jwks_uri.
        if (candidate.JwksUri is not null && candidate.Jwks is not null)
        {
            errors.Add(new("jwks", "must not be set together with jwks_uri; an agent's keys come from one place."));
        }

        if (candidate.Jwks is { Keys.Count: 0 })
        {
            errors.Add(new("jwks", "must contain at least one key."));
        }

        // Without a key source the agent could never authenticate.
        if (candidate.JwksUri is null && candidate.Jwks is null)
        {
            errors.Add(new("jwks_uri", "is required unless jwks is given; an agent's keys must come from one of the two."));
        }

        return errors;
    }

    private static void ValidateScopes(IReadOnlyList<string> scopes, List<ValidationError> errors)
    {
        if (scopes.Count == 0)
        {
            errors.Add(new("allowed_scopes", "must contain at least one scope."));
            return;
        }

        if (scopes.Any(s => !Syntax.IsScopeToken(s)))
        {
            errors.Add(new("allowed_scopes", "every scope must be printable ASCII without spaces, quotes or backslashes."));
        }

        if (scopes.Distinct(StringComparer.Ordinal).Count() != scopes.Count)
        {
            errors.Add(new("allowed_scopes", "must not contain duplicates."));
        }
    }

    private static void ValidateAudiences(string field, IReadOnlyList<string> audiences, bool required, List<ValidationError> errors)
    {
        if (audiences.Count == 0)
        {
            if (required)
            {
                errors.Add(new(field, "must contain at least one audience."));
            }

            return;
        }

        if (audiences.Any(a => !Syntax.IsAudience(a)))
        {
            errors.Add(new(field, "every audience must be an absolute http or https URL."));
        }

        if (audiences.Distinct(StringComparer.Ordinal).Count() != audiences.Count)
        {
            errors.Add(new(field, "must not contain duplicates."));
        }
    }

    // \z, not $: in .NET, $ also matches before a final newline, which would let "jira\n" through.
    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]*\z", RegexOptions.CultureInvariant)]
    private static partial Regex AgentId();
}
