using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SubactId.Core.Agents;
using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// The query string of <c>GET /admin/agents</c>: <c>after</c> to continue from the
/// <c>next_after</c> of the previous page, <c>limit</c> to size it. Agents come back in id order.
/// </summary>
public sealed class ListAgentsRequest
{
    /// <summary>Default for <see cref="Limit"/>.</summary>
    public const int DefaultLimit = 100;

    /// <summary>Largest <see cref="Limit"/> accepted.</summary>
    public const int MaxLimit = 1000;

    /// <summary>Continue strictly after this agent id. Absent starts at the first.</summary>
    [FromQuery(Name = "after")]
    public string? After { get; init; }

    /// <summary>Page size, 1 to <see cref="MaxLimit"/>. <see cref="DefaultLimit"/> when absent.</summary>
    [FromQuery(Name = "limit")]
    public string? Limit { get; init; }

    /// <summary>Validates both fields.</summary>
    /// <param name="after">The agent id to continue after. <c>null</c> for the first page.</param>
    /// <param name="limit">The page size.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public IReadOnlyList<ValidationError> TryToQuery(out string? after, out int limit)
    {
        var errors = new List<ValidationError>();

        after = After;
        if (After is not null && (After.Length is 0 or > AgentValidator.MaxAgentIdLength || After.Any(char.IsControl)))
        {
            errors.Add(new ValidationError("after", "must be an agent id, as returned in next_after."));
        }

        limit = DefaultLimit;
        if (Limit is not null && (!int.TryParse(Limit, NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit < 1 || limit > MaxLimit))
        {
            errors.Add(new ValidationError("limit", $"must be a whole number from 1 to {MaxLimit}."));
        }

        if (errors.Count > 0)
        {
            // Reset to defaults so a caller that ignores the errors never uses a rejected value.
            after = null;
            limit = DefaultLimit;
        }

        return errors;
    }
}
