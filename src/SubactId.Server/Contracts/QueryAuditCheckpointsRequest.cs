using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// The query string of <c>GET /audit/checkpoints</c>: <c>after</c> to continue from the
/// <c>next_after</c> of the previous page, <c>limit</c> to size it. Checkpoints come back oldest
/// first.
/// </summary>
public sealed class QueryAuditCheckpointsRequest
{
    /// <summary>Default for <see cref="Limit"/>.</summary>
    public const int DefaultLimit = 100;

    /// <summary>Largest <see cref="Limit"/> accepted.</summary>
    public const int MaxLimit = 1000;

    /// <summary>Continue strictly after this checkpoint id. Absent starts at the first.</summary>
    [FromQuery(Name = "after")]
    public string? After { get; init; }

    /// <summary>Page size, 1 to <see cref="MaxLimit"/>. <see cref="DefaultLimit"/> when absent.</summary>
    [FromQuery(Name = "limit")]
    public string? Limit { get; init; }

    /// <summary>Validates both fields.</summary>
    /// <param name="after">The checkpoint id to continue after. 0 for the first page.</param>
    /// <param name="limit">The page size.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public IReadOnlyList<ValidationError> TryToQuery(out long after, out int limit)
    {
        var errors = new List<ValidationError>();

        after = 0;
        if (After is not null && (!long.TryParse(After, NumberStyles.None, CultureInfo.InvariantCulture, out after) || after < 0))
        {
            errors.Add(new ValidationError("after", "must be a whole number, as returned in next_after."));
        }

        limit = DefaultLimit;
        if (Limit is not null && (!int.TryParse(Limit, NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit < 1 || limit > MaxLimit))
        {
            errors.Add(new ValidationError("limit", $"must be a whole number from 1 to {MaxLimit}."));
        }

        if (errors.Count > 0)
        {
            // Reset to defaults so a caller that ignores the errors never uses a rejected value.
            after = 0;
            limit = DefaultLimit;
        }

        return errors;
    }
}
