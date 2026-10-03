using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>Turns validation errors into the 400 response every endpoint uses for them.</summary>
public static class ValidationProblems
{
    /// <summary>
    /// A <c>400 Bad Request</c> problem-details response whose <c>errors</c> member maps each
    /// offending field to its messages, for example
    /// <c>{"errors":{"max_token_ttl":["must not exceed max_task_ttl."]}}</c>.
    /// </summary>
    /// <param name="errors">The errors to report. Must not be empty.</param>
    public static IResult ToResult(IReadOnlyList<ValidationError> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);
        ArgumentOutOfRangeException.ThrowIfZero(errors.Count);

        var byField = errors
            .GroupBy(e => e.Field, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Message).ToArray(), StringComparer.Ordinal);

        return Results.ValidationProblem(byField, title: "The request is invalid.");
    }
}
