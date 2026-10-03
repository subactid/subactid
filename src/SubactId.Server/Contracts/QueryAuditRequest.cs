using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Sponsors;
using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// The query string of <c>GET /audit</c>: any of <c>sponsor</c>, <c>agent_id</c>, <c>task_id</c>,
/// <c>from</c>, <c>to</c> and <c>decision</c> to filter, <c>limit</c> and <c>cursor</c> to page.
/// A time is an ISO 8601 timestamp or a bare date meaning midnight UTC. A bare date in <c>to</c>
/// covers that whole day, so <c>from=2026-09-01&amp;to=2026-09-30</c> is all of September.
/// </summary>
public sealed class QueryAuditRequest
{
    /// <summary>Default for <see cref="Limit"/>.</summary>
    public const int DefaultLimit = AuditQuery.DefaultLimit;

    /// <summary>Largest <see cref="Limit"/> accepted.</summary>
    public const int MaxLimit = 1000;

    /// <summary>Longest <see cref="TaskId"/> accepted: the width of the ledger's <c>task_id</c> column.</summary>
    public const int MaxTaskIdLength = 64;

    private const string DateFormat = "yyyy-MM-dd";
    private static readonly string[] TimestampFormats = ["yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"];

    /// <summary>The human the actions were taken on behalf of.</summary>
    [FromQuery(Name = "sponsor")]
    public string? Sponsor { get; init; }

    /// <summary>The agent that acted.</summary>
    [FromQuery(Name = "agent_id")]
    public string? AgentId { get; init; }

    /// <summary>The task.</summary>
    [FromQuery(Name = "task_id")]
    public string? TaskId { get; init; }

    /// <summary>Earliest time, inclusive.</summary>
    [FromQuery(Name = "from")]
    public string? From { get; init; }

    /// <summary>Latest time, exclusive. A bare date includes that whole day.</summary>
    [FromQuery(Name = "to")]
    public string? To { get; init; }

    /// <summary><c>allow</c> or <c>deny</c>.</summary>
    [FromQuery(Name = "decision")]
    public string? Decision { get; init; }

    /// <summary>Page size, 1 to <see cref="MaxLimit"/>. <see cref="DefaultLimit"/> when absent.</summary>
    [FromQuery(Name = "limit")]
    public string? Limit { get; init; }

    /// <summary>The <c>next_cursor</c> of the previous page.</summary>
    [FromQuery(Name = "cursor")]
    public string? Cursor { get; init; }

    /// <summary>Validates every field and maps the request to a domain query.</summary>
    /// <param name="query">The query. <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public IReadOnlyList<ValidationError> TryToQuery(out AuditQuery? query)
    {
        query = null;
        var errors = new List<ValidationError>();

        var sponsor = ReadId("sponsor", Sponsor, SponsorKey.MaxLength, errors);
        var agentId = ReadId("agent_id", AgentId, AgentValidator.MaxAgentIdLength, errors);
        var taskId = ReadId("task_id", TaskId, MaxTaskIdLength, errors);
        var from = ReadTime("from", From, endOfDay: false, errors);
        var to = ReadTime("to", To, endOfDay: true, errors);
        if (from is { } f && to is { } t && f >= t)
        {
            errors.Add(new ValidationError("to", "must be after from."));
        }

        AuditDecision? decision = null;
        if (Decision is not null)
        {
            decision = AuditDecisionCodes.FromCode(Decision);
            if (decision is null)
            {
                errors.Add(new ValidationError("decision", "must be allow or deny."));
            }
        }

        var limit = DefaultLimit;
        if (Limit is not null && (!int.TryParse(Limit, NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit < 1 || limit > MaxLimit))
        {
            errors.Add(new ValidationError("limit", $"must be a whole number from 1 to {MaxLimit}."));
        }

        AuditCursor? after = null;
        if (Cursor is not null && (after = AuditCursorCodec.Decode(Cursor)) is null)
        {
            errors.Add(new ValidationError("cursor", "is not a cursor from a previous page."));
        }

        if (errors.Count > 0)
        {
            return errors;
        }

        query = new AuditQuery(sponsor, agentId, taskId, from, to, decision, after, limit);
        return errors;
    }

    private static string? ReadId(string field, string? value, int maxLength, List<ValidationError> errors)
    {
        if (value is null)
        {
            return null;
        }

        // Control characters are rejected too: Postgres refuses NUL in a text parameter, which
        // would otherwise surface as a 500.
        if (value.Length == 0 || value.Length > maxLength || value.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            errors.Add(new ValidationError(field, $"must be 1 to {maxLength} characters without whitespace or control characters."));
            return null;
        }

        return value;
    }

    private static DateTimeOffset? ReadTime(string field, string? value, bool endOfDay, List<ValidationError> errors)
    {
        if (value is null)
        {
            return null;
        }

        if (DateOnly.TryParseExact(value, DateFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
        {
            var midnight = new DateTimeOffset(date.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
            if (!endOfDay)
            {
                return midnight;
            }

            if (date == DateOnly.MaxValue)
            {
                errors.Add(new ValidationError(field, "is too far in the future."));
                return null;
            }

            return midnight.AddDays(1);
        }

        if (DateTimeOffset.TryParseExact(value, TimestampFormats, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var time))
        {
            return time;
        }

        errors.Add(new ValidationError(field, "must be a date such as 2026-09-01 or a timestamp such as 2026-09-01T14:32:00Z."));
        return null;
    }
}
