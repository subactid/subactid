namespace SubactId.Core.Audit;

/// <summary>
/// A position in the ledger as ordered by the query: the time of a record, then its sequence
/// number to break ties. A page continues strictly after it.
/// </summary>
/// <param name="Ts">The record's time.</param>
/// <param name="Seq">The record's sequence number.</param>
public sealed record AuditCursor(DateTimeOffset Ts, long Seq);

/// <summary>
/// The audit query of spec section 7: every record matching the filters, oldest first, from
/// the cursor on. Every filter is optional and they combine with AND; <see cref="From"/> is
/// inclusive and <see cref="To"/> exclusive.
/// </summary>
/// <param name="Sponsor">The human the actions were taken on behalf of.</param>
/// <param name="AgentId">The agent that acted.</param>
/// <param name="TaskId">The task.</param>
/// <param name="From">Earliest time, inclusive.</param>
/// <param name="To">Latest time, exclusive.</param>
/// <param name="Decision">Only records with this decision.</param>
/// <param name="After">Continue strictly after this position.</param>
/// <param name="Limit">Most records returned.</param>
public sealed record AuditQuery(
    string? Sponsor = null,
    string? AgentId = null,
    string? TaskId = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    AuditDecision? Decision = null,
    AuditCursor? After = null,
    int Limit = AuditQuery.DefaultLimit)
{
    /// <summary>Page size when none is asked for.</summary>
    public const int DefaultLimit = 100;
}

/// <summary>Read-only, paginated, filtered access to the ledger. One projected query per page.</summary>
public interface IAuditQuery
{
    /// <summary>Up to <c>query.Limit</c> records matching <paramref name="query"/>, ordered by time then sequence number.</summary>
    Task<IReadOnlyList<AuditLedgerRecord>> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default);
}
