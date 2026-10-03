using SubactId.Core.Audit;

namespace SubactId.Server.Audit;

/// <summary>
/// Summarises a task's successful renewals. The first is written as its own record, the rest are
/// counted, and one summary with <c>count</c> is written when the task ends. The count lives on
/// the grant, so it is exact across restarts and instances. Refused renewals are never summarised.
/// </summary>
/// <remarks>
/// Follows <see cref="DenialAggregationOptions.Enabled"/>. When off, every renewal is written and
/// no summary is. Toggling it while tasks are alive can double-count renewals in the summary.
/// </remarks>
public sealed class RenewalSummary(DenialAggregationOptions options)
{
    /// <summary>
    /// Whether the renewal that brought a grant's count to <paramref name="renewals"/> gets its own
    /// record. True for the first renewal, and for every renewal when summarising is off.
    /// </summary>
    /// <param name="renewals">The grant's count after this renewal.</param>
    public bool WritesThrough(int renewals) => renewals <= 1 || !options.Enabled;

    /// <summary>
    /// The records that end a task: a renewal summary if it renewed more than once, then
    /// <paramref name="terminal"/>. The summary is a <c>token.refreshed</c> record with the terminal
    /// record's task, agent, sponsor, audience, scope and depth, no <c>jti</c>, and <c>count</c>
    /// set to the renewals after the first.
    /// </summary>
    /// <param name="terminal">The <c>task.expired</c> or <c>task.revoked</c> record.</param>
    /// <param name="renewals">How many times the task's grant was used to refresh.</param>
    public IReadOnlyList<AuditEvent> Ending(AuditEvent terminal, int renewals)
    {
        ArgumentNullException.ThrowIfNull(terminal);

        if (!options.Enabled || renewals < 2)
        {
            return [terminal];
        }

        var summary = new AuditEvent(
            terminal.Ts,
            AuditEvents.TokenRefreshed,
            terminal.TaskId,
            terminal.AgentId,
            terminal.Sponsor,
            terminal.Audience,
            terminal.Scope,
            Jti: null,
            DelegationDepth: terminal.DelegationDepth,
            Decision: AuditDecision.Allow,
            Count: renewals - 1);
        return [summary, terminal];
    }
}
