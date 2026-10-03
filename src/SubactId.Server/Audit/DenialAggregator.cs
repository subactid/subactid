using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SubactId.Core.Audit;

namespace SubactId.Server.Audit;

/// <summary>
/// Collapses unattributable denials into one summary record per reason per window.
/// </summary>
/// <remarks>
/// <para>
/// Every denial is still audited. The first occurrence of a reason opens a window and is written
/// immediately. Later occurrences in the window are counted, and one summary with the count is
/// written when the window closes.
/// </para>
/// <para>
/// Denials that name an agent, human or task are never aggregated.
/// </para>
/// <para>
/// The key is the event and reason, both from the server's fixed sets. Nothing caller-supplied
/// is part of it, so a caller cannot force a new row per request.
/// </para>
/// </remarks>
/// <param name="clock">The clock.</param>
/// <param name="options">The window and whether aggregation is on.</param>
/// <param name="logger">Where a denial that had to be carried over is reported.</param>
public sealed class DenialAggregator(TimeProvider clock, DenialAggregationOptions options, ILogger<DenialAggregator>? logger = null)
{
    private readonly Lock gate = new();
    private readonly Dictionary<DenialKey, int> suppressed = [];
    private readonly ILogger log = logger ?? NullLogger<DenialAggregator>.Instance;

    /// <summary>
    /// Records a denial. It is written now, or counted into its reason's summary when aggregation
    /// says so. If the ledger cannot take it now and it names nobody, it is carried over into the
    /// next summary for its reason and the refusal can still be answered: denials are never
    /// dropped (spec section 8). A denial that names an agent, a person, a task or a token cannot
    /// be summarised without losing who it names, so its write failure propagates and the request
    /// fails without a refusal being answered.
    /// </summary>
    /// <param name="record">The denial.</param>
    /// <param name="audit">The ledger.</param>
    public async Task RecordAsync(AuditEvent record, IAuditWriter audit)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(audit);

        if (!ShouldWriteThrough(record))
        {
            return;
        }

        try
        {
            // Not cancellable by the caller, so a client that hangs up cannot drop its denial.
            await audit.AppendAsync(record, CancellationToken.None);
        }
        catch (Exception exception) when (IsUnattributedDenial(record, out _))
        {
            CarryOver(record);
            log.LogWarning(exception, "A refusal ({Event}, {Reason}) could not be recorded now; it is counted into the next summary for that reason.", record.Event, record.Reason);
        }
    }

    /// <summary>
    /// Whether the caller must write <paramref name="record"/> to the ledger itself. When
    /// <c>false</c>, the record has been counted and reaches the ledger when the window is drained.
    /// </summary>
    /// <param name="record">The record about to be written.</param>
    public bool ShouldWriteThrough(AuditEvent record)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (!options.Enabled || !IsAggregatable(record, out var key))
        {
            return true;
        }

        lock (gate)
        {
            if (!suppressed.TryGetValue(key, out var count))
            {
                // First of its kind this window: open the window and write it now.
                suppressed[key] = 0;
                return true;
            }

            // Saturating, so the count never overflows.
            suppressed[key] = count == int.MaxValue ? count : count + 1;
            return false;
        }
    }

    /// <summary>
    /// Takes back a denial that names nobody but could not be written: a record its caller failed
    /// to write through, or a summary whose flush failed. It is counted into the next summary for
    /// its reason, so it reaches the ledger at the next drain rather than being lost. Applies
    /// whether or not aggregation is on, since it is how a denial is kept, not how it is reduced.
    /// </summary>
    /// <param name="record">The record that was not written. A summary carries its count back.</param>
    /// <exception cref="ArgumentException"><paramref name="record"/> is not a denial that names nobody.</exception>
    public void CarryOver(AuditEvent record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!IsUnattributedDenial(record, out var key))
        {
            throw new ArgumentException("Only a denial that names nobody can be carried over; any other record is written by its caller or not at all.", nameof(record));
        }

        var weight = record.Count is { } count && count > 0 ? count : 1;
        lock (gate)
        {
            var held = suppressed.GetValueOrDefault(key);
            suppressed[key] = held > int.MaxValue - weight ? int.MaxValue : held + weight;
        }
    }

    /// <summary>
    /// Takes the counts accumulated since the last drain and closes every window. Reasons that
    /// occurred only once produce no summary, since that occurrence was already written.
    /// </summary>
    public IReadOnlyList<AuditEvent> Drain()
    {
        var now = clock.GetUtcNow();
        lock (gate)
        {
            if (suppressed.Count == 0)
            {
                return [];
            }

            var summaries = new List<AuditEvent>(suppressed.Count);
            foreach (var (key, count) in suppressed)
            {
                if (count > 0)
                {
                    summaries.Add(new AuditEvent(now, key.Event, Decision: AuditDecision.Deny, Reason: key.Reason, Count: count));
                }
            }

            suppressed.Clear();
            return summaries;
        }
    }

    /// <summary>
    /// Whether a record is an unattributable denial: no agent, human, task or <c>jti</c>, and not
    /// already a summary.
    /// </summary>
    /// <param name="record">The record.</param>
    /// <param name="key">The window it belongs to, when it is aggregatable.</param>
    private static bool IsAggregatable(AuditEvent record, [NotNullWhen(true)] out DenialKey key)
    {
        key = default;
        return record.Count is null && IsUnattributedDenial(record, out key);
    }

    /// <summary>Whether a record, summary or not, is a denial that names no agent, human, task or <c>jti</c>.</summary>
    private static bool IsUnattributedDenial(AuditEvent record, [NotNullWhen(true)] out DenialKey key)
    {
        key = default;
        if (record.Decision != AuditDecision.Deny
            || record.Reason is not { Length: > 0 } reason
            || record.AgentId is not null
            || record.Sponsor is not null
            || record.TaskId is not null
            || record.Jti is not null)
        {
            return false;
        }

        key = new DenialKey(record.Event, reason);
        return true;
    }

    /// <summary>One window: an event and the reason it was denied for.</summary>
    /// <param name="Event">The event name.</param>
    /// <param name="Reason">The machine-readable reason.</param>
    private readonly record struct DenialKey(string Event, string Reason);
}
