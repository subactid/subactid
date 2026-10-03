using System.Text.Json.Serialization;
using SubactId.Core.Audit;

namespace SubactId.Server.Contracts;

/// <summary>
/// One ledger record as published by the audit query and posted to the audit sink (spec
/// section 7). Only the fields listed here leave the server.
/// </summary>
public sealed class AuditRecordPayload
{
    /// <summary>Sequence number, and the position this record is sealed at inside its checkpoint.</summary>
    public required long Seq { get; init; }

    /// <summary>
    /// The checkpoint whose signed root covers this record, or <c>null</c> when it is not sealed
    /// yet. Always written, even when null.
    /// </summary>
    public required long? Checkpoint { get; init; }

    /// <summary>When the event happened, written exactly as it was hashed.</summary>
    [JsonConverter(typeof(AuditTimestampConverter))]
    public required DateTimeOffset Ts { get; init; }

    /// <summary>Event name.</summary>
    public required string Event { get; init; }

    /// <summary>Task involved, if any.</summary>
    public required string? TaskId { get; init; }

    /// <summary>Agent involved, if any.</summary>
    public required string? AgentId { get; init; }

    /// <summary>The human on whose behalf the action was taken, if any.</summary>
    public required string? Sponsor { get; init; }

    /// <summary>Audience requested or issued, if any.</summary>
    public required string? Audience { get; init; }

    /// <summary>Space-separated scope string, if any.</summary>
    public required string? Scope { get; init; }

    /// <summary>Token identifier, if a token was involved.</summary>
    public required string? Jti { get; init; }

    /// <summary>Delegation depth of the token, if any.</summary>
    public required int? DelegationDepth { get; init; }

    /// <summary>The decision, <c>allow</c> or <c>deny</c>, for authorization events.</summary>
    public required string? Decision { get; init; }

    /// <summary>Machine-readable reason. Always present for a denial.</summary>
    public required string? Reason { get; init; }

    /// <summary>
    /// How many events a summary record stands for. Omitted on a single-event record, which
    /// readers treat as one. Omitted rather than null because the leaf hash excludes the key.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required int? Count { get; init; }

    /// <summary>
    /// Extra detail no other field holds, such as what an <c>audit.archived</c> record names.
    /// Omitted when absent, like <see cref="Count"/>.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required string? Detail { get; init; }

    /// <summary>The payload for a ledger record.</summary>
    /// <param name="record">The record as read from the ledger.</param>
    /// <param name="checkpoint">The checkpoint that seals it, or <c>null</c> when it is not sealed yet.</param>
    public static AuditRecordPayload From(AuditLedgerRecord record, long? checkpoint)
    {
        ArgumentNullException.ThrowIfNull(record);

        var auditEvent = record.Event;
        return new AuditRecordPayload
        {
            Seq = record.Seq,
            Checkpoint = checkpoint,
            Ts = auditEvent.Ts,
            Event = auditEvent.Event,
            TaskId = auditEvent.TaskId,
            AgentId = auditEvent.AgentId,
            Sponsor = auditEvent.Sponsor,
            Audience = auditEvent.Audience,
            Scope = auditEvent.Scope,
            Jti = auditEvent.Jti,
            DelegationDepth = auditEvent.DelegationDepth,
            Decision = AuditDecisionCodes.ToCode(auditEvent.Decision),
            Reason = auditEvent.Reason,
            Count = auditEvent.Count,
            Detail = auditEvent.Detail,
        };
    }
}

/// <summary>The body of one delivery to the audit sink: a batch of records in sequence order.</summary>
public sealed class AuditDeliveryPayload
{
    /// <summary>The records, in sequence order.</summary>
    public required IReadOnlyList<AuditRecordPayload> Records { get; init; }
}
