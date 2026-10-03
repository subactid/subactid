namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// One record of the append-only audit ledger (spec section 7).
/// No foreign keys: audit history must outlive the rows it refers to.
/// <para>
/// Records are sealed by the signed checkpoint covering their sequence number, in
/// <c>audit_checkpoints</c>.
/// </para>
/// </summary>
public sealed class AuditEventRow
{
    /// <summary>Monotonic sequence number, and the order a checkpoint's leaves are taken in.</summary>
    public long Seq { get; set; }

    /// <summary>When the event happened.</summary>
    public DateTimeOffset Ts { get; set; }

    /// <summary>Event name, for example <c>token.issued</c> or <c>token.denied</c>.</summary>
    public required string Event { get; set; }

    /// <summary>Task involved, if any.</summary>
    public string? TaskId { get; set; }

    /// <summary>Agent involved, if any.</summary>
    public string? AgentId { get; set; }

    /// <summary>The human on whose behalf the action was taken, if any.</summary>
    public string? Sponsor { get; set; }

    /// <summary>Audience requested or issued, if any.</summary>
    public string? Audience { get; set; }

    /// <summary>Space-separated scope string as issued or requested, if any.</summary>
    public string? Scope { get; set; }

    /// <summary>Token identifier, if a token was involved.</summary>
    public string? Jti { get; set; }

    /// <summary>Delegation depth of the token, if any.</summary>
    public int? DelegationDepth { get; set; }

    /// <summary><c>allow</c> or <c>deny</c> for authorization decisions.</summary>
    public string? Decision { get; set; }

    /// <summary>Machine-readable reason, always present for a denial.</summary>
    public string? Reason { get; set; }

    /// <summary>How many events a summary record stands for. Null on a single-event record.</summary>
    public int? Count { get; set; }

    /// <summary>Extra detail no other column holds. In v0.1, only set on <c>audit.archived</c> records.</summary>
    public string? Detail { get; set; }
}
