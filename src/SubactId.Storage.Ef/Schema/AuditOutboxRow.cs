namespace SubactId.Storage.Ef.Schema;

/// <summary>Pending delivery of an audit event to an external sink. Drained asynchronously.</summary>
public sealed class AuditOutboxRow
{
    /// <summary>Surrogate key.</summary>
    public long Id { get; set; }

    /// <summary>The audit record to deliver.</summary>
    public long AuditSeq { get; set; }

    /// <summary>When the entry was queued.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Number of delivery attempts so far.</summary>
    public int Attempts { get; set; }

    /// <summary>Failure description from the last attempt, if any.</summary>
    public string? LastError { get; set; }

    /// <summary>When the next delivery may be tried. Pushed back after each failure.</summary>
    public DateTimeOffset NextAttemptAt { get; set; }
}
