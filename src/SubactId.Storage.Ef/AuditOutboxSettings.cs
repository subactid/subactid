namespace SubactId.Storage.Ef;

/// <summary>Whether the audit writer queues each record for delivery to an external sink.</summary>
/// <param name="Enabled"><c>true</c> when a sink is configured.</param>
public sealed record AuditOutboxSettings(bool Enabled)
{
    /// <summary>No sink: nothing is queued.</summary>
    public static readonly AuditOutboxSettings Disabled = new(false);
}
