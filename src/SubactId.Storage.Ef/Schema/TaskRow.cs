namespace SubactId.Storage.Ef.Schema;

/// <summary>A task: the unit of delegated authority that every token belongs to.</summary>
public sealed class TaskRow
{
    /// <summary>Task is live and may be refreshed.</summary>
    public const string StatusActive = "active";

    /// <summary>Task passed its expiry and was marked terminal by the sweeper.</summary>
    public const string StatusExpired = "expired";

    /// <summary>Task was revoked explicitly, directly or through a parent.</summary>
    public const string StatusRevoked = "revoked";

    /// <summary>Identifier, for example <c>task_01HQZX9K4M</c>.</summary>
    public required string TaskId { get; set; }

    /// <summary>The agent the task was issued to.</summary>
    public required string AgentId { get; set; }

    /// <summary>The human the task acts on behalf of. Always the <c>sub</c> of every token.</summary>
    public required string Sponsor { get; set; }

    /// <summary>
    /// The same human as named by the configured key claim. Signals are matched to tasks by it.
    /// Usually equal to <see cref="Sponsor"/>.
    /// </summary>
    public required string SponsorKey { get; set; }

    /// <summary>
    /// The identity provider session the subject token came from. Null when the token has no <c>sid</c>.
    /// </summary>
    public string? SessionId { get; set; }

    /// <summary>The task this one was delegated from, if any.</summary>
    public string? ParentTaskId { get; set; }

    /// <summary>Position in the delegation chain. 1 for a task created directly from a user token.</summary>
    public int DelegationDepth { get; set; }

    /// <summary>The audience tokens under this task are issued for.</summary>
    public required string Audience { get; set; }

    /// <summary>Scopes granted at task creation. Later tokens and grants may only narrow these.</summary>
    public required string[] Scopes { get; set; }

    /// <summary>One of the <c>Status*</c> constants.</summary>
    public required string Status { get; set; }

    /// <summary>When the task was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>When the task expires. No token may outlive this instant.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When the task was revoked, if it was.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>Machine-readable reason for revocation, if any.</summary>
    public string? RevocationReason { get; set; }
}
