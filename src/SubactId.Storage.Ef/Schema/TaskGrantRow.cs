namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// A task grant (the <c>refresh_token</c> of spec section 3). Stored only as a hash.
/// </summary>
public sealed class TaskGrantRow
{
    /// <summary>Surrogate key.</summary>
    public long Id { get; set; }

    /// <summary>SHA-256 of the grant value. The plaintext is never stored.</summary>
    public required byte[] GrantHash { get; set; }

    /// <summary>The task the grant is bound to.</summary>
    public required string TaskId { get; set; }

    /// <summary>The agent the grant is bound to. Any other agent presenting it is refused.</summary>
    public required string AgentId { get; set; }

    /// <summary>Scopes the grant may refresh into. Never wider than the task's scopes.</summary>
    public required string[] Scopes { get; set; }

    /// <summary>When the grant was issued.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>When the grant stops working, at the latest the task expiry.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When the grant was revoked, if it was.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>When the grant was last used to refresh.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>How many times the grant has been used to refresh.</summary>
    public int Renewals { get; set; }
}
