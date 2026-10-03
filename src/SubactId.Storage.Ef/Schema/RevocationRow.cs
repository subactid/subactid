namespace SubactId.Storage.Ef.Schema;

/// <summary>An explicit revocation of a token, a task, every task of an agent, every task acting for one human (by sponsor key or upstream <c>sub</c>), or every task of one identity provider session (spec section 6).</summary>
public sealed class RevocationRow
{
    /// <summary>Surrogate key.</summary>
    public long Id { get; set; }

    /// <summary>Token identifier, when a single token was revoked.</summary>
    public string? Jti { get; set; }

    /// <summary>Task identifier, when a task and its descendants were revoked.</summary>
    public string? TaskId { get; set; }

    /// <summary>Agent identifier, when all of an agent's tasks were revoked.</summary>
    public string? AgentId { get; set; }

    /// <summary>The human, as the configured key claim names them, when every task acting for them was revoked.</summary>
    public string? SponsorKey { get; set; }

    /// <summary>The identity provider's session, when every task started from it was revoked.</summary>
    public string? SessionId { get; set; }

    /// <summary>The human's upstream <c>sub</c>, when a logout named the person and no session.</summary>
    public string? Subject { get; set; }

    /// <summary>
    /// For a revocation that signs the person out: subject tokens issued before this instant may not
    /// start a task. Such a row, like one by session, is removed once
    /// <c>SubactId:Revocations:SignOutRetention</c> has passed since <see cref="RevokedAt"/>.
    /// </summary>
    public DateTimeOffset? IssuedBefore { get; set; }

    /// <summary>When the revocation took effect.</summary>
    public DateTimeOffset RevokedAt { get; set; }

    /// <summary>Machine-readable reason, for example <c>operator_kill_switch</c>.</summary>
    public required string Reason { get; set; }

    /// <summary>Who or what performed the revocation.</summary>
    public string? RevokedBy { get; set; }

    /// <summary>For a token revocation, when the token expires. The record can be purged after that.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }
}
