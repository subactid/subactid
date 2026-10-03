namespace SubactId.Storage.Ef.Schema;

/// <summary>A client assertion <c>jti</c> that has already been used, kept until the assertion would have expired.</summary>
public sealed class AssertionReplayRow
{
    /// <summary>The agent that presented the assertion.</summary>
    public required string AgentId { get; set; }

    /// <summary>The assertion's <c>jti</c>.</summary>
    public required string Jti { get; set; }

    /// <summary>When the record may be purged: the assertion's expiry plus clock skew.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
