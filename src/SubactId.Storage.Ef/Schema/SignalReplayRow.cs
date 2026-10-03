namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// The identifier of a signal already accepted from outside, kept until the signal would have
/// expired. Keyed by issuer, unlike <see cref="AssertionReplayRow"/>, which is keyed by agent.
/// </summary>
public sealed class SignalReplayRow
{
    /// <summary>The issuer that signed the signal.</summary>
    public required string Issuer { get; set; }

    /// <summary>The signal's <c>jti</c>.</summary>
    public required string Jti { get; set; }

    /// <summary>When the record may be purged.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
