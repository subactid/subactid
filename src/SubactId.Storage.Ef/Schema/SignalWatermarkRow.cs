namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// The <c>iat</c> of the latest Shared Signals account event applied for one human. An event
/// issued before it arrived late and is not applied. Kept after a block is lifted, because that is
/// when a late <c>account-disabled</c> would otherwise block the person again.
/// </summary>
public sealed class SignalWatermarkRow
{
    /// <summary>The human, as the configured key claim names them.</summary>
    public required string SponsorKey { get; set; }

    /// <summary>The <c>iat</c> of the latest event applied.</summary>
    public DateTimeOffset EventAt { get; set; }
}
