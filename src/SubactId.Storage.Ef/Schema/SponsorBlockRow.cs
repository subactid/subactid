namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// A human this control plane refuses to act for. A row exists only while the person is blocked.
/// Lifting the block deletes it.
/// </summary>
public sealed class SponsorBlockRow
{
    /// <summary>Placed by an operator through the admin API.</summary>
    public const string SourceAdmin = "admin";

    /// <summary>Placed by the outbound check against the identity provider.</summary>
    public const string SourcePoll = "poll";

    /// <summary>Placed by an OpenID Connect back-channel logout token.</summary>
    public const string SourceLogout = "logout";

    /// <summary>Placed by a SCIM deactivation or deletion.</summary>
    public const string SourceScim = "scim";

    /// <summary>Placed by a Shared Signals or CAEP security event token.</summary>
    public const string SourceSsf = "ssf";

    /// <summary>The account exists and is disabled.</summary>
    public const string KindDisabled = "disabled";

    /// <summary>The account no longer exists.</summary>
    public const string KindDeleted = "deleted";

    /// <summary>The human, as the configured key claim names them. Not necessarily the <c>sub</c>.</summary>
    public required string SponsorKey { get; set; }

    /// <summary>One of the <c>Source*</c> constants. Only that source may lift the block.</summary>
    public required string Source { get; set; }

    /// <summary>One of the <c>Kind*</c> constants.</summary>
    public required string Kind { get; set; }

    /// <summary>When the block was placed.</summary>
    public DateTimeOffset BlockedAt { get; set; }

    /// <summary>
    /// For a SCIM block, whether a user record's deletion placed or restated it. Lifted only when a
    /// new user record naming the person is created. <c>false</c> for other sources.
    /// </summary>
    public bool PlacedByDeletion { get; set; }
}
