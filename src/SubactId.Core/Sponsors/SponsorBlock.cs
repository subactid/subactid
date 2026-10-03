namespace SubactId.Core.Sponsors;

/// <summary>
/// A standing refusal to act for one human. A person with no block may be acted for.
/// </summary>
/// <param name="SponsorKey">The human, as the configured key claim named them. Not necessarily the <c>sub</c>.</param>
/// <param name="Source">What placed the block. Only that source may lift it.</param>
/// <param name="Kind">Whether the person is disabled or gone; the two are answered differently.</param>
/// <param name="BlockedAt">When the block was placed.</param>
/// <param name="PlacedByDeletion">
/// For a SCIM block: whether the deletion of a user record placed or restated it. The deleted
/// record is gone, so no write to another record can stand for it: such a block is lifted only
/// when a new user record naming the person is created. <c>false</c> for every other source.
/// </param>
public sealed record SponsorBlock(
    string SponsorKey,
    SponsorBlockSource Source,
    SponsorBlockKind Kind,
    DateTimeOffset BlockedAt,
    bool PlacedByDeletion = false);

/// <summary>
/// What placed a block. Only the source that placed a block may lift it.
/// </summary>
public enum SponsorBlockSource
{
    /// <summary>An operator, through the admin API.</summary>
    Admin,

    /// <summary>The outbound check against the identity provider's admin API.</summary>
    Poll,

    /// <summary>An OpenID Connect back-channel logout token.</summary>
    Logout,

    /// <summary>A SCIM deactivation or deletion.</summary>
    Scim,

    /// <summary>A Shared Signals or CAEP security event token.</summary>
    Ssf,
}

/// <summary>Why a human may not be acted for. Each maps to one audit reason and one denial.</summary>
public enum SponsorBlockKind
{
    /// <summary>The account exists and is disabled.</summary>
    Disabled,

    /// <summary>The account no longer exists.</summary>
    Deleted,
}

/// <summary>The block standing on a human after a write, and whether the write changed anything.</summary>
/// <param name="Standing">The block now on the human: the one written, or the one that was already there.</param>
/// <param name="Written">Whether the write placed the block or changed its kind.</param>
public sealed record SponsorBlockWrite(SponsorBlock Standing, bool Written);
