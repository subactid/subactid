namespace SubactId.Core.Scim;

/// <summary>
/// A user record created over SCIM 2.0. Only identifiers and the active state are stored, not a profile.
/// </summary>
/// <param name="Id">The SCIM <c>id</c>, assigned by this control plane.</param>
/// <param name="UserName">The client's <c>userName</c>. Unique, as SCIM requires.</param>
/// <param name="ExternalId">The client's own identifier for the person, when it sends one.</param>
/// <param name="SponsorKey">
/// The key tasks use for this person, resolved from the configured attribute when the record was written.
/// </param>
/// <param name="Active">Whether the client says the person is active. <c>false</c> is what blocks them.</param>
/// <param name="CreatedAt">When the record was created.</param>
/// <param name="UpdatedAt">When it last changed.</param>
public sealed record ScimUser(
    string Id,
    string UserName,
    string? ExternalId,
    string SponsorKey,
    bool Active,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>Which users a listing asks for: at most one equality, and where in the result to start.</summary>
/// <param name="UserName">Only the user with this <c>userName</c>.</param>
/// <param name="ExternalId">Only the user with this <c>externalId</c>.</param>
/// <param name="StartIndex">One-based index of the first user returned, as SCIM counts.</param>
/// <param name="Count">Most users returned.</param>
public sealed record ScimUserFilter(string? UserName, string? ExternalId, int StartIndex, int Count);

/// <summary>One page of a listing, with the total number of matches that SCIM requires.</summary>
/// <param name="Users">The page.</param>
/// <param name="TotalResults">How many matched the filter, not how many are in the page.</param>
public sealed record ScimUserPage(IReadOnlyList<ScimUser> Users, int TotalResults);
