using System.Text.Json.Serialization;
using SubactId.Core.Scim;

namespace SubactId.Server.Contracts;

/// <summary>
/// The SCIM 2.0 schema URNs and literals this receiver uses, as defined by RFC 7643 and RFC 7644.
/// </summary>
public static class ScimSchemas
{
    /// <summary>The core User schema.</summary>
    public const string User = "urn:ietf:params:scim:schemas:core:2.0:User";

    /// <summary>The ServiceProviderConfig schema.</summary>
    public const string ServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

    /// <summary>The list-response message schema.</summary>
    public const string ListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    /// <summary>The error message schema.</summary>
    public const string Error = "urn:ietf:params:scim:api:messages:2.0:Error";

    /// <summary>The patch-request message schema.</summary>
    public const string PatchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    /// <summary>The media type SCIM responses carry (RFC 7644 section 3.1).</summary>
    public const string MediaType = "application/scim+json";
}

/// <summary>
/// The <c>meta</c> complex attribute every SCIM resource carries.
/// </summary>
/// <param name="ResourceType">The resource's type, <c>User</c> here.</param>
/// <param name="Created">When the resource was created.</param>
/// <param name="LastModified">When it last changed.</param>
/// <param name="Location">Its absolute URI, which a client may address it by.</param>
public sealed record ScimMeta(
    [property: JsonPropertyName("resourceType")] string ResourceType,
    [property: JsonPropertyName("created")] DateTimeOffset Created,
    [property: JsonPropertyName("lastModified")] DateTimeOffset LastModified,
    [property: JsonPropertyName("location")] string Location);

/// <summary>
/// A provisioned user as this receiver reports it. Only identifiers and the active flag are kept
/// and returned, not the rest of what the client sent.
/// </summary>
/// <param name="Schemas">The resource's schemas.</param>
/// <param name="Id">The identifier this control plane assigned.</param>
/// <param name="UserName">The client's <c>userName</c>.</param>
/// <param name="ExternalId">The client's own identifier, when it sent one.</param>
/// <param name="Active">Whether the client says the person is active.</param>
/// <param name="Meta">The resource's metadata.</param>
public sealed record ScimUserResponse(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("userName")] string UserName,
    [property: JsonPropertyName("externalId")] string? ExternalId,
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("meta")] ScimMeta Meta)
{
    /// <summary>The user as the receiver reports it.</summary>
    /// <param name="user">The stored user.</param>
    /// <param name="location">The resource's absolute URI.</param>
    public static ScimUserResponse From(ScimUser user, string location)
    {
        ArgumentNullException.ThrowIfNull(user);

        return new ScimUserResponse(
            [ScimSchemas.User],
            user.Id,
            user.UserName,
            user.ExternalId,
            user.Active,
            new ScimMeta("User", user.CreatedAt, user.UpdatedAt, location));
    }
}

/// <summary>
/// A page of users. <c>Resources</c> is capitalised because RFC 7644 section 3.4.2 names it that way.
/// </summary>
/// <param name="Schemas">The message's schemas.</param>
/// <param name="TotalResults">How many users matched, not how many are in this page.</param>
/// <param name="StartIndex">One-based index of the first user returned.</param>
/// <param name="ItemsPerPage">How many are in this page.</param>
/// <param name="Resources">The page.</param>
public sealed record ScimListResponse(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("totalResults")] int TotalResults,
    [property: JsonPropertyName("startIndex")] int StartIndex,
    [property: JsonPropertyName("itemsPerPage")] int ItemsPerPage,
    [property: JsonPropertyName("Resources")] IReadOnlyList<ScimUserResponse> Resources)
{
    /// <summary>The page as the receiver reports it.</summary>
    /// <param name="page">The stored page and its total.</param>
    /// <param name="startIndex">The one-based index that was asked for.</param>
    /// <param name="resources">The users, already mapped.</param>
    public static ScimListResponse From(ScimUserPage page, int startIndex, IReadOnlyList<ScimUserResponse> resources)
    {
        ArgumentNullException.ThrowIfNull(page);
        ArgumentNullException.ThrowIfNull(resources);

        return new ScimListResponse([ScimSchemas.ListResponse], page.TotalResults, startIndex, resources.Count, resources);
    }
}

/// <summary>
/// A SCIM error (RFC 7644 section 3.12). <c>status</c> is a string there, not a number.
/// </summary>
/// <param name="Schemas">The message's schemas.</param>
/// <param name="Status">The HTTP status, as a string.</param>
/// <param name="ScimType">The machine-readable error type, when one applies.</param>
/// <param name="Detail">What went wrong. A fixed sentence per failure that never echoes client input.</param>
public sealed record ScimErrorResponse(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("scimType")] string? ScimType,
    [property: JsonPropertyName("detail")] string Detail)
{
    /// <summary>An error with <paramref name="status"/> and <paramref name="detail"/>.</summary>
    /// <param name="status">The HTTP status.</param>
    /// <param name="scimType">The SCIM error type, or <c>null</c>.</param>
    /// <param name="detail">A fixed sentence describing the failure.</param>
    public static ScimErrorResponse Of(int status, string? scimType, string detail) =>
        new([ScimSchemas.Error], status.ToString(System.Globalization.CultureInfo.InvariantCulture), scimType, detail);
}

/// <summary>Whether a SCIM capability is supported.</summary>
/// <param name="Supported">Whether it is.</param>
public sealed record ScimSupported([property: JsonPropertyName("supported")] bool Supported);

/// <summary>Bulk support, which is not offered. The schema requires the maxima, so they are zero.</summary>
/// <param name="Supported">Always <c>false</c>.</param>
/// <param name="MaxOperations">Zero.</param>
/// <param name="MaxPayloadSize">Zero.</param>
public sealed record ScimBulkSupported(
    [property: JsonPropertyName("supported")] bool Supported,
    [property: JsonPropertyName("maxOperations")] int MaxOperations,
    [property: JsonPropertyName("maxPayloadSize")] int MaxPayloadSize);

/// <summary>Filter support and the largest page the receiver will return.</summary>
/// <param name="Supported">Whether filtering is offered.</param>
/// <param name="MaxResults">Most resources returned in one page.</param>
public sealed record ScimFilterSupported(
    [property: JsonPropertyName("supported")] bool Supported,
    [property: JsonPropertyName("maxResults")] int MaxResults);

/// <summary>How a client authenticates, as the configuration document describes it.</summary>
/// <param name="Type">The scheme's type, <c>oauthbearertoken</c> here.</param>
/// <param name="Name">Its human-readable name.</param>
/// <param name="Description">What a client has to present.</param>
/// <param name="Primary">Whether it is the primary scheme.</param>
public sealed record ScimAuthenticationScheme(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("primary")] bool Primary);

/// <summary>
/// The <c>meta</c> of a document that is not a resource with a history, so it has no timestamps.
/// </summary>
/// <param name="ResourceType">The document's type.</param>
/// <param name="Location">Its absolute URI.</param>
public sealed record ScimDocumentMeta(
    [property: JsonPropertyName("resourceType")] string ResourceType,
    [property: JsonPropertyName("location")] string Location);

/// <summary>
/// What this receiver supports (the SCIM ServiceProviderConfig document).
/// </summary>
/// <param name="Schemas">The resource's schemas.</param>
/// <param name="Patch">Patch support.</param>
/// <param name="Bulk">Bulk support, which is none.</param>
/// <param name="Filter">Filter support and the page ceiling.</param>
/// <param name="ChangePassword">Password change, which is not offered.</param>
/// <param name="Sort">Sorting, which is not offered.</param>
/// <param name="Etag">Entity tags, which are not offered.</param>
/// <param name="AuthenticationSchemes">How a client authenticates.</param>
/// <param name="Meta">The resource's metadata.</param>
public sealed record ScimServiceProviderConfigResponse(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("patch")] ScimSupported Patch,
    [property: JsonPropertyName("bulk")] ScimBulkSupported Bulk,
    [property: JsonPropertyName("filter")] ScimFilterSupported Filter,
    [property: JsonPropertyName("changePassword")] ScimSupported ChangePassword,
    [property: JsonPropertyName("sort")] ScimSupported Sort,
    [property: JsonPropertyName("etag")] ScimSupported Etag,
    [property: JsonPropertyName("authenticationSchemes")] IReadOnlyList<ScimAuthenticationScheme> AuthenticationSchemes,
    [property: JsonPropertyName("meta")] ScimDocumentMeta Meta);
