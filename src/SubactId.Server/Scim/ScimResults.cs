using System.Text.Json;
using SubactId.Core.Scim;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;

namespace SubactId.Server.Scim;

/// <summary>
/// Builds the SCIM receiver's responses, with SCIM's media type and, for failures, SCIM's error shape.
///
/// <para>
/// A failure's <c>detail</c> is a fixed sentence per kind of failure. Client input is never
/// echoed into it.
/// </para>
/// </summary>
public static class ScimResults
{
    /// <summary>SCIM error type for a filter the receiver does not support.</summary>
    public const string InvalidFilter = "invalidFilter";

    /// <summary>SCIM error type for a value that is missing or unusable.</summary>
    public const string InvalidValue = "invalidValue";

    /// <summary>SCIM error type for a body that is not of the shape the operation takes.</summary>
    public const string InvalidSyntax = "invalidSyntax";

    /// <summary>SCIM error type for a value that is already somebody else's.</summary>
    public const string Uniqueness = "uniqueness";

    /// <summary>A SCIM response with <paramref name="value"/> as its body.</summary>
    /// <param name="value">The body.</param>
    /// <param name="statusCode">The status.</param>
    public static IResult Json(object value, int statusCode) =>
        Results.Json(value, SubactIdJson.Options, ScimSchemas.MediaType, statusCode);

    /// <summary>A SCIM error response.</summary>
    /// <param name="statusCode">The status.</param>
    /// <param name="scimType">The SCIM error type, or <c>null</c> when none applies.</param>
    /// <param name="detail">A fixed sentence naming the failure.</param>
    public static IResult Error(int statusCode, string? scimType, string detail) =>
        Results.Json(ScimErrorResponse.Of(statusCode, scimType, detail), SubactIdJson.Options, ScimSchemas.MediaType, statusCode);

    /// <summary>A user as the receiver reports it.</summary>
    /// <param name="http">The request, for the resource's own URI.</param>
    /// <param name="user">The user.</param>
    /// <param name="statusCode">The status.</param>
    public static IResult Resource(HttpContext http, ScimUser user, int statusCode)
    {
        ArgumentNullException.ThrowIfNull(user);

        return Json(ScimUserResponse.From(user, UserLocation(http, user.Id)), statusCode);
    }

    /// <summary>The response for <paramref name="failure"/>.</summary>
    /// <param name="failure">Why the request could not be carried out.</param>
    public static IResult Failed(ScimFailure? failure) => failure switch
    {
        ScimFailure.NotFound => Error(StatusCodes.Status404NotFound, null, "No such resource."),
        ScimFailure.UserNameTaken => Error(StatusCodes.Status409Conflict, Uniqueness, "A user with that userName already exists."),
        ScimFailure.MissingUserName => Error(StatusCodes.Status400BadRequest, InvalidValue, "A userName is required."),
        ScimFailure.MissingSponsorKey => Error(
            StatusCodes.Status400BadRequest,
            InvalidValue,
            "The attribute this receiver is configured to identify people by, externalId or userName, is missing or is not a usable identifier."),
        ScimFailure.InvalidValue => Error(
            StatusCodes.Status400BadRequest,
            InvalidValue,
            "A value is not of the type the attribute takes."),
        ScimFailure.Capacity => Error(
            StatusCodes.Status507InsufficientStorage,
            null,
            "This control plane already holds as many provisioned users as it is configured to."),

        // RFC 7644 section 3.12. The user changed under the write on every retry, so the client
        // should read it again.
        ScimFailure.Changed => Error(
            StatusCodes.Status412PreconditionFailed,
            null,
            "Failed to update. The resource changed on the server; read it again and retry."),
        _ => Error(StatusCodes.Status400BadRequest, InvalidSyntax, "The request body is not valid for this operation."),
    };

    /// <summary>
    /// Reads a request body, or returns <c>null</c> when it cannot be read. The media type is
    /// checked before parsing.
    /// </summary>
    /// <typeparam name="T">The request contract.</typeparam>
    /// <param name="http">The request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<T?> ReadAsync<T>(HttpContext http, CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(http);

        return ScimBody.IsAcceptedMediaType(http.Request.ContentType)
            ? await ScimBody.ReadAsync<T>(http.Request, ScimBody.RequestOptions, cancellationToken)
            : null;
    }

    /// <summary>The refusal for an unreadable body: 415 for a wrong media type, otherwise 400.</summary>
    /// <param name="http">The request.</param>
    public static IResult Unreadable(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        return ScimBody.IsAcceptedMediaType(http.Request.ContentType)
            ? Error(StatusCodes.Status400BadRequest, InvalidSyntax, "The request body is not valid for this operation.")
            : Error(StatusCodes.Status415UnsupportedMediaType, null, "The request body must be application/scim+json or application/json, in UTF-8.");
    }

    /// <summary>The absolute URI of a user resource.</summary>
    /// <param name="http">The request, for the services holding the configured issuer.</param>
    /// <param name="id">The user's identifier.</param>
    public static string UserLocation(HttpContext http, string id) => Location(http, ScimEndpoints.UsersPath + "/" + id);

    /// <summary>
    /// The absolute URI of <paramref name="path"/>, built from the configured issuer. Never from
    /// the <c>Host</c> header, which the caller controls.
    /// </summary>
    /// <param name="http">The request, for the services holding the configured issuer.</param>
    /// <param name="path">The absolute path.</param>
    public static string Location(HttpContext http, string path)
    {
        ArgumentNullException.ThrowIfNull(http);

        var issuer = http.RequestServices.GetRequiredService<SubactIdOptions>().Issuer.AbsoluteUri.TrimEnd('/');
        return issuer + path;
    }
}
