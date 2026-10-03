using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>
/// The error body of the Shared Signals receiver (RFC 8935 section 2.4). A bad event names the
/// failed check, which is safe because the caller has already presented the push credential. A
/// missing or wrong credential is <c>authentication_failed</c> and nothing more (spec section 6),
/// so it carries no description.
/// </summary>
/// <param name="Err">The error code.</param>
/// <param name="Description">What was wrong with the event; absent on <c>authentication_failed</c>.</param>
public sealed record SecurityEventErrorResponse(
    [property: JsonPropertyName("err")] string Err,
    [property: JsonPropertyName("description"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Description = null);
