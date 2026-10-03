using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>
/// A user as a provisioning client sends it, on a create or a replace. Any other attributes are
/// dropped. Only identifiers are stored.
/// </summary>
public sealed class ScimUserRequest
{
    /// <summary>
    /// The schemas the client says the body is in. Not checked, since a Users route only takes users.
    /// </summary>
    [JsonPropertyName("schemas")]
    public IReadOnlyList<string>? Schemas { get; init; }

    /// <summary>The client's <c>userName</c>. Required, and unique across users.</summary>
    [JsonPropertyName("userName")]
    public string? UserName { get; init; }

    /// <summary>The client's own identifier for the person.</summary>
    [JsonPropertyName("externalId")]
    public string? ExternalId { get; init; }

    /// <summary>
    /// Whether the person is active, as sent. Absent or null means active, the RFC 7643 default.
    /// Kept as raw JSON so a value that is not a boolean is refused as <c>invalidValue</c>, the
    /// same as in a patch, rather than as a body that could not be read.
    /// </summary>
    [JsonPropertyName("active")]
    public JsonElement? Active { get; init; }
}

/// <summary>One operation of a SCIM patch (RFC 7644 section 3.5.2).</summary>
public sealed class ScimPatchOperation
{
    /// <summary><c>add</c>, <c>replace</c> or <c>remove</c>.</summary>
    [JsonPropertyName("op")]
    public string? Op { get; init; }

    /// <summary>The attribute the operation targets. Absent when <see cref="Value"/> is an object naming them.</summary>
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    /// <summary>The value, as raw JSON, since it may be a scalar or an object.</summary>
    [JsonPropertyName("value")]
    public JsonElement? Value { get; init; }
}

/// <summary>
/// A patch request. <c>Operations</c> is capitalised because RFC 7644 names it that way.
/// </summary>
public sealed class ScimPatchRequest
{
    /// <summary>The schemas the client says the body is in.</summary>
    [JsonPropertyName("schemas")]
    public IReadOnlyList<string>? Schemas { get; init; }

    /// <summary>The operations, applied in order.</summary>
    [JsonPropertyName("Operations")]
    public IReadOnlyList<ScimPatchOperation>? Operations { get; init; }
}
