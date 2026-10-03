namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// A user record a SCIM client provisioned. Only identifiers and state are stored, never names,
/// emails or other profile data.
/// </summary>
public sealed class ScimUserRow
{
    /// <summary>The identifier this control plane assigned. The client addresses the resource by it.</summary>
    public required string Id { get; set; }

    /// <summary>The client's <c>userName</c>. Unique.</summary>
    public required string UserName { get; set; }

    /// <summary>The client's own identifier for the person, when it sends one.</summary>
    public string? ExternalId { get; set; }

    /// <summary>The person as tasks are keyed by them, resolved when the row was written.</summary>
    public required string SponsorKey { get; set; }

    /// <summary>Whether the client says the person is active.</summary>
    public bool Active { get; set; }

    /// <summary>When the row was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>When it last changed.</summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
