using System.Text.Json;
using SubactId.Core.Scim;
using SubactId.Server.Contracts;

namespace SubactId.Server.Scim;

/// <summary>
/// Applies a SCIM patch to a user record. Only <c>active</c>, <c>userName</c> and
/// <c>externalId</c> are kept. Operations on other attributes are ignored.
///
/// Malformed operations are refused: no verb, an unknown verb, a removal without a path, a
/// pathless operation whose value is not an object, or one whose value names an attribute twice
/// in any case (RFC 7643 section 2.1 makes names case-insensitive). So is an operation on a kept attribute with
/// a value that cannot be read, such as a non-boolean <c>active</c>.
/// </summary>
public static class ScimPatch
{
    private const string Add = "add";
    private const string Replace = "replace";
    private const string Remove = "remove";
    private const string ActiveAttribute = "active";
    private const string UserNameAttribute = "username";
    private const string ExternalIdAttribute = "externalid";

    /// <summary>Whether <paramref name="operation"/> is a patch operation at all, whatever it names.</summary>
    /// <param name="operation">The operation.</param>
    public static bool IsWellFormed(ScimPatchOperation? operation)
    {
        if (operation?.Op is not { } op)
        {
            return false;
        }

        var verb = op.Trim().ToLowerInvariant();
        if (verb is not (Add or Replace or Remove))
        {
            return false;
        }

        // A removal needs a path.
        if (verb == Remove)
        {
            return !string.IsNullOrWhiteSpace(operation.Path);
        }

        if (!string.IsNullOrWhiteSpace(operation.Path))
        {
            return true;
        }

        // Without a path, the value must be an object naming each attribute once, whatever the
        // case, so a repeat is refused rather than resolved by whichever came last.
        if (operation.Value is not { ValueKind: JsonValueKind.Object } value)
        {
            return false;
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var member in value.EnumerateObject())
        {
            if (!names.Add(member.Name))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Applies <paramref name="operations"/> in order. Returns <c>null</c> when one of them sets a
    /// kept attribute to a value that cannot be read.
    /// </summary>
    /// <param name="user">The stored user.</param>
    /// <param name="operations">The operations, already checked by <see cref="IsWellFormed"/>.</param>
    public static ScimUser? Apply(ScimUser user, IReadOnlyList<ScimPatchOperation> operations)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(operations);

        var patched = user;
        foreach (var operation in operations)
        {
            if (Apply(patched, operation) is not { } next)
            {
                return null;
            }

            patched = next;
        }

        return patched;
    }

    private static ScimUser? Apply(ScimUser user, ScimPatchOperation operation)
    {
        var verb = operation.Op!.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(operation.Path))
        {
            // One pathless operation may name several attributes, so every member is applied.
            var patched = user;
            foreach (var member in operation.Value!.Value.EnumerateObject())
            {
                if (Set(patched, Attribute(member.Name), verb, member.Value) is not { } next)
                {
                    return null;
                }

                patched = next;
            }

            return patched;
        }

        return Set(user, Attribute(operation.Path), verb, operation.Value);
    }

    /// <summary>
    /// <paramref name="user"/> with one attribute set. Unchanged for attributes that are not kept.
    /// <c>null</c> when the value cannot be applied.
    /// </summary>
    private static ScimUser? Set(ScimUser user, string attribute, string verb, JsonElement? value) => attribute switch
    {
        // Removing active is a no-op. Disabling a user means replacing it with false.
        ActiveAttribute when verb == Remove => user,
        ActiveAttribute => Boolean(value) is { } active ? user with { Active = active } : null,

        // userName is required by SCIM and cannot be removed.
        UserNameAttribute when verb == Remove => null,
        UserNameAttribute => Text(value) is { } userName ? user with { UserName = userName } : null,
        ExternalIdAttribute when verb == Remove => user with { ExternalId = null },
        ExternalIdAttribute => Text(value) is { } externalId ? user with { ExternalId = externalId } : null,
        _ => user,
    };

    /// <summary>
    /// The attribute a path names, lowercased, with any schema URN, sub-attribute or filter
    /// dropped. For example <c>urn:ietf:params:scim:schemas:core:2.0:User:active</c> is
    /// <c>active</c>, and <c>name.givenName</c> is <c>name</c>.
    /// </summary>
    private static string Attribute(string path)
    {
        var trimmed = path.Trim();
        var colon = trimmed.LastIndexOf(':');
        if (colon >= 0)
        {
            trimmed = trimmed[(colon + 1)..];
        }

        var stop = trimmed.IndexOfAny(['.', '[']);
        return (stop >= 0 ? trimmed[..stop] : trimmed).ToLowerInvariant();
    }

    /// <summary>
    /// A boolean value, sent either as a boolean or as a string. Entra ID sends <c>"False"</c>,
    /// quoted. <c>null</c> when the value is neither. Shared with create and replace.
    /// </summary>
    /// <param name="value">The value as sent.</param>
    internal static bool? Boolean(JsonElement? value) => value switch
    {
        { ValueKind: JsonValueKind.True } => true,
        { ValueKind: JsonValueKind.False } => false,
        { ValueKind: JsonValueKind.String } element when bool.TryParse(element.GetString(), out var parsed) => parsed,
        _ => null,
    };

    /// <summary>A string value, or <c>null</c> when the value is not one.</summary>
    private static string? Text(JsonElement? value) =>
        value is { ValueKind: JsonValueKind.String } element ? element.GetString() : null;
}
