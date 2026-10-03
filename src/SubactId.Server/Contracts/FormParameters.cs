using Microsoft.Extensions.Primitives;
using SubactId.Core.Validation;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Contracts;

/// <summary>The form-reading and per-parameter rules the token endpoint's request types share.</summary>
internal static class FormParameters
{
    /// <summary>Most scopes one request may name.</summary>
    public const int MaxScopes = 64;

    /// <summary>Longest <c>resource</c>, <c>scope</c> or <c>client_id</c> value accepted.</summary>
    public const int MaxValueLength = Syntax.MaxValueLength;

    /// <summary>One value of <paramref name="name"/>: <c>null</c> when absent or empty (RFC 6749 section 3.2), an error when repeated.</summary>
    public static string? Single(IFormCollection form, string name, List<ValidationError> errors)
    {
        if (!form.TryGetValue(name, out StringValues values))
        {
            return null;
        }

        if (values.Count != 1)
        {
            errors.Add(new(name, "must not be repeated."));
            return null;
        }

        return string.IsNullOrEmpty(values[0]) ? null : values[0];
    }

    /// <summary>
    /// A required token-shaped value within a length limit. Subject tokens from the upstream
    /// identity provider may need a larger limit than the default.
    /// </summary>
    /// <param name="token">The value as sent.</param>
    /// <param name="name">The parameter name, for the error.</param>
    /// <param name="errors">Problems found.</param>
    /// <param name="maxLength">Longest value accepted. <see cref="Jws.MaxTokenLength"/> by default.</param>
    public static void RequireToken(string? token, string name, List<ValidationError> errors, int maxLength = Jws.MaxTokenLength)
    {
        if (token is null)
        {
            errors.Add(new(name, "is required."));
        }
        else if (token.Length > maxLength)
        {
            errors.Add(new(name, $"must be at most {maxLength} characters."));
        }
    }

    /// <summary>A required absolute http or https URL.</summary>
    public static void RequireResource(string? resource, List<ValidationError> errors)
    {
        if (resource is null)
        {
            errors.Add(new("resource", "is required."));
        }
        else if (resource.Length > MaxValueLength)
        {
            errors.Add(new("resource", $"must be at most {MaxValueLength} characters."));
        }
        else if (!Syntax.IsAudience(resource))
        {
            errors.Add(new("resource", "must be an absolute http or https URL."));
        }
    }

    /// <summary>A required list of one to <see cref="MaxScopes"/> scope tokens.</summary>
    public static void RequireScope(string? scope, IReadOnlyList<string> scopes, List<ValidationError> errors)
    {
        if (scope is null)
        {
            errors.Add(new("scope", "is required."));
        }
        else if (scope.Length > MaxValueLength)
        {
            errors.Add(new("scope", $"must be at most {MaxValueLength} characters."));
        }
        else if (scopes.Count == 0 || scopes.Count > MaxScopes || scopes.Any(s => !Syntax.IsScopeToken(s)))
        {
            errors.Add(new("scope", $"must be 1 to {MaxScopes} space-separated scopes of printable ASCII without quotes or backslashes."));
        }
    }

    /// <summary>An optional <c>client_id</c> within the value limit.</summary>
    public static void OptionalClientId(string? clientId, List<ValidationError> errors)
    {
        if (clientId is { Length: > MaxValueLength })
        {
            errors.Add(new("client_id", $"must be at most {MaxValueLength} characters."));
        }
    }

    /// <summary><paramref name="scope"/> split on spaces, in order, empty entries dropped.</summary>
    public static IReadOnlyList<string> SplitScopes(string? scope) => scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? [];
}
