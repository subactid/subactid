using System.Text.RegularExpressions;

namespace SubactId.Core.Validation;

/// <summary>
/// Lexical rules for scopes and audiences, shared by the registry and the token endpoint.
/// </summary>
public static partial class Syntax
{
    /// <summary>Longest scope, audience or URL value accepted anywhere.</summary>
    public const int MaxValueLength = 2048;

    /// <summary>Whether <paramref name="value"/> is one RFC 6749 section 3.3 scope token: printable ASCII without spaces, quotes or backslashes, within <see cref="MaxValueLength"/>.</summary>
    /// <param name="value">The candidate scope.</param>
    public static bool IsScopeToken(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length <= MaxValueLength && ScopeToken().IsMatch(value);

    /// <summary>Whether <paramref name="value"/> is an absolute http or https URL within <see cref="MaxValueLength"/>.</summary>
    /// <param name="value">The candidate audience or resource.</param>
    public static bool IsAudience(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length <= MaxValueLength && Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http";

    // RFC 6749 section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). \z, not $, which in .NET
    // also matches before a final newline.
    [GeneratedRegex(@"^[\x21\x23-\x5B\x5D-\x7E]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex ScopeToken();
}
