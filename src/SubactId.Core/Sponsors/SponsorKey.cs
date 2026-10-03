using System.Diagnostics.CodeAnalysis;

namespace SubactId.Core.Sponsors;

/// <summary>
/// The shape of a valid sponsor key, shared by the token exchange and the admin block API.
/// </summary>
public static class SponsorKey
{
    /// <summary>Longest key accepted, matching the column every task stores one in.</summary>
    public const int MaxLength = 256;

    /// <summary>
    /// Whether <paramref name="value"/> may be a key: non-empty, no longer than the column, and
    /// with no whitespace or control characters. Postgres rejects a NUL in a text parameter.
    /// </summary>
    /// <param name="value">The candidate key.</param>
    public static bool IsWellFormed([NotNullWhen(true)] string? value) =>
        value is { Length: > 0 and <= MaxLength } && !value.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c));
}
