using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace SubactId.Tokens.Issuance;

/// <summary>
/// The task grant value (the <c>refresh_token</c> of spec section 3): <c>task_grant_</c> plus
/// 256 random bits as base64url. A secret. Shown once; the server stores only its SHA-256.
/// </summary>
public static class TaskGrantSecret
{
    /// <summary>Prefix every grant value carries.</summary>
    public const string Prefix = "task_grant_";

    /// <summary>Length of a grant value.</summary>
    public const int Length = 11 + 43;

    /// <summary>A new grant value from the system cryptographic generator.</summary>
    public static string New() => Prefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    /// <summary>Whether <paramref name="value"/> has the shape of a grant: the prefix and 43 base64url characters. Does not check that it exists.</summary>
    /// <param name="value">The value as presented.</param>
    public static bool IsWellFormed([NotNullWhen(true)] string? value) =>
        value is { Length: Length } && value.StartsWith(Prefix, StringComparison.Ordinal) && Base64Url.IsValid(value.AsSpan(Prefix.Length), out var decoded) && decoded == 32;

    /// <summary>The SHA-256 the grant is stored and looked up by.</summary>
    /// <param name="grant">The grant value as presented.</param>
    public static byte[] Hash(string grant)
    {
        ArgumentException.ThrowIfNullOrEmpty(grant);

        return SHA256.HashData(Encoding.UTF8.GetBytes(grant));
    }
}
