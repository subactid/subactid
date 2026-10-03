using System.Security.Cryptography;

namespace SubactId.Tokens.Issuance;

/// <summary>
/// Identifiers of the form <c>prefix_</c> plus 26 Crockford base32 characters in ULID layout:
/// a 48-bit millisecond timestamp and 80 random bits. They sort by creation time and cannot be guessed.
/// </summary>
public static class OpaqueId
{
    /// <summary>Prefix of token identifiers (<c>jti</c>).</summary>
    public const string TokenPrefix = "tok";

    /// <summary>Prefix of task identifiers.</summary>
    public const string TaskPrefix = "task";

    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>A new identifier with <paramref name="prefix"/>.</summary>
    /// <param name="prefix">Lowercase letters only.</param>
    /// <param name="now">The creation time, encoded in the first ten characters.</param>
    public static string New(string prefix, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrEmpty(prefix);
        if (prefix.Any(c => c is < 'a' or > 'z'))
        {
            throw new ArgumentException("The prefix must be lowercase letters.", nameof(prefix));
        }

        Span<byte> bytes = stackalloc byte[16];
        var millis = (ulong)now.ToUnixTimeMilliseconds() & 0xFFFF_FFFF_FFFF;
        for (var i = 5; i >= 0; i--)
        {
            bytes[i] = (byte)millis;
            millis >>= 8;
        }

        RandomNumberGenerator.Fill(bytes[6..]);
        return prefix + "_" + Encode(bytes);
    }

    /// <summary>Crockford base32 of 128 bits as 26 characters, most significant first, 2 leading zero bits.</summary>
    private static string Encode(ReadOnlySpan<byte> bytes)
    {
        Span<char> chars = stackalloc char[26];
        var acc = 0;
        var bits = 0;
        var index = 25;
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            acc |= bytes[i] << bits;
            bits += 8;
            while (bits >= 5 && index >= 0)
            {
                chars[index--] = Alphabet[acc & 31];
                acc >>= 5;
                bits -= 5;
            }
        }

        chars[index] = Alphabet[acc & 31];
        return new string(chars);
    }
}
