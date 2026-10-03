using System.Security.Cryptography;

namespace SubactId.Tokens.Upstream;

/// <summary>
/// One public key from the upstream identity provider: RSA of at least 2048 bits, or P-256 EC.
/// Verifies only accepted algorithms that fit the key type.
/// </summary>
public sealed class UpstreamKey : IDisposable
{
    /// <summary>Algorithms accepted from the upstream identity provider.</summary>
    public static readonly IReadOnlySet<string> AllowedAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256", "PS256", "ES256" };

    private readonly RSA? rsa;
    private readonly ECDsa? ecdsa;

    private UpstreamKey(string kid, string keyType, string? algorithm, RSA? rsa, ECDsa? ecdsa)
    {
        Kid = kid;
        KeyType = keyType;
        Algorithm = algorithm;
        this.rsa = rsa;
        this.ecdsa = ecdsa;
    }

    /// <summary>Key identifier.</summary>
    public string Kid { get; }

    /// <summary><c>RSA</c> or <c>EC</c>.</summary>
    public string KeyType { get; }

    /// <summary>The JWK's <c>alg</c> member when present; a token must then use exactly that algorithm.</summary>
    public string? Algorithm { get; }

    /// <summary>Creates an RSA key. Returns <c>null</c> if the modulus is under 2048 bits or the parameters are invalid.</summary>
    /// <param name="kid">Key identifier.</param>
    /// <param name="algorithm">The JWK's <c>alg</c>, if any.</param>
    /// <param name="modulus">Unsigned big-endian modulus.</param>
    /// <param name="exponent">Unsigned big-endian public exponent.</param>
    public static UpstreamKey? CreateRsa(string kid, string? algorithm, byte[] modulus, byte[] exponent)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);

        var rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
            if (rsa.KeySize < 2048)
            {
                rsa.Dispose();
                return null;
            }

            return new UpstreamKey(kid, "RSA", algorithm, rsa, null);
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            return null;
        }
    }

    /// <summary>Creates a P-256 EC key. Returns <c>null</c> if the point is not a valid 32-byte pair on the curve.</summary>
    /// <param name="kid">Key identifier.</param>
    /// <param name="algorithm">The JWK's <c>alg</c>, if any.</param>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    public static UpstreamKey? CreateP256(string kid, string? algorithm, byte[] x, byte[] y)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);

        if (x is not { Length: 32 } || y is not { Length: 32 })
        {
            return null;
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportParameters(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
            return new UpstreamKey(kid, "EC", algorithm, null, ecdsa);
        }
        catch (CryptographicException)
        {
            ecdsa.Dispose();
            return null;
        }
    }

    /// <summary>Whether <paramref name="algorithm"/> is allowed and fits this key's type and declared <c>alg</c>.</summary>
    /// <param name="algorithm">The token's <c>alg</c> header.</param>
    public bool Supports(string algorithm) =>
        AllowedAlgorithms.Contains(algorithm)
        && (Algorithm is null || string.Equals(Algorithm, algorithm, StringComparison.Ordinal))
        && algorithm switch
        {
            "RS256" or "PS256" => rsa is not null,
            "ES256" => ecdsa is not null,
            _ => false,
        };

    /// <summary>Verifies <paramref name="signature"/> over <paramref name="data"/> with <paramref name="algorithm"/>. Never throws.</summary>
    /// <param name="algorithm">The token's <c>alg</c> header. Must satisfy <see cref="Supports"/>.</param>
    /// <param name="data">The signing input.</param>
    /// <param name="signature">The raw signature bytes.</param>
    public bool Verify(string algorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (!Supports(algorithm))
        {
            return false;
        }

        try
        {
            return algorithm switch
            {
                "RS256" => rsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "PS256" => rsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                "ES256" => signature.Length == 64
                    && ecdsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                _ => false,
            };
        }
        catch (Exception exception) when (exception is CryptographicException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        rsa?.Dispose();
        ecdsa?.Dispose();
    }
}
