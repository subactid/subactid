using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace SubactId.Tokens.Signing;

/// <summary>
/// One ES256 (ECDSA over P-256 with SHA-256) signing key. The private key is never exposed. Only
/// signatures and the public JWK leave this type.
/// </summary>
public sealed class SigningKey : IDisposable
{
    /// <summary>The only JWS algorithm this control plane signs with.</summary>
    public const string Algorithm = "ES256";

    /// <summary>Byte length of an ES256 signature in JWS (R and S, 32 bytes each).</summary>
    public const int SignatureLength = 64;

    private const string P256Oid = "1.2.840.10045.3.1.7";

    private readonly ECDsa key;

    private SigningKey(string kid, ECDsa key, PublicJwk publicJwk)
    {
        Kid = kid;
        this.key = key;
        PublicJwk = publicJwk;
    }

    /// <summary>Key identifier, published in JWKS and written into every token header.</summary>
    public string Kid { get; }

    /// <summary>The public half of the key.</summary>
    public PublicJwk PublicJwk { get; }

    /// <summary>
    /// Wraps a P-256 private key. Anything else is rejected. The result takes ownership of
    /// <paramref name="key"/>.
    /// </summary>
    /// <param name="key">The private key.</param>
    /// <param name="kid">Explicit key identifier, or <c>null</c> to use the RFC 7638 thumbprint.</param>
    /// <exception cref="SigningKeyException">The key is not a P-256 private key.</exception>
    public static SigningKey FromPrivateKey(ECDsa key, string? kid = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        ECParameters parameters;
        try
        {
            parameters = key.ExportParameters(includePrivateParameters: true);
        }
        catch (CryptographicException)
        {
            throw new SigningKeyException("The key does not contain a private key; a public key cannot sign.");
        }

        try
        {
            if (parameters.D is not { Length: > 0 })
            {
                throw new SigningKeyException("The key does not contain a private key; a public key cannot sign.");
            }

            if (parameters.Curve.Oid?.Value != P256Oid || parameters.Q.X is not { Length: 32 } || parameters.Q.Y is not { Length: 32 })
            {
                throw new SigningKeyException("The key is not on curve P-256; ES256 requires P-256.");
            }

            var x = Base64Url.EncodeToString(parameters.Q.X);
            var y = Base64Url.EncodeToString(parameters.Q.Y);
            var resolvedKid = string.IsNullOrWhiteSpace(kid) ? Thumbprint(x, y) : kid;
            return new SigningKey(resolvedKid, key, new PublicJwk(resolvedKid, x, y));
        }
        finally
        {
            if (parameters.D is not null)
            {
                CryptographicOperations.ZeroMemory(parameters.D);
            }
        }
    }

    /// <summary>Generates a fresh P-256 key. Only for development and tests; production keys come from configuration.</summary>
    /// <param name="kid">Explicit key identifier, or <c>null</c> to use the thumbprint.</param>
    public static SigningKey Generate(string? kid = null) => FromPrivateKey(ECDsa.Create(ECCurve.NamedCurves.nistP256), kid);

    /// <summary>RFC 7638 thumbprint of a P-256 public key: base64url(SHA-256) of the canonical JWK members.</summary>
    /// <param name="x">Base64url X coordinate.</param>
    /// <param name="y">Base64url Y coordinate.</param>
    public static string Thumbprint(string x, string y)
    {
        var canonical = Encoding.UTF8.GetBytes($$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}""");
        return Base64Url.EncodeToString(SHA256.HashData(canonical));
    }

    /// <summary>Signs <paramref name="data"/>, returning the 64-byte R||S signature JWS expects.</summary>
    /// <param name="data">The bytes to sign.</param>
    public byte[] Sign(ReadOnlySpan<byte> data) =>
        key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>Verifies a 64-byte R||S signature over <paramref name="data"/>.</summary>
    /// <param name="data">The signed bytes.</param>
    /// <param name="signature">The signature to check.</param>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        signature.Length == SignatureLength
        && key.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <inheritdoc />
    public void Dispose() => key.Dispose();
}
