using System.Security.Cryptography;

namespace SubactId.UnitTests.Tokens;

/// <summary>Freshly generated key material in the PEM forms operators will use.</summary>
internal static class TestKeys
{
    public static string Pkcs8Pem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportPkcs8PrivateKeyPem();
    }

    public static string Sec1Pem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportECPrivateKeyPem();
    }

    public static string PublicOnlyPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportSubjectPublicKeyInfoPem();
    }

    public static string P384Pem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        return key.ExportPkcs8PrivateKeyPem();
    }

    public static string EncryptedPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportEncryptedPkcs8PrivateKeyPem("password", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));
    }

    /// <summary>A distinctive slice of the PEM body, to prove it never appears in an error message.</summary>
    public static string Body(string pem)
    {
        var line = pem.Split('\n').First(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal));
        return line[..Math.Min(20, line.Length)];
    }
}
