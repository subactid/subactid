using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Tokens;

public class SigningKeyTests
{
    [Fact]
    public void Kid_defaults_to_the_rfc_7638_thumbprint_of_the_public_key()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = ecdsa.ExportParameters(false).Q;
        var x = Base64Url.EncodeToString(q.X!);
        var y = Base64Url.EncodeToString(q.Y!);
        var expected = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));

        using var key = SigningKey.FromPrivateKey(ecdsa);

        Assert.Equal(expected, key.Kid);
        Assert.Equal(43, key.Kid.Length);
        Assert.Equal(x, key.PublicJwk.X);
        Assert.Equal(y, key.PublicJwk.Y);
    }

    [Fact]
    public void An_explicit_kid_is_honoured()
    {
        using var key = SigningKey.Generate("2026-09");

        Assert.Equal("2026-09", key.Kid);
        Assert.Equal("2026-09", key.PublicJwk.Kid);
    }

    [Fact]
    public void Rejects_a_key_that_is_not_p256()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var exception = Assert.Throws<SigningKeyException>(() => SigningKey.FromPrivateKey(ecdsa));

        Assert.Contains("P-256", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_a_public_only_key()
    {
        using var source = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicOnly = ECDsa.Create();
        publicOnly.ImportSubjectPublicKeyInfo(source.ExportSubjectPublicKeyInfo(), out _);

        var exception = Assert.Throws<SigningKeyException>(() => SigningKey.FromPrivateKey(publicOnly));

        Assert.Contains("does not contain a private key", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Signs_and_verifies_with_a_64_byte_signature()
    {
        using var key = SigningKey.Generate();
        var data = Encoding.UTF8.GetBytes("header.payload");

        var signature = key.Sign(data);

        Assert.Equal(SigningKey.SignatureLength, signature.Length);
        Assert.True(key.Verify(data, signature));
        Assert.False(key.Verify(Encoding.UTF8.GetBytes("header.payloae"), signature));
        signature[10] ^= 0x01;
        Assert.False(key.Verify(data, signature));
    }

    [Fact]
    public void Verify_rejects_signatures_of_the_wrong_length()
    {
        using var key = SigningKey.Generate();
        var data = new byte[] { 1, 2, 3 };
        var signature = key.Sign(data);

        Assert.False(key.Verify(data, signature[..63]));
        Assert.False(key.Verify(data, [.. signature, 0]));
        Assert.False(key.Verify(data, []));
    }

    [Fact]
    public void Two_keys_do_not_verify_each_others_signatures()
    {
        using var first = SigningKey.Generate();
        using var second = SigningKey.Generate();
        var data = new byte[] { 1, 2, 3 };

        Assert.False(second.Verify(data, first.Sign(data)));
    }

    [Fact]
    public void Public_jwk_has_exactly_the_public_members_and_no_private_parameter()
    {
        using var key = SigningKey.Generate("k1");

        var json = JsonSerializer.Serialize(key.PublicJwk);
        using var document = JsonDocument.Parse(json);
        var members = document.RootElement.EnumerateObject().Select(p => p.Name).ToList();

        Assert.Equal(["kty", "crv", "use", "alg", "kid", "x", "y"], members);
        Assert.Equal("EC", document.RootElement.GetProperty("kty").GetString());
        Assert.Equal("P-256", document.RootElement.GetProperty("crv").GetString());
        Assert.Equal("sig", document.RootElement.GetProperty("use").GetString());
        Assert.Equal("ES256", document.RootElement.GetProperty("alg").GetString());
        Assert.DoesNotContain("\"d\"", json, StringComparison.Ordinal);
    }
}
