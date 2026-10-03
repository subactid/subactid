using System.Security.Cryptography;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Upstream;

public class UpstreamJwksParserTests
{
    [Fact]
    public void Parses_keycloak_shaped_rsa_and_ec_keys_and_skips_the_encryption_key()
    {
        var jwks = Jwks(RsaJwk(Rsa1, "rsa1"), EcJwk(Ec1, "ec1"), RsaJwk(Rsa2, "enc", alg: null, use: "enc"));

        var keys = UpstreamJwksParser.Parse(jwks);

        Assert.Equal(["ec1", "rsa1"], keys.Keys.Order());
        Assert.Equal("RSA", keys["rsa1"].KeyType);
        Assert.Equal("RS256", keys["rsa1"].Algorithm);
        Assert.Equal("EC", keys["ec1"].KeyType);
    }

    [Fact]
    public void Skips_keys_that_carry_private_material()
    {
        var keys = UpstreamJwksParser.Parse(Jwks(RsaJwk(Rsa1, "leaky", includePrivate: true), RsaJwk(Rsa2, "fine")));

        Assert.Equal(["fine"], keys.Keys);
    }

    [Fact]
    public void Skips_weak_rsa_keys_unsupported_curves_unknown_types_and_entries_without_a_kid()
    {
        using var weak = RSA.Create(1024);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var jwks = Jwks(
            RsaJwk(weak, "weak"),
            EcJwk(p384, "p384", crv: "P-384"),
            "{\"kid\":\"oct\",\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}",
            "{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}",
            "{\"kid\":\"ec-wrong-curve-claim\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AQ\",\"y\":\"AQ\"}",
            RsaJwk(Rsa1, "good"));

        var keys = UpstreamJwksParser.Parse(jwks);

        Assert.Equal(["good"], keys.Keys);
    }

    [Fact]
    public void Skips_keys_that_declare_an_algorithm_this_control_plane_does_not_accept()
    {
        var keys = UpstreamJwksParser.Parse(Jwks(RsaJwk(Rsa1, "rs512", alg: "RS512"), RsaJwk(Rsa2, "hs", alg: "HS256"), RsaJwk(Rsa1, "ps", alg: "PS256")));

        Assert.Equal(["ps"], keys.Keys);
    }

    [Fact]
    public void Keeps_the_first_of_duplicate_kids()
    {
        var keys = UpstreamJwksParser.Parse(Jwks(RsaJwk(Rsa1, "dup"), EcJwk(Ec1, "dup")));

        Assert.Equal("RSA", Assert.Single(keys.Values).KeyType);
    }

    [Fact]
    public void Rejects_a_point_not_on_the_curve()
    {
        var q = Ec1.ExportParameters(false).Q;
        var x = (byte[])q.X!.Clone();
        x[0] ^= 0x01;

        Assert.Null(UpstreamKey.CreateP256("bad", null, x, q.Y!));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"keys\":{}}")]
    public void Documents_that_are_not_a_jwks_are_errors(string json)
    {
        Assert.Throws<UpstreamDiscoveryException>(() => UpstreamJwksParser.Parse(json));
    }

    [Fact]
    public void An_empty_key_list_is_a_valid_but_useless_document()
    {
        Assert.Empty(UpstreamJwksParser.Parse("{\"keys\":[]}"));
    }
}
