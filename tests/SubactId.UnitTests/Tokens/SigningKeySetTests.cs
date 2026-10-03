using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Tokens;

public class SigningKeySetTests
{
    [Fact]
    public void Ephemeral_set_has_one_active_key_with_a_thumbprint_kid()
    {
        using var set = SigningKeySet.CreateEphemeral();

        var key = Assert.Single(set.Keys);
        Assert.Same(key, set.Active);
        Assert.Equal(43, key.Kid.Length);
        Assert.Same(key, set.Find(key.Kid));
        Assert.Null(set.Find("other"));
    }

    [Fact]
    public void Jwks_json_lists_every_key_and_nothing_private()
    {
        using var first = SigningKey.Generate("first");
        using var second = SigningKey.Generate("second");
        using var set = new SigningKeySet([first, second], "second");

        var json = set.ToJwks().ToJson();

        Assert.StartsWith("{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"sig\",\"alg\":\"ES256\",\"kid\":\"first\",", json, StringComparison.Ordinal);
        Assert.Contains("\"kid\":\"second\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"d\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Constructor_rejects_empty_sets_duplicate_kids_and_unknown_active_kids()
    {
        using var a = SigningKey.Generate("a");
        using var alsoA = SigningKey.Generate("a");

        Assert.Throws<SigningKeyException>(() => new SigningKeySet([], "a"));
        Assert.Throws<SigningKeyException>(() => new SigningKeySet([a, alsoA], "a"));
        Assert.Throws<SigningKeyException>(() => new SigningKeySet([a], "b"));
    }
}
