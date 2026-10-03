using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Tokens;

public class SigningKeySetLoaderTests
{
    [Fact]
    public void Loads_an_inline_pkcs8_key_and_makes_it_active()
    {
        var pem = TestKeys.Pkcs8Pem();

        using var set = SigningKeySetLoader.Load([new SigningKeySource(null, pem, null)], activeKid: null);

        var key = Assert.Single(set.Keys);
        Assert.Same(key, set.Active);
        Assert.Equal(43, key.Kid.Length);
    }

    [Fact]
    public void Loads_a_sec1_key()
    {
        using var set = SigningKeySetLoader.Load([new SigningKeySource("sec1", TestKeys.Sec1Pem(), null)], "sec1");

        Assert.Equal("sec1", set.Active.Kid);
    }

    [Fact]
    public void Loads_a_key_from_a_file()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, TestKeys.Pkcs8Pem());

            using var set = SigningKeySetLoader.Load([new SigningKeySource("file", null, path)], null);

            Assert.Equal("file", set.Active.Kid);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Two_keys_are_both_published_and_the_selected_one_signs()
    {
        using var set = SigningKeySetLoader.Load(
            [new SigningKeySource("old", TestKeys.Pkcs8Pem(), null), new SigningKeySource("new", TestKeys.Pkcs8Pem(), null)],
            "new");

        Assert.Equal(["old", "new"], set.Keys.Select(k => k.Kid));
        Assert.Equal("new", set.Active.Kid);
        var jwks = set.ToJwks().ToJson();
        Assert.Equal(["old", "new"], set.ToJwks().Keys.Select(k => k.Kid));
        Assert.DoesNotContain("\"d\"", jwks, StringComparison.Ordinal);
    }

    [Fact]
    public void Several_keys_without_an_explicit_active_kid_is_an_error()
    {
        var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load(
            [new SigningKeySource("a", TestKeys.Pkcs8Pem(), null), new SigningKeySource("b", TestKeys.Pkcs8Pem(), null)],
            null));

        Assert.Contains("no active key is selected", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void No_keys_is_an_error()
    {
        Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load([], null));
    }

    [Fact]
    public void An_unknown_active_kid_is_an_error_that_names_the_known_kids()
    {
        var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load(
            [new SigningKeySource("a", TestKeys.Pkcs8Pem(), null), new SigningKeySource("b", TestKeys.Pkcs8Pem(), null)],
            "c"));

        Assert.Contains("'c'", exception.Message, StringComparison.Ordinal);
        Assert.Contains("a, b", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_kids_are_an_error()
    {
        var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load(
            [new SigningKeySource("same", TestKeys.Pkcs8Pem(), null), new SigningKeySource("same", TestKeys.Pkcs8Pem(), null)],
            "same"));

        Assert.Contains("more than once", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_source_must_have_exactly_one_of_pem_or_path()
    {
        var pem = TestKeys.Pkcs8Pem();

        var both = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load([new SigningKeySource("k", pem, "/tmp/x.pem")], null));
        var neither = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load([new SigningKeySource("k", null, null)], null));

        Assert.Contains("exactly one", both.Message, StringComparison.Ordinal);
        Assert.Contains("exactly one", neither.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(TestKeys.Body(pem), both.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_file_is_an_error_that_names_the_path()
    {
        var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load([new SigningKeySource("k", null, "/nonexistent/key.pem")], null));

        Assert.Contains("/nonexistent/key.pem", exception.Message, StringComparison.Ordinal);
    }

    public static TheoryData<string, string, string> UnusablePems => new()
    {
        { "encrypted", TestKeys.EncryptedPem(), "encrypted" },
        { "public only", TestKeys.PublicOnlyPem(), "does not contain a private key" },
        { "wrong curve", TestKeys.P384Pem(), "P-256" },
        { "garbage", "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n", "not a PEM-encoded EC private key" },
        { "not pem", "just some text", "not a PEM-encoded EC private key" },
    };

    [Theory]
    [MemberData(nameof(UnusablePems))]
    public void Unusable_key_material_is_rejected_without_being_echoed(string _, string pem, string expectedMessage)
    {
        var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load([new SigningKeySource("k", pem, null)], null));

        Assert.StartsWith("signing key 0 ('k')", exception.Message, StringComparison.Ordinal);
        Assert.Contains(expectedMessage, exception.Message, StringComparison.Ordinal);
        if (pem.Contains("-----", StringComparison.Ordinal))
        {
            Assert.DoesNotContain(TestKeys.Body(pem), exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Loads_a_pem_with_windows_line_endings_and_no_trailing_newline()
    {
        var pem = TestKeys.Pkcs8Pem().Replace("\n", "\r\n").TrimEnd();

        using var set = SigningKeySetLoader.Load([new SigningKeySource("crlf", pem, null)], null);

        Assert.Equal("crlf", set.Active.Kid);
    }

    [Fact]
    public void The_active_kid_may_be_a_thumbprint()
    {
        var oldPem = TestKeys.Pkcs8Pem();
        var newPem = TestKeys.Pkcs8Pem();
        using var probe = SigningKeySetLoader.Load([new SigningKeySource(null, newPem, null)], null);
        var thumbprint = probe.Active.Kid;

        using var set = SigningKeySetLoader.Load([new SigningKeySource(null, oldPem, null), new SigningKeySource(null, newPem, null)], thumbprint);

        Assert.Equal(thumbprint, set.Active.Kid);
        Assert.Equal(2, set.Keys.Count);
    }

    [Fact]
    public void The_same_key_listed_twice_is_a_duplicate_even_without_explicit_kids()
    {
        var pem = TestKeys.Pkcs8Pem();

        var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load(
            [new SigningKeySource(null, pem, null), new SigningKeySource(null, pem, null)], "anything"));

        Assert.Contains("more than once", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_file_is_rejected()
    {
        var path = Path.GetTempFileName();
        try
        {
            var exception = Assert.Throws<SigningKeyException>(() => SigningKeySetLoader.Load([new SigningKeySource("k", null, path)], null));
            Assert.Contains("not a PEM-encoded EC private key", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Source_to_string_never_shows_the_pem()
    {
        var pem = TestKeys.Pkcs8Pem();

        var text = new SigningKeySource("k", pem, null).ToString();

        Assert.DoesNotContain(TestKeys.Body(pem), text, StringComparison.Ordinal);
        Assert.Contains("<redacted>", text, StringComparison.Ordinal);
    }
}
