using SubactId.Tokens.Issuance;
using Xunit;

namespace SubactId.UnitTests.Tokens.Issuance;

public class OpaqueIdTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero);

    [Fact]
    public void Has_the_prefix_an_underscore_and_26_crockford_base32_characters()
    {
        var id = OpaqueId.New(OpaqueId.TokenPrefix, Now);

        Assert.StartsWith("tok_", id, StringComparison.Ordinal);
        Assert.Equal(30, id.Length);
        Assert.Matches("^tok_[0-9A-HJKMNP-TV-Z]{26}$", id);
        Assert.Matches("^task_[0-9A-HJKMNP-TV-Z]{26}$", OpaqueId.New(OpaqueId.TaskPrefix, Now));
    }

    [Fact]
    public void The_first_ten_characters_encode_the_millisecond_timestamp()
    {
        var id = OpaqueId.New("tok", Now);

        Assert.Equal(Now.ToUnixTimeMilliseconds(), Decode(id[4..14]));
        Assert.Equal(id[4..14], OpaqueId.New("tok", Now)[4..14]);
        Assert.True(string.CompareOrdinal(OpaqueId.New("tok", Now.AddMilliseconds(1)), id) > 0);
    }

    [Fact]
    public void Identifiers_are_unique()
    {
        var ids = Enumerable.Range(0, 10_000).Select(_ => OpaqueId.New("tok", Now)).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(10_000, ids.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Tok")]
    [InlineData("tok_")]
    [InlineData("tok1")]
    public void The_prefix_must_be_lowercase_letters(string prefix)
    {
        Assert.ThrowsAny<ArgumentException>(() => OpaqueId.New(prefix, Now));
    }

    private static long Decode(string crockford)
    {
        const string alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        return crockford.Aggregate(0L, (acc, c) => (acc << 5) + alphabet.IndexOf(c, StringComparison.Ordinal));
    }
}
