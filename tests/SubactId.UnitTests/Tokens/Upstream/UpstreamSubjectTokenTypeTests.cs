using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Upstream;

/// <summary>
/// The optional <c>typ</c>-header allowlist on a subject token. Off by default (the spec does not
/// require a <c>typ</c>); when set it refuses a token whose type is absent or not on the list.
/// </summary>
public class UpstreamSubjectTokenTypeTests
{
    private static UpstreamTokenValidator Validator(IReadOnlyList<string>? acceptedTypes = null) =>
        new(new StaticUpstreamKeys(Snapshot()), Audience, new FakeTimeProvider(Now), acceptedTypes);

    private static string TokenWithTyp(string? typ)
    {
        var header = typ is null
            ? "{\"alg\":\"RS256\",\"kid\":\"rsa1\"}"
            : $"{{\"alg\":\"RS256\",\"typ\":\"{typ}\",\"kid\":\"rsa1\"}}";
        return Mint("RS256", "rsa1", Claims(), headerJson: header);
    }

    [Fact]
    public async Task With_no_allowlist_any_typ_is_accepted()
    {
        // Default behaviour: without an allowlist the validator does not look at typ at all,
        // whatever the provider puts there (Keycloak puts "JWT" on access and ID tokens alike).
        foreach (var typ in new[] { "JWT", "Bearer", "at+jwt", "ID", null })
        {
            var result = await Validator().ValidateAsync(TokenWithTyp(typ));
            Assert.True(result.IsValid, $"typ={typ ?? "(none)"} reason={result.Reason}");
        }
    }

    [Fact]
    public async Task A_typ_on_the_allowlist_is_accepted()
    {
        var result = await Validator(["at+jwt"]).ValidateAsync(TokenWithTyp("at+jwt"));

        Assert.True(result.IsValid, result.Reason.ToString());
    }

    [Fact]
    public async Task The_allowlist_is_case_insensitive()
    {
        var result = await Validator(["at+jwt"]).ValidateAsync(TokenWithTyp("AT+JWT"));

        Assert.True(result.IsValid, result.Reason.ToString());
    }

    [Fact]
    public async Task A_typ_outside_the_allowlist_is_refused()
    {
        // Where the provider marks its access tokens at+jwt (RFC 9068), a token of another type
        // with the same iss, sub and aud, such as an ID token, is kept out.
        var result = await Validator(["at+jwt"]).ValidateAsync(TokenWithTyp("JWT"));

        Assert.Equal(UpstreamRejection.UnacceptedType, result.Reason);
    }

    [Theory]
    [InlineData("at+jwt", "application/at+jwt")]
    [InlineData("application/at+jwt", "at+jwt")]
    [InlineData("application/at+jwt", "Application/AT+JWT")]
    public async Task The_application_prefix_is_optional_on_either_side(string configured, string presented)
    {
        // RFC 7515 section 4.1.9 reads a typ without a '/' as application/ plus that value, and
        // RFC 9068 section 4 accepts both spellings of at+jwt.
        var result = await Validator([configured]).ValidateAsync(TokenWithTyp(presented));

        Assert.True(result.IsValid, result.Reason.ToString());
    }

    [Theory]
    [InlineData("text/at+jwt")]
    [InlineData("application/at+jwt/x")]
    [InlineData("jwt")]
    public async Task Only_the_application_prefix_is_optional(string presented)
    {
        var result = await Validator(["at+jwt"]).ValidateAsync(TokenWithTyp(presented));

        Assert.Equal(UpstreamRejection.UnacceptedType, result.Reason);
    }

    [Fact]
    public async Task A_missing_typ_is_refused_when_an_allowlist_is_configured()
    {
        var result = await Validator(["at+jwt"]).ValidateAsync(TokenWithTyp(null));

        Assert.Equal(UpstreamRejection.UnacceptedType, result.Reason);
    }

    [Fact]
    public async Task The_type_is_checked_before_any_key_is_touched()
    {
        var keys = new StaticUpstreamKeys(Snapshot());
        var validator = new UpstreamTokenValidator(keys, Audience, new FakeTimeProvider(Now), ["at+jwt"]);

        await validator.ValidateAsync(TokenWithTyp("JWT"));

        Assert.Equal(0, keys.Gets);
    }
}
