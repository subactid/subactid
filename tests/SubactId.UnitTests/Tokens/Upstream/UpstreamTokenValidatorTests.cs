using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Upstream;

public class UpstreamTokenValidatorTests
{
    private static UpstreamTokenValidator Validator(IUpstreamKeys? keys = null, DateTimeOffset? now = null, string audience = Audience) =>
        new(keys ?? new StaticUpstreamKeys(Snapshot()), audience, new FakeTimeProvider(now ?? Now));

    [Theory]
    [InlineData("RS256")]
    [InlineData("PS256")]
    [InlineData("ES256")]
    public async Task Accepts_a_well_formed_token_for_every_allowed_algorithm(string alg)
    {
        var keys = new StaticUpstreamKeys(Snapshot(Jwks(RsaJwk(Rsa1, "rsa", alg: null), EcJwk(Ec1, "ec", alg: null))));
        var token = Mint(alg, alg == "ES256" ? "ec" : "rsa", Claims());

        var result = await Validator(keys).ValidateAsync(token);

        Assert.True(result.IsValid, result.Reason.ToString());
        Assert.Equal(UpstreamRejection.None, result.Reason);
        Assert.Equal("f47ac10b-58cc-4372-a567-0e02b2c3d479", result.Principal!.Subject);
        Assert.Equal(Issuer, result.Principal.Issuer);
        Assert.Equal(["openid", "jira:read", "jira:comment"], result.Principal.Scopes);
        Assert.Equal(Now.AddMinutes(5), result.Principal.ExpiresAt);
        Assert.Equal("openid jira:read jira:comment", result.Principal.Claims.GetProperty("scope").GetString());
        Assert.Equal(0, keys.Refreshes);
    }

    [Fact]
    public async Task A_token_bigger_than_one_of_ours_is_still_read()
    {
        // A realm with many roles and groups produces tokens several kilobytes long for the people
        // with the most access, so upstream tokens get a larger size limit than ours.
        var claims = Claims();
        claims["groups"] = Enumerable.Range(0, 300).Select(i => $"/org/department-{i}/team-{i}").ToArray();
        var token = Mint("RS256", "rsa1", claims);

        Assert.True(token.Length > JwsSegments.MaxTokenLength, $"The token is only {token.Length} characters; it does not test the limit.");
        var result = await Validator().ValidateAsync(token);

        Assert.True(result.IsValid, result.Reason.ToString());
    }

    [Fact]
    public async Task A_token_past_even_the_upstream_limit_is_refused_before_any_work()
    {
        var claims = Claims();
        claims["groups"] = Enumerable.Range(0, 800).Select(i => $"/org/department-{i}/team-{i}").ToArray();
        var token = Mint("RS256", "rsa1", claims);

        Assert.True(token.Length > JwsSegments.MaxUpstreamTokenLength, $"The token is only {token.Length} characters; it does not test the limit.");
        var result = await Validator().ValidateAsync(token);

        Assert.Equal(UpstreamRejection.Malformed, result.Reason);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("RS512")]
    [InlineData("es256")]
    public async Task Rejects_algorithms_outside_the_allowlist_before_touching_any_key(string alg)
    {
        var keys = new StaticUpstreamKeys(Snapshot());

        var result = await Validator(keys).ValidateAsync(Mint(alg, "rsa1", Claims()));

        Assert.Equal(UpstreamRejection.UnsupportedAlgorithm, result.Reason);
        Assert.Equal(0, keys.Gets);
    }

    [Fact]
    public async Task Rejects_an_algorithm_that_does_not_fit_the_named_key()
    {
        // RS256 header naming the EC key, ES256 header naming the RSA key, and PS256 against a key declared RS256.
        Assert.Equal(UpstreamRejection.KeyMismatch, (await Validator().ValidateAsync(Mint("RS256", "ec1", Claims()))).Reason);
        Assert.Equal(UpstreamRejection.KeyMismatch, (await Validator().ValidateAsync(Mint("ES256", "rsa1", Claims()))).Reason);
        Assert.Equal(UpstreamRejection.KeyMismatch, (await Validator().ValidateAsync(Mint("PS256", "rsa1", Claims()))).Reason);
    }

    [Fact]
    public async Task Rejects_a_signature_by_a_different_key_and_a_tampered_payload()
    {
        var other = await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(), rsa: Rsa2));
        Assert.Equal(UpstreamRejection.InvalidSignature, other.Reason);

        var parts = Mint("RS256", "rsa1", Claims()).Split('.');
        var tampered = $"{parts[0]}.{Base64UrlOf(Claims(("sub", "someone-else")))}.{parts[2]}";
        Assert.Equal(UpstreamRejection.InvalidSignature, (await Validator().ValidateAsync(tampered)).Reason);
    }

    [Fact]
    public async Task Refreshes_once_for_an_unknown_kid_and_accepts_the_rotated_key()
    {
        var rotated = Snapshot(Jwks(RsaJwk(Rsa2, "rsa2")));
        var keys = new StaticUpstreamKeys(Snapshot(), afterRefresh: rotated);

        var result = await Validator(keys).ValidateAsync(Mint("RS256", "rsa2", Claims(), rsa: Rsa2));

        Assert.True(result.IsValid, result.Reason.ToString());
        Assert.Equal(1, keys.Refreshes);
    }

    [Fact]
    public async Task Rejects_a_kid_that_stays_unknown_after_one_refresh()
    {
        var keys = new StaticUpstreamKeys(Snapshot());

        var result = await Validator(keys).ValidateAsync(Mint("RS256", "nope", Claims()));

        Assert.Equal(UpstreamRejection.UnknownKey, result.Reason);
        Assert.Equal(1, keys.Refreshes);
    }

    [Fact]
    public async Task Reports_keys_unavailable_when_the_upstream_cannot_be_reached_at_all()
    {
        var keys = new StaticUpstreamKeys(Snapshot(), failure: new HttpRequestException("connection refused"));

        var result = await Validator(keys).ValidateAsync(Mint("RS256", "rsa1", Claims()));

        Assert.Equal(UpstreamRejection.KeysUnavailable, result.Reason);
    }

    [Theory]
    [InlineData("https://idp.example.test/realms/other")]
    [InlineData("https://idp.example.test/realms/main/")]
    [InlineData("")]
    public async Task Rejects_tokens_from_an_untrusted_issuer(string issuer)
    {
        var result = await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("iss", issuer))));

        Assert.Equal(UpstreamRejection.UntrustedIssuer, result.Reason);
    }

    [Fact]
    public async Task Rejects_a_missing_or_non_string_issuer()
    {
        Assert.Equal(UpstreamRejection.UntrustedIssuer, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("-iss", null))))).Reason);
        Assert.Equal(UpstreamRejection.UntrustedIssuer, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("iss", 42))))).Reason);
    }

    [Fact]
    public async Task Expiry_is_enforced_with_sixty_seconds_of_skew()
    {
        var exp = Now.AddMinutes(5);
        var token = Mint("RS256", "rsa1", Claims(("exp", exp.ToUnixTimeSeconds())));

        Assert.True((await Validator(now: exp.AddSeconds(59)).ValidateAsync(token)).IsValid);
        Assert.Equal(UpstreamRejection.Expired, (await Validator(now: exp.AddSeconds(60)).ValidateAsync(token)).Reason);
    }

    [Fact]
    public async Task Missing_or_malformed_expiry_is_rejected()
    {
        Assert.Equal(UpstreamRejection.MissingExpiry, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("-exp", null))))).Reason);
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("exp", "1757426520"))))).Reason);
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("exp", -1))))).Reason);
    }

    [Fact]
    public async Task Not_before_and_issued_at_are_enforced_with_skew()
    {
        var nbf = Now.AddSeconds(30);
        Assert.True((await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("nbf", nbf.ToUnixTimeSeconds()))))).IsValid);
        Assert.Equal(UpstreamRejection.NotYetValid, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("nbf", Now.AddSeconds(61).ToUnixTimeSeconds()))))).Reason);
        Assert.Equal(UpstreamRejection.NotYetValid, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("iat", Now.AddSeconds(61).ToUnixTimeSeconds()))))).Reason);
        Assert.True((await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("iat", Now.AddSeconds(59).ToUnixTimeSeconds()))))).IsValid);
    }

    [Fact]
    public async Task Audience_may_be_a_string_or_an_array_and_must_include_this_control_plane()
    {
        Assert.True((await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("aud", new[] { "account", Audience }))))).IsValid);
        Assert.Equal(UpstreamRejection.AudienceMismatch, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("aud", "account"))))).Reason);
        Assert.Equal(UpstreamRejection.AudienceMismatch, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("aud", new[] { "account", "other" }))))).Reason);
        Assert.Equal(UpstreamRejection.AudienceMismatch, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("-aud", null))))).Reason);
        Assert.Equal(UpstreamRejection.AudienceMismatch, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("aud", "SUBACTID"))))).Reason);
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("aud", 7))))).Reason);
    }

    [Fact]
    public async Task Subject_is_required_and_scope_is_optional()
    {
        Assert.Equal(UpstreamRejection.MissingSubject, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("-sub", null))))).Reason);
        Assert.Equal(UpstreamRejection.MissingSubject, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("sub", ""))))).Reason);
        Assert.Equal(UpstreamRejection.SubTooLong, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("sub", new string('s', 257)))))).Reason);
        Assert.True((await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("sub", new string('s', 256)))))).IsValid);

        // Postgres refuses a NUL in a text parameter, so it is refused here rather than surfacing as a
        // 500 at the exchange.
        Assert.Equal(UpstreamRejection.SubMalformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("sub", "f47ac10b\u0000dead"))))).Reason);
        Assert.Equal(UpstreamRejection.SubMalformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("sub", "line\nbreak"))))).Reason);

        var noScope = await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(("-scope", null))));
        Assert.True(noScope.IsValid);
        Assert.Empty(noScope.Principal!.Scopes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("YQ==.YQ.YQ")]
    public async Task Rejects_structurally_invalid_tokens_as_malformed(string token)
    {
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(token)).Reason);
    }

    [Fact]
    public async Task Rejects_a_null_token_a_crit_header_a_missing_kid_and_a_non_object_payload()
    {
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(null)).Reason);
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(), headerJson: "{\"alg\":\"RS256\",\"kid\":\"rsa1\",\"crit\":[\"exp\"]}"))).Reason);
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync(Mint("RS256", "rsa1", Claims(), headerJson: "{\"alg\":\"RS256\"}"))).Reason);

        var parts = Mint("RS256", "rsa1", Claims()).Split('.');
        var arrayPayload = System.Buffers.Text.Base64Url.EncodeToString("[1,2,3]"u8);
        var signed = Rsa1.SignData(System.Text.Encoding.ASCII.GetBytes($"{parts[0]}.{arrayPayload}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.Equal(UpstreamRejection.Malformed, (await Validator().ValidateAsync($"{parts[0]}.{arrayPayload}.{System.Buffers.Text.Base64Url.EncodeToString(signed)}")).Reason);
    }

    [Fact]
    public async Task Signature_is_checked_before_claims_so_a_forged_token_learns_nothing_about_its_claims()
    {
        var forgedAndExpired = Mint("RS256", "rsa1", Claims(("exp", 1L)), rsa: Rsa2);

        Assert.Equal(UpstreamRejection.InvalidSignature, (await Validator().ValidateAsync(forgedAndExpired)).Reason);
    }

    [Fact]
    public void Requires_an_expected_audience()
    {
        Assert.Throws<ArgumentException>(() => new UpstreamTokenValidator(new StaticUpstreamKeys(Snapshot()), " ", new FakeTimeProvider(Now)));
    }

    private static string Base64UrlOf(Dictionary<string, object?> claims) =>
        System.Buffers.Text.Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(claims));
}
