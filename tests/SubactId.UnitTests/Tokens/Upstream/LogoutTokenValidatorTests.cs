using System.Net.Http;
using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Upstream;

/// <summary>
/// Every refusal Back-Channel Logout 1.0 section 2.4 requires, one test each. Without the events
/// check an ID token could be posted as a logout, and without the nonce check one token could
/// serve as both.
/// </summary>
public class LogoutTokenValidatorTests
{
    private const string LogoutAudience = "workbench";
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static LogoutTokenValidator Validator(IUpstreamKeys? keys = null, FakeTimeProvider? clock = null) =>
        new(keys ?? new StaticUpstreamKeys(Snapshot()), LogoutAudience, clock ?? new FakeTimeProvider(Now));

    /// <summary>A claim set that validates at <see cref="UpstreamTestData.Now"/>.</summary>
    private static Dictionary<string, object?> LogoutClaims(params (string Key, object? Value)[] overrides)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = LogoutAudience,
            ["sub"] = Human,
            ["iat"] = Now.AddSeconds(-5).ToUnixTimeSeconds(),
            ["jti"] = "logout-1",
            ["events"] = new Dictionary<string, object?> { [LogoutTokenValidator.LogoutEvent] = new Dictionary<string, object?>() },
        };
        foreach (var (key, value) in overrides)
        {
            if (value is null && key.StartsWith('-')) claims.Remove(key[1..]);
            else claims[key] = value;
        }

        return claims;
    }

    private static string Token(params (string Key, object? Value)[] overrides) => Mint("RS256", "rsa1", LogoutClaims(overrides));

    [Fact]
    public async Task A_logout_token_naming_a_person_is_accepted_with_its_replay_window()
    {
        var validation = await Validator().ValidateAsync(Token());

        Assert.Equal(LogoutRejection.None, validation.Reason);
        var signal = validation.Signal!;
        Assert.Equal((Issuer, Human, null, "logout-1"), (signal.Issuer, signal.Subject, signal.SessionId, signal.Jti));

        // No exp, so the replay record is kept as long as the token could still be accepted: its age
        // bound plus skew.
        Assert.Equal(Now.AddSeconds(-5) + LogoutTokenValidator.MaxAge + LogoutTokenValidator.ClockSkew, signal.ExpiresAt);
    }

    [Fact]
    public async Task A_logout_token_may_name_a_session_instead_of_a_person_or_both()
    {
        var session = await Validator().ValidateAsync(Token(("-sub", null), ("sid", "session-7")));
        Assert.Equal((null, "session-7"), (session.Signal!.Subject, session.Signal.SessionId));

        var both = await Validator().ValidateAsync(Token(("sid", "session-7")));
        Assert.Equal((Human, "session-7"), (both.Signal!.Subject, both.Signal.SessionId));
    }

    [Fact]
    public async Task An_exp_is_honoured_when_the_provider_sends_one()
    {
        var accepted = await Validator().ValidateAsync(Token(("exp", Now.AddMinutes(2).ToUnixTimeSeconds())));
        Assert.Equal(Now.AddMinutes(2) + LogoutTokenValidator.ClockSkew, accepted.Signal!.ExpiresAt);

        // An exp beyond the age bound extends nothing: the token is refused as too old by then anyway.
        var farOut = await Validator().ValidateAsync(Token(("exp", Now.AddDays(365).ToUnixTimeSeconds())));
        Assert.Equal(Now.AddSeconds(-5) + LogoutTokenValidator.MaxAge + LogoutTokenValidator.ClockSkew, farOut.Signal!.ExpiresAt);

        var expired = await Validator().ValidateAsync(Token(("exp", Now.AddMinutes(-2).ToUnixTimeSeconds())));
        Assert.Equal(LogoutRejection.Expired, expired.Reason);
    }

    [Fact]
    public async Task An_id_token_is_not_a_logout_token()
    {
        // Without the events claim, this is what an ID token looks like.
        var withoutEvents = await Validator().ValidateAsync(Token(("-events", null)));
        Assert.Equal(LogoutRejection.NotALogoutEvent, withoutEvents.Reason);

        var wrongEvent = await Validator().ValidateAsync(Token(("events", new Dictionary<string, object?> { ["http://schemas.openid.net/event/something-else"] = new Dictionary<string, object?>() })));
        Assert.Equal(LogoutRejection.NotALogoutEvent, wrongEvent.Reason);

        var notAnObject = await Validator().ValidateAsync(Token(("events", "backchannel-logout")));
        Assert.Equal(LogoutRejection.NotALogoutEvent, notAnObject.Reason);
    }

    [Fact]
    public async Task A_token_carrying_a_nonce_is_refused()
    {
        // The other half of the same rule, so one token cannot serve as both.
        var validation = await Validator().ValidateAsync(Token(("nonce", "n-0S6_WzA2Mj")));

        Assert.Equal(LogoutRejection.NoncePresent, validation.Reason);
    }

    [Fact]
    public async Task A_token_naming_neither_a_person_nor_a_session_is_refused()
    {
        // Acting on it would mean revoking everything or nothing, so it is refused.
        var validation = await Validator().ValidateAsync(Token(("-sub", null)));

        Assert.Equal(LogoutRejection.NoSubjectOrSession, validation.Reason);
    }

    [Theory]
    [InlineData("iss", "https://idp.attacker.example", LogoutRejection.UntrustedIssuer)]
    [InlineData("aud", "someone-else", LogoutRejection.AudienceMismatch)]
    public async Task A_token_from_or_for_somebody_else_is_refused(string claim, object value, LogoutRejection expected)
    {
        Assert.Equal(expected, (await Validator().ValidateAsync(Token((claim, value)))).Reason);
    }

    [Fact]
    public async Task The_audience_may_be_an_array_containing_the_configured_client()
    {
        var validation = await Validator().ValidateAsync(Token(("aud", new[] { "account", LogoutAudience })));

        Assert.Equal(LogoutRejection.None, validation.Reason);
    }

    [Fact]
    public async Task The_configured_audience_is_not_the_audience_a_subject_token_carries()
    {
        // Subact ID's own audience on a logout token is a configuration mistake, so it is refused.
        var validation = await Validator().ValidateAsync(Token(("aud", Audience)));

        Assert.Equal(LogoutRejection.AudienceMismatch, validation.Reason);
    }

    [Fact]
    public async Task A_token_with_no_issued_at_or_one_out_of_its_window_is_refused()
    {
        Assert.Equal(LogoutRejection.MissingIssuedAt, (await Validator().ValidateAsync(Token(("-iat", null)))).Reason);
        Assert.Equal(LogoutRejection.NotYetValid, (await Validator().ValidateAsync(Token(("iat", Now.AddMinutes(5).ToUnixTimeSeconds())))).Reason);

        // A token held and spent later is why there is an age bound.
        Assert.Equal(LogoutRejection.TooOld, (await Validator().ValidateAsync(Token(("iat", Now.AddHours(-1).ToUnixTimeSeconds())))).Reason);
    }

    [Fact]
    public async Task A_token_with_no_usable_jti_is_refused_because_it_could_not_be_replay_checked()
    {
        Assert.Equal(LogoutRejection.MissingJti, (await Validator().ValidateAsync(Token(("-jti", null)))).Reason);
        Assert.Equal(LogoutRejection.MissingJti, (await Validator().ValidateAsync(Token(("jti", "")))).Reason);
        Assert.Equal(LogoutRejection.MissingJti, (await Validator().ValidateAsync(Token(("jti", 7)))).Reason);

        // A jti that is there but carries a control character is malformed, not missing.
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync(Token(("jti", "j\u0000ti")))).Reason);
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync(Token(("jti", "j\nti")))).Reason);
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("sid")]
    public async Task An_identifier_with_a_control_character_is_malformed_rather_than_a_storage_fault(string claim)
    {
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync(Token((claim, "session\u00001")))).Reason);
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("sid")]
    public async Task An_identifier_longer_than_the_column_it_is_matched_against_is_refused(string claim)
    {
        var tooLong = new string('x', LogoutTokenValidator.MaxIdentifierLength + 1);

        Assert.Equal(LogoutRejection.IdentifierTooLong, (await Validator().ValidateAsync(Token((claim, tooLong)))).Reason);
    }

    [Fact]
    public async Task A_forged_or_unsigned_token_is_refused()
    {
        // Signed with a key the upstream does not publish.
        var forged = Mint("RS256", "rsa1", LogoutClaims(), rsa: Rsa2);
        Assert.Equal(LogoutRejection.InvalidSignature, (await Validator().ValidateAsync(forged)).Reason);

        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync("not-a-token")).Reason);
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync(null)).Reason);
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync("")).Reason);
    }

    [Fact]
    public async Task A_token_naming_a_key_the_upstream_does_not_publish_is_refused_after_one_refresh()
    {
        var keys = new StaticUpstreamKeys(Snapshot());

        Assert.Equal(LogoutRejection.UnknownKey, (await Validator(keys).ValidateAsync(Mint("RS256", "nope", LogoutClaims()))).Reason);
        Assert.Equal(1, keys.Refreshes);
    }

    [Fact]
    public async Task An_algorithm_this_control_plane_does_not_accept_is_refused_before_any_key_is_fetched()
    {
        var keys = new StaticUpstreamKeys(Snapshot());

        Assert.Equal(LogoutRejection.UnsupportedAlgorithm, (await Validator(keys).ValidateAsync(Mint("HS256", "rsa1", LogoutClaims()))).Reason);
        Assert.Equal(0, keys.Gets);
    }

    [Fact]
    public async Task An_identity_provider_whose_keys_cannot_be_fetched_is_not_a_bad_token()
    {
        var keys = new StaticUpstreamKeys(Snapshot(), failure: new HttpRequestException("down"));

        Assert.Equal(LogoutRejection.KeysUnavailable, (await Validator(keys).ValidateAsync(Token())).Reason);
    }

    [Fact]
    public async Task A_header_that_names_no_key_or_demands_an_extension_is_refused()
    {
        var noKid = Mint("RS256", "rsa1", LogoutClaims(), headerJson: "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync(noKid)).Reason);

        var crit = Mint("RS256", "rsa1", LogoutClaims(), headerJson: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"rsa1\",\"crit\":[\"x\"]}");
        Assert.Equal(LogoutRejection.Malformed, (await Validator().ValidateAsync(crit)).Reason);
    }

    [Fact]
    public void An_audience_must_be_configured_for_the_validator_to_exist()
    {
        Assert.Throws<ArgumentException>(() => new LogoutTokenValidator(new StaticUpstreamKeys(Snapshot()), "  ", new FakeTimeProvider(Now)));
    }
}
