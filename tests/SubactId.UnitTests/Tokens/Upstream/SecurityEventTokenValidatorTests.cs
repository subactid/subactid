using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Upstream;

/// <summary>
/// What a security event token must be before this control plane ends somebody's tasks on it.
/// It is trusted only against the transmitter's own keys, and a subject identifier in a format
/// this receiver does not read is refused, not guessed at.
/// </summary>
public class SecurityEventTokenValidatorTests
{
    private const string StreamAudience = "https://subactid.internal.example.com/events";
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static SecurityEventTokenValidator Validator(IUpstreamKeys? keys = null, FakeTimeProvider? clock = null) =>
        new(keys ?? new StaticUpstreamKeys(Snapshot()), StreamAudience, Issuer, clock ?? new FakeTimeProvider(Now));

    private static Dictionary<string, object?> Subject(string sub) => new()
    {
        ["format"] = "iss_sub",
        ["iss"] = Issuer,
        ["sub"] = sub,
    };

    /// <summary>A claim set that validates at <see cref="UpstreamTestData.Now"/>.</summary>
    private static Dictionary<string, object?> EventClaims(params (string Key, object? Value)[] overrides)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = StreamAudience,
            ["iat"] = Now.AddSeconds(-5).ToUnixTimeSeconds(),
            ["jti"] = "event-1",
            ["events"] = new Dictionary<string, object?>
            {
                [SecurityEventTokenValidator.AccountDisabled] = new Dictionary<string, object?> { ["subject"] = Subject(Human) },
            },
        };
        foreach (var (key, value) in overrides)
        {
            if (value is null && key.StartsWith('-')) claims.Remove(key[1..]);
            else claims[key] = value;
        }

        return claims;
    }

    private static string Token(params (string Key, object? Value)[] overrides) => Mint("RS256", "rsa1", EventClaims(overrides));

    private static Dictionary<string, object?> OneEvent(string type, object? subject) =>
        new() { [type] = subject is null ? new Dictionary<string, object?>() : new Dictionary<string, object?> { ["subject"] = subject } };

    [Fact]
    public async Task An_account_disabled_event_is_accepted_and_names_the_person_and_its_replay_window()
    {
        var validation = await Validator().ValidateAsync(Token());

        Assert.True(validation.IsValid);
        var signal = validation.Signal!;
        Assert.Equal((Issuer, "event-1"), (signal.Issuer, signal.Jti));

        var action = Assert.Single(signal.Actions);
        Assert.Equal((SecurityEventKind.AccountDisabled, Human), (action.Kind, action.SponsorKey));

        // A SET has no expiry of its own, so the age bound decides how long the replay record lasts.
        Assert.Equal(Now.AddSeconds(-5) + SecurityEventTokenValidator.MaxAge + SecurityEventTokenValidator.ClockSkew, signal.ExpiresAt);
    }

    [Theory]
    [InlineData(SecurityEventTokenValidator.SessionRevoked, SecurityEventKind.SessionsRevoked)]
    [InlineData(SecurityEventTokenValidator.AccountDisabled, SecurityEventKind.AccountDisabled)]
    [InlineData(SecurityEventTokenValidator.AccountEnabled, SecurityEventKind.AccountEnabled)]
    [InlineData(SecurityEventTokenValidator.AccountPurged, SecurityEventKind.AccountPurged)]
    public async Task Each_event_this_receiver_acts_on_is_read_as_what_it_asks_for(string eventType, SecurityEventKind expected)
    {
        var validation = await Validator().ValidateAsync(Token(("events", OneEvent(eventType, Subject(Human)))));

        Assert.True(validation.IsValid);
        Assert.Equal(expected, Assert.Single(validation.Signal!.Actions).Kind);
    }

    [Fact]
    public async Task A_subject_stated_once_for_the_whole_token_is_used_by_every_event_in_it()
    {
        var validation = await Validator().ValidateAsync(Token(
            ("sub_id", Subject(Human)),
            ("events", new Dictionary<string, object?>
            {
                [SecurityEventTokenValidator.SessionRevoked] = new Dictionary<string, object?>(),
                [SecurityEventTokenValidator.AccountDisabled] = new Dictionary<string, object?>(),
            })));

        Assert.True(validation.IsValid);
        Assert.Equal(2, validation.Signal!.Actions.Count);
        Assert.All(validation.Signal.Actions, a => Assert.Equal(Human, a.SponsorKey));
    }

    [Fact]
    public async Task A_token_naming_one_person_at_the_top_and_another_in_the_event_is_acted_on_for_neither()
    {
        // Acting on either would be a guess about which person it asks to stop.
        var validation = await Validator().ValidateAsync(Token(
            ("sub_id", Subject(Human)),
            ("events", OneEvent(SecurityEventTokenValidator.AccountDisabled, Subject("somebody-else")))));

        Assert.Equal(SecurityEventRejection.AmbiguousSubject, validation.Reason);
    }

    [Fact]
    public async Task A_subject_stated_at_the_top_stands_beside_an_event_subject_this_receiver_cannot_read()
    {
        // A transmitter may name the person once for the token in a readable format and again inside
        // the event in an unreadable one. That is one person named twice.
        var email = new Dictionary<string, object?> { ["format"] = "email", ["email"] = "ada@example.com" };

        var validation = await Validator().ValidateAsync(Token(
            ("sub_id", Subject(Human)),
            ("events", OneEvent(SecurityEventTokenValidator.AccountDisabled, email))));

        Assert.True(validation.IsValid);
        Assert.Equal(Human, Assert.Single(validation.Signal!.Actions).SponsorKey);
    }

    [Fact]
    public async Task An_opaque_subject_carries_the_key_tasks_are_stored_under()
    {
        var validation = await Validator().ValidateAsync(Token(
            ("events", OneEvent(SecurityEventTokenValidator.AccountDisabled, new Dictionary<string, object?> { ["format"] = "opaque", ["id"] = "oid-42" }))));

        Assert.True(validation.IsValid);
        Assert.Equal("oid-42", Assert.Single(validation.Signal!.Actions).SponsorKey);
    }

    [Fact]
    public async Task A_subject_from_another_identity_provider_is_not_our_person()
    {
        // A transmitter may speak for several identity providers. Only the one this control plane
        // exchanges tokens from is accepted.
        var elsewhere = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = "https://idp.somewhere-else.test", ["sub"] = Human };

        var validation = await Validator().ValidateAsync(Token(("events", OneEvent(SecurityEventTokenValidator.AccountDisabled, elsewhere))));

        Assert.Equal(SecurityEventRejection.UnsupportedSubjectFormat, validation.Reason);
    }

    [Theory]
    [InlineData("email")]
    [InlineData("phone_number")]
    [InlineData("did")]
    public async Task A_subject_format_this_receiver_does_not_read_is_refused_rather_than_guessed_at(string format)
    {
        var subject = new Dictionary<string, object?> { ["format"] = format, ["email"] = "ada@example.com", ["id"] = "something" };

        var validation = await Validator().ValidateAsync(Token(("events", OneEvent(SecurityEventTokenValidator.AccountDisabled, subject))));

        Assert.Equal(SecurityEventRejection.UnsupportedSubjectFormat, validation.Reason);
    }

    [Fact]
    public async Task An_event_this_receiver_acts_on_that_names_nobody_is_refused()
    {
        var validation = await Validator().ValidateAsync(Token(("events", OneEvent(SecurityEventTokenValidator.AccountDisabled, null))));

        Assert.Equal(SecurityEventRejection.NoUsableSubject, validation.Reason);
    }

    [Fact]
    public async Task A_token_carrying_only_events_this_receiver_does_not_act_on_is_valid_and_asks_for_nothing()
    {
        // Credential changes and compliance events are valid but need no action here. Refusing them
        // would make the transmitter retry forever or drop the stream.
        var validation = await Validator().ValidateAsync(Token(("events", new Dictionary<string, object?>
        {
            ["https://schemas.openid.net/secevent/caep/event-type/credential-change"] = new Dictionary<string, object?>(),
            ["https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"] = new Dictionary<string, object?>(),
        })));

        Assert.True(validation.IsValid);
        Assert.Empty(validation.Signal!.Actions);
    }

    [Fact]
    public async Task An_event_signed_by_anybody_but_the_transmitter_is_refused()
    {
        var forged = Mint("RS256", "rsa1", EventClaims(), rsa: Rsa2);

        Assert.Equal(SecurityEventRejection.InvalidSignature, (await Validator().ValidateAsync(forged)).Reason);
    }

    [Fact]
    public async Task An_event_from_another_issuer_or_for_another_stream_is_refused()
    {
        Assert.Equal(SecurityEventRejection.UntrustedIssuer, (await Validator().ValidateAsync(Token(("iss", "https://transmitter.somewhere-else.test")))).Reason);
        Assert.Equal(SecurityEventRejection.UntrustedIssuer, (await Validator().ValidateAsync(Token(("-iss", null)))).Reason);
        Assert.Equal(SecurityEventRejection.AudienceMismatch, (await Validator().ValidateAsync(Token(("aud", "somebody-elses-stream")))).Reason);
        Assert.Equal(SecurityEventRejection.AudienceMismatch, (await Validator().ValidateAsync(Token(("-aud", null)))).Reason);

        // An array of audiences is accepted when ours is among them.
        Assert.True((await Validator().ValidateAsync(Token(("aud", new[] { "another", StreamAudience })))).IsValid);
    }

    [Fact]
    public async Task An_event_is_only_fresh_for_as_long_as_it_could_still_be_acted_on()
    {
        Assert.Equal(SecurityEventRejection.MissingIssuedAt, (await Validator().ValidateAsync(Token(("-iat", null)))).Reason);
        Assert.Equal(SecurityEventRejection.NotYetValid, (await Validator().ValidateAsync(Token(("iat", Now.AddMinutes(5).ToUnixTimeSeconds())))).Reason);
        Assert.Equal(SecurityEventRejection.TooOld, (await Validator().ValidateAsync(Token(("iat", Now.Add(-SecurityEventTokenValidator.MaxAge).AddMinutes(-5).ToUnixTimeSeconds())))).Reason);
        Assert.Equal(SecurityEventRejection.Malformed, (await Validator().ValidateAsync(Token(("iat", "not-a-time")))).Reason);
    }

    [Fact]
    public async Task A_token_with_no_events_claim_is_not_a_security_event_token()
    {
        Assert.Equal(SecurityEventRejection.NotASecurityEvent, (await Validator().ValidateAsync(Token(("-events", null)))).Reason);
        Assert.Equal(SecurityEventRejection.NotASecurityEvent, (await Validator().ValidateAsync(Token(("events", "account-disabled")))).Reason);
    }

    [Fact]
    public async Task A_token_with_no_usable_identifier_cannot_be_checked_for_replay()
    {
        Assert.Equal(SecurityEventRejection.MissingJti, (await Validator().ValidateAsync(Token(("-jti", null)))).Reason);
        Assert.Equal(SecurityEventRejection.MissingJti, (await Validator().ValidateAsync(Token(("jti", "")))).Reason);
        Assert.Equal(SecurityEventRejection.MissingJti, (await Validator().ValidateAsync(Token(("jti", new string('j', 257))))).Reason);

        // A jti that is there but carries a control character is malformed, not missing.
        Assert.Equal(SecurityEventRejection.Malformed, (await Validator().ValidateAsync(Token(("jti", "j\u0000ti")))).Reason);
        Assert.Equal(SecurityEventRejection.Malformed, (await Validator().ValidateAsync(Token(("jti", "j\nti")))).Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("not-a-token")]
    public async Task Something_that_is_not_a_compact_jws_is_refused(string token)
    {
        Assert.Equal(SecurityEventRejection.Malformed, (await Validator().ValidateAsync(token)).Reason);
    }

    [Fact]
    public async Task A_missing_body_is_refused_like_any_other_malformed_token()
    {
        Assert.Equal(SecurityEventRejection.Malformed, (await Validator().ValidateAsync(null)).Reason);
    }

    [Fact]
    public async Task A_key_or_an_algorithm_this_control_plane_will_not_use_is_refused()
    {
        Assert.Equal(SecurityEventRejection.UnsupportedAlgorithm, (await Validator().ValidateAsync(Mint("none", "rsa1", EventClaims()))).Reason);
        Assert.Equal(SecurityEventRejection.UnknownKey, (await Validator().ValidateAsync(Mint("RS256", "not-published", EventClaims()))).Reason);
    }

    [Fact]
    public async Task Keys_that_cannot_be_fetched_are_their_own_refusal_rather_than_a_bad_token()
    {
        var keys = new StaticUpstreamKeys(Snapshot(), failure: new System.Net.Http.HttpRequestException("down"));

        var validation = await Validator(keys).ValidateAsync(Token());

        Assert.Equal(SecurityEventRejection.KeysUnavailable, validation.Reason);
    }
}
