using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Tokens.ClientAuth;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.ClientAuth.ClientAuthTestData;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.ClientAuth;

public class ClientAssertionAuthenticatorTests
{
    private static readonly string AgentJwks = Jwks(RsaJwk(Rsa1, "rsa1"), EcJwk(Ec1, "ec1"));

    private sealed class Harness
    {
        public InMemoryAgentRepository Agents { get; init; } = new(Agent());
        public StaticAgentKeys Keys { get; init; } = new(Snapshot(AgentJwks));
        public InMemoryReplayStore Replays { get; init; } = new();
        public FakeTimeProvider Clock { get; init; } = new(Now);

        public ClientAssertionAuthenticator Build() => new(Agents, Keys, Replays, new Uri(SubactIdIssuer), Clock);
    }

    [Theory]
    [InlineData("RS256", "rsa1")]
    [InlineData("ES256", "ec1")]
    public async Task Accepts_a_valid_assertion_and_records_its_jti(string alg, string kid)
    {
        var harness = new Harness();
        var claims = Assertion();

        var result = await harness.Build().AuthenticateAsync(Mint(alg, kid, claims));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Equal("jira-triage", result.Agent!.AgentId);
        var recorded = Assert.Single(harness.Replays.Recorded);
        Assert.Equal(("jira-triage", (string)claims["jti"]!), recorded.Key);
        Assert.Equal(Now.AddMinutes(2) + ClientAssertionAuthenticator.ClockSkew, recorded.Value);
    }

    /// <summary>
    /// The instance is the agent's own claim about which copy of it is running. It is carried so the
    /// ledger can tell pods apart, length-bounded, and never checked: it does not affect authorization.
    /// </summary>
    [Fact]
    public async Task An_agent_may_say_which_instance_of_it_is_acting()
    {
        var harness = new Harness();

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("instance", "pod-7f4c9"))));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Equal("pod-7f4c9", result.Instance);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task A_blank_instance_is_the_same_as_none(string instance)
    {
        var harness = new Harness();

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("instance", instance))));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Null(result.Instance);
    }

    [Fact]
    public async Task An_assertion_without_an_instance_carries_none()
    {
        var harness = new Harness();

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion()));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Null(result.Instance);
    }

    [Theory]
    [InlineData("pod-1\n2026-10-01 INFO forged line")]
    [InlineData("pod-1\r")]
    [InlineData("pod\u00001")]
    [InlineData("pod-1\u001b[31m")]
    public async Task An_instance_with_a_control_character_is_rejected(string instance)
    {
        // It is signed into every token, and tool servers log act: a newline would forge a line.
        var harness = new Harness();

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("instance", instance))));

        Assert.False(result.IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.Malformed, result.Reason);
    }

    [Fact]
    public async Task An_over_long_instance_is_rejected()
    {
        var harness = new Harness();
        var tooLong = new string('p', ClientAssertionAuthenticator.MaxInstanceLength + 1);

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("instance", tooLong))));

        Assert.False(result.IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.Malformed, result.Reason);
        Assert.Empty(harness.Replays.Recorded);
    }

    [Fact]
    public async Task An_instance_at_the_limit_is_accepted()
    {
        var harness = new Harness();
        var atLimit = new string('p', ClientAssertionAuthenticator.MaxInstanceLength);

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("instance", atLimit))));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Equal(atLimit, result.Instance);
    }

    [Fact]
    public async Task A_replayed_assertion_is_rejected()
    {
        var harness = new Harness();
        var assertion = Mint("RS256", "rsa1", Assertion());
        var authenticator = harness.Build();

        Assert.True((await authenticator.AuthenticateAsync(assertion)).IsAuthenticated);
        var replay = await authenticator.AuthenticateAsync(assertion);

        Assert.False(replay.IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.Replayed, replay.Reason);
        Assert.Single(harness.Replays.Recorded);
    }

    [Fact]
    public async Task A_valid_assertion_signed_with_another_agents_key_is_rejected()
    {
        // The other agent uses the same kid label but a different key; only jira-triage's JWKS is consulted.
        var harness = new Harness();

        var sameKid = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(), rsa: Rsa2));
        Assert.Equal(ClientAssertionRejection.InvalidSignature, sameKid.Reason);

        var otherKid = await harness.Build().AuthenticateAsync(Mint("RS256", "other-agent-key", Assertion(), rsa: Rsa2));
        Assert.Equal(ClientAssertionRejection.UnknownKey, otherKid.Reason);
        Assert.Empty(harness.Replays.Recorded);
    }

    [Fact]
    public async Task An_assertion_for_another_agent_id_is_checked_against_that_agents_keys_only()
    {
        var harness = new Harness { Agents = new InMemoryAgentRepository(Agent("jira-triage"), Agent("db-reader")) };

        await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion("db-reader")));

        Assert.Equal(["db-reader"], harness.Keys.AgentsAsked);
    }

    [Fact]
    public async Task An_unknown_kid_triggers_one_refresh_and_a_rotated_key_is_accepted()
    {
        var rotated = Snapshot(Jwks(RsaJwk(Rsa2, "rsa2")));
        var harness = new Harness { Keys = new StaticAgentKeys(Snapshot(AgentJwks), afterRefresh: rotated) };

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa2", Assertion(), rsa: Rsa2));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Equal(1, harness.Keys.Refreshes);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("RS512")]
    public async Task Disallowed_algorithms_are_rejected_before_any_lookup(string alg)
    {
        var harness = new Harness();

        var result = await harness.Build().AuthenticateAsync(Mint(alg, "rsa1", Assertion()));

        Assert.Equal(ClientAssertionRejection.UnsupportedAlgorithm, result.Reason);
        Assert.Equal(0, harness.Keys.Gets);
    }

    [Fact]
    public async Task The_algorithm_must_fit_the_named_key()
    {
        Assert.Equal(ClientAssertionRejection.KeyMismatch, (await new Harness().Build().AuthenticateAsync(Mint("ES256", "rsa1", Assertion()))).Reason);
        Assert.Equal(ClientAssertionRejection.KeyMismatch, (await new Harness().Build().AuthenticateAsync(Mint("RS256", "ec1", Assertion()))).Reason);
    }

    [Fact]
    public async Task Issuer_and_subject_must_agree_and_match_client_id_when_given()
    {
        var authenticator = new Harness().Build();

        Assert.Equal(ClientAssertionRejection.IssuerSubjectMismatch, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("sub", "someone-else"))))).Reason);
        Assert.Equal(ClientAssertionRejection.ClientIdMismatch, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion()), clientId: "db-reader")).Reason);
        Assert.True((await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion()), clientId: "jira-triage")).IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("-iss", null))))).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("sub", 7))))).Reason);
    }

    [Fact]
    public async Task Unknown_and_keyless_agents_are_rejected_without_touching_keys()
    {
        var harness = new Harness { Agents = new InMemoryAgentRepository(Agent("keyless", noJwks: true)) };
        var authenticator = harness.Build();

        Assert.Equal(ClientAssertionRejection.UnknownAgent, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion("nobody")))).Reason);
        Assert.Equal(ClientAssertionRejection.NoRegisteredKeys, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion("keyless")))).Reason);
        Assert.Equal(0, harness.Keys.Gets);
    }

    /// <summary>
    /// A registration may carry its keys inline instead of a URL (spec section 2), as <c>agent init</c>
    /// writes. Such an agent has no <c>jwks_uri</c> and must still authenticate.
    /// </summary>
    [Fact]
    public async Task An_agent_whose_registration_carries_its_keys_inline_can_authenticate()
    {
        var harness = new Harness { Agents = new InMemoryAgentRepository(AgentWithInlineKeys("inline")) };

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion("inline")));

        Assert.True(result.IsAuthenticated, result.Reason.ToString());
        Assert.Equal("inline", result.Agent!.AgentId);
    }

    [Fact]
    public async Task An_agent_with_neither_a_jwks_uri_nor_inline_keys_is_rejected()
    {
        var harness = new Harness { Agents = new InMemoryAgentRepository(Agent("keyless", noJwks: true)) };

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion("keyless")));

        Assert.Equal(ClientAssertionRejection.NoRegisteredKeys, result.Reason);
        Assert.Equal(0, harness.Keys.Gets);
    }

    private static Agent AgentWithInlineKeys(string id)
    {
        var keyless = Agent(id, noJwks: true);
        return keyless with { Jwks = new AgentJwks([new AgentJwk { Kid = "rsa1", Kty = "RSA" }]) };
    }

    [Fact]
    public async Task A_disabled_agent_is_reported_only_for_an_assertion_that_verified()
    {
        // Before the signature is checked a disabled agent must look like any other bad credential, or ids could be enumerated.
        var harness = new Harness { Agents = new InMemoryAgentRepository(Agent("disabled", enabled: false)) };
        var authenticator = harness.Build();

        Assert.Equal(ClientAssertionRejection.InvalidSignature, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion("disabled"), rsa: Rsa2))).Reason);
        Assert.Equal(ClientAssertionRejection.UnknownKey, (await authenticator.AuthenticateAsync(Mint("RS256", "nope", Assertion("disabled")))).Reason);
        Assert.Equal(ClientAssertionRejection.AgentDisabled, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion("disabled")))).Reason);
        Assert.Empty(harness.Replays.Recorded);
    }

    [Fact]
    public async Task A_disabled_agent_is_accepted_to_revoke_with_every_other_check_still_applied()
    {
        var harness = new Harness { Agents = new InMemoryAgentRepository(Agent("disabled", enabled: false)) };
        var authenticator = harness.Build();
        var assertion = Mint("RS256", "rsa1", Assertion("disabled"));

        var accepted = await authenticator.AuthenticateToRevokeAsync(assertion);

        Assert.Equal("disabled", accepted.Agent!.AgentId);
        Assert.Equal(ClientAssertionRejection.Replayed, (await authenticator.AuthenticateToRevokeAsync(assertion)).Reason);
        Assert.Equal(ClientAssertionRejection.InvalidSignature, (await authenticator.AuthenticateToRevokeAsync(Mint("RS256", "rsa1", Assertion("disabled"), rsa: Rsa2))).Reason);
        Assert.Equal(ClientAssertionRejection.AgentDisabled, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion("disabled")))).Reason);
    }

    [Fact]
    public async Task Keys_unavailable_is_reported_when_the_agents_jwks_cannot_be_fetched()
    {
        var harness = new Harness { Keys = new StaticAgentKeys(Snapshot(AgentJwks), failure: new HttpRequestException("down")) };

        Assert.Equal(ClientAssertionRejection.KeysUnavailable, (await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion()))).Reason);
    }

    [Fact]
    public async Task A_jwks_url_the_egress_guard_refuses_is_reported_as_refused_not_unavailable()
    {
        // The connection layer throws the refusal; the fetch fails with it wrapped, as SocketsHttpHandler wraps it.
        var refused = new HttpRequestException("'agent.internal' refused (agent.internal:443)", new DestinationRefusedException("'agent.internal' refused"));
        var harness = new Harness { Keys = new StaticAgentKeys(Snapshot(AgentJwks), failure: refused) };

        var result = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion()));

        Assert.Equal(ClientAssertionRejection.KeysRefused, result.Reason);
        Assert.Null(result.AttributedAgentId);
    }

    [Fact]
    public async Task Audience_must_be_this_control_plane_as_issuer_or_token_endpoint()
    {
        var authenticator = new Harness().Build();

        Assert.True((await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("aud", SubactIdIssuer))))).IsAuthenticated);
        Assert.True((await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("aud", new[] { "https://other", TokenEndpoint }))))).IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.WrongAudience, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("aud", "https://jira.internal"))))).Reason);
        Assert.Equal(ClientAssertionRejection.WrongAudience, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("aud", SubactIdIssuer + "/"))))).Reason);
        Assert.Equal(ClientAssertionRejection.WrongAudience, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("-aud", null))))).Reason);
        Assert.Equal(ClientAssertionRejection.WrongAudience, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("aud", 5))))).Reason);
    }

    [Fact]
    public async Task Expiry_lifetime_and_not_before_are_enforced_with_skew()
    {
        var harness = new Harness();
        var authenticator = harness.Build();
        long At(TimeSpan offset) => (Now + offset).ToUnixTimeSeconds();

        Assert.Equal(ClientAssertionRejection.MissingExpiry, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("-exp", null))))).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("exp", "soon"))))).Reason);
        Assert.True((await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("exp", At(TimeSpan.FromSeconds(-59))))))).IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.Expired, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("exp", At(TimeSpan.FromSeconds(-60))))))).Reason);
        Assert.True((await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("exp", At(TimeSpan.FromMinutes(6))))))).IsAuthenticated);
        Assert.Equal(ClientAssertionRejection.LifetimeTooLong, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("exp", At(TimeSpan.FromMinutes(6) + TimeSpan.FromSeconds(1))))))).Reason);
        Assert.Equal(ClientAssertionRejection.NotYetValid, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("nbf", At(TimeSpan.FromSeconds(61))))))).Reason);
        Assert.Equal(ClientAssertionRejection.NotYetValid, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("iat", At(TimeSpan.FromSeconds(61))))))).Reason);
        Assert.True((await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("nbf", At(TimeSpan.FromSeconds(59))))))).IsAuthenticated);
    }

    [Fact]
    public async Task An_issuer_with_a_control_character_is_malformed_before_any_agent_is_looked_up()
    {
        var harness = new Harness();

        var outcome = await harness.Build().AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: [("iss", "jira\u0000triage"), ("sub", "jira\u0000triage")])));

        Assert.Equal(ClientAssertionRejection.Malformed, outcome.Reason);
        Assert.Empty(harness.Replays.Recorded);
    }

    [Fact]
    public async Task Jti_is_required_bounded_and_only_consumed_by_accepted_assertions()
    {
        var harness = new Harness();
        var authenticator = harness.Build();

        Assert.Equal(ClientAssertionRejection.MissingJti, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("-jti", null))))).Reason);
        Assert.Equal(ClientAssertionRejection.MissingJti, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("jti", ""))))).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("jti", new string('j', 257)))))).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("jti", "j\u0000ti"))))).Reason);

        var rejected = Assertion(overrides: ("aud", "https://wrong"));
        Assert.Equal(ClientAssertionRejection.WrongAudience, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", rejected))).Reason);
        Assert.Empty(harness.Replays.Recorded);
    }

    [Fact]
    public async Task Structural_problems_are_malformed()
    {
        var authenticator = new Harness().Build();

        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(null)).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync("a.b")).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(), headerJson: "{\"alg\":\"RS256\"}"))).Reason);
        Assert.Equal(ClientAssertionRejection.Malformed, (await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(), headerJson: "{\"alg\":\"RS256\",\"kid\":\"rsa1\",\"crit\":[\"b64\"]}"))).Reason);
    }

    [Fact]
    public async Task Signature_is_checked_before_claims()
    {
        var forgedAndExpired = Mint("RS256", "rsa1", Assertion(overrides: ("exp", 1L)), rsa: Rsa2);

        Assert.Equal(ClientAssertionRejection.InvalidSignature, (await new Harness().Build().AuthenticateAsync(forgedAndExpired)).Reason);
    }

    [Fact]
    public async Task Expired_replay_records_are_purged_at_most_once_per_minute()
    {
        var harness = new Harness();
        var authenticator = harness.Build();

        await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion()));
        await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion()));
        Assert.Equal(1, harness.Replays.Purges);

        harness.Clock.Advance(TimeSpan.FromSeconds(61));
        await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion(overrides: ("exp", harness.Clock.GetUtcNow().AddMinutes(2).ToUnixTimeSeconds()))));
        Assert.Equal(2, harness.Replays.Purges);
    }

    [Fact]
    public async Task Authenticators_sharing_a_purge_gate_purge_once_per_interval_between_them()
    {
        // The server builds one authenticator per request; the throttle must live outside them.
        var harness = new Harness();
        var gate = new ReplayPurgeGate();

        for (var request = 0; request < 3; request++)
        {
            var perRequest = new ClientAssertionAuthenticator(harness.Agents, harness.Keys, harness.Replays, new Uri(SubactIdIssuer), harness.Clock, gate);
            Assert.True((await perRequest.AuthenticateAsync(Mint("RS256", "rsa1", Assertion()))).IsAuthenticated);
        }

        Assert.Equal(1, harness.Replays.Purges);
    }

    [Fact]
    public async Task A_registration_whose_jwks_url_is_not_https_is_treated_as_having_no_keys()
    {
        // Only reachable through storage, never through the validator; it must still be a clean rejection.
        var agent = Agent(jwks: new Uri("http://jira-triage.example/jwks.json"));
        var server = new FakeJsonServer { ["http://jira-triage.example/jwks.json"] = AgentJwks };
        using var keys = new AgentKeyCache(server.CreateClient, new FakeTimeProvider(Now));
        var authenticator = new ClientAssertionAuthenticator(new InMemoryAgentRepository(agent), keys, new InMemoryReplayStore(), new Uri(SubactIdIssuer), new FakeTimeProvider(Now));

        var result = await authenticator.AuthenticateAsync(Mint("RS256", "rsa1", Assertion()));

        Assert.Equal(ClientAssertionRejection.NoRegisteredKeys, result.Reason);
        Assert.Empty(server.Requests);
    }

    [Fact]
    public void Accepted_audiences_are_the_issuer_and_its_token_endpoint_without_a_trailing_slash()
    {
        var authenticator = new ClientAssertionAuthenticator(new InMemoryAgentRepository(), new StaticAgentKeys(Snapshot(AgentJwks)), new InMemoryReplayStore(), new Uri(SubactIdIssuer + "/"), new FakeTimeProvider(Now));

        Assert.Equal([SubactIdIssuer, TokenEndpoint], authenticator.AcceptedAudiences);
    }
}
