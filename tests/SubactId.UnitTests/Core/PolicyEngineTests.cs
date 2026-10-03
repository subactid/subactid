using SubactId.Core.Agents;
using SubactId.Core.Policy;
using Xunit;

namespace SubactId.UnitTests.Core;

public class PolicyEngineTests
{
    private static readonly Agent JiraTriage = new(
        "jira-triage",
        "Jira triage agent",
        SponsorRequired: true,
        AllowedScopes: ["jira:read", "jira:comment", "confluence:read"],
        AllowedAudiences: ["https://jira.internal", "https://confluence.internal"],
        MaxTaskTtl: TimeSpan.FromMinutes(30),
        MaxTokenTtl: TimeSpan.FromMinutes(5),
        MaxDelegationDepth: 2,
        HighRiskAudiences: [],
        JwksUri: null,
        Jwks: null,
        Enabled: true,
        CreatedAt: DateTimeOffset.UnixEpoch,
        UpdatedAt: DateTimeOffset.UnixEpoch);

    private static readonly string[] UserScopes = ["jira:read", "jira:comment", "jira:admin", "confluence:read"];

    [Fact]
    public void The_spec_example_is_allowed_with_exactly_the_requested_scopes()
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:read", "jira:comment"], "https://jira.internal", depth: 1);

        Assert.True(decision.IsAllowed);
        Assert.Equal(PolicyDenialReason.None, decision.Reason);
        Assert.Equal(["jira:read", "jira:comment"], decision.EffectiveScopes);
    }

    [Fact]
    public void Effective_scope_is_the_intersection_of_user_agent_and_requested_scopes()
    {
        // jira:admin: user has it, agent may not. confluence:read: allowed, not requested. jira:write: requested, nobody has it.
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:admin", "jira:write", "jira:comment"], "https://jira.internal", depth: 1);

        Assert.True(decision.IsAllowed);
        Assert.Equal(["jira:comment"], decision.EffectiveScopes);
    }

    [Fact]
    public void A_scope_the_user_does_not_hold_is_never_granted_even_if_the_agent_and_request_name_it()
    {
        var decision = PolicyEngine.Evaluate(["confluence:read"], JiraTriage, ["jira:read", "confluence:read"], "https://confluence.internal", depth: 1);

        Assert.Equal(["confluence:read"], decision.EffectiveScopes);
    }

    [Fact]
    public void An_empty_intersection_is_invalid_scope_not_an_empty_token()
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:write"], "https://jira.internal", depth: 1);

        Assert.False(decision.IsAllowed);
        Assert.Equal(PolicyDenialReason.EmptyScopeIntersection, decision.Reason);
        Assert.Equal("invalid_scope", decision.Reason.ToErrorCode());
        Assert.Equal("scope_intersection_empty", decision.Reason.ToAuditReason());
        Assert.Empty(decision.EffectiveScopes);
    }

    [Fact]
    public void Requesting_no_scope_is_denied_rather_than_defaulted_to_everything()
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, [], "https://jira.internal", depth: 1);

        Assert.Equal(PolicyDenialReason.EmptyScopeIntersection, decision.Reason);
    }

    [Fact]
    public void A_user_with_no_scopes_gets_nothing()
    {
        var decision = PolicyEngine.Evaluate([], JiraTriage, ["jira:read"], "https://jira.internal", depth: 1);

        Assert.Equal(PolicyDenialReason.EmptyScopeIntersection, decision.Reason);
    }

    [Theory]
    [InlineData("JIRA:READ")]
    [InlineData("jira:read ")]
    [InlineData(" jira:read")]
    [InlineData("jira:rea")]
    [InlineData("jira:read*")]
    [InlineData("")]
    public void Scopes_match_exactly_and_case_sensitively(string requested)
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, [requested], "https://jira.internal", depth: 1);

        Assert.Equal(PolicyDenialReason.EmptyScopeIntersection, decision.Reason);
    }

    [Fact]
    public void Repeated_requested_scopes_appear_once_in_requested_order()
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:comment", "jira:read", "jira:comment"], "https://jira.internal", depth: 1);

        Assert.Equal(["jira:comment", "jira:read"], decision.EffectiveScopes);
    }

    [Theory]
    [InlineData("https://db.internal")]
    [InlineData("https://jira.internal/")]
    [InlineData("HTTPS://jira.internal")]
    [InlineData("http://jira.internal")]
    [InlineData("https://jira.internal.example.com")]
    public void An_audience_outside_allowed_audiences_is_invalid_target(string audience)
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:read"], audience, depth: 1);

        Assert.False(decision.IsAllowed);
        Assert.Equal(PolicyDenialReason.AudienceNotAllowed, decision.Reason);
        Assert.Equal("invalid_target", decision.Reason.ToErrorCode());
        Assert.Equal("audience_not_allowed", decision.Reason.ToAuditReason());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_missing_audience_is_invalid_target(string? audience)
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:read"], audience, depth: 1);

        Assert.Equal(PolicyDenialReason.AudienceMissing, decision.Reason);
        Assert.Equal("invalid_target", decision.Reason.ToErrorCode());
    }

    [Fact]
    public void Effective_scopes_cannot_be_grown_after_the_decision_is_made()
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:read"], "https://jira.internal", depth: 1);

        Assert.IsNotType<List<string>>(decision.EffectiveScopes);
        Assert.IsNotType<string[]>(decision.EffectiveScopes);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)decision.EffectiveScopes).Add("jira:admin"));
        Assert.Throws<NotSupportedException>(() => ((IList<string>)decision.EffectiveScopes)[0] = "jira:admin");
        Assert.Equal(["jira:read"], decision.EffectiveScopes);
    }

    [Fact]
    public void A_disabled_agent_is_access_denied_before_anything_else_is_looked_at()
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage with { Enabled = false }, ["jira:read"], "https://jira.internal", depth: 1);

        Assert.Equal(PolicyDenialReason.AgentDisabled, decision.Reason);
        Assert.Equal("access_denied", decision.Reason.ToErrorCode());
        Assert.Equal("agent_disabled", decision.Reason.ToAuditReason());
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(int.MaxValue, false)]
    public void Depth_may_not_exceed_the_agents_max_delegation_depth(int depth, bool allowed)
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:read"], "https://jira.internal", depth);

        Assert.Equal(allowed, decision.IsAllowed);
        if (!allowed)
        {
            Assert.Equal(PolicyDenialReason.DelegationDepthExceeded, decision.Reason);
            Assert.Equal("access_denied", decision.Reason.ToErrorCode());
            Assert.Equal("delegation_depth_exceeded", decision.Reason.ToAuditReason());
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void A_non_positive_depth_is_denied_not_treated_as_a_first_hop(int depth)
    {
        var decision = PolicyEngine.Evaluate(UserScopes, JiraTriage, ["jira:read"], "https://jira.internal", depth);

        Assert.Equal(PolicyDenialReason.InvalidDelegationDepth, decision.Reason);
        Assert.Equal("access_denied", decision.Reason.ToErrorCode());
    }

    [Fact]
    public void A_delegation_hop_narrows_against_the_parent_tokens_scopes_not_the_humans()
    {
        // The parent token was issued with jira:read only; the sub-agent cannot get jira:comment back even though the human holds it.
        var parentTokenScopes = new[] { "jira:read" };

        var decision = PolicyEngine.Evaluate(parentTokenScopes, JiraTriage, ["jira:read", "jira:comment"], "https://jira.internal", depth: 2);

        Assert.True(decision.IsAllowed);
        Assert.Equal(["jira:read"], decision.EffectiveScopes);
    }

    [Fact]
    public void Denials_are_reported_in_a_fixed_order_so_audit_reasons_are_stable()
    {
        // Everything is wrong at once: disabled wins, then depth, then audience, then scope.
        var disabled = JiraTriage with { Enabled = false };
        Assert.Equal(PolicyDenialReason.AgentDisabled, PolicyEngine.Evaluate([], disabled, [], "https://nowhere", depth: 9).Reason);
        Assert.Equal(PolicyDenialReason.DelegationDepthExceeded, PolicyEngine.Evaluate([], JiraTriage, [], "https://nowhere", depth: 9).Reason);
        Assert.Equal(PolicyDenialReason.AudienceNotAllowed, PolicyEngine.Evaluate([], JiraTriage, [], "https://nowhere", depth: 1).Reason);
        Assert.Equal(PolicyDenialReason.EmptyScopeIntersection, PolicyEngine.Evaluate([], JiraTriage, [], "https://jira.internal", depth: 1).Reason);
    }

    [Fact]
    public void Every_denial_reason_maps_to_a_spec_error_code_and_an_audit_reason()
    {
        var spec = new[] { "invalid_grant", "invalid_scope", "invalid_target", "access_denied" };

        foreach (var reason in Enum.GetValues<PolicyDenialReason>().Where(r => r != PolicyDenialReason.None))
        {
            Assert.Contains(reason.ToErrorCode(), spec);
            Assert.Matches("^[a-z_]+$", reason.ToAuditReason());
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => PolicyDenialReason.None.ToErrorCode());
        Assert.Throws<ArgumentOutOfRangeException>(() => PolicyDenialReason.None.ToAuditReason());
    }

    [Fact]
    public void Null_inputs_are_a_programming_error_not_a_denial()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyEngine.Evaluate(null!, JiraTriage, [], "https://jira.internal", 1));
        Assert.Throws<ArgumentNullException>(() => PolicyEngine.Evaluate([], null!, [], "https://jira.internal", 1));
        Assert.Throws<ArgumentNullException>(() => PolicyEngine.Evaluate([], JiraTriage, null!, "https://jira.internal", 1));
    }

    /// <summary>
    /// Property: for random inputs the effective scope set is a subset of every input set, has no
    /// duplicates, is exactly their intersection, and a request never yields more than it asked for.
    /// A failing case prints the seed so it can be replayed.
    /// </summary>
    [Fact]
    public void Effective_scopes_are_always_a_subset_of_user_agent_and_requested_scopes()
    {
        const int Cases = 5_000;
        var seed = Environment.TickCount;
        var random = new Random(seed);
        string[] universe = ["a", "b", "c", "d", "e", "A", "a ", "", "a:b", "b:a"];
        string[] audiences = ["https://jira.internal", "https://confluence.internal", "https://db.internal", "", " "];

        for (var i = 0; i < Cases; i++)
        {
            var userScopes = Pick(random, universe);
            var agentScopes = Pick(random, universe);
            var requested = Pick(random, universe);
            var audience = audiences[random.Next(audiences.Length)];
            var depth = random.Next(-1, 5);
            var agent = JiraTriage with { AllowedScopes = agentScopes, MaxDelegationDepth = random.Next(1, 4), Enabled = random.Next(4) != 0 };

            var decision = PolicyEngine.Evaluate(userScopes, agent, requested, audience, depth);
            var context = $"seed {seed}, case {i}";

            var expected = requested.Where(s => s.Length > 0 && userScopes.Contains(s, StringComparer.Ordinal) && agentScopes.Contains(s, StringComparer.Ordinal)).Distinct(StringComparer.Ordinal).ToList();
            Assert.True(decision.EffectiveScopes.All(userScopes.Contains), context);
            Assert.True(decision.EffectiveScopes.All(agentScopes.Contains), context);
            Assert.True(decision.EffectiveScopes.All(requested.Contains), context);
            Assert.True(decision.EffectiveScopes.Distinct(StringComparer.Ordinal).Count() == decision.EffectiveScopes.Count, context);
            Assert.True(decision.IsAllowed == (decision.EffectiveScopes.Count > 0), context);

            var shouldAllow = agent.Enabled && depth >= 1 && depth <= agent.MaxDelegationDepth && agent.AllowedAudiences.Contains(audience) && expected.Count > 0;
            Assert.True(decision.IsAllowed == shouldAllow, context);
            if (shouldAllow)
            {
                Assert.True(expected.SequenceEqual(decision.EffectiveScopes, StringComparer.Ordinal), context);
            }
        }
    }

    private static string[] Pick(Random random, string[] universe)
    {
        var count = random.Next(0, universe.Length + 2);
        var picked = new string[count];
        for (var i = 0; i < count; i++)
        {
            picked[i] = universe[random.Next(universe.Length)];
        }

        return picked;
    }
}
