using SubactId.Core.Agents;
using SubactId.Core.Delegation;
using SubactId.Core.Tokens;
using Xunit;

namespace SubactId.UnitTests.Core;

public class TaskTokenClaimsTests
{
    private static readonly Uri Issuer = new("https://subactid.internal.example.com");
    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);
    private const string Sponsor = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static Agent Agent(string id = "jira-triage", int maxTokenMinutes = 5, int maxDepth = 2, bool enabled = true) => new(
        id, "Agent " + id, true, ["jira:read", "jira:comment", "confluence:read"], ["https://jira.internal"],
        TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(maxTokenMinutes), maxDepth, [], null, null, enabled, Now.AddDays(-1), Now.AddDays(-1));

    private static DelegationTask Task(string agentId = "jira-triage", string sponsor = Sponsor, int depth = 1, DelegationTaskStatus status = DelegationTaskStatus.Active, DateTimeOffset? expiresAt = null, string? parent = null) => new(
        "task_01HQZX9K4M", agentId, sponsor, sponsor, null, parent, depth, "https://jira.internal", ["jira:read", "jira:comment"], status, Now.AddMinutes(-5), expiresAt ?? Now.AddMinutes(25), null, null);

    private static TaskTokenClaims Issue(DelegationTask? task = null, Agent? agent = null, IReadOnlyList<string>? scopes = null, string? instance = "pod-7f9c4b", ActorClaim? from = null, TimeSpan? requested = null, DateTimeOffset? now = null) =>
        TaskTokenClaims.Issue(Issuer, task ?? Task(), agent ?? Agent(), scopes ?? ["jira:read", "jira:comment"], instance, from, requested ?? TimeSpan.FromMinutes(5), now ?? Now, "tok_01HQZX9K5P");

    [Fact]
    public void The_spec_example_claims_are_built_with_the_human_as_sub_and_the_agent_in_act()
    {
        var claims = Issue();

        Assert.Equal(Sponsor, claims.Subject);
        Assert.Equal("https://jira.internal", claims.Audience);
        Assert.Equal(Now, claims.IssuedAt);
        Assert.Equal(Now.AddMinutes(5), claims.ExpiresAt);
        Assert.Equal("tok_01HQZX9K5P", claims.Jti);
        Assert.Equal(["jira:read", "jira:comment"], claims.Scopes);
        Assert.Equal("agent:jira-triage", claims.ClientId);
        Assert.Equal(new ActorClaim("agent:jira-triage", "pod-7f9c4b", 1, null), claims.Actor);
        Assert.Equal(new TaskClaim("task_01HQZX9K4M", Now.AddMinutes(25), Sponsor), claims.Task);
    }

    /// <summary>
    /// The registration says which audiences need per-call introspection, and this claim carries
    /// that to the tool server.
    /// </summary>
    [Fact]
    public void Introspect_required_follows_the_agents_high_risk_audiences()
    {
        Assert.False(Issue().IntrospectRequired);

        var risky = Agent() with { HighRiskAudiences = ["https://jira.internal"] };
        Assert.True(Issue(agent: risky).IntrospectRequired);

        var elsewhere = Agent() with { HighRiskAudiences = ["https://db.internal"] };
        Assert.False(Issue(agent: elsewhere).IntrospectRequired);
    }

    [Theory]
    [InlineData(5, 5, 25, 5)]
    [InlineData(10, 5, 25, 5)]
    [InlineData(2, 5, 25, 2)]
    [InlineData(10, 10, 3, 3)]
    [InlineData(1, 5, 0.5, 0.5)]
    public void Lifetime_is_the_smallest_of_requested_agent_max_and_remaining_task_time(double requestedMinutes, int agentMaxMinutes, double remainingMinutes, double expectedMinutes)
    {
        var claims = Issue(Task(expiresAt: Now.AddMinutes(remainingMinutes)), Agent(maxTokenMinutes: agentMaxMinutes), requested: TimeSpan.FromMinutes(requestedMinutes));

        Assert.Equal(Now.AddMinutes(expectedMinutes), claims.ExpiresAt);
    }

    [Fact]
    public void Lifetime_never_exceeds_remaining_task_time_for_any_input()
    {
        var seed = Environment.TickCount;
        var random = new Random(seed);

        for (var i = 0; i < 5_000; i++)
        {
            var now = Now.AddSeconds(random.Next(0, 3600));
            var task = Task(expiresAt: Now.AddSeconds(random.Next(1, 7200)));
            var agent = Agent(maxTokenMinutes: random.Next(1, 30));
            var requested = TimeSpan.FromSeconds(random.Next(1, 3600));

            if (task.ExpiresAt <= now)
            {
                Assert.Throws<InvalidOperationException>(() => Issue(task, agent, requested: requested, now: now));
                continue;
            }

            var claims = Issue(task, agent, requested: requested, now: now);
            var context = $"seed {seed}, case {i}";
            Assert.True(claims.ExpiresAt <= task.ExpiresAt, context);
            Assert.True(claims.ExpiresAt <= now + agent.MaxTokenTtl, context);
            Assert.True(claims.ExpiresAt <= now + requested, context);
            Assert.True(claims.ExpiresAt > now, context);
            Assert.True(claims.Task.ExpiresAt == task.ExpiresAt, context);
        }
    }

    [Fact]
    public void Sub_is_never_the_agent_under_any_input()
    {
        var seed = Environment.TickCount;
        var random = new Random(seed);
        string[] sponsors = [Sponsor, "alice", "jira-triage", "agent:jira-triage", "AGENT:jira-triage", "Agent:x", "agent:", "", "agent-jira-triage"];
        string[] agents = ["jira-triage", "alice", "db-reader", "agent"];

        for (var i = 0; i < 2_000; i++)
        {
            var sponsor = sponsors[random.Next(sponsors.Length)];
            var agentId = agents[random.Next(agents.Length)];
            var task = Task(agentId, sponsor);
            var agent = Agent(agentId);
            var context = $"seed {seed}, case {i}: sponsor '{sponsor}', agent '{agentId}'";

            if (sponsor.Length == 0 || sponsor.StartsWith("agent:", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Throws<ArgumentException>(() => Issue(task, agent));
                continue;
            }

            var claims = Issue(task, agent);
            Assert.True(claims.Subject == sponsor, context);
            Assert.True(claims.Task.Sponsor == sponsor, context);
            Assert.False(ActorClaim.IsAgentSubject(claims.Subject), context);
            Assert.True(claims.Actor.Subject == "agent:" + agentId, context);
            Assert.True(claims.ClientId == claims.Actor.Subject, context);
            Assert.True(claims.Subject != claims.Actor.Subject, context);
        }
    }

    [Fact]
    public void A_delegation_hop_nests_the_previous_actor_inside_the_new_one_with_depth_increasing_outward()
    {
        var first = Issue().Actor;
        var second = Issue(Task("db-reader", depth: 2, parent: "task_parent"), Agent("db-reader"), instance: "pod-3a1f88", from: first).Actor;
        var third = Issue(Task("summarizer", depth: 3, parent: "task_parent2"), Agent("summarizer", maxDepth: 3), instance: null, from: second).Actor;

        // RFC 8693 section 4.1: the current actor is outermost; the one it was delegated from nests inside.
        Assert.Equal("agent:summarizer", third.Subject);
        Assert.Equal(3, third.Depth);
        Assert.Null(third.Instance);
        Assert.Equal("agent:db-reader", third.Actor!.Subject);
        Assert.Equal(2, third.Actor.Depth);
        Assert.Equal("pod-3a1f88", third.Actor.Instance);
        Assert.Equal("agent:jira-triage", third.Actor.Actor!.Subject);
        Assert.Equal(1, third.Actor.Actor.Depth);
        Assert.Null(third.Actor.Actor.Actor);
        Assert.Equal(second, third.Actor);
    }

    [Fact]
    public void The_chain_depth_must_match_the_task_record()
    {
        var first = Issue().Actor;

        Assert.Throws<ArgumentException>(() => Issue(Task("db-reader", depth: 1), Agent("db-reader"), from: first));
        Assert.Throws<ArgumentException>(() => Issue(Task("db-reader", depth: 2), Agent("db-reader"), from: null));
    }

    [Fact]
    public void Scopes_must_be_non_empty_and_within_the_tasks_scopes()
    {
        Assert.Throws<ArgumentException>(() => Issue(scopes: []));
        Assert.Throws<ArgumentException>(() => Issue(scopes: ["jira:read", "confluence:read"]));
        Assert.Throws<ArgumentException>(() => Issue(scopes: [""]));
        Assert.Equal(["jira:read"], Issue(scopes: ["jira:read", "jira:read"]).Scopes);
    }

    [Theory]
    [InlineData(DelegationTaskStatus.Revoked)]
    [InlineData(DelegationTaskStatus.Expired)]
    public void No_token_is_issued_under_a_task_that_is_not_active(DelegationTaskStatus status)
    {
        Assert.Throws<InvalidOperationException>(() => Issue(Task(status: status)));
    }

    [Fact]
    public void No_token_is_issued_once_the_task_has_run_out()
    {
        Assert.Throws<InvalidOperationException>(() => Issue(Task(expiresAt: Now)));
        Assert.Throws<InvalidOperationException>(() => Issue(Task(expiresAt: Now.AddSeconds(-1))));
    }

    [Fact]
    public void No_token_is_issued_to_a_disabled_agent_even_when_the_task_is_live()
    {
        Assert.Throws<InvalidOperationException>(() => Issue(agent: Agent(enabled: false)));
    }

    [Fact]
    public void The_chain_may_not_be_deeper_than_the_agents_max_delegation_depth()
    {
        var first = Issue().Actor;

        Assert.Throws<ArgumentException>(() => Issue(Task("db-reader", depth: 2), Agent("db-reader", maxDepth: 1), from: first));
    }

    [Fact]
    public void An_agent_without_a_positive_max_token_ttl_cannot_be_issued_a_token()
    {
        Assert.Throws<ArgumentException>(() => Issue(agent: Agent(maxTokenMinutes: 0)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void A_blank_instance_is_recorded_as_none(string? instance)
    {
        Assert.Null(Issue(instance: instance).Actor.Instance);
    }

    [Fact]
    public void The_agent_must_be_the_tasks_agent()
    {
        Assert.Throws<ArgumentException>(() => Issue(Task("jira-triage"), Agent("db-reader")));
    }

    [Fact]
    public void A_non_positive_requested_lifetime_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Issue(requested: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => Issue(requested: TimeSpan.FromSeconds(-1)));
    }

    [Theory]
    [InlineData("agent:jira-triage", true)]
    [InlineData("AGENT:jira-triage", true)]
    [InlineData("agent:", true)]
    [InlineData("agent", false)]
    [InlineData("agent-jira", false)]
    [InlineData("f47ac10b-58cc-4372-a567-0e02b2c3d479", false)]
    public void An_agent_subject_is_recognised_by_its_prefix_in_any_case(string subject, bool isAgent)
    {
        Assert.Equal(isAgent, ActorClaim.IsAgentSubject(subject));
    }
}
