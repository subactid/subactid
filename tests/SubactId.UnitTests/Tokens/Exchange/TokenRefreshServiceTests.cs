using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Grants;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Tokens.ClientAuth;
using Xunit;
using static SubactId.UnitTests.NoAggregationHelper;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Exchange;

public class TokenRefreshServiceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    /// <summary>A task and grant as the exchange would have left them, with the real authenticator, redeemer, policy engine and signer over in-memory storage.</summary>
    private sealed class Harness
    {
        public Agent Agent { get; init; } = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:read", "jira:comment", "confluence:read"] };
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryReplayStore Replays { get; } = new();
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public SigningKeySet Keys { get; } = SigningKeySet.CreateEphemeral();
        public string GrantValue { get; } = TaskGrantSecret.New();
        public DelegationTask Task { get; init; } = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddMinutes(-10), Now.AddMinutes(20), null, null);
        public IReadOnlyList<string> GrantScopes { get; init; } = ["jira:read", "jira:comment"];
        public FixedSponsorStatus Sponsors { get; init; } = new(SponsorStatus.Active);

        /// <summary>What the gate asks the provider through, when not <see cref="Sponsors"/> directly.</summary>
        public ISponsorStatusSource? Upstream { get; init; }
        public InMemorySponsorBlocks Blocks { get; init; } = new();
        public AgentRegistrationLimits Limits { get; init; } = AgentRegistrationLimits.Default;

        /// <summary>Whether renewals after the first are summarised, as <c>SubactId:Audit:Aggregation:Enabled</c> says.</summary>
        public bool Summarise { get; init; } = true;

        /// <summary>The registry the service reads the agent from, so a test can change it between refreshes.</summary>
        public InMemoryAgentRepository Agents { get; private set; } = null!;

        public TokenRefreshService Build()
        {
            Agents = new InMemoryAgentRepository(Agent);
            Tasks.Stored.Add(Task);
            Grants.Stored.Add(new TaskGrant(TaskGrantSecret.Hash(GrantValue), Task.TaskId, Task.AgentId, GrantScopes, Task.CreatedAt, Task.ExpiresAt, null, null));
            var options = new SubactIdOptions
            {
                Issuer = new Uri(ClientAuthTestData.SubactIdIssuer),
                UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri(Issuer + "/.well-known/openid-configuration"), Audience = Audience, SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
                Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = "unused" },
                Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromHours(1), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
                Agents = Limits,
                Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 100 },
                Signing = new SigningOptions { Keys = [] },
                Admin = new AdminOptions(),
                Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval, Aggregation = new DenialAggregationOptions { Enabled = Summarise } },
            };
            var actors = new ClientAssertionAuthenticator(Agents, new StaticAgentKeys(ClientAuthTestData.Snapshot(Jwks(RsaJwk(Rsa2, "agent-key")))), Replays, options.Issuer, Clock);
            return new TokenRefreshService(actors, new TaskGrantRedeemer(Grants, Tasks), new SponsorGate(Blocks, Upstream ?? Sponsors), Grants, Audit, new PassThroughUnitOfWork(), new TokenAudit(Audit, Clock, NoAggregation(Clock)), new RenewalSummary(options.Audit.Aggregation), Keys, options, Clock);
        }
    }

    private static string Assertion(string agentId = "jira-triage") => Mint("RS256", "agent-key", ClientAuthTestData.Assertion(agentId), rsa: Rsa2);

    private static RefreshTokenRequest Request(string? grant, string scope = "jira:read", string resource = "https://jira.internal", string? assertion = null) =>
        new(RefreshTokenRequest.RefreshTokenGrantType, grant, resource, scope, assertion ?? Assertion(), RefreshTokenRequest.JwtBearerAssertionType, null);

    private static Task<TokenOutcome> Refresh(Harness harness, string scope = "jira:read", string resource = "https://jira.internal", string? grant = null) =>
        harness.Build().RefreshAsync(Request(grant ?? harness.GrantValue, scope, resource), []);

    [Fact]
    public async Task A_token_bound_lowered_since_registration_holds_the_refreshed_token()
    {
        var harness = new Harness
        {
            Agent = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:read", "jira:comment"], MaxTokenTtl = TimeSpan.FromMinutes(10) },
            Limits = AgentRegistrationLimits.Default with { MaxTokenTtl = TimeSpan.FromMinutes(2) },
        };

        var outcome = await Refresh(harness);

        Assert.Equal(120, outcome.Response!.ExpiresIn);
    }

    [Fact]
    public async Task A_refresh_issues_a_fresh_token_under_the_same_task_with_a_new_jti_and_its_own_audit_record()
    {
        var harness = new Harness();

        var outcome = await Refresh(harness);

        var response = outcome.Response!;
        Assert.Equal("task_1", response.TaskId);
        Assert.Equal("jira:read", response.Scope);
        Assert.Equal(harness.GrantValue, response.RefreshToken);
        Assert.Equal(Now.AddMinutes(20), response.TaskExpiresAt);
        Assert.Equal(300, response.ExpiresIn);

        Assert.True(Jws.TryVerify(harness.Keys, response.AccessToken, out _, out var payload));
        using var claims = JsonDocument.Parse(payload!);
        var root = claims.RootElement;
        Assert.Equal(Human, root.GetProperty("sub").GetString());
        Assert.Equal("agent:jira-triage", root.GetProperty("act").GetProperty("sub").GetString());
        Assert.Equal("task_1", root.GetProperty("task").GetProperty("id").GetString());
        Assert.Equal("jira:read", root.GetProperty("scope").GetString());
        Assert.StartsWith("tok_", root.GetProperty("jti").GetString(), StringComparison.Ordinal);

        var refreshed = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.TokenRefreshed, "task_1", "jira-triage", Human, "https://jira.internal", "jira:read", 1, AuditDecision.Allow), (refreshed.Event, refreshed.TaskId, refreshed.AgentId, refreshed.Sponsor, refreshed.Audience, refreshed.Scope, refreshed.DelegationDepth, refreshed.Decision));
        Assert.Equal(root.GetProperty("jti").GetString(), refreshed.Jti);
        Assert.Equal(Now, harness.Grants.Stored.Single().LastUsedAt);
    }

    [Fact]
    public async Task The_first_renewal_is_written_through_and_the_rest_are_counted_on_the_grant()
    {
        var harness = new Harness();
        var service = harness.Build();

        var first = await service.RefreshAsync(Request(harness.GrantValue), []);
        var second = await service.RefreshAsync(Request(harness.GrantValue), []);
        var third = await service.RefreshAsync(Request(harness.GrantValue), []);

        Assert.NotNull(first.Response);
        Assert.NotNull(second.Response);
        Assert.NotNull(third.Response);
        var written = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.TokenRefreshed, AuditDecision.Allow, (int?)null), (written.Event, written.Decision, written.Count));
        Assert.NotNull(written.Jti);
        Assert.Equal(3, harness.Grants.Stored.Single().Renewals);
    }

    [Fact]
    public async Task With_summarising_off_each_refresh_writes_its_own_record_with_a_different_jti()
    {
        var harness = new Harness { Summarise = false };
        var service = harness.Build();

        var first = await service.RefreshAsync(Request(harness.GrantValue), []);
        var second = await service.RefreshAsync(Request(harness.GrantValue), []);

        Assert.NotNull(first.Response);
        Assert.NotNull(second.Response);
        Assert.Equal(2, harness.Audit.Events.Count);
        Assert.NotEqual(harness.Audit.Events[0].Jti, harness.Audit.Events[1].Jti);
        Assert.All(harness.Audit.Events, e => Assert.Null(e.Count));
        Assert.Equal(2, harness.Grants.Stored.Single().Renewals);
    }

    [Theory]
    [InlineData("jira:read jira:admin")]
    [InlineData("jira:read confluence:read")]
    [InlineData("jira:comment jira:read confluence:read")]
    public async Task Widening_scope_on_refresh_is_invalid_scope_even_when_the_agent_could_have_it(string scope)
    {
        // confluence:read is allowed for the agent but was not granted; it can never come back through refresh.
        var harness = new Harness();

        var outcome = await Refresh(harness, scope);

        Assert.Equal(OAuthErrorResponse.InvalidScope, outcome.Error!.Error);
        var denied = AssertDenied(harness, TokenRefreshService.ScopeWidened);
        Assert.Equal(("task_1", scope, Human), (denied.TaskId, denied.Scope, denied.Sponsor));
    }

    [Fact]
    public async Task A_narrowed_refresh_sticks_so_a_later_refresh_cannot_widen_back_to_the_original_grant()
    {
        var harness = new Harness();
        var service = harness.Build();

        var narrowed = await service.RefreshAsync(Request(harness.GrantValue, "jira:read"), []);
        var widened = await service.RefreshAsync(Request(harness.GrantValue, "jira:read jira:comment"), []);
        var again = await service.RefreshAsync(Request(harness.GrantValue, "jira:read"), []);

        Assert.Equal("jira:read", narrowed.Response!.Scope);
        Assert.Equal(OAuthErrorResponse.InvalidScope, widened.Error!.Error);
        Assert.Equal("jira:read", again.Response!.Scope);
        Assert.Equal(["jira:read"], harness.Grants.Stored.Single().Scopes);
        var denied = Assert.Single(harness.Audit.Events, e => e.Decision == AuditDecision.Deny);
        Assert.Equal((TokenRefreshService.ScopeWidened, "jira:read jira:comment"), (denied.Reason, denied.Scope));
    }

    [Fact]
    public async Task A_refresh_asking_for_the_whole_grant_keeps_it_in_the_grants_own_order()
    {
        var harness = new Harness();

        var outcome = await Refresh(harness, "jira:comment jira:read");

        Assert.Equal("jira:comment jira:read", outcome.Response!.Scope);
        Assert.Equal(["jira:read", "jira:comment"], harness.Grants.Stored.Single().Scopes);
    }

    [Fact]
    public async Task A_registration_narrowed_for_a_while_narrows_the_token_but_not_the_grant()
    {
        var harness = new Harness();
        var service = harness.Build();

        // The operator takes jira:comment away from the agent for a while.
        await harness.Agents.UpdateAsync(harness.Agent with { AllowedScopes = ["jira:read"] });
        var during = await service.RefreshAsync(Request(harness.GrantValue, "jira:read jira:comment"), []);

        Assert.Equal("jira:read", during.Response!.Scope);
        Assert.Equal(["jira:read", "jira:comment"], harness.Grants.Stored.Single().Scopes);

        // Once it is given back, the task can use what its grant always held.
        await harness.Agents.UpdateAsync(harness.Agent);
        var after = await service.RefreshAsync(Request(harness.GrantValue, "jira:read jira:comment"), []);

        Assert.Equal("jira:read jira:comment", after.Response!.Scope);
        Assert.Equal(["jira:read", "jira:comment"], harness.Grants.Stored.Single().Scopes);
    }

    [Fact]
    public async Task A_refresh_decided_against_scopes_a_concurrent_refresh_narrowed_is_decided_again_and_cannot_widen_them()
    {
        var harness = new Harness();
        var service = harness.Build();
        harness.Grants.NarrowOnMarkUsed = ["jira:read"];

        var outcome = await service.RefreshAsync(Request(harness.GrantValue, "jira:read jira:comment"), []);

        Assert.Equal(OAuthErrorResponse.InvalidScope, outcome.Error!.Error);
        Assert.Equal(["jira:read"], harness.Grants.Stored.Single().Scopes);
        AssertDenied(harness, TokenRefreshService.ScopeWidened);
    }

    [Fact]
    public async Task A_refresh_still_within_a_concurrently_narrowed_grant_is_issued()
    {
        var harness = new Harness();
        var service = harness.Build();
        harness.Grants.NarrowOnMarkUsed = ["jira:read"];

        var outcome = await service.RefreshAsync(Request(harness.GrantValue, "jira:read"), []);

        Assert.Equal("jira:read", outcome.Response!.Scope);
        Assert.Equal(["jira:read"], harness.Grants.Stored.Single().Scopes);
        Assert.Equal(2, harness.Grants.Stored.Single().Renewals);
    }

    [Fact]
    public async Task Refresh_after_the_task_expired_is_access_denied()
    {
        var harness = new Harness();
        var service = harness.Build();
        harness.Clock.Advance(TimeSpan.FromMinutes(20));

        var later = harness.Clock.GetUtcNow();
        var assertion = Mint("RS256", "agent-key", ClientAuthTestData.Assertion("jira-triage", ("exp", later.AddMinutes(2).ToUnixTimeSeconds()), ("iat", later.ToUnixTimeSeconds())), rsa: Rsa2);
        var outcome = await service.RefreshAsync(Request(harness.GrantValue, assertion: assertion), []);

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        Assert.Equal("task_expired", outcome.Error.Reason);
        Assert.Equal("task_expired", AssertDenied(harness, "task_expired").Reason);
        Assert.Equal("task_1", harness.Audit.Events.Single().TaskId);
    }

    [Fact]
    public async Task Refresh_under_a_revoked_task_is_access_denied()
    {
        var harness = new Harness { Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Revoked, Now.AddMinutes(-10), Now.AddMinutes(20), Now.AddMinutes(-1), "operator_kill_switch") };

        var outcome = await Refresh(harness);

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        Assert.Equal("task_revoked", outcome.Error.Reason);
        var denied = AssertDenied(harness, "task_revoked");
        Assert.Equal(("task_1", Human, "https://jira.internal", "jira:read"), (denied.TaskId, denied.Sponsor, denied.Audience, denied.Scope));
    }

    [Fact]
    public async Task An_unknown_grant_and_another_agents_grant_are_both_invalid_grant_not_found()
    {
        var harness = new Harness();
        var service = harness.Build();

        Assert.Equal(OAuthErrorResponse.InvalidGrant, (await service.RefreshAsync(Request(TaskGrantSecret.New()), [])).Error!.Error);
        Assert.Equal("grant_not_found", harness.Audit.Events[^1].Reason);

        var other = new Harness { Agent = ClientAuthTestData.Agent("db-reader") };
        var stolen = await other.Build().RefreshAsync(Request(harness.GrantValue, assertion: Assertion("db-reader")), []);
        Assert.Equal(OAuthErrorResponse.InvalidGrant, stolen.Error!.Error);
        Assert.Equal(("grant_not_found", "db-reader"), (other.Audit.Events.Single().Reason, other.Audit.Events.Single().AgentId));
    }

    [Fact]
    public async Task A_resource_other_than_the_tasks_audience_is_invalid_target()
    {
        var harness = new Harness();

        var outcome = await Refresh(harness, resource: "https://confluence.internal");

        Assert.Equal(OAuthErrorResponse.InvalidTarget, outcome.Error!.Error);
        AssertDenied(harness, TokenRefreshService.AudienceMismatch);
    }

    [Fact]
    public async Task The_policy_is_re_evaluated_against_the_agents_current_registration()
    {
        // Since the exchange, an administrator removed jira:read from the agent and the task's audience from its allowed audiences.
        var narrowed = new Harness { Agent = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:comment"] } };
        var narrowedOutcome = await Refresh(narrowed, "jira:read");
        Assert.Equal(OAuthErrorResponse.InvalidScope, narrowedOutcome.Error!.Error);
        AssertDenied(narrowed, "scope_intersection_empty");

        var moved = new Harness { Agent = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:read"], AllowedAudiences = ["https://confluence.internal"] } };
        var movedOutcome = await Refresh(moved, "jira:read");
        Assert.Equal(OAuthErrorResponse.InvalidTarget, movedOutcome.Error!.Error);
        AssertDenied(moved, "audience_not_allowed");
    }

    [Fact]
    public async Task A_disabled_agent_cannot_refresh()
    {
        var harness = new Harness { Agent = ClientAuthTestData.Agent(enabled: false) };

        var outcome = await Refresh(harness);

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        Assert.Equal("agent_disabled", outcome.Error.Reason);
        AssertDenied(harness, "agent_disabled");
    }

    [Fact]
    public async Task A_grant_revoked_between_being_read_and_being_used_stops_the_issue()
    {
        var harness = new Harness();
        harness.Grants.RevokeOnMarkUsed = true;

        var outcome = await Refresh(harness);

        Assert.Null(outcome.Response);
        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        Assert.Null(outcome.Error.Reason);
        var denied = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.TokenDenied, TokenRefreshService.GrantRevokedDuringRefresh), (denied.Event, denied.Reason));
    }

    [Theory]
    [InlineData(SponsorStatus.Disabled, OAuthErrorResponse.AccessDenied, SponsorGate.SponsorDisabled)]
    [InlineData(SponsorStatus.NotFound, OAuthErrorResponse.AccessDenied, SponsorGate.SponsorNotFound)]
    [InlineData(SponsorStatus.Unavailable, OAuthErrorResponse.TemporarilyUnavailable, SponsorGate.SponsorStatusUnavailable)]
    public async Task A_sponsor_who_is_not_confirmed_active_cannot_be_refreshed_for(SponsorStatus status, string error, string reason)
    {
        var harness = new Harness { Sponsors = new FixedSponsorStatus(status) };

        var outcome = await Refresh(harness);

        Assert.Null(outcome.Response);
        Assert.Equal(error, outcome.Error!.Error);
        Assert.Equal(error == OAuthErrorResponse.AccessDenied ? reason : null, outcome.Error.Reason);
        var denied = AssertDenied(harness, reason);
        Assert.Equal(("task_1", Human, "https://jira.internal", "jira:read"), (denied.TaskId, denied.Sponsor, denied.Audience, denied.Scope));
        Assert.Equal([Human], harness.Sponsors.Asked);
    }

    [Fact]
    public async Task The_sponsor_is_asked_about_on_every_refresh_not_once_per_task()
    {
        var harness = new Harness();
        var service = harness.Build();

        await service.RefreshAsync(Request(harness.GrantValue), []);
        await service.RefreshAsync(Request(harness.GrantValue), []);
        harness.Sponsors.Status = SponsorStatus.Disabled;
        var third = await service.RefreshAsync(Request(harness.GrantValue), []);

        Assert.Equal(3, harness.Sponsors.Asked.Count);
        Assert.Equal(OAuthErrorResponse.AccessDenied, third.Error!.Error);
        Assert.Equal(SponsorGate.SponsorDisabled, harness.Audit.Events[^1].Reason);
    }

    [Fact]
    public async Task The_sponsor_answer_may_be_no_older_than_the_token_about_to_be_issued()
    {
        // The agent's max_token_ttl is 5 minutes and the task has 20 left: 5 minutes.
        var harness = new Harness();
        await Refresh(harness);
        Assert.Equal([TimeSpan.FromMinutes(5)], harness.Sponsors.MaxAges);

        // An agent capped at 30 seconds gets a 30 second bound, whatever the cache is configured to.
        var shortLived = new Harness { Agent = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:read", "jira:comment"], MaxTokenTtl = TimeSpan.FromSeconds(30) } };
        await Refresh(shortLived);
        Assert.Equal([TimeSpan.FromSeconds(30)], shortLived.Sponsors.MaxAges);

        // A task with 2 minutes left bounds it to 2 minutes.
        var ending = new Harness { Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddMinutes(-28), Now.AddMinutes(2), null, null) };
        await Refresh(ending);
        Assert.Equal([TimeSpan.FromMinutes(2)], ending.Sponsors.MaxAges);
    }

    [Fact]
    public async Task The_sponsor_answer_may_be_no_older_than_the_task()
    {
        // Created 30 seconds ago: an answer from before that belongs to no exchange of this task.
        var young = new Harness { Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddSeconds(-30), Now.AddMinutes(20), null, null) };

        await Refresh(young);

        Assert.Equal([TimeSpan.FromSeconds(30)], young.Sponsors.MaxAges);
    }

    [Fact]
    public async Task A_new_tasks_first_refresh_does_not_reuse_a_status_an_earlier_task_of_the_same_human_cached()
    {
        // An earlier task's refresh cached "active" a minute ago. The human was disabled at the
        // provider since, and then a new task was exchanged (which asks as of now and keeps nothing).
        var provider = new FixedSponsorStatus(SponsorStatus.Active);
        var clock = new FakeTimeProvider(Now.AddMinutes(-1));
        var cache = new SponsorStatusCache(provider, TimeSpan.FromMinutes(5), clock);
        Assert.Equal(SponsorStatus.Active, await cache.GetAsync(Human, TimeSpan.FromMinutes(5)));
        provider.Status = SponsorStatus.Disabled;
        clock.SetUtcNow(Now);

        var harness = new Harness { Upstream = cache, Task = new("task_2", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddSeconds(-10), Now.AddMinutes(20), null, null) };

        var outcome = await Refresh(harness);

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        AssertDenied(harness, SponsorGate.SponsorDisabled);
    }

    [Fact]
    public async Task A_task_with_seconds_left_is_refused_rather_than_answered_with_a_dead_token()
    {
        // Three seconds left: a token issued here would expire before it could be used. The task has
        // not expired, so the reason is its own, not task_expired.
        var ending = new Harness { Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddMinutes(-28), Now.AddSeconds(3), null, null) };

        var outcome = await Refresh(ending);

        Assert.Null(outcome.Response);
        Assert.Equal("access_denied", outcome.Error!.Error);
        Assert.Equal("task_ending", outcome.Error.Reason);
        Assert.Equal("task_ending", ending.Audit.Events.Single().Reason);
        Assert.Empty(ending.Sponsors.Asked);
    }

    [Fact]
    public async Task A_task_with_just_over_the_minimum_left_still_gets_a_token()
    {
        var ending = new Harness { Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddMinutes(-28), Now.AddSeconds(30), null, null) };

        var outcome = await Refresh(ending);

        Assert.Null(outcome.Error);
        Assert.Equal(30, outcome.Response!.ExpiresIn);
    }

    [Fact]
    public async Task A_revoked_task_is_reported_before_the_sponsor_is_asked_about()
    {
        var harness = new Harness
        {
            Sponsors = new FixedSponsorStatus(SponsorStatus.Disabled),
            Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Revoked, Now.AddMinutes(-10), Now.AddMinutes(20), Now.AddMinutes(-1), "operator_kill_switch"),
        };

        var outcome = await Refresh(harness);

        Assert.Equal("task_revoked", harness.Audit.Events.Single().Reason);
        Assert.Empty(harness.Sponsors.Asked);
    }

    [Fact]
    public async Task A_delegated_task_cannot_be_refreshed_until_its_chain_can_be_rebuilt()
    {
        var harness = new Harness { Task = new("task_2", "jira-triage", Human, Human, null, "task_1", 2, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Active, Now.AddMinutes(-10), Now.AddMinutes(20), null, null) };

        var outcome = await Refresh(harness);

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        Assert.Equal(TokenRefreshService.DelegationChainUnavailable, outcome.Error.Reason);
        AssertDenied(harness, TokenRefreshService.DelegationChainUnavailable);
    }

    [Fact]
    public async Task An_invalid_request_is_denied_before_the_agent_is_authenticated()
    {
        var harness = new Harness();

        var outcome = await harness.Build().RefreshAsync(Request(harness.GrantValue) with { ClientAssertionType = "wrong" }, []);

        Assert.Equal(OAuthErrorResponse.InvalidRequest, outcome.Error!.Error);
        Assert.Contains("client_assertion_type", outcome.Error.ErrorDescription, StringComparison.Ordinal);
        AssertDenied(harness, "invalid_request");
        Assert.Empty(harness.Replays.Recorded);
    }

    private static AuditEvent AssertDenied(Harness harness, string reason)
    {
        var denied = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.TokenDenied, AuditDecision.Deny, reason), (denied.Event, denied.Decision, denied.Reason));
        Assert.Null(harness.Grants.Stored.Single().LastUsedAt);
        return denied;
    }
}

internal sealed class FixedSponsorStatus(SponsorStatus status) : ISponsorStatusSource
{
    public SponsorStatus Status { get; set; } = status;

    public List<string> Asked { get; } = [];

    public List<TimeSpan> MaxAges { get; } = [];

    public Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        Asked.Add(subject);
        MaxAges.Add(maxAge);
        return Task.FromResult(Status);
    }
}
