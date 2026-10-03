using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Core.Validation;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Tokens.ClientAuth;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.NoAggregationHelper;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Tokens.Exchange;

public class TokenExchangeServiceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    /// <summary>The whole exchange with in-memory storage; the real authenticator, validator, policy engine and signer.</summary>
    private sealed class Harness
    {
        public Agent Agent { get; init; } = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:read", "jira:comment", "confluence:read"] };
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryReplayStore Replays { get; } = new();
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public SigningKeySet Keys { get; } = SigningKeySet.CreateEphemeral();
        public TimeSpan DefaultTaskTtl { get; init; } = TimeSpan.FromHours(1);
        public TimeSpan DefaultTokenTtl { get; init; } = TimeSpan.FromMinutes(5);
        public Exception? AgentKeysFailure { get; init; }
        public FixedSponsorStatus Sponsors { get; init; } = new(SponsorStatus.Active);
        public InMemorySponsorBlocks Blocks { get; init; } = new();
        public RecordingFence Fence { get; } = new();
        public SubactId.UnitTests.Revocation.InMemoryRevocations Revocations { get; } = new();
        public AgentRegistrationLimits Limits { get; init; } = AgentRegistrationLimits.Default;
        public string SponsorKeyClaim { get; init; } = UpstreamIdpOptions.DefaultSponsorKeyClaim;

        public TokenExchangeService Build()
        {
            var options = new SubactIdOptions
            {
                Issuer = new Uri(ClientAuthTestData.SubactIdIssuer),
                UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = SponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri(Issuer + "/.well-known/openid-configuration"), Audience = Audience, SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
                Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = "unused" },
                Tokens = new TokenOptions { DefaultTaskTtl = DefaultTaskTtl, DefaultTokenTtl = DefaultTokenTtl },
                Agents = Limits,
                Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 100 },
                Signing = new SigningOptions { Keys = [] },
                Admin = new AdminOptions(),
                Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
            };
            var agents = new InMemoryAgentRepository(Agent);
            var actors = new ClientAssertionAuthenticator(agents, new StaticAgentKeys(ClientAuthTestData.Snapshot(Jwks(RsaJwk(Rsa2, "agent-key"))), failure: AgentKeysFailure), Replays, options.Issuer, Clock);
            var subjects = new UpstreamTokenValidator(new StaticUpstreamKeys(Snapshot()), Audience, Clock);
            return new TokenExchangeService(actors, subjects, new SponsorGate(Blocks, Sponsors), Blocks, Fence, Revocations, Tasks, Grants, Audit, new PassThroughUnitOfWork(), new TokenAudit(Audit, Clock, NoAggregation(Clock)), Keys, options, Clock);
        }
    }

    private static string ActorAssertion(string agentId = "jira-triage") => Mint("RS256", "agent-key", ClientAuthTestData.Assertion(agentId), rsa: Rsa2);

    private static string SubjectToken(params (string Key, object? Value)[] overrides) => Mint("RS256", "rsa1", Claims(overrides));

    private static ExchangeTokenRequest Request(string? subject = null, string? actor = null, string resource = "https://jira.internal", string scope = "jira:read jira:comment", string? clientId = null) => new(
        ExchangeTokenRequest.TokenExchangeGrantType,
        subject ?? SubjectToken(),
        ExchangeTokenRequest.AccessTokenType,
        actor ?? ActorAssertion(),
        ExchangeTokenRequest.JwtTokenType,
        ExchangeTokenRequest.AccessTokenType,
        resource,
        scope,
        clientId);

    private static Task<TokenOutcome> Exchange(Harness harness, ExchangeTokenRequest? request = null) => harness.Build().ExchangeAsync(request ?? Request(), []);

    [Fact]
    public async Task The_spec_happy_path_issues_a_token_a_task_and_a_grant_with_two_audit_records()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness);

        var response = outcome.Response!;
        Assert.Null(outcome.Error);
        Assert.Equal(ExchangeTokenRequest.AccessTokenType, response.IssuedTokenType);
        Assert.Equal("Bearer", response.TokenType);
        Assert.Equal(300, response.ExpiresIn);
        Assert.Equal("jira:read jira:comment", response.Scope);
        Assert.StartsWith("task_grant_", response.RefreshToken, StringComparison.Ordinal);
        Assert.StartsWith("task_", response.TaskId, StringComparison.Ordinal);
        Assert.Equal(Now.AddMinutes(30), response.TaskExpiresAt);

        // The token: signed by the active key, sub is the human, the agent is in act.
        Assert.True(Jws.TryVerify(harness.Keys, response.AccessToken, out var header, out var payload));
        Assert.Equal("at+jwt", header!.Typ);
        using var claims = JsonDocument.Parse(payload!);
        var root = claims.RootElement;
        Assert.Equal(ClientAuthTestData.SubactIdIssuer, root.GetProperty("iss").GetString());
        Assert.Equal(Human, root.GetProperty("sub").GetString());
        Assert.Equal("https://jira.internal", root.GetProperty("aud").GetString());
        Assert.Equal(Now.AddMinutes(5).ToUnixTimeSeconds(), root.GetProperty("exp").GetInt64());
        Assert.Equal("jira:read jira:comment", root.GetProperty("scope").GetString());
        Assert.Equal("agent:jira-triage", root.GetProperty("client_id").GetString());
        Assert.Equal("agent:jira-triage", root.GetProperty("act").GetProperty("sub").GetString());
        Assert.Equal(1, root.GetProperty("act").GetProperty("depth").GetInt32());
        Assert.Equal(response.TaskId, root.GetProperty("task").GetProperty("id").GetString());
        Assert.Equal(Human, root.GetProperty("task").GetProperty("sponsor").GetString());

        // Storage: the task, and the grant under its hash only.
        var task = Assert.Single(harness.Tasks.Stored);
        Assert.Equal((response.TaskId, "jira-triage", Human, 1, DelegationTaskStatus.Active), (task.TaskId, task.AgentId, task.Sponsor, task.DelegationDepth, task.Status));
        Assert.Equal(["jira:read", "jira:comment"], task.Scopes);
        var grant = Assert.Single(harness.Grants.Stored);
        Assert.Equal(TaskGrantSecret.Hash(response.RefreshToken), grant.GrantHash.ToArray());
        Assert.Equal((response.TaskId, "jira-triage", task.ExpiresAt), (grant.TaskId, grant.AgentId, grant.ExpiresAt));
        Assert.Equal(task.Scopes, grant.Scopes);

        // Audit: one record, token.issued, allow, fully attributed. It is the task's creation too.
        var issued = Assert.Single(harness.Audit.Events);
        Assert.Equal(AuditEvents.TokenIssued, issued.Event);
        Assert.Equal((response.TaskId, "jira-triage", Human, "https://jira.internal", "jira:read jira:comment", 1, AuditDecision.Allow), (issued.TaskId, issued.AgentId, issued.Sponsor, issued.Audience, issued.Scope, issued.DelegationDepth, issued.Decision));
        Assert.Equal(root.GetProperty("jti").GetString(), issued.Jti);
    }

    [Fact]
    public async Task An_exchange_writes_one_record_in_one_append()
    {
        // An exchange writes one record in one append. A second record or a second append would add
        // cost to every exchange and a row to a table that refuses DELETE.
        var harness = new Harness();

        await Exchange(harness);

        Assert.Equal(1, harness.Audit.Appends);
        Assert.Equal([AuditEvents.TokenIssued], harness.Audit.Events.Select(e => e.Event));
    }

    [Fact]
    public async Task Scope_is_narrowed_to_what_the_user_holds_and_the_agent_may_have()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(scope: "jira:admin jira:comment confluence:read"));

        // jira:admin: nobody. confluence:read: the agent may, the user's token does not carry it.
        Assert.Equal("jira:comment", outcome.Response!.Scope);
        Assert.Equal(["jira:comment"], harness.Tasks.Stored.Single().Scopes);
    }

    [Fact]
    public async Task The_agents_registration_decides_both_lifetimes()
    {
        // The server-wide settings apply only to a registration that names no lifetime: an agent
        // registered for a six-hour job gets a six-hour task, whatever the default is.
        var longJob = new Harness
        {
            Agent = ClientAuthTestData.Agent() with { MaxTaskTtl = TimeSpan.FromHours(6), MaxTokenTtl = TimeSpan.FromMinutes(5), AllowedScopes = ["jira:read", "jira:comment", "confluence:read"] },
            DefaultTaskTtl = TimeSpan.FromMinutes(30),
            DefaultTokenTtl = TimeSpan.FromMinutes(5),
        };

        var outcome = await Exchange(longJob);

        Assert.Equal(Now.AddHours(6), outcome.Response!.TaskExpiresAt);
        Assert.Equal(300, outcome.Response.ExpiresIn);
    }

    [Fact]
    public async Task A_token_is_never_issued_past_the_end_of_its_task()
    {
        // The task is shorter than the token lifetime the registration asks for, so the token is cut
        // to the task (invariant 3).
        var shortTask = new Harness
        {
            Agent = ClientAuthTestData.Agent() with { MaxTaskTtl = TimeSpan.FromMinutes(2), MaxTokenTtl = TimeSpan.FromMinutes(5), AllowedScopes = ["jira:read", "jira:comment", "confluence:read"] },
        };

        var outcome = await Exchange(shortTask);

        Assert.Equal(Now.AddMinutes(2), outcome.Response!.TaskExpiresAt);
        Assert.Equal(120, outcome.Response.ExpiresIn);
    }

    [Fact]
    public async Task An_invalid_request_is_denied_and_audited_before_anything_is_authenticated()
    {
        var harness = new Harness();

        var outcome = await harness.Build().ExchangeAsync(Request(resource: "not-a-url"), [new ValidationError("scope", "must not be repeated.")]);

        Assert.Equal(OAuthErrorResponse.InvalidRequest, outcome.Error!.Error);
        Assert.Contains("resource", outcome.Error.ErrorDescription, StringComparison.Ordinal);
        Assert.Contains("scope must not be repeated", outcome.Error.ErrorDescription, StringComparison.Ordinal);
        AssertDenied(harness, "invalid_request", agentId: null);
        Assert.Empty(harness.Replays.Recorded);
    }

    [Fact]
    public async Task A_bad_actor_assertion_is_invalid_client_and_the_subject_token_is_never_looked_at()
    {
        var harness = new Harness();
        var forged = Mint("RS256", "agent-key", ClientAuthTestData.Assertion(), rsa: Rsa1);

        var outcome = await Exchange(harness, Request(actor: forged, subject: "not-even-a-token"));

        Assert.Equal(OAuthErrorResponse.InvalidClient, outcome.Error!.Error);
        Assert.Equal("Client authentication failed.", outcome.Error.ErrorDescription);
        Assert.Null(outcome.Error.Reason);
        AssertDenied(harness, "actor_invalid_signature", agentId: null);
    }

    [Fact]
    public async Task A_replayed_actor_assertion_is_invalid_client()
    {
        var harness = new Harness();
        var assertion = ActorAssertion();
        var service = harness.Build();

        Assert.NotNull((await service.ExchangeAsync(Request(actor: assertion), [])).Response);
        var replay = await service.ExchangeAsync(Request(actor: assertion), []);

        Assert.Equal(OAuthErrorResponse.InvalidClient, replay.Error!.Error);
        Assert.Equal("actor_replayed", harness.Audit.Events[^1].Reason);

        // Only access_denied carries a reason, so an authentication failure says nothing more.
        Assert.Null(replay.Error.Reason);
    }

    [Fact]
    public async Task A_disabled_agent_is_access_denied_as_the_spec_says_not_invalid_client()
    {
        var harness = new Harness { Agent = ClientAuthTestData.Agent(enabled: false) with { AllowedScopes = ["jira:read", "jira:comment"] } };

        var outcome = await Exchange(harness);

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        Assert.Equal("agent_disabled", outcome.Error.Reason);
        // The caller proved the agent's key before this refusal, so the record names it.
        AssertDenied(harness, "agent_disabled", agentId: "jira-triage");
    }

    [Theory]
    [InlineData("exp", 1L, "subject_expired")]
    [InlineData("iss", "https://evil.example", "subject_untrusted_issuer")]
    [InlineData("aud", "someone-else", "subject_audience_mismatch")]
    public async Task A_bad_subject_token_is_invalid_grant_with_the_precise_audit_reason(string claim, object value, string reason)
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(subject: SubjectToken((claim, value))));

        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        AssertDenied(harness, reason, agentId: "jira-triage");
    }

    [Fact]
    public async Task A_subject_token_naming_an_agent_as_the_human_is_invalid_grant()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("sub", "agent:jira-triage"))));

        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        AssertDenied(harness, TokenExchangeService.SubjectIsAgent, agentId: "jira-triage");
        Assert.Empty(harness.Tasks.Stored);
    }

    [Fact]
    public async Task An_empty_scope_intersection_is_invalid_scope()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(scope: "jira:admin"));

        Assert.Equal(OAuthErrorResponse.InvalidScope, outcome.Error!.Error);
        Assert.Null(outcome.Error.Reason);
        var denied = AssertDenied(harness, "scope_intersection_empty", agentId: "jira-triage");
        Assert.Equal((Human, "https://jira.internal", "jira:admin"), (denied.Sponsor, denied.Audience, denied.Scope));
    }

    [Fact]
    public async Task An_audience_outside_allowed_audiences_is_invalid_target()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(resource: "https://db.internal"));

        Assert.Equal(OAuthErrorResponse.InvalidTarget, outcome.Error!.Error);
        AssertDenied(harness, "audience_not_allowed", agentId: "jira-triage");
    }

    [Fact]
    public async Task A_client_id_naming_another_agent_is_invalid_client()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(clientId: "db-reader"));

        Assert.Equal(OAuthErrorResponse.InvalidClient, outcome.Error!.Error);
        AssertDenied(harness, "actor_client_id_mismatch", agentId: null);
    }

    [Fact]
    public async Task No_token_leaves_and_no_allow_is_audited_when_storage_fails_inside_the_transaction()
    {
        var harness = new Harness();
        harness.Grants.FailNextAdd = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => Exchange(harness));

        Assert.Empty(harness.Audit.Events);
    }

    [Fact]
    public async Task An_unreachable_jwks_is_temporarily_unavailable_not_a_bad_credential()
    {
        var harness = new Harness { AgentKeysFailure = new HttpRequestException("down") };

        var outcome = await Exchange(harness);

        Assert.Equal(OAuthErrorResponse.TemporarilyUnavailable, outcome.Error!.Error);
        AssertDenied(harness, "actor_keys_unavailable", agentId: null);
    }

    [Fact]
    public async Task A_jwks_url_the_egress_guard_refuses_is_a_bad_credential_not_an_outage()
    {
        var harness = new Harness { AgentKeysFailure = new HttpRequestException("refused", new DestinationRefusedException("refused")) };

        var outcome = await Exchange(harness);

        // Asking again is refused again, so it is not answered as something to retry.
        Assert.Equal(OAuthErrorResponse.InvalidClient, outcome.Error!.Error);
        AssertDenied(harness, "actor_keys_refused", agentId: null);
    }

    [Fact]
    public async Task A_disabled_agent_presenting_a_forged_assertion_looks_like_any_other_bad_credential()
    {
        var harness = new Harness { Agent = ClientAuthTestData.Agent(enabled: false) };
        var forged = Mint("RS256", "agent-key", ClientAuthTestData.Assertion(), rsa: Rsa1);

        var outcome = await Exchange(harness, Request(actor: forged));

        Assert.Equal(OAuthErrorResponse.InvalidClient, outcome.Error!.Error);
        AssertDenied(harness, "actor_invalid_signature", agentId: null);
    }

    [Fact]
    public async Task Deny_writes_the_record_for_decisions_made_before_the_services()
    {
        var harness = new Harness();

        var outcome = await new TokenAudit(harness.Audit, harness.Clock, NoAggregation(harness.Clock)).DenyAsync(OAuthErrorResponse.UnsupportedGrantType, "Only token exchange is supported.", "unsupported_grant_type");

        Assert.Equal(OAuthErrorResponse.UnsupportedGrantType, outcome.Error!.Error);
        AssertDenied(harness, "unsupported_grant_type", agentId: null);
    }

    [Fact]
    public async Task An_access_denied_answered_before_an_agent_is_known_carries_no_reason()
    {
        // The reason is for an agent that has proved its key. Nothing is said to anyone else.
        var harness = new Harness();
        var audit = new TokenAudit(harness.Audit, harness.Clock, NoAggregation(harness.Clock));

        var anonymous = await audit.DenyAsync(OAuthErrorResponse.AccessDenied, "Refused.", "task_revoked");
        var known = await audit.DenyAsync(OAuthErrorResponse.AccessDenied, "Refused.", "task_revoked", "jira-triage");
        var otherError = await audit.DenyAsync(OAuthErrorResponse.InvalidGrant, "Refused.", "grant_not_found", "jira-triage");

        Assert.Null(anonymous.Error!.Reason);
        Assert.Equal("task_revoked", known.Error!.Reason);
        Assert.Null(otherError.Error!.Reason);
    }

    [Theory]
    [InlineData(SponsorBlockKind.Disabled, SponsorGate.SponsorDisabled)]
    [InlineData(SponsorBlockKind.Deleted, SponsorGate.SponsorNotFound)]
    public async Task A_human_blocked_here_cannot_start_a_new_task(SponsorBlockKind kind, string reason)
    {
        var harness = new Harness();
        await harness.Blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Admin, kind, Now.AddMinutes(-1)));

        var outcome = await Exchange(harness, Request());

        Assert.Null(outcome.Response);
        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        Assert.Equal(reason, outcome.Error.Reason);
        var denied = AssertDenied(harness, reason, "jira-triage");
        Assert.Equal((Human, "https://jira.internal"), (denied.Sponsor, denied.Audience));
    }

    [Theory]
    [InlineData(SponsorStatus.Disabled, OAuthErrorResponse.AccessDenied, SponsorGate.SponsorDisabled)]
    [InlineData(SponsorStatus.NotFound, OAuthErrorResponse.AccessDenied, SponsorGate.SponsorNotFound)]
    [InlineData(SponsorStatus.Unavailable, OAuthErrorResponse.TemporarilyUnavailable, SponsorGate.SponsorStatusUnavailable)]
    public async Task A_human_the_identity_provider_will_not_confirm_cannot_start_a_new_task(SponsorStatus status, string error, string reason)
    {
        // The subject token still verifies, because it was issued before the person was disabled. The
        // person is refused, not the token.
        var harness = new Harness { Sponsors = new FixedSponsorStatus(status) };

        var outcome = await Exchange(harness, Request());

        Assert.Null(outcome.Response);
        Assert.Equal(error, outcome.Error!.Error);
        Assert.Equal(error == OAuthErrorResponse.AccessDenied ? reason : null, outcome.Error.Reason);
        AssertDenied(harness, reason, "jira-triage");
        Assert.Equal([Human], harness.Sponsors.Asked);
    }

    [Fact]
    public async Task The_identity_provider_is_asked_as_of_now_so_the_first_renewal_inherits_no_answer()
    {
        var harness = new Harness();

        Assert.NotNull((await Exchange(harness, Request())).Response);

        // Zero, not a token lifetime: a cached answer would be reused by this task's first renewal,
        // which must catch a human disabled in between.
        Assert.Equal([SponsorGate.AsOfNow], harness.Sponsors.MaxAges);
    }

    [Fact]
    public async Task A_blocked_human_is_recorded_as_blocked_and_not_as_the_scope_they_no_longer_hold()
    {
        var harness = new Harness();
        await harness.Blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, Now.AddMinutes(-1)));

        var outcome = await Exchange(harness, Request(scope: "confluence:read"));

        Assert.Equal(OAuthErrorResponse.AccessDenied, outcome.Error!.Error);
        AssertDenied(harness, SponsorGate.SponsorDisabled, "jira-triage");
    }

    [Fact]
    public async Task A_subject_token_that_cannot_name_the_human_for_a_later_signal_is_invalid_grant()
    {
        var harness = new Harness { SponsorKeyClaim = "oid" };

        var outcome = await Exchange(harness, Request());

        Assert.Null(outcome.Response);
        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        AssertDenied(harness, TokenExchangeService.SponsorKeyMissing, "jira-triage");

        // Refused before the identity provider is asked: there is nothing to ask about.
        Assert.Empty(harness.Sponsors.Asked);
    }

    [Theory]
    [InlineData(42)]
    [InlineData("")]
    public async Task A_key_claim_that_is_not_a_usable_string_is_no_key_at_all(object value)
    {
        var harness = new Harness { SponsorKeyClaim = "oid" };

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("oid", value))));

        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        AssertDenied(harness, TokenExchangeService.SponsorKeyMissing, "jira-triage");
    }

    [Fact]
    public async Task A_task_is_keyed_by_the_configured_claim_while_the_subject_stays_the_human()
    {
        // Entra ID's sub is pairwise per application and cannot match a later signal, so a deployment
        // there keys tasks by oid. What sub means does not change.
        var harness = new Harness { SponsorKeyClaim = "oid" };

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("oid", "oid-42"))));

        Assert.NotNull(outcome.Response);
        var task = Assert.Single(harness.Tasks.Stored);
        Assert.Equal((Human, "oid-42"), (task.Sponsor, task.SponsorKey));

        // The block list is read by that key, by the sponsor check and again inside the fence. The
        // identity provider, where asked, is still asked by the subject it issued. The fence holds
        // off revocations by either.
        Assert.Equal(["oid-42", "oid-42"], harness.Blocks.Asked);
        Assert.Equal([Human], harness.Sponsors.Asked);
        Assert.Equal(("oid-42", Human, (string?)null, "jira-triage"), Assert.Single(harness.Fence.Entered));
    }

    [Theory]
    [InlineData("Alice Example")]
    [InlineData("oid\u000042")]
    [InlineData("oid\t42")]
    public async Task A_key_claim_the_admin_API_could_never_be_asked_to_block_is_no_key_either(string value)
    {
        // A key with a space cannot be named in an admin path, and Postgres refuses a NUL. Either is
        // refused here, under the admin API's rule.
        var harness = new Harness { SponsorKeyClaim = "oid" };

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("oid", value))));

        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        AssertDenied(harness, TokenExchangeService.SponsorKeyMissing, "jira-triage");
        Assert.Empty(harness.Tasks.Stored);
    }

    [Theory]
    [InlineData("session\u00001")]
    [InlineData("session\n1")]
    public async Task A_session_id_that_could_not_be_stored_is_invalid_grant_not_a_storage_fault(string value)
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("sid", value))));

        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);
        AssertDenied(harness, TokenExchangeService.SessionIdMalformed, "jira-triage");
        Assert.Empty(harness.Tasks.Stored);
    }

    [Theory]
    [InlineData(SponsorBlockKind.Disabled, SponsorGate.SponsorDisabled)]
    [InlineData(SponsorBlockKind.Deleted, SponsorGate.SponsorNotFound)]
    public async Task A_block_that_lands_after_the_sponsor_check_still_refuses_the_task(SponsorBlockKind kind, string reason)
    {
        // The block commits while the exchange is between its sponsor check and its transaction:
        // the revocation that came with it walked before this task existed, so the task is
        // refused here instead of being left live.
        var harness = new Harness();
        harness.Fence.OnEnter = () => harness.Blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Admin, kind, Now));

        var outcome = await Exchange(harness, Request());

        Assert.Null(outcome.Response);
        Assert.Equal((OAuthErrorResponse.AccessDenied, reason), (outcome.Error!.Error, outcome.Error.Reason));
        Assert.Empty(harness.Tasks.Stored);
        Assert.Empty(harness.Grants.Stored);
        var denied = AssertDenied(harness, reason, "jira-triage");
        Assert.Equal((Human, "https://jira.internal"), (denied.Sponsor, denied.Audience));
        Assert.DoesNotContain(harness.Audit.Events, e => e.Event == AuditEvents.TokenIssued);
    }

    private static SubactId.Core.Revocation.Revocation SessionLogout(string sessionId) =>
        new(null, null, null, null, sessionId, Now, "sponsor_logged_out", "identity_provider");

    private static SubactId.Core.Revocation.Revocation PersonLogout(DateTimeOffset issuedBefore, string subject = Human) =>
        new(null, null, null, null, null, Now, "sponsor_logged_out", "identity_provider", Subject: subject, IssuedBefore: issuedBefore);

    private static void AssertSignedOut(Harness harness, TokenOutcome outcome)
    {
        Assert.Null(outcome.Response);
        Assert.Equal(OAuthErrorResponse.InvalidGrant, outcome.Error!.Error);

        // invalid_grant carries no reason; the record does, naming the agent and the person.
        Assert.Null(outcome.Error.Reason);
        var denied = AssertDenied(harness, TokenExchangeService.SubjectLoggedOut, "jira-triage");
        Assert.Equal((Human, "https://jira.internal", "jira:read jira:comment"), (denied.Sponsor, denied.Audience, denied.Scope));
    }

    [Fact]
    public async Task A_subject_token_of_a_session_that_was_logged_out_cannot_start_a_task()
    {
        var harness = new Harness();
        harness.Revocations.Stored.Add(SessionLogout("session-1"));

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("sid", "session-1"))));

        AssertSignedOut(harness, outcome);
    }

    [Fact]
    public async Task A_subject_token_of_another_session_or_with_no_session_is_not_refused_by_a_session_logout()
    {
        var harness = new Harness();
        harness.Revocations.Stored.Add(SessionLogout("session-1"));

        Assert.NotNull((await Exchange(harness, Request(subject: SubjectToken(("sid", "session-2"))))).Response);
        Assert.NotNull((await Exchange(harness, Request(subject: SubjectToken()))).Response);
    }

    [Fact]
    public async Task A_subject_token_issued_before_a_logout_of_the_person_cannot_start_a_task()
    {
        // The subject token was issued a minute ago; the logout token now.
        var harness = new Harness();
        harness.Revocations.Stored.Add(PersonLogout(Now));

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("sid", "session-1"))));

        AssertSignedOut(harness, outcome);
    }

    [Fact]
    public async Task A_subject_token_issued_after_a_logout_of_the_person_or_in_the_same_second_starts_a_task()
    {
        // Signing out is not being blocked: a new sign-in works. iat has whole-second resolution,
        // so a token from the logout's own second cannot be told apart and is let through.
        var harness = new Harness();
        harness.Revocations.Stored.Add(PersonLogout(Now.AddMinutes(-2)));
        harness.Revocations.Stored.Add(PersonLogout(Now.AddMinutes(-1)));

        Assert.NotNull((await Exchange(harness, Request())).Response);
    }

    [Fact]
    public async Task A_logout_of_somebody_else_does_not_refuse_this_person()
    {
        var harness = new Harness();
        harness.Revocations.Stored.Add(PersonLogout(Now, subject: "somebody-else"));

        Assert.NotNull((await Exchange(harness, Request())).Response);
    }

    [Fact]
    public async Task A_transmitters_session_revocation_by_sponsor_key_signs_out_older_subject_tokens()
    {
        var harness = new Harness();
        harness.Revocations.Stored.Add(new(null, null, null, Human, null, Now, "ssf_sessions_revoked", "signals_transmitter", IssuedBefore: Now));

        AssertSignedOut(harness, await Exchange(harness, Request()));
    }

    [Fact]
    public async Task An_operators_kill_switch_ends_what_runs_and_does_not_refuse_the_next_task()
    {
        var harness = new Harness();
        harness.Revocations.Stored.Add(new(null, null, null, Human, null, Now, "operator_kill_switch", "admin"));

        Assert.NotNull((await Exchange(harness, Request())).Response);
    }

    [Fact]
    public async Task A_subject_token_without_an_iat_cannot_be_shown_to_postdate_a_logout_and_is_refused()
    {
        var harness = new Harness();
        harness.Revocations.Stored.Add(PersonLogout(Now.AddDays(-1)));

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("-iat", null))));

        AssertSignedOut(harness, outcome);
    }

    [Fact]
    public async Task A_logout_that_lands_after_the_sponsor_check_still_refuses_the_task()
    {
        // The logout commits while the exchange is between its checks and its transaction. It is
        // read inside the fence, after the block, so the task is refused rather than left live.
        var harness = new Harness();
        harness.Fence.OnEnter = () =>
        {
            harness.Revocations.Stored.Add(SessionLogout("session-1"));
            return Task.CompletedTask;
        };

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("sid", "session-1"))));

        AssertSignedOut(harness, outcome);
        Assert.Equal(1, harness.Revocations.SignOutChecks);
    }

    [Fact]
    public async Task The_exchange_enters_the_fence_for_the_person_their_session_and_the_agent_before_the_last_block_check()
    {
        var harness = new Harness();

        var outcome = await Exchange(harness, Request(subject: SubjectToken(("sid", "session-1"))));

        Assert.NotNull(outcome.Response);
        var entered = Assert.Single(harness.Fence.Entered);
        Assert.Equal((Human, Human, "session-1", "jira-triage"), entered);
        // The block store is read once by the sponsor check and once more after the fence.
        Assert.Equal([Human, Human], harness.Blocks.Asked);
    }

    [Fact]
    public async Task Server_bounds_lowered_since_registration_hold_the_task_and_its_token()
    {
        // Registered under looser bounds: an hour per task, ten minutes per token. The operator has
        // since lowered the bounds to twenty minutes and two; they apply to this exchange.
        var harness = new Harness
        {
            Agent = ClientAuthTestData.Agent() with { AllowedScopes = ["jira:read", "jira:comment"], MaxTaskTtl = TimeSpan.FromHours(1), MaxTokenTtl = TimeSpan.FromMinutes(10) },
            Limits = AgentRegistrationLimits.Default with { MaxTaskTtl = TimeSpan.FromMinutes(20), MaxTokenTtl = TimeSpan.FromMinutes(2) },
        };

        var outcome = await Exchange(harness, Request());

        Assert.NotNull(outcome.Response);
        Assert.Equal(120, outcome.Response.ExpiresIn);
        Assert.Equal(Now.AddMinutes(20), outcome.Response.TaskExpiresAt);
        Assert.Equal(Now.AddMinutes(20), Assert.Single(harness.Tasks.Stored).ExpiresAt);
    }

    [Fact]
    public async Task A_human_blocked_under_another_key_is_not_this_human()
    {
        var harness = new Harness();
        await harness.Blocks.BlockAsync(new SponsorBlock("somebody-else", SponsorBlockSource.Admin, SponsorBlockKind.Disabled, Now.AddMinutes(-1)));

        Assert.NotNull((await Exchange(harness, Request())).Response);
    }

    private static AuditEvent AssertDenied(Harness harness, string reason, string? agentId)
    {
        var denied = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.TokenDenied, AuditDecision.Deny, reason, agentId), (denied.Event, denied.Decision, denied.Reason, denied.AgentId));
        Assert.Empty(harness.Tasks.Stored);
        Assert.Empty(harness.Grants.Stored);
        return denied;
    }
}

public class AuditReasonTests
{
    [Theory]
    [InlineData(ClientAssertionRejection.InvalidSignature, "actor_invalid_signature")]
    [InlineData(ClientAssertionRejection.IssuerSubjectMismatch, "actor_issuer_subject_mismatch")]
    [InlineData(ClientAssertionRejection.Replayed, "actor_replayed")]
    public void Prefixes_and_snake_cases_the_enum_name(ClientAssertionRejection rejection, string expected)
    {
        Assert.Equal(expected, AuditReason.Of("actor", rejection));
    }

    [Fact]
    public void Every_rejection_reason_fits_the_ledger_column()
    {
        foreach (var reason in Enum.GetValues<ClientAssertionRejection>().Select(r => AuditReason.Of("actor", r)).Concat(Enum.GetValues<UpstreamRejection>().Select(r => AuditReason.Of("subject", r))))
        {
            Assert.Matches("^[a-z_]+$", reason);
            Assert.True(reason.Length <= 128);
        }
    }
}

internal sealed class RecordingFence : IRevocationFence
{
    public List<(string SponsorKey, string Subject, string? SessionId, string AgentId)> Entered { get; } = [];

    /// <summary>Runs as the fence is entered: what another unit of work committed just before.</summary>
    public Func<Task>? OnEnter { get; set; }

    public async Task EnterIssueAsync(string sponsorKey, string subject, string? sessionId, string agentId, CancellationToken cancellationToken = default)
    {
        Entered.Add((sponsorKey, subject, sessionId, agentId));
        if (OnEnter is { } onEnter)
        {
            await onEnter();
        }
    }
}

internal sealed class InMemorySponsorBlocks : ISponsorRepository
{
    public Dictionary<string, SponsorBlock> Stored { get; } = new(StringComparer.Ordinal);

    public List<string> Asked { get; } = [];

    /// <summary>The <c>iat</c> of the latest Shared Signals account event applied, per person.</summary>
    public Dictionary<string, DateTimeOffset> Watermarks { get; } = new(StringComparer.Ordinal);

    public Task<SponsorBlock?> FindAsync(string sponsorKey, CancellationToken cancellationToken = default)
    {
        Asked.Add(sponsorKey);
        return Task.FromResult(Stored.GetValueOrDefault(sponsorKey));
    }

    public Task<SponsorBlockWrite> BlockAsync(SponsorBlock block, CancellationToken cancellationToken = default)
    {
        if (!Stored.TryGetValue(block.SponsorKey, out var existing))
        {
            Stored[block.SponsorKey] = block;
            return Task.FromResult(new SponsorBlockWrite(block, Written: true));
        }

        if (existing.Source != block.Source)
        {
            return Task.FromResult(new SponsorBlockWrite(existing, Written: false));
        }

        // A deletion marks the block whatever else changes, and nothing here clears the mark.
        var placedByDeletion = existing.PlacedByDeletion || block.PlacedByDeletion;
        if (existing.Kind != block.Kind)
        {
            Stored[block.SponsorKey] = block with { PlacedByDeletion = placedByDeletion };
            return Task.FromResult(new SponsorBlockWrite(Stored[block.SponsorKey], Written: true));
        }

        Stored[block.SponsorKey] = existing with { PlacedByDeletion = placedByDeletion };
        return Task.FromResult(new SponsorBlockWrite(Stored[block.SponsorKey], Written: false));
    }

    public Task<bool> UnblockAsync(string sponsorKey, SponsorBlockSource source, bool unlessPlacedByDeletion = false, CancellationToken cancellationToken = default)
    {
        if (Stored.TryGetValue(sponsorKey, out var block) && block.Source == source && !(unlessPlacedByDeletion && block.PlacedByDeletion))
        {
            Stored.Remove(sponsorKey);
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public Task ForgetDeletionAsync(string sponsorKey, SponsorBlockSource source, CancellationToken cancellationToken = default)
    {
        if (Stored.TryGetValue(sponsorKey, out var block) && block.Source == source)
        {
            Stored[sponsorKey] = block with { PlacedByDeletion = false };
        }

        return Task.CompletedTask;
    }

    public Task<bool> AdvanceSignalWatermarkAsync(string sponsorKey, DateTimeOffset eventAt, CancellationToken cancellationToken = default)
    {
        if (Watermarks.TryGetValue(sponsorKey, out var latest) && latest > eventAt)
        {
            return Task.FromResult(false);
        }

        Watermarks[sponsorKey] = eventAt;
        return Task.FromResult(true);
    }
}

internal sealed class InMemoryTasks : ITaskRepository
{
    public List<DelegationTask> Stored { get; } = [];

    public Task AddAsync(DelegationTask task, CancellationToken cancellationToken = default) { Stored.Add(task); return Task.CompletedTask; }

    public Task<DelegationTask?> FindAsync(string agentId, string taskId, CancellationToken cancellationToken = default) => Task.FromResult(Stored.FirstOrDefault(t => t.AgentId == agentId && t.TaskId == taskId));
}

internal sealed class InMemoryGrants : ITaskGrantRepository
{
    public List<TaskGrant> Stored { get; } = [];

    public bool FailNextAdd { get; set; }

    public int Finds { get; private set; }

    /// <summary>Simulates a revocation landing between the redeemer's read and the issue.</summary>
    public bool RevokeOnMarkUsed { get; set; }

    public Task AddAsync(TaskGrant grant, CancellationToken cancellationToken = default)
    {
        if (FailNextAdd) throw new InvalidOperationException("storage down");
        Stored.Add(grant);
        return Task.CompletedTask;
    }

    public Task<TaskGrant?> FindAsync(string agentId, ReadOnlyMemory<byte> grantHash, CancellationToken cancellationToken = default)
    {
        Finds++;
        return Task.FromResult(Stored.FirstOrDefault(g => g.AgentId == agentId && g.GrantHash.Span.SequenceEqual(grantHash.Span)));
    }

    /// <summary>Simulates a concurrent refresh narrowing the grant to these scopes between the redeemer's read and the issue.</summary>
    public IReadOnlyList<string>? NarrowOnMarkUsed { get; set; }

    public Task<int?> MarkUsedAsync(string agentId, ReadOnlyMemory<byte> grantHash, IReadOnlyList<string> heldScopes, IReadOnlyList<string> scopes, DateTimeOffset usedAt, CancellationToken cancellationToken = default)
    {
        var index = Stored.FindIndex(g => g.AgentId == agentId && g.GrantHash.Span.SequenceEqual(grantHash.Span) && g.RevokedAt is null);
        if (index < 0 || RevokeOnMarkUsed) return Task.FromResult<int?>(null);
        if (NarrowOnMarkUsed is { } narrowed)
        {
            NarrowOnMarkUsed = null;
            Stored[index] = Stored[index] with { Scopes = narrowed, Renewals = Stored[index].Renewals + 1 };
        }

        if (!Stored[index].Scopes.SequenceEqual(heldScopes, StringComparer.Ordinal)) return Task.FromResult<int?>(null);
        Stored[index] = Stored[index] with { Scopes = scopes, LastUsedAt = usedAt, Renewals = Stored[index].Renewals + 1 };
        return Task.FromResult<int?>(Stored[index].Renewals);
    }

    public Task<int> RevokeByTaskAsync(string agentId, string taskId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}

internal sealed class InMemoryAudit : IAuditWriter
{
    public List<AuditEvent> Events { get; } = [];

    /// <summary>How many times the writer was called, not how many records it was given. This is
    /// what the exchange's cost is counted in.</summary>
    public int Appends { get; private set; }

    public Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default) { Appends++; Events.Add(auditEvent); return Task.FromResult((long)Events.Count); }

    public Task AppendAsync(IReadOnlyList<AuditEvent> auditEvents, CancellationToken cancellationToken = default) { Appends++; Events.AddRange(auditEvents); return Task.CompletedTask; }
}

/// <summary>No transaction: work runs as is. A throw inside still surfaces, which is all the service tests need.</summary>
internal sealed class PassThroughUnitOfWork : IUnitOfWork
{
    public Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> work, CancellationToken cancellationToken = default) => work(cancellationToken);
}
