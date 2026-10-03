using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Core.Tokens;
using SubactId.Server.Audit;
using SubactId.Server.Contracts;
using SubactId.Server.Introspection;
using SubactId.Server.Tokens;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using SubactId.UnitTests.Revocation;
using SubactId.UnitTests.Tokens.ClientAuth;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;
using static SubactId.UnitTests.NoAggregationHelper;

namespace SubactId.UnitTests.Introspection;

public class IntrospectionServiceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private static readonly Uri Issuer = new(ClientAuthTestData.SubactIdIssuer);
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 12, 0, 0, TimeSpan.Zero);

    private sealed class Harness
    {
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryRevocations Revocations { get; } = new();
        public SigningKeySet Keys { get; } = SigningKeySet.CreateEphemeral();
        public Agent Agent { get; init; } = ClientAuthTestData.Agent("jira-triage");
        public DelegationTask Task { get; init; } = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddMinutes(-5), Now.AddMinutes(25), null, null);

        public InMemoryAgentRepository Agents { get; } = new();
        public InMemoryAudit Audit { get; } = new();

        public IntrospectionService Build()
        {
            Tasks.Stored.Add(Task);
            Agents.AddAsync(Agent).GetAwaiter().GetResult();
            return new IntrospectionService(Keys, Revocations, Tasks, Agents, new TokenAudit(Audit, Clock, NoAggregation(Clock)), Clock);
        }

        public string Token(string jti = "tok_1", SigningKeySet? keys = null) =>
            TaskTokenSerializer.Sign(keys ?? Keys, TaskTokenClaims.Issue(Issuer, Task, Agent, ["jira:read"], "pod-7f9c4b", null, TimeSpan.FromMinutes(5), Now, jti));
    }

    private static string Json(IntrospectionResponse response) => JsonSerializer.Serialize(response, SubactIdJson.CreateOptions());

    [Fact]
    public async Task A_live_token_is_active_with_its_claims_and_nothing_null_written()
    {
        var harness = new Harness();
        var token = harness.Token();

        var response = await harness.Build().IntrospectAsync(token);

        Assert.True(response.Active);
        Assert.Equal(("jira:read", "agent:jira-triage", Human, "https://jira.internal", ClientAuthTestData.SubactIdIssuer, "tok_1", "task_1", "Bearer"), (response.Scope, response.ClientId, response.Sub, response.Aud, response.Iss, response.Jti, response.TaskId, response.TokenType));
        Assert.Equal(Now.AddMinutes(5).ToUnixTimeSeconds(), response.Exp);
        Assert.Equal(Now.ToUnixTimeSeconds(), response.Iat);
        Assert.Equal("""{"sub":"agent:jira-triage","instance":"pod-7f9c4b","depth":1}""", response.Act!.Value.GetRawText());
        Assert.Equal(new IntrospectionTask("task_1", Now.AddMinutes(25).ToUnixTimeSeconds(), Human), response.Task);
        Assert.Null(response.IntrospectRequired);
        Assert.Null(response.RevokedAt);
        var json = Json(response);
        Assert.StartsWith("""{"active":true,"scope":"jira:read","client_id":"agent:jira-triage","sub":"f47ac10b""", json, StringComparison.Ordinal);
        Assert.DoesNotContain("null", json, StringComparison.Ordinal);
        Assert.DoesNotContain("revoked_at", json, StringComparison.Ordinal);
        Assert.DoesNotContain("introspect_required", json, StringComparison.Ordinal);
        Assert.Contains($$"""
            "task":{"id":"task_1","exp":{{Now.AddMinutes(25).ToUnixTimeSeconds()}},"sponsor":"{{Human}}"}
            """, json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_live_token_for_a_high_risk_audience_says_introspection_is_required()
    {
        var harness = new Harness { Agent = ClientAuthTestData.Agent("jira-triage") with { HighRiskAudiences = ["https://jira.internal"] } };
        var token = harness.Token();

        var response = await harness.Build().IntrospectAsync(token);

        Assert.True(response.IntrospectRequired);
        Assert.Contains("\"introspect_required\":true", Json(response), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_token_revoked_by_jti_is_inactive_at_once_with_the_time_and_reason_well_before_its_exp()
    {
        var harness = new Harness();
        var token = harness.Token("tok_r");
        var service = harness.Build();
        Assert.True((await service.IntrospectAsync(token)).Active);

        harness.Revocations.Stored.Add(new SubactId.Core.Revocation.Revocation("tok_r", null, null, null, null, Now.AddSeconds(30), "client_revoked", "jira-triage", Now.AddMinutes(5)));
        harness.Clock.Advance(TimeSpan.FromSeconds(31));
        var response = await service.IntrospectAsync(token);

        Assert.False(response.Active);
        Assert.Equal((Now.AddSeconds(30), "client_revoked"), (response.RevokedAt, response.RevocationReason));
        Assert.Equal("""{"active":false,"revoked_at":"2026-09-11T12:00:30Z","revocation_reason":"client_revoked"}""", Json(response));
        Assert.True(harness.Clock.GetUtcNow() < Now.AddMinutes(5));
    }

    [Fact]
    public async Task A_token_under_a_revoked_task_is_inactive_with_the_tasks_time_and_reason()
    {
        var harness = new Harness();
        var token = harness.Token();
        var service = harness.Build();
        harness.Tasks.Stored[0] = harness.Task with { Status = DelegationTaskStatus.Revoked, RevokedAt = Now.AddMinutes(1), RevocationReason = "operator_kill_switch" };

        var response = await service.IntrospectAsync(token);

        Assert.Equal((false, Now.AddMinutes(1), "operator_kill_switch"), (response.Active, response.RevokedAt, response.RevocationReason));
        Assert.Null(response.Sub);
    }

    [Fact]
    public async Task A_token_whose_task_ran_out_is_plainly_inactive_because_expiry_is_not_a_revocation()
    {
        // Swept: the task is marked expired.
        var swept = new Harness();
        var sweptToken = swept.Token();
        var sweptService = swept.Build();
        swept.Tasks.Stored[0] = swept.Task with { Status = DelegationTaskStatus.Expired };
        var response = await sweptService.IntrospectAsync(sweptToken);
        Assert.Equal((false, null, null), (response.Active, response.RevokedAt, response.RevocationReason));

        Assert.Equal("""{"active":false}""", Json(response));

        // A token never outlives its task (invariant 3), so an unswept task past its expiry always has an expired token, which is plain inactive.
        var unswept = new Harness { Task = new("task_1", "jira-triage", Human, Human, null, null, 1, "https://jira.internal", ["jira:read", "jira:comment"], DelegationTaskStatus.Active, Now.AddMinutes(-28), Now.AddMinutes(2), null, null) };
        var token = unswept.Token();
        var service = unswept.Build();
        unswept.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.True((await service.IntrospectAsync(token)).Active);
        unswept.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(token)));
    }

    [Fact]
    public async Task An_expired_token_and_anything_that_is_not_our_token_are_inactive_with_nothing_else()
    {
        var harness = new Harness();
        var service = harness.Build();
        var token = harness.Token();
        using var otherKeys = SigningKeySet.CreateEphemeral();

        foreach (var candidate in new[] { "not-a-token", "", harness.Token(keys: otherKeys), TaskGrantSecret.New() })
        {
            Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(candidate)));
        }

        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(null)));
        harness.Clock.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(token)));
    }

    [Fact]
    public async Task A_token_of_ours_that_is_not_a_task_token_is_inactive()
    {
        var harness = new Harness();
        var service = harness.Build();
        var payload = System.Text.Encoding.UTF8.GetBytes("{\"iss\":\"subactid\",\"sub\":\"subactid\",\"aud\":\"https://idp/token\",\"exp\":" + Now.AddMinutes(1).ToUnixTimeSeconds() + ",\"jti\":\"kc_1\"}");

        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(Jws.Sign(harness.Keys, payload, typ: "JWT"))));
    }

    [Theory]
    [InlineData("JWT")]
    [InlineData("health")]
    public async Task A_task_token_payload_signed_with_another_typ_is_not_a_task_token(string typ)
    {
        // The same keys sign the control plane's client assertion to the identity provider and its
        // health probe. Only a token typed at+jwt is read as a task token.
        var harness = new Harness();
        var service = harness.Build();
        var payload = TaskTokenSerializer.ToJson(TaskTokenClaims.Issue(Issuer, harness.Task, harness.Agent, ["jira:read"], null, null, TimeSpan.FromMinutes(5), Now, "tok_1"));

        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(Jws.Sign(harness.Keys, payload, typ: typ))));
        Assert.True((await service.IntrospectAsync(Jws.Sign(harness.Keys, payload))).Active);
    }

    [Fact]
    public async Task A_token_of_a_disabled_agent_is_inactive_with_the_reason_and_nothing_else()
    {
        var harness = new Harness();
        var token = harness.Token();
        var service = harness.Build();
        await harness.Agents.UpdateAsync(harness.Agent with { Enabled = false });

        var response = await service.IntrospectAsync(token);

        Assert.Equal("""{"active":false,"revocation_reason":"agent_disabled"}""", Json(response));
        await harness.Agents.DeleteAsync(harness.Agent.AgentId);
        Assert.Equal("""{"active":false,"revocation_reason":"agent_disabled"}""", Json(await service.IntrospectAsync(token)));
    }

    [Theory]
    [InlineData("sub", "\"agent:jira-triage\"")]
    [InlineData("client_id", "\"jira-triage\"")]
    [InlineData("client_id", "\"agent:\"")]
    [InlineData("act", "\"agent:jira-triage\"")]
    [InlineData("task", "\"task_1\"")]
    [InlineData("task", "{\"id\":\"task_1\",\"sponsor\":\"f47ac10b-58cc-4372-a567-0e02b2c3d479\"}")]
    [InlineData("jti", "42")]
    [InlineData("exp", "\"soon\"")]
    public async Task A_signed_payload_with_a_claim_of_the_wrong_shape_is_not_a_task_token(string claim, string value)
    {
        var harness = new Harness();
        var service = harness.Build();
        var payload = System.Text.Encoding.UTF8.GetString(TaskTokenSerializer.ToJson(TaskTokenClaims.Issue(Issuer, harness.Task, harness.Agent, ["jira:read"], null, null, TimeSpan.FromMinutes(5), Now, "tok_1")));
        using var document = JsonDocument.Parse(payload);
        var members = document.RootElement.EnumerateObject().Select(p => p.Name == claim ? $"\"{claim}\":{value}" : $"\"{p.Name}\":{p.Value.GetRawText()}");
        var tampered = "{" + string.Join(",", members) + "}";
        var token = Jws.Sign(harness.Keys, System.Text.Encoding.UTF8.GetBytes(tampered));

        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(token)));
    }

    [Fact]
    public async Task The_hint_is_ignored_and_a_bad_request_is_an_error_with_a_denial_record()
    {
        var harness = new Harness();
        var service = harness.Build();
        var token = harness.Token();

        Assert.True((await service.IntrospectAsync(new IntrospectTokenRequest(token, "refresh_token"), [])).Response!.Active);
        Assert.True((await service.IntrospectAsync(new IntrospectTokenRequest(token, "whatever"), [])).Response!.Active);
        Assert.False((await service.IntrospectAsync(new IntrospectTokenRequest(TaskGrantSecret.New(), "refresh_token"), [])).Response!.Active);

        var missing = await service.IntrospectAsync(new IntrospectTokenRequest(null, null), []);
        Assert.Null(missing.Response);
        Assert.Equal(OAuthErrorResponse.InvalidRequest, missing.Error!.Error);
        Assert.Equal("invalid_request", Assert.Single(harness.Audit.Events).Reason);
    }

    [Fact]
    public async Task A_token_whose_task_is_unknown_is_inactive()
    {
        var harness = new Harness();
        var token = harness.Token();
        var service = harness.Build();
        harness.Tasks.Stored.Clear();

        Assert.Equal("""{"active":false}""", Json(await service.IntrospectAsync(token)));
    }
}

public class IntrospectTokenRequestTests
{
    [Fact]
    public void Token_is_required_and_bounded_and_the_hint_is_free_text()
    {
        Assert.Equal("token", Assert.Single(new IntrospectTokenRequest(null, null).Validate()).Field);
        Assert.Empty(new IntrospectTokenRequest("eyJ", null).Validate());
        Assert.Empty(new IntrospectTokenRequest("eyJ", "anything").Validate());
        Assert.Equal("token", Assert.Single(new IntrospectTokenRequest(new string('a', 8193), null).Validate()).Field);
    }
}
