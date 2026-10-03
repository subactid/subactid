using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.IntegrationTests.Tokens;
using SubactId.Storage.Ef.Schema;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Revocation;

[Collection(PostgresCollection.Name)]
public class RevocationEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private HttpClient admin = null!;
    private string agentId = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);
        factory.Keycloak.Users[Human] = true;
        client = factory.CreateClient();
        admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
        agentId = UniqueId("jira-triage");
        using var created = await admin.PostAsync("/admin/agents", new StringContent($$"""
            {"agent_id": "{{agentId}}", "display_name": "Jira triage", "allowed_scopes": ["jira:read", "jira:comment"],
             "allowed_audiences": ["https://jira.internal"], "max_task_ttl": "PT30M", "max_token_ttl": "PT5M", "max_delegation_depth": 2,
             "jwks_uri": "https://agents.example.test/{{agentId}}/jwks.json"}
            """, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        admin.Dispose();
        await factory.DisposeAsync();
    }

    [Fact]
    public async Task An_operator_kills_a_task_its_grant_stops_refreshing_and_a_repeat_is_a_no_op()
    {
        var (taskId, grant, _) = await ExchangeAsync();

        using var killed = await admin.DeleteAsync($"/admin/tasks/{taskId}");
        Assert.Equal(HttpStatusCode.OK, killed.StatusCode);
        Assert.Equal(1, (await killed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked_tasks").GetInt32());

        using var refresh = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant)));
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        Assert.Equal("access_denied", (await refresh.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        using var again = await admin.DeleteAsync($"/admin/tasks/{taskId}");
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(0, (await again.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked_tasks").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/admin/tasks/{UniqueId("task")}")).StatusCode);

        await using var db = postgres.CreateDbContext();
        var revokedEvents = await db.AuditEvents.AsNoTracking().Where(e => e.TaskId == taskId && e.Event == AuditEvents.TaskRevoked).ToListAsync();
        var record = Assert.Single(revokedEvents);
        Assert.Equal((agentId, Human, "operator_kill_switch"), (record.AgentId, record.Sponsor, record.Reason));
        Assert.Equal((TaskRow.StatusRevoked, "operator_kill_switch"), (await db.Tasks.AsNoTracking().Where(t => t.TaskId == taskId).Select(t => new { t.Status, t.RevocationReason }).SingleAsync()) is { } row ? (row.Status, row.RevocationReason) : default);
        Assert.Single(await db.Revocations.AsNoTracking().Where(r => r.TaskId == taskId).ToListAsync());
    }

    [Fact]
    public async Task An_operator_kills_every_task_of_an_agent()
    {
        await ExchangeAsync();
        await ExchangeAsync();

        using var killed = await admin.DeleteAsync($"/admin/agents/{agentId}/tasks");
        Assert.Equal(HttpStatusCode.OK, killed.StatusCode);
        Assert.Equal(2, (await killed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked_tasks").GetInt32());
        Assert.Equal(0, (await (await admin.DeleteAsync($"/admin/agents/{agentId}/tasks")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked_tasks").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/admin/agents/{UniqueId("ghost")}/tasks")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.DeleteAsync($"/admin/agents/{agentId}/tasks")).StatusCode);

        await using var db = postgres.CreateDbContext();
        Assert.Equal(0, await db.Tasks.AsNoTracking().CountAsync(t => t.AgentId == agentId && t.Status == TaskRow.StatusActive));
        Assert.Single(await db.Revocations.AsNoTracking().Where(r => r.AgentId == agentId).ToListAsync());
    }

    [Fact]
    public async Task A_task_renewed_more_than_once_ends_with_one_renewal_summary_before_its_revocation_record()
    {
        var (taskId, grant, _) = await ExchangeAsync();
        foreach (var _ in Enumerable.Range(0, 3))
        {
            using var renewed = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant)));
            Assert.Equal(HttpStatusCode.OK, renewed.StatusCode);
        }

        using var revoked = await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke(grant, "refresh_token")));
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);

        // The first renewal as it happened, the two after it as one summary carrying their count,
        // then the end of the task — in that order, in the same append.
        await using var db = postgres.CreateDbContext();
        var events = await db.AuditEvents.AsNoTracking().Where(e => e.TaskId == taskId).OrderBy(e => e.Seq).Select(e => new { e.Event, e.Jti, e.Decision, e.Count, e.Reason }).ToListAsync();
        Assert.Equal([AuditEvents.TokenIssued, AuditEvents.TokenRefreshed, AuditEvents.TokenRefreshed, AuditEvents.TaskRevoked], events.Select(e => e.Event));
        Assert.NotNull(events[1].Jti);
        Assert.Null(events[1].Count);
        Assert.Null(events[2].Jti);
        Assert.Equal(2, events[2].Count);
        Assert.Equal("allow", events[2].Decision);
        Assert.Equal("client_revoked", events[3].Reason);
        Assert.Null(events[3].Count);
        Assert.Equal(3, (await db.Set<TaskGrantRow>().AsNoTracking().SingleAsync(g => g.TaskId == taskId)).Renewals);
    }

    [Fact]
    public async Task A_disabled_agent_can_still_revoke_its_own_grant_and_gets_the_same_empty_200()
    {
        var (taskId, grant, _) = await ExchangeAsync();
        using var disabled = await admin.PatchAsync($"/admin/agents/{agentId}", new StringContent("""{"enabled": false}""", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);

        using var revoked = await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke(grant)));

        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Equal(0, revoked.Content.Headers.ContentLength);
        await using var db = postgres.CreateDbContext();
        var task = await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId);
        Assert.Equal((TaskRow.StatusRevoked, "client_revoked"), (task.Status, task.RevocationReason));
        Assert.True(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.TaskId == taskId && e.Event == AuditEvents.TaskRevoked && e.Reason == "client_revoked"));
    }

    [Fact]
    public async Task An_agent_revokes_its_grant_or_its_token_and_anything_else_is_the_same_empty_200()
    {
        var (taskId, grant, jti) = await ExchangeAsync();
        var (_, _, otherJti) = await ExchangeAsync();
        var accessToken = (await ExchangeBodyAsync()).GetProperty("access_token").GetString()!;

        using var byToken = await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke(accessToken, "access_token")));
        Assert.Equal(HttpStatusCode.OK, byToken.StatusCode);
        Assert.Equal(0, byToken.Content.Headers.ContentLength);
        Assert.Equal("no-store", byToken.Headers.CacheControl?.ToString());
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke(accessToken)))).StatusCode);

        using var byGrant = await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke(grant, "refresh_token")));
        Assert.Equal(HttpStatusCode.OK, byGrant.StatusCode);
        using var refresh = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant)));
        Assert.Equal("access_denied", (await refresh.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke("garbage")))).StatusCode);
        // An unrecognised hint is ignored (RFC 7009 section 2.1), so it is the same empty 200.
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(Revoke(grant, "id_token")))).StatusCode);
        var unauthenticated = Revoke(grant);
        unauthenticated.Remove("client_assertion");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(unauthenticated))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/oauth2/revoke", new StringContent("{}", Encoding.UTF8, "application/json"))).StatusCode);

        await using var db = postgres.CreateDbContext();
        var tokenRevocations = await db.Revocations.AsNoTracking().Where(r => r.Jti != null && r.RevokedBy == agentId).ToListAsync();
        var tokenRevocation = Assert.Single(tokenRevocations);
        Assert.Equal("client_revoked", tokenRevocation.Reason);
        Assert.Single(await db.AuditEvents.AsNoTracking().Where(e => e.Event == AuditEvents.TokenRevoked && e.Jti == tokenRevocation.Jti).ToListAsync());
        Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
        Assert.Equal("client_revoked", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).RevocationReason);
        _ = (jti, otherJti);
    }

    private async Task<(string TaskId, string Grant, string Jti)> ExchangeAsync()
    {
        var body = await ExchangeBodyAsync();
        using var payload = JsonDocument.Parse(System.Buffers.Text.Base64Url.DecodeFromChars(body.GetProperty("access_token").GetString()!.Split('.')[1]));
        return (body.GetProperty("task_id").GetString()!, body.GetProperty("refresh_token").GetString()!, payload.RootElement.GetProperty("jti").GetString()!);
    }

    private async Task<JsonElement> ExchangeBodyAsync()
    {
        var now = DateTimeOffset.UtcNow;
        using var response = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = Mint(IdpKey, IdpKid, new() { ["iss"] = IdpIssuer, ["sub"] = Human, ["aud"] = "subactid", ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["scope"] = "jira:read jira:comment" }),
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = Assertion(),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read jira:comment",
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private Dictionary<string, string> Refresh(string grant) => new()
    {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = grant,
        ["resource"] = "https://jira.internal",
        ["scope"] = "jira:read",
        ["client_assertion"] = Assertion(),
        ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    };

    private Dictionary<string, string> Revoke(string token, string? hint = null)
    {
        var form = new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_assertion"] = Assertion(),
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        };
        if (hint is not null) form["token_type_hint"] = hint;
        return form;
    }

    private string Assertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") });
    }
}
