using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using SubactId.IntegrationTests.Endpoints;
using SubactId.IntegrationTests.Tokens;
using SubactId.Tokens.Issuance;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Introspection;

/// <summary>A revoked token returns <c>active: false</c> immediately, before its <c>exp</c>.</summary>
[Collection(PostgresCollection.Name)]
public class IntrospectionEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
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
        // The exchange checks the human, so the stand-in identity provider must know them.
        // Otherwise every exchange is access_denied.
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
    public async Task A_revoked_token_is_inactive_immediately_before_its_exp_and_a_killed_task_shows_the_operators_reason()
    {
        var (taskId, accessToken) = await ExchangeAsync();
        var (otherTaskId, otherToken) = await ExchangeAsync();

        using var live = await Introspect(accessToken);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal("no-store", live.Headers.CacheControl?.ToString());
        var active = await live.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(active.GetProperty("active").GetBoolean());
        Assert.Equal(["active", "scope", "client_id", "sub", "act", "task", "aud", "iss", "exp", "iat", "jti", "task_id", "token_type"], active.EnumerateObject().Select(p => p.Name));
        Assert.Equal((taskId, Human), (active.GetProperty("task").GetProperty("id").GetString(), active.GetProperty("task").GetProperty("sponsor").GetString()));
        Assert.Equal((Human, "agent:" + agentId, "jira:read jira:comment", taskId), (active.GetProperty("sub").GetString(), active.GetProperty("client_id").GetString(), active.GetProperty("scope").GetString(), active.GetProperty("task_id").GetString()));
        Assert.Equal(1, active.GetProperty("act").GetProperty("depth").GetInt32());
        var exp = DateTimeOffset.FromUnixTimeSeconds(active.GetProperty("exp").GetInt64());

        // The agent revokes the token by jti. The next introspection, before exp, is inactive with the time and reason.
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = accessToken, ["client_assertion"] = Assertion(), ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }))).StatusCode);
        using var revoked = await Introspect(accessToken);
        var inactive = await revoked.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["active", "revoked_at", "revocation_reason"], inactive.EnumerateObject().Select(p => p.Name));
        Assert.False(inactive.GetProperty("active").GetBoolean());
        Assert.Equal("client_revoked", inactive.GetProperty("revocation_reason").GetString());
        var revokedAt = inactive.GetProperty("revoked_at").GetDateTimeOffset();
        Assert.True(revokedAt < exp.AddMinutes(-4), $"revoked at {revokedAt:O}, exp {exp:O}");
        Assert.True(DateTimeOffset.UtcNow < exp);

        // An operator kills the other task; its token is inactive with the operator's reason.
        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync($"/admin/tasks/{otherTaskId}")).StatusCode);
        var killed = await (await Introspect(otherToken)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal((false, "operator_kill_switch"), (killed.GetProperty("active").GetBoolean(), killed.GetProperty("revocation_reason").GetString()));

        // No other token is affected.
        Assert.Equal("""{"active":false}""", await (await Introspect("garbage")).Content.ReadAsStringAsync());
        Assert.Equal("""{"active":false}""", await (await client.PostAsync("/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = TaskGrantSecret.New(), ["token_type_hint"] = "refresh_token" }))).Content.ReadAsStringAsync());

        // Disabling the agent makes its remaining tokens inactive at once.
        var (_, thirdToken) = await ExchangeAsync();
        Assert.Equal(HttpStatusCode.OK, (await admin.PatchAsync($"/admin/agents/{agentId}", new StringContent("{\"enabled\": false}", Encoding.UTF8, "application/json"))).StatusCode);
        Assert.Equal("""{"active":false,"revocation_reason":"agent_disabled"}""", await (await Introspect(thirdToken)).Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string>()))).StatusCode);
    }

    private Task<HttpResponseMessage> Introspect(string token) =>
        client.PostAsync("/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token, ["token_type_hint"] = "access_token" }));

    private async Task<(string TaskId, string AccessToken)> ExchangeAsync()
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
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return (body.GetProperty("task_id").GetString()!, body.GetProperty("access_token").GetString()!);
    }

    private string Assertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") });
    }
}
