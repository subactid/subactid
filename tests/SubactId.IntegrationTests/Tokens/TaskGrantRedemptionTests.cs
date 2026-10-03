using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;
using SubactId.Storage.Postgres.Repositories;
using SubactId.Tokens.Grants;
using SubactId.Tokens.Issuance;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Tokens;

/// <summary>Against the real database: a grant is unusable by a different agent, and the stored value cannot be used to reconstruct the grant.</summary>
[Collection(PostgresCollection.Name)]
public class TaskGrantRedemptionTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private string agentId = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);
        // The exchange checks the human, so the stand-in identity provider must know them.
        // Otherwise every exchange is access_denied.
        factory.Keycloak.Users["f47ac10b-58cc-4372-a567-0e02b2c3d479"] = true;
        client = factory.CreateClient();
        agentId = UniqueId("jira-triage");

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
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
        await factory.DisposeAsync();
    }

    [Fact]
    public async Task A_grant_issued_by_the_exchange_is_redeemable_only_by_its_agent_and_only_by_its_plaintext()
    {
        using var response = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Exchange()));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var grantValue = body.GetProperty("refresh_token").GetString()!;
        var taskId = body.GetProperty("task_id").GetString()!;

        await using var db = postgres.CreateDbContext();
        var redeemer = new TaskGrantRedeemer(new EfTaskGrantRepository(db, postgres.Dialect), new EfTaskRepository(db, postgres.Dialect));
        var now = DateTimeOffset.UtcNow;

        // The plaintext never reaches the database: the row holds only its SHA-256, and no column contains the value.
        var row = await db.Set<TaskGrantRow>().AsNoTracking().SingleAsync(g => g.TaskId == taskId);
        Assert.Equal(TaskGrantSecret.Hash(grantValue), row.GrantHash);
        Assert.Equal(32, row.GrantHash.Length);
        var everything = string.Join("|", row.TaskId, row.AgentId, string.Join(' ', row.Scopes), Convert.ToHexString(row.GrantHash), Base64Url.EncodeToString(row.GrantHash));
        Assert.DoesNotContain(grantValue, everything, StringComparison.Ordinal);
        Assert.DoesNotContain(grantValue[TaskGrantSecret.Prefix.Length..], everything, StringComparison.Ordinal);

        // Its agent redeems it and gets the task back.
        var owner = await redeemer.RedeemAsync(NewAgent(agentId), grantValue, now);
        Assert.True(owner.IsAccepted);
        Assert.Equal(taskId, owner.Task!.TaskId);

        // Another registered agent cannot, with the very same value.
        var other = await redeemer.RedeemAsync(NewAgent(UniqueId("db-reader")), grantValue, now);
        Assert.Equal(TaskGrantRejection.NotFound, other.Reason);

        // What the database stores cannot be turned back into a grant.
        foreach (var reconstructed in new[] { TaskGrantSecret.Prefix + Base64Url.EncodeToString(row.GrantHash), Convert.ToHexString(row.GrantHash), Base64Url.EncodeToString(row.GrantHash) })
        {
            Assert.Equal(TaskGrantRejection.NotFound, (await redeemer.RedeemAsync(NewAgent(agentId), reconstructed, now)).Reason);
        }
    }

    private Dictionary<string, string> Exchange()
    {
        var now = DateTimeOffset.UtcNow;
        return new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = Mint(IdpKey, IdpKid, new() { ["iss"] = IdpIssuer, ["sub"] = "f47ac10b-58cc-4372-a567-0e02b2c3d479", ["aud"] = "subactid", ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["scope"] = "jira:read jira:comment" }),
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") }),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read jira:comment",
        };
    }
}
