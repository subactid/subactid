using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Storage.Ef.Schema;
using SubactId.Tokens.Issuance;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Tokens;

/// <summary>Through HTTP: widening fails, a narrowing sticks, refresh after task expiry is access_denied, and every refresh writes its own record.</summary>
[Collection(PostgresCollection.Name)]
public class TokenRefreshEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private string agentId = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);
        factory.Keycloak.Users[Human] = true;
        client = factory.CreateClient();
        agentId = UniqueId("jira-triage");

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
        using var created = await admin.PostAsync("/admin/agents", new StringContent($$"""
            {"agent_id": "{{agentId}}", "display_name": "Jira triage", "allowed_scopes": ["jira:read", "jira:comment", "confluence:read"],
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
    public async Task A_refresh_issues_a_new_token_under_the_same_task_and_the_first_renewal_is_recorded_as_it_happens()
    {
        var (taskId, grant, firstJti) = await ExchangeAsync();

        using var first = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant, "jira:read")));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var body = await first.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(taskId, body.GetProperty("task_id").GetString());
        Assert.Equal("jira:read", body.GetProperty("scope").GetString());
        Assert.Equal(grant, body.GetProperty("refresh_token").GetString());
        var refreshedJti = Jti(body.GetProperty("access_token").GetString()!);
        Assert.NotEqual(firstJti, refreshedJti);

        using var second = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant, "jira:read")));
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        // The first renewal is in the ledger straight away. The second is counted on the grant and
        // written as one summary when the task ends.
        await using var db = postgres.CreateDbContext();
        var events = await db.AuditEvents.AsNoTracking().Where(e => e.TaskId == taskId).OrderBy(e => e.Seq).Select(e => new { e.Event, e.Jti, e.Scope, e.Decision, e.Count }).ToListAsync();
        Assert.Equal([AuditEvents.TokenIssued, AuditEvents.TokenRefreshed], events.Select(e => e.Event));
        Assert.Equal((refreshedJti, "jira:read", (int?)null), (events[1].Jti, events[1].Scope, events[1].Count));
        Assert.Equal(2, events.Select(e => e.Jti).Distinct().Count());
        var row = await db.Set<TaskGrantRow>().AsNoTracking().SingleAsync(g => g.TaskId == taskId);
        Assert.Equal(2, row.Renewals);
        Assert.NotNull(row.LastUsedAt);
    }

    /// <summary>
    /// Disabling the user at the identity provider makes the next refresh fail, within one token
    /// lifetime. The server calls a stand-in for Keycloak's admin API through its real HTTP client,
    /// authenticating with a <c>private_key_jwt</c> the stand-in verifies against the server's
    /// published signing key.
    /// </summary>
    [Fact]
    public async Task Disabling_the_user_at_the_identity_provider_makes_the_next_refresh_fail()
    {
        var (taskId, grant, _) = await ExchangeAsync();

        using var before = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant, "jira:read")));
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        Assert.Equal(1, factory.Keycloak.VerifiedAssertions);

        factory.Keycloak.Users[Human] = false;
        factory.Clock.Advance(ServerFactory.SponsorCacheTtl + TimeSpan.FromSeconds(1));

        await AssertError(Refresh(grant, "jira:read"), HttpStatusCode.BadRequest, "access_denied", "sponsor_disabled");
        await using var db = postgres.CreateDbContext();
        var denial = await db.AuditEvents.AsNoTracking().OrderByDescending(e => e.Seq).FirstAsync();
        Assert.Equal((taskId, Human), (denial.TaskId, denial.Sponsor));

        factory.Keycloak.Users.TryRemove(Human, out _);
        factory.Clock.Advance(ServerFactory.SponsorCacheTtl + TimeSpan.FromSeconds(1));
        await AssertError(Refresh(grant, "jira:read"), HttpStatusCode.BadRequest, "access_denied", "sponsor_not_found");
    }

    [Fact]
    public async Task Widening_scope_on_refresh_fails_with_invalid_scope()
    {
        var (_, grant, _) = await ExchangeAsync();

        await AssertError(Refresh(grant, "jira:read confluence:read"), HttpStatusCode.BadRequest, "invalid_scope", "scope_widened");
    }

    [Fact]
    public async Task A_narrowed_refresh_sticks_and_a_later_refresh_asking_for_the_original_scope_is_invalid_scope()
    {
        var (taskId, grant, _) = await ExchangeAsync();

        using var narrowed = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant, "jira:read")));
        Assert.Equal(HttpStatusCode.OK, narrowed.StatusCode);

        await AssertError(Refresh(grant, "jira:read jira:comment"), HttpStatusCode.BadRequest, "invalid_scope", "scope_widened");
        await AssertError(Refresh(grant, "jira:comment"), HttpStatusCode.BadRequest, "invalid_scope", "scope_widened");

        using var again = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant, "jira:read")));
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(["jira:read"], (await db.Set<TaskGrantRow>().AsNoTracking().SingleAsync(g => g.TaskId == taskId)).Scopes);
    }

    [Fact]
    public async Task Concurrent_refreshes_never_leave_the_grant_wider_than_a_narrowing_that_succeeded()
    {
        var (taskId, grant, _) = await ExchangeAsync();

        var forms = Enumerable.Range(0, 12).Select(i => Refresh(grant, i % 2 == 0 ? "jira:read" : "jira:read jira:comment")).ToList();
        var responses = await Task.WhenAll(forms.Select(form => client.PostAsync("/oauth2/token", new FormUrlEncodedContent(form))));
        try
        {
            // Every narrowing request is within whatever the grant holds, so each one is issued.
            Assert.All(responses.Where((_, i) => i % 2 == 0), r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        await using var db = postgres.CreateDbContext();
        Assert.Equal(["jira:read"], (await db.Set<TaskGrantRow>().AsNoTracking().SingleAsync(g => g.TaskId == taskId)).Scopes);
        await AssertError(Refresh(grant, "jira:read jira:comment"), HttpStatusCode.BadRequest, "invalid_scope", "scope_widened");
    }

    [Fact]
    public async Task Refresh_after_the_task_expired_fails_with_access_denied()
    {
        var (taskId, grant, _) = await ExchangeAsync();
        await using (var db = postgres.CreateDbContext())
        {
            await db.Set<TaskRow>().Where(t => t.TaskId == taskId).ExecuteUpdateAsync(s => s.SetProperty(t => t.ExpiresAt, DateTimeOffset.UtcNow.AddSeconds(-1)));
        }

        await AssertError(Refresh(grant, "jira:read"), HttpStatusCode.BadRequest, "access_denied", "task_expired");
    }

    [Fact]
    public async Task An_unknown_grant_and_a_missing_client_assertion_are_refused()
    {
        var (_, grant, _) = await ExchangeAsync();

        await AssertError(Refresh(TaskGrantSecret.New(), "jira:read"), HttpStatusCode.BadRequest, "invalid_grant", "grant_not_found");
        var unauthenticated = Refresh(grant, "jira:read");
        unauthenticated.Remove("client_assertion");
        await AssertError(unauthenticated, HttpStatusCode.BadRequest, "invalid_request", "invalid_request");

        using var repeated = await client.PostAsync("/oauth2/token", new StringContent("grant_type=refresh_token&grant_type=refresh_token", Encoding.UTF8, "application/x-www-form-urlencoded"));
        Assert.Equal(HttpStatusCode.BadRequest, repeated.StatusCode);
        Assert.Equal("invalid_request", (await repeated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    private async Task AssertError(Dictionary<string, string> form, HttpStatusCode status, string error, string reason)
    {
        using var response = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(form));

        Assert.Equal(status, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(error, body.GetProperty("error").GetString());
        Assert.DoesNotContain("task_grant_", body.ToString(), StringComparison.Ordinal);

        // An access_denied tells the agent the reason on its record; nothing else carries one.
        if (error == "access_denied")
        {
            Assert.Equal(reason, body.GetProperty("reason").GetString());
        }
        else
        {
            Assert.False(body.TryGetProperty("reason", out _));
        }

        await using var db = postgres.CreateDbContext();
        var denial = await db.AuditEvents.AsNoTracking().OrderByDescending(e => e.Seq).FirstAsync();
        Assert.Equal((AuditEvents.TokenDenied, "deny", reason), (denial.Event, denial.Decision, denial.Reason));
    }

    private async Task<(string TaskId, string Grant, string Jti)> ExchangeAsync()
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
        return (body.GetProperty("task_id").GetString()!, body.GetProperty("refresh_token").GetString()!, Jti(body.GetProperty("access_token").GetString()!));
    }

    private Dictionary<string, string> Refresh(string grant, string scope) => new()
    {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = grant,
        ["resource"] = "https://jira.internal",
        ["scope"] = scope,
        ["client_assertion"] = Assertion(),
        ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    };

    private string Assertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") });
    }

    private static string Jti(string token)
    {
        using var payload = JsonDocument.Parse(System.Buffers.Text.Base64Url.DecodeFromChars(token.Split('.')[1]));
        return payload.RootElement.GetProperty("jti").GetString()!;
    }
}
