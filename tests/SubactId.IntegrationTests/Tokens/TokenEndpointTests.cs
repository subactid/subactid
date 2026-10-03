using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Storage.Ef.Schema;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Tokens;

[Collection(PostgresCollection.Name)]
public class TokenEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private string agentId = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);
        // The exchange checks the human, so the stand-in identity provider must know them.
        // Otherwise every exchange is access_denied.
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
    public async Task The_spec_exchange_answers_the_documented_response_with_a_verifiable_token_and_a_full_audit_trail()
    {
        var before = DateTimeOffset.UtcNow;
        using var response = await client.PostAsync("/oauth2/token", Form(Exchange()));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["access_token", "issued_token_type", "token_type", "expires_in", "scope", "refresh_token", "task_id", "task_expires_at"], body.EnumerateObject().Select(p => p.Name));
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal("jira:read jira:comment", body.GetProperty("scope").GetString());
        Assert.InRange(body.GetProperty("expires_in").GetInt64(), 295, 300);
        var taskId = body.GetProperty("task_id").GetString()!;
        var grantValue = body.GetProperty("refresh_token").GetString()!;
        Assert.StartsWith("task_", taskId, StringComparison.Ordinal);
        Assert.StartsWith("task_grant_", grantValue, StringComparison.Ordinal);
        Assert.EndsWith("Z", body.GetProperty("task_expires_at").GetString(), StringComparison.Ordinal);

        // The token verifies against the key the server publishes, and its claims are the spec's.
        using var serverKey = ECDsa.Create();
        serverKey.ImportFromPem(ServerFactory.SigningKeyPem);
        using var keys = new SigningKeySet([SigningKey.FromPrivateKey(serverKey, "test-key")], "test-key");
        Assert.True(Jws.TryVerify(keys, body.GetProperty("access_token").GetString(), out var header, out var payload));
        Assert.Equal("at+jwt", header!.Typ);
        using var claims = JsonDocument.Parse(payload!);
        var root = claims.RootElement;
        Assert.Equal(ServerFactory.Issuer, root.GetProperty("iss").GetString());
        Assert.Equal(Human, root.GetProperty("sub").GetString());
        Assert.Equal("https://jira.internal", root.GetProperty("aud").GetString());
        Assert.Equal("agent:" + agentId, root.GetProperty("act").GetProperty("sub").GetString());
        Assert.Equal(1, root.GetProperty("act").GetProperty("depth").GetInt32());
        Assert.Equal(taskId, root.GetProperty("task").GetProperty("id").GetString());
        Assert.Equal(Human, root.GetProperty("task").GetProperty("sponsor").GetString());
        var jti = root.GetProperty("jti").GetString();

        // Storage: an active task, and the grant under its hash only.
        await using var db = postgres.CreateDbContext();
        var task = await db.Set<TaskRow>().AsNoTracking().SingleAsync(t => t.TaskId == taskId);
        Assert.Equal((agentId, Human, 1, TaskRow.StatusActive), (task.AgentId, task.Sponsor, task.DelegationDepth, task.Status));
        Assert.Equal(["jira:read", "jira:comment"], task.Scopes);
        Assert.InRange(task.ExpiresAt, before.AddMinutes(30), DateTimeOffset.UtcNow.AddMinutes(30));
        var grant = await db.Set<TaskGrantRow>().AsNoTracking().SingleAsync(g => g.TaskId == taskId);
        Assert.Equal(TaskGrantSecret.Hash(grantValue), grant.GrantHash);
        Assert.Equal(agentId, grant.AgentId);

        // Audit: one record, token.issued, allow, attributed to the human and the agent. It also
        // records the task's creation, so nothing else is written for this task_id.
        var events = await db.AuditEvents.AsNoTracking().Where(e => e.TaskId == taskId).OrderBy(e => e.Seq).ToListAsync();
        var issued = Assert.Single(events);
        Assert.Equal(AuditEvents.TokenIssued, issued.Event);
        Assert.Equal(("allow", agentId, Human, "https://jira.internal", "jira:read jira:comment", 1), (issued.Decision, issued.AgentId, issued.Sponsor, issued.Audience, issued.Scope, issued.DelegationDepth));
        Assert.Equal(jti, issued.Jti);
    }

    [Fact]
    public async Task Every_documented_error_code_comes_back_as_an_oauth_error_body_and_a_denial_record()
    {
        var assertion = ActorAssertion();

        using var first = await client.PostAsync("/oauth2/token", Form(Exchange(actor: assertion)));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        await AssertError(Form(Exchange(actor: assertion)), HttpStatusCode.Unauthorized, "invalid_client", "actor_replayed");
        await AssertError(Form(Exchange(subject: SubjectToken(("exp", DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds())))), HttpStatusCode.BadRequest, "invalid_grant", "subject_expired");
        await AssertError(Form(Exchange(scope: "jira:admin")), HttpStatusCode.BadRequest, "invalid_scope", "scope_intersection_empty");
        await AssertError(Form(Exchange(resource: "https://db.internal")), HttpStatusCode.BadRequest, "invalid_target", "audience_not_allowed");
        await AssertError(Form(Exchange(grantType: "client_credentials")), HttpStatusCode.BadRequest, "unsupported_grant_type", "unsupported_grant_type");
        await AssertError(Form(Exchange(scope: "")), HttpStatusCode.BadRequest, "invalid_request", "invalid_request");
        await AssertError(new StringContent("{}", Encoding.UTF8, "application/json"), HttpStatusCode.BadRequest, "invalid_request", "invalid_request");

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
        Assert.Equal(HttpStatusCode.OK, (await admin.PatchAsync($"/admin/agents/{agentId}", new StringContent("{\"enabled\": false}", Encoding.UTF8, "application/json"))).StatusCode);
        await AssertError(Form(Exchange()), HttpStatusCode.BadRequest, "access_denied", "agent_disabled");
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/introspect")]
    [InlineData("/oauth2/revoke")]
    public async Task A_form_body_over_64_KiB_is_refused_as_invalid_request_uncached_and_recorded(string path)
    {
        long before;
        await using (var db = postgres.CreateDbContext())
        {
            before = await db.AuditEvents.AsNoTracking().MaxAsync(e => (long?)e.Seq) ?? 0;
        }

        var fields = Exchange();
        fields["pad"] = new string('a', 64 * 1024);

        using var response = await client.PostAsync(path, Form(fields));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("invalid_request", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        await using (var db = postgres.CreateDbContext())
        {
            var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Seq > before).SingleAsync();
            Assert.Equal((AuditEvents.TokenDenied, "deny", "invalid_request", (string?)null), (denial.Event, denial.Decision, denial.Reason, denial.Sponsor));
        }

        // The same exchange without the padding is well-formed.
        fields.Remove("pad");
        if (path == "/oauth2/token")
        {
            using var accepted = await client.PostAsync(path, Form(fields));
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        }
    }

    private async Task AssertError(HttpContent content, HttpStatusCode status, string error, string reason)
    {
        using var response = await client.PostAsync("/oauth2/token", content);

        Assert.Equal(status, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(error, body.GetProperty("error").GetString());
        Assert.False(string.IsNullOrEmpty(body.GetProperty("error_description").GetString()));
        Assert.DoesNotContain("eyJ", body.ToString(), StringComparison.Ordinal);

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

    private static FormUrlEncodedContent Form(Dictionary<string, string> fields) => new(fields);

    private Dictionary<string, string> Exchange(string? subject = null, string? actor = null, string resource = "https://jira.internal", string scope = "jira:read jira:comment", string grantType = GrantType) => new()
    {
        ["grant_type"] = grantType,
        ["subject_token"] = subject ?? SubjectToken(),
        ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        ["actor_token"] = actor ?? ActorAssertion(),
        ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
        ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        ["resource"] = resource,
        ["scope"] = scope,
    };

    private static string SubjectToken(params (string Key, object? Value)[] overrides)
    {
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = IdpIssuer,
            ["sub"] = Human,
            ["aud"] = "subactid",
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["scope"] = "openid jira:read jira:comment",
        };
        foreach (var (key, value) in overrides) claims[key] = value;
        return Mint(IdpKey, IdpKid, claims);
    }

    private string ActorAssertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new Dictionary<string, object?>
        {
            ["iss"] = agentId,
            ["sub"] = agentId,
            ["aud"] = ServerFactory.Issuer + "/oauth2/token",
            ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        });
    }
}
