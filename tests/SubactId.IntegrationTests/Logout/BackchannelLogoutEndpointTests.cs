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
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Logout;

/// <summary>
/// The back-channel logout receiver over HTTP against a real database. A session logout ends
/// that session's tasks, a subject logout ends all of the person's, an invalid token changes
/// nothing, and a repeated token ends them once.
/// </summary>
[Collection(PostgresCollection.Name)]
public class BackchannelLogoutEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private string agentId = null!;
    private string human = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);
        human = UniqueId("human");
        factory.Keycloak.Users[human] = true;
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
    public async Task A_session_logout_ends_that_sessions_tasks_and_leaves_the_others()
    {
        var here = await ExchangeAsync(Session(1));
        var elsewhere = await ExchangeAsync(Session(2));
        var sessionless = await ExchangeAsync(null);

        using var response = await PostAsync(LogoutToken(sessionId: Session(1)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == here)).Status);
        Assert.Equal("sponsor_logged_out", (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == here)).RevocationReason);
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == elsewhere)).Status);
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == sessionless)).Status);
    }

    [Fact]
    public async Task A_subject_logout_ends_every_task_of_that_person_and_they_may_start_again()
    {
        var first = await ExchangeAsync(Session(1));
        var second = await ExchangeAsync(null);

        using var response = await PostAsync(LogoutToken());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using (var db = postgres.CreateDbContext())
        {
            Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == first)).Status);
            Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == second)).Status);

            var events = await db.AuditEvents.AsNoTracking().Where(e => e.Sponsor == human).ToListAsync();
            Assert.Contains(events, e => e.Event == AuditEvents.SponsorSignal && e.Reason == "sponsor_logged_out");
            Assert.Contains(events, e => e.Event == AuditEvents.TaskRevoked && e.Reason == "sponsor_logged_out");
        }

        // Signing out is not being disabled, so a new sign-in starts a new task.
        await ExchangeAsync(null);
    }

    [Fact]
    public async Task A_subject_token_of_a_logged_out_session_cannot_start_a_new_task_even_with_nothing_running()
    {
        // The session ends before any task was started from it; its access token is still valid.
        var stale = SubjectToken(Session(1));
        using (var logout = await PostAsync(LogoutToken(sessionId: Session(1))))
        {
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        var before = await LastSeqAsync();
        using var refused = await ExchangeResponseAsync(stale);

        await AssertSignedOutAsync(refused, before);

        // Other sessions of the same person are untouched, and the person is not blocked.
        await ExchangeAsync(Session(2));
        await ExchangeAsync(null);
    }

    [Fact]
    public async Task A_subject_token_issued_before_a_logout_of_the_person_cannot_start_a_new_task()
    {
        var stale = SubjectToken(Session(1), DateTimeOffset.UtcNow.AddMinutes(-1));
        using (var logout = await PostAsync(LogoutToken()))
        {
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        var before = await LastSeqAsync();
        using var refused = await ExchangeResponseAsync(stale);

        await AssertSignedOutAsync(refused, before);

        // Signing in again issues a newer token, which starts a task.
        await ExchangeAsync(Session(2));
    }

    [Fact]
    public async Task The_same_logout_token_twice_ends_the_tasks_once_and_is_accepted_both_times()
    {
        // A resent logout gets a 200 that does nothing.
        var taskId = await ExchangeAsync(null);
        var token = LogoutToken();

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(token)).StatusCode);

        using var replay = await PostAsync(token);

        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(1, await db.AuditEvents.AsNoTracking().CountAsync(e => e.Sponsor == human && e.Event == AuditEvents.SponsorSignal));
        Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
    }

    [Fact]
    public async Task A_token_that_does_not_validate_changes_nothing()
    {
        var taskId = await ExchangeAsync(null);

        // Signed with a key the identity provider does not publish.
        using var forged = await PostAsync(Mint(System.Security.Cryptography.RSA.Create(2048), IdpKid, LogoutClaims()));

        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
    }

    [Fact]
    public async Task A_request_that_is_not_a_form_or_carries_no_token_is_refused()
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(null)).StatusCode);

        using var notAForm = await client.PostAsync("/backchannel-logout", new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, notAForm.StatusCode);
    }

    [Fact]
    public async Task A_session_id_with_a_nul_is_refused_at_the_exchange_and_at_the_logout_rather_than_failing_in_storage()
    {
        var now = DateTimeOffset.UtcNow;
        using var exchange = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = Mint(IdpKey, IdpKid, new() { ["iss"] = IdpIssuer, ["sub"] = human, ["aud"] = "subactid", ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["scope"] = "jira:read", ["sid"] = "session\u00001" }),
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = Assertion(),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read",
        }));
        Assert.Equal(HttpStatusCode.BadRequest, exchange.StatusCode);
        Assert.Equal("invalid_grant", (await exchange.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        var claims = LogoutClaims(sessionId: "session\u00001");
        using var logout = await PostAsync(Mint(IdpKey, IdpKid, claims));
        Assert.Equal(HttpStatusCode.BadRequest, logout.StatusCode);

        claims = LogoutClaims();
        claims["jti"] = "jti\u00001";
        using var replayProof = await PostAsync(Mint(IdpKey, IdpKid, claims));
        Assert.Equal(HttpStatusCode.BadRequest, replayProof.StatusCode);

        await using var db = postgres.CreateDbContext();
        Assert.True(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Event == AuditEvents.TokenDenied && e.Reason == "session_id_malformed" && e.Sponsor == human));
    }

    [Fact]
    public async Task A_body_that_is_not_a_form_is_refused_uncached_and_recorded()
    {
        var before = await LastSeqAsync();

        using var notAForm = await client.PostAsync("/backchannel-logout", new StringContent("{}", Encoding.UTF8, "application/json"));

        await AssertRefusedAndRecordedAsync(notAForm, before);
    }

    [Fact]
    public async Task A_form_over_the_field_limit_is_refused_uncached_and_recorded_rather_than_failing()
    {
        var before = await LastSeqAsync();
        var fields = string.Join('&', Enumerable.Range(0, 1100).Select(i => $"a{i}="));

        using var oversized = await client.PostAsync("/backchannel-logout", new StringContent(fields, Encoding.UTF8, "application/x-www-form-urlencoded"));

        await AssertRefusedAndRecordedAsync(oversized, before);
    }

    [Fact]
    public async Task A_form_over_64_KiB_is_refused_uncached_and_recorded_as_malformed()
    {
        var taskId = await ExchangeAsync(null);
        var before = await LastSeqAsync();

        // A valid logout, padded past the limit: not read, so nothing ends.
        using var oversized = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["logout_token"] = LogoutToken(),
            ["pad"] = new string('a', 64 * 1024),
        }));

        await AssertRefusedAndRecordedAsync(oversized, before);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
    }

    private async Task<long> LastSeqAsync()
    {
        await using var db = postgres.CreateDbContext();
        return await db.AuditEvents.AsNoTracking().MaxAsync(e => (long?)e.Seq) ?? 0;
    }

    private async Task AssertRefusedAndRecordedAsync(HttpResponseMessage response, long before)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("invalid_request", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        await using var db = postgres.CreateDbContext();
        var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Seq > before && e.Event == AuditEvents.SignalDenied).SingleAsync();
        Assert.Equal(("deny", "logout_malformed", (string?)null), (denial.Decision, denial.Reason, denial.Sponsor));
    }

    /// <summary>
    /// A session id of this test's own. Identity providers do not reuse them, and a session logged
    /// out by another test stays logged out in the shared database.
    /// </summary>
    private string Session(int number) => $"{human}-session-{number}";

    private Dictionary<string, object?> LogoutClaims(string? sessionId = null, string? subject = null)
    {
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = IdpIssuer,
            ["aud"] = ServerFactory.LogoutAudience,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["events"] = new Dictionary<string, object?> { [LogoutTokenValidator.LogoutEvent] = new Dictionary<string, object?>() },
        };
        if (sessionId is not null) claims["sid"] = sessionId;
        claims["sub"] = subject ?? human;
        return claims;
    }

    private string LogoutToken(string? sessionId = null) => Mint(IdpKey, IdpKid, LogoutClaims(sessionId));

    private Task<HttpResponseMessage> PostAsync(string? logoutToken) =>
        client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            logoutToken is null ? [] : new Dictionary<string, string> { ["logout_token"] = logoutToken }));

    private async Task<string> ExchangeAsync(string? sessionId)
    {
        using var response = await ExchangeResponseAsync(SubjectToken(sessionId));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("task_id").GetString()!;
    }

    private string SubjectToken(string? sessionId, DateTimeOffset? issuedAt = null)
    {
        var now = DateTimeOffset.UtcNow;
        var subject = new Dictionary<string, object?>
        {
            ["iss"] = IdpIssuer,
            ["sub"] = human,
            ["aud"] = "subactid",
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = (issuedAt ?? now).ToUnixTimeSeconds(),
            ["scope"] = "jira:read jira:comment",
        };
        if (sessionId is not null) subject["sid"] = sessionId;
        return Mint(IdpKey, IdpKid, subject);
    }

    private Task<HttpResponseMessage> ExchangeResponseAsync(string subjectToken) =>
        client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = Assertion(),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read jira:comment",
        }));

    /// <summary>Asserts <paramref name="response"/> is the signed-out refusal, recorded as a denial naming the agent and the person.</summary>
    private async Task AssertSignedOutAsync(HttpResponseMessage response, long before)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.False(body.TryGetProperty("reason", out _));

        await using var db = postgres.CreateDbContext();
        var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Seq > before && e.Event == AuditEvents.TokenDenied).SingleAsync();
        Assert.Equal(("deny", "subject_logged_out", human, agentId), (denial.Decision, denial.Reason, denial.Sponsor, denial.AgentId));
        Assert.False(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Seq > before && e.Event == AuditEvents.TokenIssued));
    }

    private string Assertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") });
    }
}
