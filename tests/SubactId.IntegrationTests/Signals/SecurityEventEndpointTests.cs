using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.IntegrationTests.Tokens;
using SubactId.Server.Signals;
using SubactId.Storage.Ef.Schema;
using SubactId.Tokens.Upstream;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Signals;

/// <summary>
/// The Shared Signals receiver over HTTP against a real database. An account disabled at the
/// identity provider ends that person's tasks and stops them starting another. A push that fails
/// either half of the guard changes nothing.
/// </summary>
[Collection(PostgresCollection.Name)]
public class SecurityEventEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
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
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.SsfBearerToken);
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
    public async Task An_account_disabled_event_ends_the_tasks_and_refuses_the_next_exchange()
    {
        var taskId = await ExchangeAsync();

        using var response = await PostAsync(Token(SecurityEventTokenValidator.AccountDisabled));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        await using var db = postgres.CreateDbContext();
        var task = await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId);
        Assert.Equal((TaskRow.StatusRevoked, "ssf_account_disabled"), (task.Status, task.RevocationReason));

        var events = await db.AuditEvents.AsNoTracking().Where(e => e.Sponsor == human).ToListAsync();
        Assert.Contains(events, e => e.Event == AuditEvents.SponsorSignal && e.Reason == "ssf_account_disabled");
        Assert.Contains(events, e => e.Event == AuditEvents.TaskRevoked && e.Reason == "ssf_account_disabled");

        using var refused = await ExchangeResponseAsync();
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("access_denied", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Sessions_being_revoked_ends_the_tasks_and_the_person_may_start_again()
    {
        var taskId = await ExchangeAsync();

        using var response = await PostAsync(Token(SecurityEventTokenValidator.SessionRevoked));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        await using (var db = postgres.CreateDbContext())
        {
            Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
        }

        // Sessions ending is not the account closing.
        await ExchangeAsync();
    }

    [Fact]
    public async Task Sessions_being_revoked_refuses_a_subject_token_issued_before_and_records_the_refusal()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.SessionRevoked, issuedAt: now))).StatusCode);

        long before;
        await using (var db = postgres.CreateDbContext())
        {
            // Nothing was running, and the signal is still on the record.
            Assert.True(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Sponsor == human && e.Event == AuditEvents.SponsorSignal && e.Reason == "ssf_sessions_revoked"));
            before = await db.AuditEvents.AsNoTracking().MaxAsync(e => (long?)e.Seq) ?? 0;
        }

        using var refused = await ExchangeResponseAsync(issuedAt: now.AddMinutes(-1));

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("invalid_grant", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        await using (var db = postgres.CreateDbContext())
        {
            var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Seq > before && e.Event == AuditEvents.TokenDenied).SingleAsync();
            Assert.Equal(("deny", "subject_logged_out", human, agentId), (denial.Decision, denial.Reason, denial.Sponsor, denial.AgentId));
        }

        // A token from a sign-in after the event starts a task.
        await ExchangeAsync();
    }

    [Fact]
    public async Task An_account_enabled_event_issued_before_the_disabling_does_not_lift_the_block()
    {
        // Delivered out of order: the enabling was issued first and arrives last.
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.AccountDisabled, issuedAt: now))).StatusCode);

        using (var late = await PostAsync(Token(SecurityEventTokenValidator.AccountEnabled, issuedAt: now.AddMinutes(-1))))
        {
            Assert.Equal(HttpStatusCode.Accepted, late.StatusCode);
        }

        using (var refused = await ExchangeResponseAsync())
        {
            Assert.Equal("access_denied", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }

        await using (var db = postgres.CreateDbContext())
        {
            var block = await db.SponsorBlocks.AsNoTracking().SingleAsync(b => b.SponsorKey == human);
            Assert.Equal(SponsorBlockRow.SourceSsf, block.Source);
            var watermark = await db.SignalWatermarks.AsNoTracking().SingleAsync(w => w.SponsorKey == human);
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds()), watermark.EventAt);
            var refusal = await db.AuditEvents.AsNoTracking().SingleAsync(e => e.Sponsor == human && e.Event == AuditEvents.SponsorUnblocked);
            Assert.Equal(("deny", "signal_out_of_order"), (refusal.Decision, refusal.Reason));
            Assert.False(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Sponsor == human && e.Reason == "ssf_account_enabled"));
        }

        // An enabling issued after it lifts it.
        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.AccountEnabled, issuedAt: now.AddSeconds(1)))).StatusCode);
        await ExchangeAsync();
    }

    [Fact]
    public async Task An_account_disabled_event_issued_before_an_enabling_already_applied_does_not_block_again()
    {
        // Disabled, then enabled again. A disabling issued between the two arrives last: it is
        // answered as delivered, blocks nobody, ends nothing, and its refusal is on the record.
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.AccountDisabled, issuedAt: now.AddMinutes(-2)))).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.AccountEnabled, issuedAt: now))).StatusCode);
        var taskId = await ExchangeAsync();

        using (var late = await PostAsync(Token(SecurityEventTokenValidator.AccountDisabled, issuedAt: now.AddMinutes(-1))))
        {
            Assert.Equal(HttpStatusCode.Accepted, late.StatusCode);
        }

        await using (var db = postgres.CreateDbContext())
        {
            Assert.False(await db.SponsorBlocks.AsNoTracking().AnyAsync(b => b.SponsorKey == human));
            Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
            var refusal = await db.AuditEvents.AsNoTracking().SingleAsync(e => e.Sponsor == human && e.Event == AuditEvents.SponsorBlocked);
            Assert.Equal(("deny", "signal_out_of_order"), (refusal.Decision, refusal.Reason));
            Assert.Equal(1, await db.AuditEvents.AsNoTracking().CountAsync(e => e.Sponsor == human && e.Reason == "ssf_account_disabled"));
        }

        await ExchangeAsync();
    }

    [Fact]
    public async Task An_account_enabled_event_lets_the_person_start_again()
    {
        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.AccountDisabled))).StatusCode);
        using (var refused = await ExchangeResponseAsync())
        {
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        }

        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enable-1"))).StatusCode);

        await ExchangeAsync();
    }

    [Fact]
    public async Task The_same_event_twice_is_acted_on_once_and_answered_as_delivered_both_times()
    {
        // A resent event gets the same 202 as the first time (RFC 8935).
        var taskId = await ExchangeAsync();
        var token = Token(SecurityEventTokenValidator.AccountDisabled);

        Assert.Equal(HttpStatusCode.Accepted, (await PostAsync(token)).StatusCode);

        using var replay = await PostAsync(token);

        Assert.Equal(HttpStatusCode.Accepted, replay.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(1, await db.AuditEvents.AsNoTracking().CountAsync(e => e.Sponsor == human && e.Event == AuditEvents.SponsorSignal));
        Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
    }

    [Fact]
    public async Task An_event_signed_by_the_identity_provider_rather_than_the_transmitter_changes_nothing()
    {
        // The transmitter and the identity provider are separate trust roots. A key that can mint a
        // subject token cannot end everybody's tasks.
        var taskId = await ExchangeAsync();

        using var forged = await PostAsync(Mint(IdpKey, IdpKid, Claims(SecurityEventTokenValidator.AccountDisabled, "forged")));

        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.Equal("invalid_key", (await forged.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("err").GetString());
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
    }

    [Fact]
    public async Task A_push_without_the_credential_changes_nothing_and_is_recorded()
    {
        var taskId = await ExchangeAsync();

        using var stranger = factory.CreateClient();
        using var refused = await stranger.PostAsync(SecurityEventEndpoints.EventsPath, Body(Token(SecurityEventTokenValidator.AccountDisabled)));

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        // authentication_failed and nothing more (spec section 6).
        var body = await refused.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["err"], body.EnumerateObject().Select(p => p.Name));
        Assert.Equal("authentication_failed", body.GetProperty("err").GetString());
        Assert.Equal("Bearer", refused.Headers.WwwAuthenticate.Single().Scheme);

        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);

        var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Event == AuditEvents.SsfDenied).OrderBy(e => e.Seq).LastAsync();
        Assert.Null(denial.Sponsor);
    }

    [Fact]
    public async Task A_body_that_is_not_a_security_event_token_is_refused()
    {
        using var wrongType = await client.PostAsync(SecurityEventEndpoints.EventsPath, new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, wrongType.StatusCode);
        Assert.Equal("invalid_request", (await wrongType.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("err").GetString());

        using var notAToken = await PostAsync("not-a-token");
        Assert.Equal(HttpStatusCode.BadRequest, notAToken.StatusCode);
    }

    [Fact]
    public async Task An_authenticated_push_that_is_not_a_security_event_token_by_type_is_recorded()
    {
        await using (var db = postgres.CreateDbContext())
        {
            var before = await db.AuditEvents.AsNoTracking().MaxAsync(e => (long?)e.Seq) ?? 0;

            using var wrongType = await client.PostAsync(SecurityEventEndpoints.EventsPath, new StringContent("{}", Encoding.UTF8, "application/json"));

            Assert.Equal(HttpStatusCode.BadRequest, wrongType.StatusCode);
            var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Seq > before && e.Event == AuditEvents.SignalDenied).SingleAsync();
            Assert.Equal(("deny", "ssf_malformed", (string?)null), (denial.Decision, denial.Reason, denial.Sponsor));
        }
    }

    [Fact]
    public async Task An_event_this_receiver_does_not_act_on_is_accepted_and_changes_nothing()
    {
        var taskId = await ExchangeAsync();

        using var response = await PostAsync(Mint(TransmitterKey, TransmitterKid, new Dictionary<string, object?>
        {
            ["iss"] = ServerFactory.TransmitterIssuer,
            ["aud"] = ServerFactory.StreamAudience,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = UniqueId("evt"),
            ["events"] = new Dictionary<string, object?>
            {
                ["https://schemas.openid.net/secevent/caep/event-type/credential-change"] = new Dictionary<string, object?>
                {
                    ["subject"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = IdpIssuer, ["sub"] = human },
                },
            },
        }));

        // Accepted, so the transmitter stops retrying, but not acted on.
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
    }

    private Dictionary<string, object?> Claims(string eventType, string jti, DateTimeOffset? issuedAt = null) => new()
    {
        ["iss"] = ServerFactory.TransmitterIssuer,
        ["aud"] = ServerFactory.StreamAudience,
        ["iat"] = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
        ["jti"] = jti,
        ["events"] = new Dictionary<string, object?>
        {
            [eventType] = new Dictionary<string, object?>
            {
                ["subject"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = IdpIssuer, ["sub"] = human },
            },
        },
    };

    private string Token(string eventType, string? jti = null, DateTimeOffset? issuedAt = null) =>
        Mint(TransmitterKey, TransmitterKid, Claims(eventType, jti ?? UniqueId("evt"), issuedAt));

    private static StringContent Body(string token) => new(token, Encoding.UTF8, SecurityEventEndpoints.MediaType);

    private Task<HttpResponseMessage> PostAsync(string token) => client.PostAsync(SecurityEventEndpoints.EventsPath, Body(token));

    private async Task<string> ExchangeAsync()
    {
        using var response = await ExchangeResponseAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("task_id").GetString()!;
    }

    private async Task<HttpResponseMessage> ExchangeResponseAsync(DateTimeOffset? issuedAt = null)
    {
        var now = DateTimeOffset.UtcNow;
        var subject = Mint(IdpKey, IdpKid, new()
        {
            ["iss"] = IdpIssuer,
            ["sub"] = human,
            ["aud"] = "subactid",
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = (issuedAt ?? now).ToUnixTimeSeconds(),
            ["scope"] = "jira:read jira:comment",
        });

        // Awaited before the client goes: disposing it while the request is in flight cancels it.
        using var exchange = factory.CreateClient();
        return await exchange.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subject,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = Assertion(),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read jira:comment",
        }));
    }

    private string Assertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") });
    }
}
