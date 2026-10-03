using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Core.Sponsors;
using SubactId.IntegrationTests.Endpoints;
using SubactId.IntegrationTests.Tokens;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Admin;

/// <summary>
/// The sponsor routes against a real database. Blocking a human ends their live tasks and stops
/// the next exchange, the kill switch alone does not, and an operator can lift only their own
/// block. Tasks are made by real exchanges.
/// </summary>
[Collection(PostgresCollection.Name)]
public class SponsorEndpointsTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private HttpClient admin = null!;
    private string agentId = null!;
    private string human = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);

        // A human unique to this test, because a block outlives one case.
        human = UniqueId("human");
        factory.Keycloak.Users[human] = true;
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
    public async Task Blocking_a_human_ends_their_tasks_and_stops_the_next_exchange()
    {
        var (taskId, grant) = await ExchangeAsync();

        using var blocked = await admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block", null);

        Assert.Equal(HttpStatusCode.OK, blocked.StatusCode);
        var body = await blocked.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, body.GetProperty("revoked_tasks").GetInt32());
        Assert.Equal(human, body.GetProperty("sponsor").GetProperty("sponsor_key").GetString());
        Assert.Equal("admin", body.GetProperty("sponsor").GetProperty("source").GetString());
        Assert.Equal("disabled", body.GetProperty("sponsor").GetProperty("kind").GetString());

        // The task is revoked, so its grant is dead.
        await using (var db = postgres.CreateDbContext())
        {
            var task = await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId);
            Assert.Equal((TaskRow.StatusRevoked, "sponsor_blocked"), (task.Status, task.RevocationReason));
        }

        using var refreshed = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Refresh(grant)));
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);

        // The agent is told the task is over, not merely that the person is refused for now.
        var ended = await refreshed.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(("access_denied", "task_revoked"), (ended.GetProperty("error").GetString(), ended.GetProperty("reason").GetString()));

        // And they cannot start another, even though the identity provider still has them enabled.
        using var again = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Exchange()));
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        var error = await again.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("access_denied", error.GetProperty("error").GetString());
        Assert.Equal("sponsor_disabled", error.GetProperty("reason").GetString());

        await using var ledger = postgres.CreateDbContext();
        var events = await ledger.AuditEvents.AsNoTracking().Where(e => e.Sponsor == human).ToListAsync();
        Assert.Contains(events, e => e.Event == AuditEvents.SponsorBlocked);
        Assert.Contains(events, e => e.Event == AuditEvents.TaskRevoked && e.Reason == "sponsor_blocked");
        Assert.Contains(events, e => e.Event == AuditEvents.TokenDenied && e.Reason == "sponsor_disabled");
    }

    [Fact]
    public async Task The_block_is_visible_until_an_operator_lifts_it_and_then_the_human_may_start_again()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}")).StatusCode);

        using var blocked = await admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block", null);
        Assert.Equal(HttpStatusCode.OK, blocked.StatusCode);

        using var read = await admin.GetAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}");
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal("admin", (await read.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("source").GetString());

        using var lifted = await admin.DeleteAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block");
        Assert.Equal(HttpStatusCode.NoContent, lifted.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block")).StatusCode);

        await ExchangeAsync();
    }

    [Fact]
    public async Task Blocking_again_keeps_the_block_as_placed_and_records_it_once()
    {
        using var first = await admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block", null);
        var placedAt = (await first.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("sponsor").GetProperty("blocked_at").GetString();
        factory.Clock.Advance(TimeSpan.FromMinutes(1));

        using var second = await admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block", null);

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(placedAt, (await second.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("sponsor").GetProperty("blocked_at").GetString());
        await using var db = postgres.CreateDbContext();
        Assert.Equal(1, await db.AuditEvents.AsNoTracking().CountAsync(e => e.Sponsor == human && e.Event == AuditEvents.SponsorBlocked));
    }

    [Fact]
    public async Task An_operator_neither_takes_over_nor_lifts_a_block_a_provisioning_feed_placed_but_still_ends_the_tasks()
    {
        // The task starts before the feed's block, which is written straight to storage and so
        // ends nothing itself.
        var (taskId, _) = await ExchangeAsync();
        var placedAt = new DateTimeOffset(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);
        await using (var db = postgres.CreateDbContext())
        {
            await new EfSponsorRepository(db, postgres.Dialect).BlockAsync(new SponsorBlock(human, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, placedAt));
        }

        using var put = await admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block", null);
        Assert.Equal(HttpStatusCode.Conflict, put.StatusCode);

        // The operator's kill switch still ends what is running, recorded as a block ends it.
        await using (var db = postgres.CreateDbContext())
        {
            var task = await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId);
            Assert.Equal((TaskRow.StatusRevoked, "sponsor_blocked"), (task.Status, task.RevocationReason));
        }

        using var delete = await admin.DeleteAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block");
        Assert.Equal(HttpStatusCode.Conflict, delete.StatusCode);

        using var read = await admin.GetAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}");
        var standing = await read.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(("scim", "deleted"), (standing.GetProperty("source").GetString(), standing.GetProperty("kind").GetString()));
        Assert.Equal(placedAt, standing.GetProperty("blocked_at").GetDateTimeOffset());

        // The refused block is a denial on the ledger, and nothing records it as placed or lifted.
        await using var ledger = postgres.CreateDbContext();
        var events = await ledger.AuditEvents.AsNoTracking().Where(e => e.Sponsor == human || e.TaskId == taskId).ToListAsync();
        var refused = Assert.Single(events, e => e.Event == AuditEvents.SponsorBlocked);
        Assert.Equal(("deny", "sponsor_blocked_elsewhere"), (refused.Decision, refused.Reason));
        var refusedLift = Assert.Single(events, e => e.Event == AuditEvents.SponsorUnblocked);
        Assert.Equal(("deny", "sponsor_block_not_owned"), (refusedLift.Decision, refusedLift.Reason));
        Assert.Contains(events, e => e.Event == AuditEvents.TaskRevoked && e.TaskId == taskId && e.Reason == "sponsor_blocked");
    }

    [Fact]
    public async Task The_kill_switch_ends_the_tasks_but_leaves_the_human_able_to_start_another()
    {
        var (taskId, _) = await ExchangeAsync();

        using var killed = await admin.DeleteAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/tasks");

        Assert.Equal(HttpStatusCode.OK, killed.StatusCode);
        Assert.Equal(1, (await killed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked_tasks").GetInt32());
        await using (var db = postgres.CreateDbContext())
        {
            var task = await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId);
            Assert.Equal((TaskRow.StatusRevoked, "operator_kill_switch"), (task.Status, task.RevocationReason));
        }

        // Nothing standing against the person, so a new task starts.
        await ExchangeAsync();

        // A repeat finds nothing live, which is not an error.
        using var repeat = await admin.DeleteAsync($"/admin/sponsors/{Uri.EscapeDataString(UniqueId("nobody"))}/tasks");
        Assert.Equal(HttpStatusCode.OK, repeat.StatusCode);
        Assert.Equal(0, (await repeat.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked_tasks").GetInt32());
    }

    [Fact]
    public async Task A_key_the_server_could_never_have_stored_is_a_bad_request()
    {
        using var response = await admin.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(new string('k', 257))}/block", null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_sponsor_routes_sit_behind_the_admin_key_like_every_other_admin_route()
    {
        // One request is enough: AdminEndpointsTests covers the /admin guard, and this only checks
        // that these routes sit under it.
        using var anonymous = factory.CreateClient();

        using var refused = await anonymous.PutAsync($"/admin/sponsors/{Uri.EscapeDataString(human)}/block", null);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.False(await db.SponsorBlocks.AsNoTracking().AnyAsync(s => s.SponsorKey == human));
    }

    private async Task<(string TaskId, string Grant)> ExchangeAsync()
    {
        using var response = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(Exchange()));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return (body.GetProperty("task_id").GetString()!, body.GetProperty("refresh_token").GetString()!);
    }

    private Dictionary<string, string> Exchange()
    {
        var now = DateTimeOffset.UtcNow;
        return new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = Mint(IdpKey, IdpKid, new() { ["iss"] = IdpIssuer, ["sub"] = human, ["aud"] = "subactid", ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["scope"] = "jira:read jira:comment" }),
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = Assertion(),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read jira:comment",
        };
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

    private string Assertion()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(AgentKey, AgentKid, new() { ["iss"] = agentId, ["sub"] = agentId, ["aud"] = ServerFactory.Issuer + "/oauth2/token", ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") });
    }
}
