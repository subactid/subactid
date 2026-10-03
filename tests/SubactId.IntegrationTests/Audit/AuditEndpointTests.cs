using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Admin;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

[Collection(PostgresCollection.Name)]
public class AuditEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private static readonly DateTimeOffset September = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    private DatabaseServerFactory factory = null!;
    private HttpClient client = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new DatabaseServerFactory(postgres);
        client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        await factory.DisposeAsync();
    }

    [Fact]
    public async Task The_spec_query_answers_the_ledger_records_of_that_month_in_pages()
    {
        var human = UniqueId("human");
        await using var db = postgres.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
        await writer.AppendAsync(
        [
            new AuditEvent(September.AddDays(-1), AuditEvents.TokenIssued, "task_aug", "jira-triage", human, "https://jira.internal", "jira:read", "tok_aug", 1, AuditDecision.Allow),
            new AuditEvent(September.AddDays(1), AuditEvents.TokenIssued, "task_1", "jira-triage", human, "https://jira.internal", "jira:read jira:comment", "tok_1", 1, AuditDecision.Allow),
            new AuditEvent(September.AddDays(1), AuditEvents.TokenRefreshed, "task_1", "jira-triage", human, "https://jira.internal", "jira:read", "tok_2", 1, AuditDecision.Allow),
            new AuditEvent(September.AddDays(2), AuditEvents.TokenDenied, null, "db-agent", human, "https://db.internal", "db:write", null, null, AuditDecision.Deny, "audience_not_allowed"),
            new AuditEvent(September.AddMonths(1), AuditEvents.TokenIssued, "task_oct", "jira-triage", human, Decision: AuditDecision.Allow),
        ]);
        var stored = await db.AuditEvents.AsNoTracking().Where(e => e.Sponsor == human).OrderBy(e => e.Seq).ToListAsync();

        using var first = await client.GetAsync($"/audit?sponsor={human}&from=2026-09-01&to=2026-09-30&limit=2");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal("application/json", first.Content.Headers.ContentType?.MediaType);
        var page = await first.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["records", "next_cursor", "archived_before"], page.EnumerateObject().Select(p => p.Name));
        // Nothing has been archived, so there is no earliest online instant. The key is still present.
        Assert.Equal(JsonValueKind.Null, page.GetProperty("archived_before").ValueKind);
        var records = page.GetProperty("records");
        Assert.Equal(2, records.GetArrayLength());
        var issued = records[0];
        Assert.Equal(["seq", "checkpoint", "ts", "event", "task_id", "agent_id", "sponsor", "audience", "scope", "jti", "delegation_depth", "decision", "reason"], issued.EnumerateObject().Select(p => p.Name));
        // Three fractional digits even when the millisecond is zero. The record's leaf was hashed over
        // this form, so a shorter ts could not be recomputed into the signed tree.
        Assert.Equal((stored[1].Seq, "2026-09-02T00:00:00.000Z", "token.issued", "task_1", "jira-triage", human), (issued.GetProperty("seq").GetInt64(), issued.GetProperty("ts").GetString(), issued.GetProperty("event").GetString(), issued.GetProperty("task_id").GetString(), issued.GetProperty("agent_id").GetString(), issued.GetProperty("sponsor").GetString()));
        Assert.Equal(("jira:read jira:comment", 1, "allow"), (issued.GetProperty("scope").GetString(), issued.GetProperty("delegation_depth").GetInt32(), issued.GetProperty("decision").GetString()));
        Assert.Equal("tok_1", issued.GetProperty("jti").GetString());

        // Nothing has sealed these yet. The key is still present.
        Assert.Equal(JsonValueKind.Null, issued.GetProperty("checkpoint").ValueKind);
        var cursor = page.GetProperty("next_cursor").GetString();
        Assert.NotNull(cursor);

        using var second = await client.GetAsync($"/audit?sponsor={human}&from=2026-09-01&to=2026-09-30&limit=2&cursor={Uri.EscapeDataString(cursor)}");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var last = await second.Content.ReadFromJsonAsync<JsonElement>();
        var denied = Assert.Single(last.GetProperty("records").EnumerateArray());
        Assert.Equal(("token.denied", "deny", "audience_not_allowed", "db-agent"), (denied.GetProperty("event").GetString(), denied.GetProperty("decision").GetString(), denied.GetProperty("reason").GetString(), denied.GetProperty("agent_id").GetString()));
        Assert.Equal(JsonValueKind.Null, denied.GetProperty("task_id").ValueKind);
        Assert.Equal(JsonValueKind.Null, last.GetProperty("next_cursor").ValueKind);

        using var denials = await client.GetAsync($"/audit?sponsor={human}&decision=deny");
        var onlyDenials = await denials.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["token.denied"], onlyDenials.GetProperty("records").EnumerateArray().Select(r => r.GetProperty("event").GetString()));
    }

    [Fact]
    public async Task A_bad_query_answers_every_field_error_at_once()
    {
        using var response = await client.GetAsync("/audit?from=last-month&to=2026-09-30&decision=perhaps&limit=5000&cursor=***&sponsor=a%20b");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["sponsor", "from", "decision", "limit", "cursor"], body.GetProperty("errors").EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task The_query_needs_the_admin_key_and_a_refusal_is_audited()
    {
        using var anonymous = factory.CreateClient();
        using var response = await anonymous.GetAsync("/audit");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer realm=\"subactid-admin\"", response.Headers.WwwAuthenticate.ToString());
        await using var db = postgres.CreateDbContext();
        var latest = await db.AuditEvents.AsNoTracking().OrderByDescending(e => e.Seq).FirstAsync();
        Assert.Equal((AuditEvents.AdminDenied, "deny", "missing_api_key"), (latest.Event, latest.Decision, latest.Reason));
    }
}
