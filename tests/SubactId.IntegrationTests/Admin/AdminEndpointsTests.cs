using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Server.Contracts;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Admin;

[Collection(PostgresCollection.Name)]
public class AdminEndpointsTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
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
    public async Task Requests_without_a_valid_key_are_refused_and_audited()
    {
        using var anonymous = factory.CreateClient();
        using var missing = await anonymous.GetAsync("/admin/agents");
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal("Bearer realm=\"subactid-admin\"", missing.Headers.WwwAuthenticate.ToString());
        Assert.Equal("application/problem+json", missing.Content.Headers.ContentType?.MediaType);

        anonymous.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "not-the-key");
        using var wrong = await anonymous.DeleteAsync("/admin/agents/jira-triage");
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        var denials = await LatestAuditAsync(2);
        Assert.Equal([AuditEvents.AdminDenied, AuditEvents.AdminDenied], denials.Select(d => d.Event));
        Assert.Equal(["deny", "deny"], denials.Select(d => d.Decision));
        Assert.Equal(["missing_api_key", "invalid_api_key"], denials.Select(d => d.Reason));
    }

    [Fact]
    public async Task Register_read_update_and_delete_an_agent_with_an_audit_record_per_mutation()
    {
        var agentId = UniqueId("jira-triage");

        // Create.
        using var created = await client.PostAsync("/admin/agents", Json(Registration(agentId)));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal($"/admin/agents/{agentId}", created.Headers.Location?.ToString());
        var body = await created.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(agentId, body.GetProperty("agent_id").GetString());
        Assert.Equal("PT30M", body.GetProperty("max_task_ttl").GetString());
        Assert.True(body.GetProperty("enabled").GetBoolean());
        Assert.Equal(["agent_id", "display_name", "sponsor_required", "allowed_scopes", "allowed_audiences", "max_task_ttl", "max_token_ttl", "max_delegation_depth", "high_risk_audiences", "jwks_uri", "jwks", "enabled", "created_at", "updated_at"],
            body.EnumerateObject().Select(p => p.Name));
        var registered = Assert.Single(await LatestAuditAsync(1));
        Assert.Equal((AuditEvents.AgentRegistered, agentId, "allow"), (registered.Event, registered.AgentId, registered.Decision));

        // Read.
        using var one = await client.GetAsync($"/admin/agents/{agentId}");
        Assert.Equal(HttpStatusCode.OK, one.StatusCode);
        Assert.Equal(body.ToString(), (await one.Content.ReadFromJsonAsync<JsonElement>()).ToString());
        var list = await client.GetFromJsonAsync<JsonElement>($"/admin/agents?after={Uri.EscapeDataString(agentId[..^1])}&limit=1000");
        Assert.Contains(list.GetProperty("agents").EnumerateArray(), a => a.GetProperty("agent_id").GetString() == agentId);

        // Disable.
        using var patched = await client.PatchAsync($"/admin/agents/{agentId}", Json("{\"enabled\": false, \"allowed_scopes\": [\"jira:read\"]}"));
        Assert.Equal(HttpStatusCode.OK, patched.StatusCode);
        var afterPatch = await patched.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(afterPatch.GetProperty("enabled").GetBoolean());
        Assert.Equal(["jira:read"], afterPatch.GetProperty("allowed_scopes").EnumerateArray().Select(s => s.GetString()));
        Assert.False((await client.GetFromJsonAsync<JsonElement>($"/admin/agents/{agentId}")).GetProperty("enabled").GetBoolean());
        var updated = Assert.Single(await LatestAuditAsync(1));
        Assert.Equal((AuditEvents.AgentUpdated, agentId, "changed:allowed_scopes,enabled"), (updated.Event, updated.AgentId, updated.Reason));

        // Delete.
        using var deleted = await client.DeleteAsync($"/admin/agents/{agentId}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/admin/agents/{agentId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync($"/admin/agents/{agentId}")).StatusCode);
        var removed = Assert.Single(await LatestAuditAsync(1));
        Assert.Equal((AuditEvents.AgentDeleted, agentId), (removed.Event, removed.AgentId));
    }

    [Fact]
    public async Task Invalid_payloads_answer_400_with_per_field_errors()
    {
        using var response = await client.PostAsync("/admin/agents", Json("{\"agent_id\": \"Bad Id\", \"max_task_ttl\": \"PT5M\", \"max_token_ttl\": \"PT6M\"}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal(["display_name", "allowed_scopes", "allowed_audiences", "max_delegation_depth"], errors.EnumerateObject().Select(p => p.Name));
        Assert.Equal("is required.", errors.GetProperty("display_name")[0].GetString());
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("\"a string\"")]
    [InlineData("42")]
    [InlineData("{\"agent_id\": \"ok\", \"allowed_scopes\": \"not-an-array\"}")]
    [InlineData("{\"agent_id\": \"ok\", \"max_task_ttl\": 7}")]
    [InlineData("{ not json at all")]
    public async Task A_body_that_cannot_be_read_at_all_is_a_400_problem_document(string body)
    {
        // These never reach the request type's validation because the host refuses to bind them.
        // They are still a 4xx, and the answer names neither the parameter nor the exception.
        using var response = await client.PostAsync("/admin/agents", Json(body));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var problem = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Exception", problem, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("RegisterAgentRequest", problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("high_risk_audience")]
    [InlineData("enable")]
    public async Task A_member_the_registration_does_not_have_is_a_400_that_names_it(string member)
    {
        // A misspelt optional field would otherwise register the agent without it: no high-risk
        // audiences, so revocation stops being immediate for the audience meant to be one.
        var body = Registration(UniqueId("x")).TrimEnd()[..^1] + $", \"{member}\": [\"https://jira.internal\"]}}";

        using var response = await client.PostAsync("/admin/agents", Json(body));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal([member], errors.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task A_member_an_update_does_not_have_is_a_400_and_changes_nothing()
    {
        var agentId = UniqueId("x");
        using (var created = await client.PostAsync("/admin/agents", Json(Registration(agentId))))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        using var response = await client.PatchAsync($"/admin/agents/{agentId}", Json("{\"enable\": false}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal(["enable"], errors.EnumerateObject().Select(p => p.Name));
        Assert.True((await client.GetFromJsonAsync<JsonElement>($"/admin/agents/{agentId}")).GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task A_whole_registration_can_be_sent_back_as_an_update_but_not_under_another_id()
    {
        var agentId = UniqueId("x");
        using (var created = await client.PostAsync("/admin/agents", Json(Registration(agentId))))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        using var same = await client.PatchAsync($"/admin/agents/{agentId}", Json(Registration(agentId).Replace("Jira triage agent", "Renamed", StringComparison.Ordinal)));
        Assert.Equal(HttpStatusCode.OK, same.StatusCode);
        Assert.Equal("Renamed", (await same.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("display_name").GetString());

        using var other = await client.PatchAsync($"/admin/agents/{agentId}", Json(Registration(UniqueId("y"))));
        Assert.Equal(HttpStatusCode.BadRequest, other.StatusCode);
        var errors = (await other.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal(["agent_id"], errors.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task An_update_reports_every_invalid_field_not_only_the_first()
    {
        var agentId = UniqueId("x");
        using (var created = await client.PostAsync("/admin/agents", Json(Registration(agentId))))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        using var response = await client.PatchAsync($"/admin/agents/{agentId}", Json("{\"jwks_uri\": \"not a url\", \"display_name\": \"\", \"max_delegation_depth\": 0}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal(["display_name", "jwks_uri", "max_delegation_depth"], errors.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task The_agent_list_is_paged_by_id_with_next_after()
    {
        var prefix = UniqueId("pg");
        foreach (var suffix in new[] { "b", "a", "c" })
        {
            using var created = await client.PostAsync("/admin/agents", Json(Registration($"{prefix}-{suffix}")));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var first = await client.GetFromJsonAsync<JsonElement>($"/admin/agents?after={prefix}&limit=2");
        Assert.Equal([$"{prefix}-a", $"{prefix}-b"], first.GetProperty("agents").EnumerateArray().Select(a => a.GetProperty("agent_id").GetString()));
        Assert.Equal($"{prefix}-b", first.GetProperty("next_after").GetString());

        var second = await client.GetFromJsonAsync<JsonElement>($"/admin/agents?after={prefix}-b&limit=1");
        Assert.Equal([$"{prefix}-c"], second.GetProperty("agents").EnumerateArray().Select(a => a.GetProperty("agent_id").GetString()));
    }

    [Theory]
    [InlineData("limit=0", "limit")]
    [InlineData("limit=1001", "limit")]
    [InlineData("limit=ten", "limit")]
    [InlineData("after=", "after")]
    public async Task A_bad_page_request_is_a_400_that_names_the_field(string query, string field)
    {
        using var response = await client.GetAsync($"/admin/agents?{query}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal([field], errors.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task A_malformed_duration_is_a_400_that_names_the_field()
    {
        using var response = await client.PostAsync("/admin/agents", Json(Registration(UniqueId("x")).Replace("\"PT30M\"", "\"30 minutes\"", StringComparison.Ordinal)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal(["max_task_ttl"], errors.EnumerateObject().Select(p => p.Name));
    }

    [Theory]
    [InlineData("{\"agent_id\": \"ok\", \"max_task_ttl\": \"30m\"}", "max_task_ttl")]
    [InlineData("{\"agent_id\": \"ok\", \"max_task_ttl\": 7}", "max_task_ttl")]
    [InlineData("{\"agent_id\": \"ok\", \"allowed_scopes\": \"x\"}", "allowed_scopes")]
    [InlineData("{\"agent_id\": \"ok\", \"allowed_scopes\": [1]}", "allowed_scopes")]
    [InlineData("{\"agent_id\": \"ok\", \"max_delegation_depth\": \"two\"}", "max_delegation_depth")]
    public async Task A_value_of_the_wrong_type_is_rejected_per_field(string body, string field)
    {
        using var registered = await client.PostAsync("/admin/agents", Json(body));
        var agentId = UniqueId("typed");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync("/admin/agents", Json(Registration(agentId)))).StatusCode);
        using var patched = await client.PatchAsync($"/admin/agents/{agentId}", Json(body.Replace("\"agent_id\": \"ok\", ", string.Empty, StringComparison.Ordinal)));

        foreach (var response in new[] { registered, patched })
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal([field], problem.GetProperty("errors").EnumerateObject().Select(p => p.Name));
            Assert.DoesNotContain("Exception", problem.ToString(), StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task A_body_that_is_not_json_names_no_field()
    {
        using var response = await client.PostAsync("/admin/agents", Json("{\"agent_id\": }"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False((await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task Duplicate_registration_is_409_and_a_patch_that_breaks_the_registration_is_400()
    {
        var agentId = UniqueId("dup");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync("/admin/agents", Json(Registration(agentId)))).StatusCode);

        using var duplicate = await client.PostAsync("/admin/agents", Json(Registration(agentId)));
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);

        // The refused registration is on the ledger as a denial, beside the one that succeeded.
        await using (var db = postgres.CreateDbContext())
        {
            var registrations = await db.AuditEvents.AsNoTracking().Where(e => e.AgentId == agentId && e.Event == AuditEvents.AgentRegistered).OrderBy(e => e.Seq).ToListAsync();
            Assert.Equal(2, registrations.Count);
            Assert.Equal(("allow", (string?)null), (registrations[0].Decision, registrations[0].Reason));
            Assert.Equal(("deny", "agent_already_exists"), (registrations[1].Decision, registrations[1].Reason));
        }

        using var broken = await client.PatchAsync($"/admin/agents/{agentId}", Json("{\"max_token_ttl\": \"PT1H\"}"));
        Assert.Equal(HttpStatusCode.BadRequest, broken.StatusCode);
        var errors = (await broken.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.Equal("must not exceed max_task_ttl.", errors.GetProperty("max_token_ttl")[0].GetString());

        using var unknown = await client.PatchAsync($"/admin/agents/{UniqueId("missing")}", Json("{\"enabled\": false}"));
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Fact]
    public async Task An_agent_with_tasks_cannot_be_deleted()
    {
        var agentId = UniqueId("busy");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync("/admin/agents", Json(Registration(agentId)))).StatusCode);
        await using (var db = postgres.CreateDbContext())
        {
            await new EfTaskRepository(db, postgres.Dialect).AddAsync(NewTask(agentId));
        }

        using var response = await client.DeleteAsync($"/admin/agents/{agentId}");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("tasks", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/admin/agents/{agentId}")).StatusCode);

        // The refused deletion is on the ledger as a denial.
        await using var ledger = postgres.CreateDbContext();
        var refused = Assert.Single(await ledger.AuditEvents.AsNoTracking().Where(e => e.AgentId == agentId && e.Event == AuditEvents.AgentDeleted).ToListAsync());
        Assert.Equal(("deny", "agent_has_tasks"), (refused.Decision, refused.Reason));
    }

    private static StringContent Json(string json) => new(json, System.Text.Encoding.UTF8, "application/json");

    private static string Registration(string agentId) => $$"""
        {
          "agent_id": "{{agentId}}",
          "display_name": "Jira triage agent",
          "sponsor_required": true,
          "allowed_scopes": ["jira:read", "jira:comment", "confluence:read"],
          "allowed_audiences": ["https://jira.internal", "https://confluence.internal"],
          "max_task_ttl": "PT30M",
          "max_token_ttl": "PT5M",
          "max_delegation_depth": 2,
          "high_risk_audiences": ["https://db.internal"],
          "jwks_uri": "https://jira-triage.agents.internal/.well-known/jwks.json"
        }
        """;

    private async Task<List<(string Event, string? AgentId, string? Decision, string? Reason)>> LatestAuditAsync(int count)
    {
        await using var db = postgres.CreateDbContext();
        var rows = await db.AuditEvents.AsNoTracking().OrderByDescending(e => e.Seq).Take(count).ToListAsync();
        rows.Reverse();
        return rows.Select(r => (r.Event, r.AgentId, r.Decision, r.Reason)).ToList();
    }
}
