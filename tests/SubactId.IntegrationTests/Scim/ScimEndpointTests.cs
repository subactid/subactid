using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.IntegrationTests.Tokens;
using SubactId.Server.Contracts;
using SubactId.Server.Scim;
using SubactId.Storage.Ef.Schema;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Scim;

/// <summary>
/// The SCIM receiver over HTTP against a real database. Deactivating somebody ends their running
/// tasks and stops them starting another, and a client without the credential changes nothing.
/// </summary>
[Collection(PostgresCollection.Name)]
public class ScimEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private ExchangeServerFactory factory = null!;
    private HttpClient client = null!;
    private string agentId = null!;
    private string human = null!;
    private string userName = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new ExchangeServerFactory(postgres);
        human = UniqueId("human");
        userName = UniqueId("ada") + "@example.com";
        factory.Keycloak.Users[human] = true;
        client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.ScimBearerToken);
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
    public async Task A_deactivation_ends_the_tasks_running_for_that_person_and_refuses_the_next_exchange()
    {
        var taskId = await ExchangeAsync();
        var id = await CreateAsync();

        using var response = await PatchAsync(id, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "value": {"active": false}}]}
            """);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ScimSchemas.MediaType, response.Content.Headers.ContentType?.MediaType);
        Assert.False((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean());

        await using var db = postgres.CreateDbContext();
        var task = await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId);
        Assert.Equal((TaskRow.StatusRevoked, "scim_deactivated"), (task.Status, task.RevocationReason));

        var events = await db.AuditEvents.AsNoTracking().Where(e => e.Sponsor == human).ToListAsync();
        Assert.Contains(events, e => e.Event == AuditEvents.SponsorSignal && e.Reason == "scim_deactivated");
        Assert.Contains(events, e => e.Event == AuditEvents.TaskRevoked && e.Reason == "scim_deactivated");

        // And a still-valid subject token cannot open a new task: the block is checked at the
        // exchange, not only at refresh.
        // A token-endpoint error is a 400 with the reason in the body (RFC 6749 section 5.2).
        using var refused = await ExchangeResponseAsync();
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("access_denied", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_reactivation_lets_the_person_start_again()
    {
        var id = await CreateAsync();
        using (var deactivated = await PatchAsync(id, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "path": "active", "value": false}]}
            """))
        {
            Assert.Equal(HttpStatusCode.OK, deactivated.StatusCode);
        }

        using var response = await PatchAsync(id, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "path": "active", "value": true}]}
            """);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await ExchangeAsync();
    }

    [Fact]
    public async Task A_second_record_under_the_same_key_reactivated_does_not_lift_the_block_the_first_placed()
    {
        var id = await CreateAsync();
        using (var deactivated = await PatchAsync(id, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "path": "active", "value": false}]}
            """))
        {
            Assert.Equal(HttpStatusCode.OK, deactivated.StatusCode);
        }

        // Another record naming the same person, created and restated as active.
        using var second = await client.PostAsync(ScimEndpoints.UsersPath, Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{UniqueId("ada")}}@example.com", "externalId": "{{human}}", "active": true}
            """));
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        var secondId = (await second.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        using (var restated = await PatchAsync(secondId, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "path": "active", "value": true}]}
            """))
        {
            Assert.Equal(HttpStatusCode.OK, restated.StatusCode);
        }

        using (var refused = await ExchangeResponseAsync())
        {
            Assert.Equal("access_denied", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }

        await using (var db = postgres.CreateDbContext())
        {
            Assert.Equal(SponsorBlockRow.SourceScim, (await db.SponsorBlocks.AsNoTracking().SingleAsync(b => b.SponsorKey == human)).Source);
            Assert.False(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Sponsor == human && e.Reason == "scim_reactivated"));
        }

        // The record that placed the block, reactivated, lifts it.
        using (var reactivated = await PatchAsync(id, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "path": "active", "value": true}]}
            """))
        {
            Assert.Equal(HttpStatusCode.OK, reactivated.StatusCode);
        }

        await ExchangeAsync();
    }

    [Fact]
    public async Task A_deletion_ends_the_tasks_and_keeps_refusing_the_person()
    {
        var taskId = await ExchangeAsync();
        var id = await CreateAsync();

        using var response = await client.DeleteAsync(ScimPath(id));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);

        // The record is gone and the refusal is not.
        using var gone = await client.GetAsync(ScimPath(id));
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        using var refused = await ExchangeResponseAsync();
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("access_denied", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_deletion_holds_while_another_record_is_resent_as_active_and_lifts_for_a_new_record()
    {
        // Two records name the person and one is deleted.
        var id = await CreateAsync();
        var otherName = UniqueId("ada") + "@example.com";
        var otherId = await CreateAnotherAsync(otherName);
        using (var deleted = await client.DeleteAsync(ScimPath(id)))
        {
            Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        }

        // The other record, re-sent and patched as active, is not a new record: the block stays.
        using (var resent = await client.PutAsync(ScimPath(otherId), Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{otherName}}", "externalId": "{{human}}", "active": true}
            """)))
        {
            Assert.Equal(HttpStatusCode.OK, resent.StatusCode);
        }

        using (var patched = await PatchAsync(otherId, """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "replace", "path": "active", "value": true}]}
            """))
        {
            Assert.Equal(HttpStatusCode.OK, patched.StatusCode);
        }

        using (var refused = await ExchangeResponseAsync())
        {
            Assert.Equal("access_denied", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }

        await using (var db = postgres.CreateDbContext())
        {
            var block = await db.SponsorBlocks.AsNoTracking().SingleAsync(b => b.SponsorKey == human);
            Assert.Equal((SponsorBlockRow.SourceScim, SponsorBlockRow.KindDeleted, true), (block.Source, block.Kind, block.PlacedByDeletion));
            Assert.False(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Sponsor == human && e.Reason == "scim_reactivated"));
        }

        // A new record naming the person is what lifts it.
        await CreateAnotherAsync(UniqueId("ada") + "@example.com");

        await ExchangeAsync();
        await using (var db = postgres.CreateDbContext())
        {
            Assert.False(await db.SponsorBlocks.AsNoTracking().AnyAsync(b => b.SponsorKey == human));
            Assert.True(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Sponsor == human && e.Reason == "scim_reactivated"));
        }
    }

    [Fact]
    public async Task A_provisioning_client_can_find_a_person_it_already_created()
    {
        var id = await CreateAsync();

        using var found = await client.GetAsync($"/scim/v2/Users?filter=userName%20eq%20%22{Uri.EscapeDataString(userName)}%22");

        Assert.Equal(HttpStatusCode.OK, found.StatusCode);
        var page = await found.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, page.GetProperty("totalResults").GetInt32());
        Assert.Equal(id, page.GetProperty("Resources")[0].GetProperty("id").GetString());

        // A filter this receiver does not serve is refused rather than answered with everybody.
        using var refused = await client.GetAsync("/scim/v2/Users?filter=displayName%20eq%20%22Ada%22");
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("invalidFilter", (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scimType").GetString());
    }

    [Fact]
    public async Task A_request_without_the_provisioning_credential_changes_nothing_and_is_recorded()
    {
        var taskId = await ExchangeAsync();
        var id = await CreateAsync();

        using var stranger = factory.CreateClient();
        using var refused = await stranger.DeleteAsync(ScimPath(id));

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal("Bearer", refused.Headers.WwwAuthenticate.Single().Scheme);

        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusActive, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
        Assert.True(await db.AuditEvents.AsNoTracking().AnyAsync(e => e.Event == AuditEvents.ScimDenied));

        // The refusal names nobody: nothing in an unauthenticated request is worth recording.
        var denial = await db.AuditEvents.AsNoTracking().Where(e => e.Event == AuditEvents.ScimDenied).OrderBy(e => e.Seq).LastAsync();
        Assert.Null(denial.Sponsor);
    }

    [Fact]
    public async Task The_configuration_document_says_what_is_here()
    {
        using var response = await client.GetAsync("/scim/v2/ServiceProviderConfig");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var config = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(config.GetProperty("patch").GetProperty("supported").GetBoolean());
        Assert.False(config.GetProperty("bulk").GetProperty("supported").GetBoolean());
        Assert.False(config.GetProperty("etag").GetProperty("supported").GetBoolean());
        Assert.Equal("oauthbearertoken", config.GetProperty("authenticationSchemes")[0].GetProperty("type").GetString());

        // The location is built from the configured issuer, never from the request's own host.
        Assert.StartsWith(ServerFactory.Issuer, config.GetProperty("meta").GetProperty("location").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_second_record_for_one_user_name_is_refused_as_a_conflict()
    {
        await CreateAsync();

        using var again = await client.PostAsync(ScimEndpoints.UsersPath, Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{UniqueId("other")}}"}
            """));

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Equal("uniqueness", (await again.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scimType").GetString());
    }

    [Fact]
    public async Task A_user_that_could_never_be_matched_to_a_person_is_refused_at_setup()
    {
        // Provisioning fails here, visibly, rather than later when a deactivation matches nothing.
        using var response = await client.PostAsync(ScimEndpoints.UsersPath, Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}"}
            """));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalidValue", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scimType").GetString());
    }

    [Fact]
    public async Task A_body_that_is_not_scim_json_is_refused_without_saying_more()
    {
        using var wrongType = await client.PostAsync(ScimEndpoints.UsersPath, new StringContent("{}", Encoding.UTF8, "text/plain"));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongType.StatusCode);

        using var notJson = await client.PostAsync(ScimEndpoints.UsersPath, Body("{not json"));
        Assert.Equal(HttpStatusCode.BadRequest, notJson.StatusCode);

        var error = await notJson.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalidSyntax", error.GetProperty("scimType").GetString());

        // Nothing the parser had to say reaches the client.
        Assert.DoesNotContain("json", error.GetProperty("detail").GetString()!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Attribute_names_are_read_whatever_their_case_so_a_capitalised_deactivation_blocks()
    {
        var taskId = await ExchangeAsync();
        var id = await CreateAsync();

        using var response = await client.PutAsync(ScimPath(id), Body($$"""
            {"Schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "UserName": "{{userName}}", "ExternalId": "{{human}}", "Active": false}
            """));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean());
        await using var db = postgres.CreateDbContext();
        Assert.Equal(TaskRow.StatusRevoked, (await db.Tasks.AsNoTracking().SingleAsync(t => t.TaskId == taskId)).Status);
        Assert.Equal("scim", (await db.SponsorBlocks.AsNoTracking().SingleAsync(b => b.SponsorKey == human)).Source);
    }

    [Fact]
    public async Task An_active_given_as_a_boolean_string_is_read_and_anything_else_is_invalid_value()
    {
        var id = await CreateAsync();

        using var quoted = await client.PutAsync(ScimPath(id), Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}", "active": "False"}
            """));
        Assert.Equal(HttpStatusCode.OK, quoted.StatusCode);
        Assert.False((await quoted.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean());

        using var unreadable = await client.PutAsync(ScimPath(id), Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}", "active": "maybe"}
            """));
        Assert.Equal(HttpStatusCode.BadRequest, unreadable.StatusCode);
        Assert.Equal("invalidValue", (await unreadable.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scimType").GetString());
    }

    [Fact]
    public async Task An_attribute_given_twice_in_different_cases_is_refused_rather_than_guessed_at()
    {
        var id = await CreateAsync();

        using var response = await client.PutAsync(ScimPath(id), Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}", "active": false, "Active": true}
            """));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalidSyntax", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scimType").GetString());
    }

    [Fact]
    public async Task A_body_sent_as_plain_json_is_read_and_answered_as_scim_json()
    {
        // Okta and Entra send application/scim+json; other provisioning clients send plain JSON.
        using var response = await client.PostAsync(ScimEndpoints.UsersPath, new StringContent($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}"}
            """, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("application/scim+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A_body_that_is_neither_scim_json_nor_json_is_unsupported_media_type()
    {
        using var response = await client.PostAsync(ScimEndpoints.UsersPath, new StringContent($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}"}
            """, Encoding.UTF8, "application/xml"));

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task A_body_declared_in_a_charset_other_than_utf_8_is_unsupported_media_type()
    {
        // JSON between systems is UTF-8 (RFC 8259 section 8.1). A body in another charset is
        // refused rather than read as UTF-8 and misread.
        using var response = await client.PostAsync(ScimEndpoints.UsersPath, new StringContent($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}"}
            """, Encoding.Latin1, "application/scim+json"));

        Assert.Equal("iso-8859-1", response.RequestMessage!.Content!.Headers.ContentType!.CharSet);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task A_person_this_receiver_never_heard_of_is_not_found()
    {
        using var response = await client.GetAsync(ScimPath("scim_nobody"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(ScimSchemas.MediaType, response.Content.Headers.ContentType?.MediaType);
    }

    private static string ScimPath(string id) => ScimEndpoints.UsersPath + "/" + id;

    private static StringContent Body(string json) => new(json, Encoding.UTF8, ScimSchemas.MediaType);

    private Task<HttpResponseMessage> PatchAsync(string id, string json) =>
        client.PatchAsync(ScimPath(id), Body(json));

    private async Task<string> CreateAsync()
    {
        using var response = await client.PostAsync(ScimEndpoints.UsersPath, Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{userName}}", "externalId": "{{human}}",
             "name": {"givenName": "Ada", "familyName": "Lovelace"}, "emails": [{"value": "{{userName}}", "primary": true}]}
            """));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();

        // What a client sends beyond the identifiers is not stored, so it is not read back either.
        Assert.False(created.TryGetProperty("name", out _));
        Assert.False(created.TryGetProperty("emails", out _));
        Assert.Equal(human, created.GetProperty("externalId").GetString());
        Assert.Equal(ScimEndpoints.UsersPath, new Uri(response.Headers.Location!.ToString()).AbsolutePath[..ScimEndpoints.UsersPath.Length]);
        return created.GetProperty("id").GetString()!;
    }

    private async Task<string> CreateAnotherAsync(string otherUserName)
    {
        using var response = await client.PostAsync(ScimEndpoints.UsersPath, Body($$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{otherUserName}}", "externalId": "{{human}}", "active": true}
            """));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
    }

    private async Task<string> ExchangeAsync()
    {
        using var response = await ExchangeResponseAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("task_id").GetString()!;
    }

    private async Task<HttpResponseMessage> ExchangeResponseAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var subject = Mint(IdpKey, IdpKid, new()
        {
            ["iss"] = IdpIssuer,
            ["sub"] = human,
            ["aud"] = "subactid",
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
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
