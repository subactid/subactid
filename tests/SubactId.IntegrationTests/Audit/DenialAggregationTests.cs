using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SubactId.IntegrationTests.Admin;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Server.Audit;
using Xunit;

namespace SubactId.IntegrationTests.Audit;

/// <summary>
/// Aggregation through the real stack: requests over HTTP, records read back from Postgres
/// through the audit query.
/// </summary>
[Collection(PostgresCollection.Name)]
public class DenialAggregationTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private DatabaseServerFactory factory = null!;
    private HttpClient client = null!;
    private HttpClient admin = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new DatabaseServerFactory(postgres);
        client = factory.CreateClient();
        admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        admin.Dispose();
        await factory.DisposeAsync();
    }

    [Fact]
    public async Task A_flood_of_denials_that_name_nobody_costs_one_record_and_then_a_count()
    {
        const int Requests = 40;
        var since = DateTimeOffset.UtcNow.AddSeconds(-5);
        var before = await DenialsAsync(since);

        for (var i = 0; i < Requests; i++)
        {
            using var response = await PostGarbageAsync();
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // The first opens the window and is written straight away.
        var written = (await DenialsAsync(since)).Count - before.Count;
        Assert.InRange(written, 1, 5);

        // The rest are counted, and reach the ledger when the window closes.
        var flushed = await factory.Services.GetRequiredService<IEnumerable<IHostedService>>()
            .OfType<DenialAggregationFlusher>()
            .Single()
            .FlushAsync();
        Assert.True(flushed > 0, "The window closed without writing a summary.");

        var summaries = (await DenialsAsync(since))
            .Where(r => r.TryGetProperty("count", out _))
            .ToList();
        Assert.NotEmpty(summaries);
        Assert.Equal(Requests - written, summaries.Sum(r => r.GetProperty("count").GetInt32()));
        Assert.All(summaries, r =>
        {
            Assert.Equal("deny", r.GetProperty("decision").GetString());
            Assert.Equal(JsonValueKind.Null, r.GetProperty("agent_id").ValueKind);
            Assert.Equal(JsonValueKind.Null, r.GetProperty("sponsor").ValueKind);
        });
    }

    [Fact]
    public async Task A_record_that_stands_for_one_event_publishes_no_count_field()
    {
        var since = DateTimeOffset.UtcNow.AddSeconds(-5);
        using var response = await PostGarbageAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // Absent rather than null, because that is how it was hashed.
        var records = await DenialsAsync(since);
        Assert.NotEmpty(records);
        Assert.Contains(records, r => !r.TryGetProperty("count", out _));
    }

    private Task<HttpResponseMessage> PostGarbageAsync() =>
        client.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["subject_token"] = "not.a.token",
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["actor_token"] = "garbage",
                ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
                ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["resource"] = "https://jira.internal",
                ["scope"] = "jira:read",
            }));

    private async Task<IReadOnlyList<JsonElement>> DenialsAsync(DateTimeOffset since)
    {
        var from = Uri.EscapeDataString(since.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
        var page = await admin.GetFromJsonAsync<JsonElement>($"/audit?decision=deny&from={from}&limit=1000");
        return [.. page.GetProperty("records").EnumerateArray()];
    }
}
