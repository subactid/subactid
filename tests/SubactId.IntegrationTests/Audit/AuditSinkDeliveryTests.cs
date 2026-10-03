using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Endpoints;
using SubactId.IntegrationTests.Tokens;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using static SubactId.IntegrationTests.Tokens.ExchangeServerFactory;

namespace SubactId.IntegrationTests.Audit;

/// <summary>With the sink unavailable, exchanges still succeed, and the events are delivered after the sink recovers.</summary>
[Collection(PostgresCollection.Name)]
public class AuditSinkDeliveryTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(30);

    private AuditSinkFactory factory = null!;
    private HttpClient client = null!;
    private string agentId = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new AuditSinkFactory(postgres);
        // The exchange checks the human, so the stand-in identity provider must know them.
        // Otherwise every exchange is access_denied.
        factory.Keycloak.Users[Human] = true;
        client = factory.CreateClient();
        agentId = UniqueId("sink");

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
        using var created = await admin.PostAsync("/admin/agents", new StringContent($$"""
            {"agent_id": "{{agentId}}", "display_name": "Sink test", "allowed_scopes": ["jira:read", "jira:comment"],
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
    public async Task Exchanges_succeed_while_the_sink_is_down_and_their_events_arrive_once_it_is_back()
    {
        factory.Sink.Down = true;

        // Two exchanges with nothing listening at the sink: both succeed, both are fully recorded.
        var firstTask = await ExchangeAsync();
        var secondTask = await ExchangeAsync();
        await using var db = postgres.CreateDbContext();
        var expected = await db.AuditEvents.AsNoTracking().Where(e => e.AgentId == agentId).OrderBy(e => e.Seq).ToListAsync();
        Assert.Equal([AuditEvents.AgentRegistered, AuditEvents.TokenIssued, AuditEvents.TokenIssued], expected.Select(e => e.Event));
        var seqs = expected.Select(e => e.Seq).ToList();

        // The drain tries, fails, and records the failure without delivering anything.
        await WaitUntilAsync(async () =>
        {
            var tried = await db.AuditOutbox.AsNoTracking().Where(o => seqs.Contains(o.AuditSeq)).ToListAsync();
            return tried.Count == seqs.Count && tried.All(o => o.Attempts >= 1 && o.LastError is not null);
        });
        Assert.NotEmpty(factory.Sink.Refused);
        Assert.Empty(factory.Sink.Deliveries);
        var failed = await db.AuditOutbox.AsNoTracking().Where(o => seqs.Contains(o.AuditSeq)).ToListAsync();
        Assert.All(failed, o => Assert.StartsWith("AuditSinkException: The audit sink answered 503.", o.LastError, StringComparison.Ordinal));
        Assert.All(failed, o => Assert.True(o.NextAttemptAt > o.CreatedAt));

        // The sink comes back: every record is delivered exactly once, each request in sequence
        // order, with the sink's credential, and the queue empties as it goes.
        factory.Sink.Down = false;
        await WaitUntilAsync(async () => await db.AuditOutbox.AsNoTracking().CountAsync(o => seqs.Contains(o.AuditSeq)) == 0);

        Assert.All(factory.Sink.Deliveries, d => Assert.Equal(d.Records.Select(r => r.GetProperty("seq").GetInt64()).Order(), d.Records.Select(r => r.GetProperty("seq").GetInt64())));
        var delivered = factory.Sink.Deliveries.SelectMany(d => d.Records).Where(r => r.GetProperty("agent_id").GetString() == agentId).OrderBy(r => r.GetProperty("seq").GetInt64()).ToList();
        Assert.Equal(seqs, delivered.Select(r => r.GetProperty("seq").GetInt64()));
        Assert.All(factory.Sink.Deliveries, d => Assert.Equal("Bearer " + AuditSinkFactory.SinkToken, d.Authorization));
        foreach (var (row, record) in expected.Zip(delivered))
        {
            Assert.Equal(row.Event, record.GetProperty("event").GetString());
            Assert.Equal(row.TaskId, record.GetProperty("task_id").GetString());
            Assert.Equal(row.Sponsor, record.GetProperty("sponsor").GetString());
            Assert.Equal(row.Seq, record.GetProperty("seq").GetInt64());

            // Delivered within a drain tick, before the sealing pass runs, so the sink is told the
            // record is not sealed yet.
            Assert.Equal(JsonValueKind.Null, record.GetProperty("checkpoint").ValueKind);
        }

        Assert.Contains(firstTask, delivered.Select(r => r.GetProperty("task_id").GetString()));
        Assert.Contains(secondTask, delivered.Select(r => r.GetProperty("task_id").GetString()));

        // Delivered entries are deleted, and no later pass sends them again.
        var deliveries = factory.Sink.Deliveries.Count;
        await Task.Delay(TimeSpan.FromSeconds(2));
        Assert.Equal(delivered.Count, factory.Sink.Deliveries.SelectMany(d => d.Records).Count(r => r.GetProperty("agent_id").GetString() == agentId));
        Assert.Empty(await db.AuditOutbox.AsNoTracking().Where(o => seqs.Contains(o.AuditSeq)).ToListAsync());
        Assert.True(deliveries >= 1);
    }

    private async Task<string> ExchangeAsync()
    {
        using var response = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = SubjectToken(),
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = ActorAssertion(),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["resource"] = "https://jira.internal",
            ["scope"] = "jira:read jira:comment",
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("task_id").GetString()!;
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> condition)
    {
        var deadline = DateTimeOffset.UtcNow + Deadline;
        while (!await condition())
        {
            Assert.True(DateTimeOffset.UtcNow < deadline, "The condition did not hold before the deadline.");
            await Task.Delay(200);
        }
    }

    private static string SubjectToken()
    {
        var now = DateTimeOffset.UtcNow;
        return Mint(IdpKey, IdpKid, new Dictionary<string, object?>
        {
            ["iss"] = IdpIssuer,
            ["sub"] = Human,
            ["aud"] = "subactid",
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["scope"] = "openid jira:read jira:comment",
        });
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

/// <summary>The exchange-capable server with a sink configured, the drain on a one-second interval, and the sink itself stood in for by <see cref="FakeAuditSink"/>.</summary>
internal sealed class AuditSinkFactory(PostgresDatabaseFixture postgres) : ExchangeServerFactory(postgres)
{
    public const string SinkUrl = "https://siem.example.test/subactid/audit";
    public const string SinkToken = "sink-token-for-tests-only";

    public FakeAuditSink Sink { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            var configured = services.Single(d => d.ServiceType == typeof(SubactIdOptions));
            var options = (SubactIdOptions)configured.ImplementationInstance!;
            services.Remove(configured);
            var withSink = new SubactIdOptions
            {
                Issuer = options.Issuer,
                UpstreamIdp = options.UpstreamIdp,
                Database = options.Database,
                Tokens = options.Tokens,
                Agents = options.Agents,
                Tasks = options.Tasks,
                Signing = options.Signing,
                Admin = options.Admin,
                Audit = new AuditOptions { SinkUrl = new Uri(SinkUrl), SinkBearerToken = SinkToken, DrainInterval = TimeSpan.FromSeconds(1), DrainBatchSize = 3, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
            };
            services.AddSingleton(withSink);
            services.RemoveAll<AuditOutboxSettings>();
            services.AddSingleton(new AuditOutboxSettings(true));
            services.AddSubactIdAuditDelivery(withSink.Audit);
            services.AddHttpClient(HttpAuditSink.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Sink);
        });
    }
}

/// <summary>The sink as the drain sees it: answers 503 while <see cref="Down"/>, otherwise records each delivery and answers 202.</summary>
internal sealed class FakeAuditSink : HttpMessageHandler
{
    public volatile bool Down;

    public ConcurrentQueue<(string? Authorization, IReadOnlyList<JsonElement> Records)> Deliveries { get; } = [];

    public ConcurrentQueue<string> Refused { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Assert.Equal(AuditSinkFactory.SinkUrl, request.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, request.Method);
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        if (Down)
        {
            Refused.Enqueue(body);
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("{\"error\":\"down\"}", Encoding.UTF8, "application/json") };
        }

        using var document = JsonDocument.Parse(body);
        Deliveries.Enqueue((request.Headers.Authorization?.ToString(), document.RootElement.GetProperty("records").EnumerateArray().Select(r => r.Clone()).ToList()));
        return new HttpResponseMessage(HttpStatusCode.Accepted);
    }
}
