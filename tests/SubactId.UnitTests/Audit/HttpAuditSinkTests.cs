using System.Net;
using System.Text.Json;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class HttpAuditSinkTests
{
    private static readonly Uri SinkUrl = new("https://sink.example.test/audit");
    private static readonly DateTimeOffset Ts = new(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero);

    [Fact]
    public async Task A_batch_is_posted_as_the_spec_records_in_sequence_order()
    {
        var handler = new RecordingHandler(HttpStatusCode.Accepted);
        var sink = Build(handler);
        var first = new AuditLedgerRecord(10428, new AuditEvent(Ts, AuditEvents.TokenIssued, "task_01HQZX9K4M", "jira-triage", "f47ac10b-58cc-4372-a567-0e02b2c3d479", "https://jira.internal", "jira:read jira:comment", "tok_01HQZX9K5P", 1, AuditDecision.Allow));
        var second = new AuditLedgerRecord(10429, new AuditEvent(Ts.AddSeconds(1), AuditEvents.TokenDenied, AgentId: "jira-triage", Decision: AuditDecision.Deny, Reason: "invalid_scope"));

        // The first is sealed, the second is not: a record queued before the sealing pass reached it
        // is sent as unsealed.
        await sink.DeliverAsync([first, second], new Dictionary<long, long> { [10428] = 7 });

        var request = Assert.Single(handler.Requests);
        Assert.Equal((HttpMethod.Post, SinkUrl, "application/json"), (request.Method, request.Url, request.ContentType));
        Assert.Null(request.Authorization);
        using var body = JsonDocument.Parse(request.Body);
        var records = body.RootElement.GetProperty("records");
        Assert.Equal(["records"], body.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(2, records.GetArrayLength());
        var record = records[0];
        Assert.Equal(
            ["seq", "checkpoint", "ts", "event", "task_id", "agent_id", "sponsor", "audience", "scope", "jti", "delegation_depth", "decision", "reason"],
            record.EnumerateObject().Select(p => p.Name));
        Assert.Equal(10428, record.GetProperty("seq").GetInt64());
        Assert.Equal("2026-09-09T14:03:41.882Z", record.GetProperty("ts").GetString());
        Assert.Equal("token.issued", record.GetProperty("event").GetString());
        Assert.Equal("task_01HQZX9K4M", record.GetProperty("task_id").GetString());
        Assert.Equal("f47ac10b-58cc-4372-a567-0e02b2c3d479", record.GetProperty("sponsor").GetString());
        Assert.Equal("jira:read jira:comment", record.GetProperty("scope").GetString());
        Assert.Equal("tok_01HQZX9K5P", record.GetProperty("jti").GetString());
        Assert.Equal(1, record.GetProperty("delegation_depth").GetInt32());
        Assert.Equal("allow", record.GetProperty("decision").GetString());
        Assert.Equal(JsonValueKind.Null, record.GetProperty("reason").ValueKind);
        Assert.Equal(7, record.GetProperty("checkpoint").GetInt64());
        var denial = records[1];
        Assert.Equal((10429L, "token.denied", "deny", "invalid_scope"), (denial.GetProperty("seq").GetInt64(), denial.GetProperty("event").GetString(), denial.GetProperty("decision").GetString(), denial.GetProperty("reason").GetString()));
        Assert.Equal(JsonValueKind.Null, denial.GetProperty("task_id").ValueKind);
        Assert.Equal(JsonValueKind.Null, denial.GetProperty("delegation_depth").ValueKind);
    }

    [Fact]
    public async Task A_record_the_sealing_pass_has_not_reached_says_so_rather_than_leaving_the_field_out()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK);
        await Build(handler).DeliverAsync([Unsealed(1)], NothingSealed);

        using var body = JsonDocument.Parse(handler.Requests.Single().Body);
        Assert.Equal(JsonValueKind.Null, body.RootElement.GetProperty("records")[0].GetProperty("checkpoint").ValueKind);
    }

    [Fact]
    public async Task A_configured_bearer_token_is_presented_and_nothing_else_carries_it()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        var sink = Build(handler, bearerToken: "sink-secret-SENTINEL");

        await sink.DeliverAsync([Unsealed(1)], NothingSealed);

        var request = handler.Requests.Single();
        Assert.Equal("Bearer sink-secret-SENTINEL", request.Authorization);
        Assert.DoesNotContain("SENTINEL", request.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("SENTINEL", new AuditOptions { SinkUrl = SinkUrl, SinkBearerToken = "sink-secret-SENTINEL", DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 1, CheckpointInterval = AuditOptions.DefaultCheckpointInterval }.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task Anything_but_success_is_a_failure_that_names_the_status_and_nothing_from_the_answer(HttpStatusCode status)
    {
        var handler = new RecordingHandler(status, "{\"error\":\"SENTINEL body\"}");

        var exception = await Assert.ThrowsAsync<AuditSinkException>(() => Build(handler).DeliverAsync([Unsealed(1)], NothingSealed));

        Assert.Equal($"The audit sink answered {(int)status}.", exception.Message);
    }

    [Fact]
    public async Task A_transport_failure_surfaces_as_is()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK) { Failure = new HttpRequestException("Connection refused") };

        await Assert.ThrowsAsync<HttpRequestException>(() => Build(handler).DeliverAsync([Unsealed(1)], NothingSealed));
    }

    [Fact]
    public async Task An_empty_batch_sends_nothing()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK);

        await Build(handler).DeliverAsync([], NothingSealed);

        Assert.Empty(handler.Requests);
    }

    private static HttpAuditSink Build(RecordingHandler handler, string? bearerToken = null) =>
        new(new SingleClientFactory(handler), new AuditOptions { SinkUrl = SinkUrl, SinkBearerToken = bearerToken, DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval });

    /// <summary>A record the sealing pass has not reached.</summary>
    private static AuditLedgerRecord Unsealed(long seq) => new(seq, new AuditEvent(Ts, AuditEvents.AgentRegistered, AgentId: "a"));

    private static readonly Dictionary<long, long> NothingSealed = [];

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.Equal(HttpAuditSink.HttpClientName, name);
            return new HttpClient(handler, disposeHandler: false);
        }
    }

    private sealed class RecordingHandler(HttpStatusCode status, string? responseBody = null) : HttpMessageHandler
    {
        public List<(HttpMethod Method, Uri? Url, string? ContentType, string? Authorization, string Body)> Requests { get; } = [];

        public Exception? Failure { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method, request.RequestUri, request.Content?.Headers.ContentType?.MediaType, request.Headers.Authorization?.ToString(), await request.Content!.ReadAsStringAsync(cancellationToken)));
            if (Failure is not null)
            {
                throw Failure;
            }

            return new HttpResponseMessage(status) { Content = responseBody is null ? null : new StringContent(responseBody) };
        }
    }
}
