using System.Text.Json;
using SubactId.Core.Audit;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class AuditQueryResponseTests
{
    private static readonly DateTimeOffset Ts = new(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero);

    [Fact]
    public void A_full_page_plus_one_yields_the_page_and_a_cursor_at_its_last_record()
    {
        var records = Enumerable.Range(1, 4).Select(Record).ToList();

        var response = AuditQueryResponse.From(records, 3, NothingSealed);

        Assert.Equal([1, 2, 3], response.Records.Select(r => r.Seq));
        Assert.Equal(AuditCursorCodec.Encode(records[2]), response.NextCursor);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    public void A_short_or_exactly_full_page_is_the_last_one(int count)
    {
        var response = AuditQueryResponse.From(Enumerable.Range(1, count).Select(Record).ToList(), 3, NothingSealed);

        Assert.Equal(count, response.Records.Count);
        Assert.Null(response.NextCursor);
    }

    [Fact]
    public void The_page_serialises_as_records_and_next_cursor_in_the_spec_shape()
    {
        var json = JsonSerializer.Serialize(AuditQueryResponse.From([Record(10428)], 1, new Dictionary<long, long> { [10428] = 42 }), SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        Assert.Equal(["records", "next_cursor", "archived_before"], document.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("next_cursor").ValueKind);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("archived_before").ValueKind);
        var record = document.RootElement.GetProperty("records")[0];
        Assert.Equal(["seq", "checkpoint", "ts", "event", "task_id", "agent_id", "sponsor", "audience", "scope", "jti", "delegation_depth", "decision", "reason"], record.EnumerateObject().Select(p => p.Name));
        Assert.Equal(42, record.GetProperty("checkpoint").GetInt64());
        Assert.Equal(Ts.AddSeconds(10428).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture), record.GetProperty("ts").GetString());
        Assert.Equal("allow", record.GetProperty("decision").GetString());
    }

    /// <summary>
    /// An unsealed record is published with <c>checkpoint</c> as an explicit null, not with the key
    /// left out, so a reader can tell it is not sealed yet.
    /// </summary>
    [Fact]
    public void An_unsealed_record_publishes_a_null_checkpoint()
    {
        var json = JsonSerializer.Serialize(AuditQueryResponse.From([Record(7)], 1, NothingSealed), SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("records")[0].GetProperty("checkpoint").ValueKind);
    }

    /// <summary>
    /// Spec section 7 publishes the leaf formula and section 7.1 sends the same shape to a sink, so
    /// the published <c>ts</c> must be the one the leaf was taken over. It always carries three
    /// fractional digits: a record hashed as <c>.330Z</c> and published as <c>.33Z</c> fails against
    /// its checkpoint.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(330)]
    [InlineData(882)]
    public void A_records_published_ts_is_the_one_its_leaf_was_computed_over(int millisecond)
    {
        var at = new DateTimeOffset(2026, 9, 9, 14, 3, 41, millisecond, TimeSpan.Zero);
        var record = new AuditLedgerRecord(1, new AuditEvent(at, AuditEvents.TokenIssued, "task_1", "jira-triage", "human", Decision: AuditDecision.Allow));

        var json = JsonSerializer.Serialize(AuditQueryResponse.From([record], 1, NothingSealed), SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        var published = document.RootElement.GetProperty("records")[0].GetProperty("ts").GetString();
        using var canonical = JsonDocument.Parse(AuditHash.CanonicalJson(record.Event));
        Assert.Equal(canonical.RootElement.GetProperty("ts").GetString(), published);
    }

    private static readonly Dictionary<long, long> NothingSealed = [];

    private static AuditLedgerRecord Record(int seq) =>
        new(seq, new AuditEvent(Ts.AddSeconds(seq), AuditEvents.TokenIssued, $"task_{seq}", "jira-triage", "human", Decision: AuditDecision.Allow));
}
