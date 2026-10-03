using SubactId.Core.Audit;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class QueryAuditRequestTests
{
    [Fact]
    public void An_empty_request_is_the_whole_ledger_in_pages_of_one_hundred()
    {
        var errors = new QueryAuditRequest().TryToQuery(out var query);

        Assert.Empty(errors);
        Assert.Equal(new AuditQuery(), query);
        Assert.Equal(100, query!.Limit);
    }

    [Fact]
    public void The_spec_query_maps_to_all_of_september_for_the_sponsor()
    {
        var request = new QueryAuditRequest { Sponsor = "f47ac10b-58cc-4372-a567-0e02b2c3d479", From = "2026-09-01", To = "2026-09-30" };

        var errors = request.TryToQuery(out var query);

        Assert.Empty(errors);
        Assert.Equal("f47ac10b-58cc-4372-a567-0e02b2c3d479", query!.Sponsor);
        Assert.Equal(new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero), query.From);
        Assert.Equal(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), query.To);
    }

    [Fact]
    public void Every_filter_is_read_and_timestamps_are_taken_as_given()
    {
        var request = new QueryAuditRequest
        {
            Sponsor = "human",
            AgentId = "jira-triage",
            TaskId = "task_01HQZX9K4M",
            From = "2026-09-01T14:32:00Z",
            To = "2026-09-01T17:32:00.5+02:00",
            Decision = "deny",
            Limit = "7",
        };

        var errors = request.TryToQuery(out var query);

        Assert.Empty(errors);
        Assert.Equal(new AuditQuery("human", "jira-triage", "task_01HQZX9K4M", new DateTimeOffset(2026, 9, 1, 14, 32, 0, TimeSpan.Zero), new DateTimeOffset(2026, 9, 1, 15, 32, 0, 500, TimeSpan.Zero), AuditDecision.Deny, null, 7), query);
    }

    [Fact]
    public void A_naive_timestamp_is_utc()
    {
        var errors = new QueryAuditRequest { From = "2026-09-01T14:32:00" }.TryToQuery(out var query);

        Assert.Empty(errors);
        Assert.Equal(new DateTimeOffset(2026, 9, 1, 14, 32, 0, TimeSpan.Zero), query!.From);
    }

    [Fact]
    public void Every_bad_field_is_reported_at_once_without_echoing_a_value()
    {
        var request = new QueryAuditRequest
        {
            Sponsor = "has space",
            AgentId = new string('a', 129),
            TaskId = string.Empty,
            From = "yesterday",
            To = "09/30/2026",
            Decision = "maybe",
            Limit = "0",
            Cursor = "not-a-cursor",
        };

        var errors = request.TryToQuery(out var query);

        Assert.Null(query);
        Assert.Equal(["sponsor", "agent_id", "task_id", "from", "to", "decision", "limit", "cursor"], errors.Select(e => e.Field));
        Assert.All(errors, e => Assert.DoesNotContain("maybe", e.Message, StringComparison.Ordinal));
    }

    /// <summary>
    /// A control character in an identifier filter is refused with the per-field 400 of spec section
    /// 7.2. Postgres refuses a NUL in a text parameter, so it would otherwise surface as a 500.
    /// </summary>
    [Theory]
    [InlineData("\0")]
    [InlineData("before\0after")]
    [InlineData("bell\a")]
    [InlineData("")]
    [InlineData("")]
    public void An_identifier_filter_with_a_control_character_is_a_per_field_error(string value)
    {
        foreach (var request in new[]
                 {
                     new QueryAuditRequest { Sponsor = value },
                     new QueryAuditRequest { AgentId = value },
                     new QueryAuditRequest { TaskId = value },
                 })
        {
            var errors = request.TryToQuery(out var query);

            Assert.Null(query);
            var error = Assert.Single(errors);
            Assert.Contains("control characters", error.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(value, error.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("2026-09-30", "2026-09-01")]
    [InlineData("2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z")]
    public void To_must_be_after_from(string from, string to)
    {
        var errors = new QueryAuditRequest { From = from, To = to }.TryToQuery(out var query);

        Assert.Null(query);
        Assert.Equal(("to", "must be after from."), (errors.Single().Field, errors.Single().Message));
    }

    [Theory]
    [InlineData("09/30/2026")]
    [InlineData("30.09.2026")]
    [InlineData("2026-09-30 14:32:00")]
    [InlineData("2026-09-30T14:32")]
    [InlineData("1757426520")]
    public void Only_iso_8601_dates_and_timestamps_are_read(string value)
    {
        var errors = new QueryAuditRequest { From = value }.TryToQuery(out var query);

        Assert.Null(query);
        Assert.Equal("from", errors.Single().Field);
    }

    [Fact]
    public void The_last_representable_day_in_to_is_an_error_not_an_overflow()
    {
        var errors = new QueryAuditRequest { To = "9999-12-31" }.TryToQuery(out var query);

        Assert.Null(query);
        Assert.Equal("to", errors.Single().Field);
        Assert.Empty(new QueryAuditRequest { From = "9999-12-31" }.TryToQuery(out _));
        Assert.Empty(new QueryAuditRequest { To = "9999-12-30" }.TryToQuery(out _));
    }

    [Fact]
    public void A_bare_date_in_both_ends_is_that_one_day()
    {
        var errors = new QueryAuditRequest { From = "2026-09-30", To = "2026-09-30" }.TryToQuery(out var query);

        Assert.Empty(errors);
        Assert.Equal((new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero)), (query!.From, query.To));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("1000")]
    public void The_limit_bounds_are_inclusive(string limit)
    {
        Assert.Empty(new QueryAuditRequest { Limit = limit }.TryToQuery(out var query));
        Assert.Equal(int.Parse(limit, System.Globalization.CultureInfo.InvariantCulture), query!.Limit);
    }

    [Theory]
    [InlineData("1001")]
    [InlineData("-1")]
    [InlineData("ten")]
    [InlineData("")]
    public void Limits_outside_one_to_a_thousand_are_refused(string limit)
    {
        var errors = new QueryAuditRequest { Limit = limit }.TryToQuery(out var query);

        Assert.Null(query);
        Assert.Equal("limit", errors.Single().Field);
    }

    [Fact]
    public void A_cursor_round_trips_the_position_of_a_record()
    {
        var ts = new DateTimeOffset(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero).AddTicks(1234);
        var record = new AuditLedgerRecord(10428, new AuditEvent(ts, AuditEvents.TokenIssued));

        var cursor = AuditCursorCodec.Encode(record);
        var errors = new QueryAuditRequest { Cursor = cursor }.TryToQuery(out var query);

        Assert.Empty(errors);
        Assert.Equal(new AuditCursor(ts, 10428), query!.After);
        Assert.DoesNotContain("10428", cursor, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("!!!")]
    [InlineData("MTIz")]
    [InlineData("MTIzOjA")]
    [InlineData("LTE6MQ")]
    [InlineData("MTIzOjE6MQ")]
    [InlineData("OTk5OTk5OTk5OTk5OTk5OTk5OTk5OjE")]
    public void Anything_but_a_cursor_this_server_made_is_refused(string cursor)
    {
        Assert.Null(AuditCursorCodec.Decode(cursor));
    }

    [Fact]
    public void An_overlong_cursor_is_refused_before_it_is_decoded()
    {
        Assert.Null(AuditCursorCodec.Decode(new string('A', 65)));
    }
}
