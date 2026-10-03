using System.Text;
using SubactId.Core.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class AuditHashTests
{
    private static readonly AuditEvent SpecExample = new(
        new DateTimeOffset(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero),
        AuditEvents.TokenIssued,
        TaskId: "task_01HQZX9K4M",
        AgentId: "jira-triage",
        Sponsor: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        Audience: "https://jira.internal",
        Scope: "jira:read jira:comment",
        Jti: "tok_01HQZX9K5P",
        DelegationDepth: 1,
        Decision: AuditDecision.Allow,
        Reason: null);

    [Fact]
    public void Canonical_json_has_sorted_keys_explicit_nulls_and_a_millisecond_utc_timestamp()
    {
        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(SpecExample));

        Assert.Equal(
            "{\"agent_id\":\"jira-triage\",\"audience\":\"https://jira.internal\",\"decision\":\"allow\",\"delegation_depth\":1,"
            + "\"event\":\"token.issued\",\"jti\":\"tok_01HQZX9K5P\",\"reason\":null,\"scope\":\"jira:read jira:comment\","
            + "\"sponsor\":\"f47ac10b-58cc-4372-a567-0e02b2c3d479\",\"task_id\":\"task_01HQZX9K4M\",\"ts\":\"2026-09-09T14:03:41.882Z\"}",
            json);
    }

    [Fact]
    public void A_record_with_no_count_hashes_over_json_that_does_not_mention_count()
    {
        // Stated as bytes: a record with no count omits the key. Writing "count":null would change the
        // hash of every such record and fail audit-verify.
        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(SpecExample));

        Assert.DoesNotContain("count", json, StringComparison.Ordinal);
        Assert.Equal(AuditHash.CanonicalJson(SpecExample), AuditHash.CanonicalJson(SpecExample with { Count = null }));
    }

    [Fact]
    public void A_summary_record_hashes_over_its_count_in_key_order()
    {
        var summary = new AuditEvent(
            new DateTimeOffset(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero),
            AuditEvents.TokenDenied,
            Decision: AuditDecision.Deny,
            Reason: "actor_unknown_agent",
            Count: 4812);

        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(summary));

        Assert.Equal(
            "{\"agent_id\":null,\"audience\":null,\"count\":4812,\"decision\":\"deny\",\"delegation_depth\":null,"
            + "\"event\":\"token.denied\",\"jti\":null,\"reason\":\"actor_unknown_agent\",\"scope\":null,"
            + "\"sponsor\":null,\"task_id\":null,\"ts\":\"2026-09-09T14:03:41.882Z\"}",
            json);
    }

    /// <summary>
    /// As with <c>count</c>, a record with no detail omits the key. Writing <c>"detail":null</c>
    /// would change the hash of every such record and fail <c>audit-verify</c>.
    /// </summary>
    [Fact]
    public void A_record_with_no_detail_hashes_over_json_that_does_not_mention_detail()
    {
        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(SpecExample));

        Assert.DoesNotContain("detail", json, StringComparison.Ordinal);
        Assert.Equal(AuditHash.CanonicalJson(SpecExample), AuditHash.CanonicalJson(SpecExample with { Detail = null }));
    }

    [Fact]
    public void An_archive_record_hashes_over_its_detail_in_key_order()
    {
        var archived = new AuditEvent(
            new DateTimeOffset(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero),
            AuditEvents.AuditArchived,
            Detail: "audit_events_p202607");

        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(archived));

        Assert.Equal(
            "{\"agent_id\":null,\"audience\":null,\"decision\":null,\"delegation_depth\":null,"
            + "\"detail\":\"audit_events_p202607\",\"event\":\"audit.archived\",\"jti\":null,\"reason\":null,"
            + "\"scope\":null,\"sponsor\":null,\"task_id\":null,\"ts\":\"2026-09-09T14:03:41.882Z\"}",
            json);
    }

    [Fact]
    public void A_detail_cannot_be_changed_without_changing_the_hash()
    {
        var archived = SpecExample with { Detail = "audit_events_p202607" };

        Assert.NotEqual(AuditHash.CanonicalJson(archived), AuditHash.CanonicalJson(SpecExample with { Detail = "audit_events_p202608" }));
        Assert.NotEqual(AuditHash.CanonicalJson(archived), AuditHash.CanonicalJson(SpecExample));
    }

    [Fact]
    public void A_count_cannot_be_changed_without_changing_the_hash()
    {
        var summary = SpecExample with { Count = 2 };

        Assert.NotEqual(AuditHash.CanonicalJson(summary), AuditHash.CanonicalJson(SpecExample with { Count = 3 }));
        Assert.NotEqual(AuditHash.CanonicalJson(summary), AuditHash.CanonicalJson(SpecExample));
    }

    [Fact]
    public void Timestamps_are_normalised_to_utc_and_denials_are_lowercase()
    {
        var local = SpecExample with { Ts = new DateTimeOffset(2026, 9, 9, 16, 3, 41, 882, TimeSpan.FromHours(2)), Decision = AuditDecision.Deny, Reason = "invalid_scope" };

        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(local));

        Assert.Contains("\"ts\":\"2026-09-09T14:03:41.882Z\"", json, StringComparison.Ordinal);
        Assert.Contains("\"decision\":\"deny\"", json, StringComparison.Ordinal);
        Assert.Contains("\"reason\":\"invalid_scope\"", json, StringComparison.Ordinal);
        Assert.Equal(AuditHash.CanonicalJson(SpecExample), AuditHash.CanonicalJson(SpecExample with { Ts = SpecExample.Ts.ToOffset(TimeSpan.FromHours(-5)) }));
    }

    [Fact]
    public void Strings_are_escaped_so_a_crafted_value_cannot_forge_another_field()
    {
        var crafted = SpecExample with { Reason = "\",\"sponsor\":\"someone-else" };

        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(crafted));

        Assert.Contains("\"reason\":\"\\u0022,\\u0022sponsor\\u0022:\\u0022someone-else\"", json, StringComparison.Ordinal);
        Assert.Contains("\"sponsor\":\"f47ac10b-58cc-4372-a567-0e02b2c3d479\"", json, StringComparison.Ordinal);
    }

    /// <summary>
    /// The escaping spec section 7 publishes, stated as bytes. An SDK or auditor rebuilding a leaf
    /// must escape exactly this way, and most JSON libraries' defaults do not. Changing this means
    /// changing section 7 and every sealed record's leaf.
    /// </summary>
    [Fact]
    public void Strings_are_escaped_exactly_as_section_7_says_so_a_leaf_can_be_rebuilt_elsewhere()
    {
        var crafted = SpecExample with { Scope = "a+b<c>&'d`e\\f/g\th\u0001i\u007fj\u00e9k\U0001F512" };

        var json = Encoding.UTF8.GetString(AuditHash.CanonicalJson(crafted));

        Assert.Contains(
            "\"scope\":\"a\\u002Bb\\u003Cc\\u003E\\u0026\\u0027d\\u0060e\\\\f/g\\th\\u0001i\\u007Fj\\u00E9k\\uD83D\\uDD12\"",
            json,
            StringComparison.Ordinal);
        Assert.All(json, c => Assert.InRange(c, ' ', '~'));
    }
}
