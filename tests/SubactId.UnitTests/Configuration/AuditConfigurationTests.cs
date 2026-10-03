using Microsoft.Extensions.Configuration;
using SubactId.Core.Audit;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Configuration;

public class AuditConfigurationTests
{
    private const string TokenSentinel = "sink-token-SENTINEL-DO-NOT-LEAK";

    private static readonly Dictionary<string, string?> Complete = new()
    {
        ["SubactId:Issuer"] = "https://subactid.example.test",
        ["SubactId:UpstreamIdp:MetadataUrl"] = "https://idp.example.test/realms/main/.well-known/openid-configuration",
        ["SubactId:UpstreamIdp:Audience"] = "subactid",
        ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
        ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = "https://idp.example.test/realms/main/protocol/openid-connect/token",
        ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
        ["SubactId:Database:ConnectionString"] = "Host=db",
    };

    [Fact]
    public void Without_a_sink_delivery_is_off_and_the_drain_settings_take_their_defaults()
    {
        var audit = SubactIdOptionsLoader.Load(Build(Complete)).Options!.Audit;

        Assert.False(audit.DeliveryEnabled);
        Assert.Null(audit.SinkUrl);
        Assert.Null(audit.SinkBearerToken);
        Assert.Equal((TimeSpan.FromSeconds(5), 100), (audit.DrainInterval, audit.DrainBatchSize));
        Assert.Equal(TimeSpan.FromMinutes(1), audit.CheckpointInterval);
        Assert.Equal("AuditOptions { SinkUrl = <none>, SinkBearerToken = <none>, DrainInterval = 00:00:05, DrainBatchSize = 100, CheckpointInterval = 00:01:00, Retention = <none>, PartitionMonthsAhead = 2 }", audit.ToString());
    }

    [Fact]
    public void The_checkpoint_interval_is_the_window_a_record_can_sit_unsealed_in()
    {
        var audit = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Checkpoint:Interval", "00:00:05")))).Options!.Audit;

        Assert.Equal(TimeSpan.FromSeconds(5), audit.CheckpointInterval);
    }

    [Theory]
    [InlineData("00:00:00")]
    [InlineData("-00:01:00")]
    [InlineData("02:00:00")]
    [InlineData("not-a-duration")]
    public void An_unusable_checkpoint_interval_is_a_startup_error(string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Checkpoint:Interval", value))));

        Assert.False(result.IsValid);
        Assert.StartsWith("SubactId:Audit:Checkpoint:Interval (environment variable SubactId__Audit__Checkpoint__Interval)", result.Errors[0], StringComparison.Ordinal);
    }

    [Fact]
    public void A_sink_url_turns_delivery_on_and_the_token_never_appears_in_formatting()
    {
        var audit = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Sink:Url", "https://siem.example.test/subactid"), ("SubactId:Audit:Sink:BearerToken", TokenSentinel), ("SubactId:Audit:DrainInterval", "00:00:01"), ("SubactId:Audit:DrainBatchSize", "7")))).Options!.Audit;

        Assert.True(audit.DeliveryEnabled);
        Assert.Equal(new Uri("https://siem.example.test/subactid"), audit.SinkUrl);
        Assert.Equal(TokenSentinel, audit.SinkBearerToken);
        Assert.Equal((TimeSpan.FromSeconds(1), 7), (audit.DrainInterval, audit.DrainBatchSize));
        Assert.DoesNotContain("SENTINEL", audit.ToString(), StringComparison.Ordinal);
        Assert.Contains("SinkBearerToken = <redacted>", audit.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_token_without_a_sink_url_is_an_error_that_does_not_echo_the_token()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Sink:BearerToken", TokenSentinel))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal("SubactId:Audit:Sink:BearerToken (environment variable SubactId__Audit__Sink__BearerToken) requires SubactId:Audit:Sink:Url (environment variable SubactId__Audit__Sink__Url).", error);
        Assert.DoesNotContain("SENTINEL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_token_over_plain_http_is_refused()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Sink:Url", "http://siem.internal/subactid"), ("SubactId:Audit:Sink:BearerToken", TokenSentinel))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal("SubactId:Audit:Sink:Url (environment variable SubactId__Audit__Sink__Url) must use https when SubactId:Audit:Sink:BearerToken (environment variable SubactId__Audit__Sink__BearerToken) is set.", error);
        Assert.DoesNotContain("SENTINEL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Plain_http_without_a_token_is_allowed()
    {
        var audit = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Sink:Url", "http://localhost:8080/audit")))).Options!.Audit;

        Assert.True(audit.DeliveryEnabled);
        Assert.Null(audit.SinkBearerToken);
    }

    [Fact]
    public void Credentials_in_the_sink_url_are_refused_and_never_echoed()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Sink:Url", "https://subactid:SENTINEL@siem.example.test/subactid"))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal("SubactId:Audit:Sink:Url (environment variable SubactId__Audit__Sink__Url) must not carry credentials; use SubactId:Audit:Sink:BearerToken (environment variable SubactId__Audit__Sink__BearerToken).", error);
        Assert.DoesNotContain("SENTINEL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Formatting_drops_the_query_and_fragment_of_the_sink_url()
    {
        var audit = new AuditOptions { SinkUrl = new Uri("https://siem.example.test/subactid?key=SENTINEL#SENTINEL"), DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval };

        Assert.Equal("AuditOptions { SinkUrl = https://siem.example.test/subactid, SinkBearerToken = <none>, DrainInterval = 00:00:05, DrainBatchSize = 100, CheckpointInterval = 00:01:00, Retention = <none>, PartitionMonthsAhead = 2 }", audit.ToString());
    }

    /// <summary>
    /// Retention is unset by default. When set, it only supplies a cutoff to <c>audit-archive</c>,
    /// which nothing here runs.
    /// </summary>
    [Fact]
    public void Retention_is_unset_unless_an_operator_sets_it()
    {
        Assert.Null(SubactIdOptionsLoader.Load(Build(Complete)).Options!.Audit.Retention);
        Assert.Equal(TimeSpan.FromDays(90), SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Retention", "P90D")))).Options!.Audit.Retention);
        Assert.Equal(TimeSpan.FromDays(45), SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Retention", "45.00:00:00")))).Options!.Audit.Retention);
    }

    /// <summary>
    /// Every partition adds planning work to each /audit query, so the runway is short by default and
    /// capped at a year. Zero is refused, since next month's partition would then be made on the
    /// request path.
    /// </summary>
    [Fact]
    public void The_partition_runway_is_two_months_unless_set_and_is_held_between_one_month_and_a_year()
    {
        Assert.Equal(2, SubactIdOptionsLoader.Load(Build(Complete)).Options!.Audit.PartitionMonthsAhead);
        Assert.Equal(6, SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Partitions:MonthsAhead", "6")))).Options!.Audit.PartitionMonthsAhead);

        foreach (var outside in new[] { "0", "13" })
        {
            var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Partitions:MonthsAhead", outside))));

            Assert.Null(result.Options);
            Assert.StartsWith("SubactId:Audit:Partitions:MonthsAhead (environment variable SubactId__Audit__Partitions__MonthsAhead)", Assert.Single(result.Errors), StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Removal is by whole month, so retention shorter than the longest month would make last month a
    /// candidate the day it ended.
    /// </summary>
    [Theory]
    [InlineData("P30D")]
    [InlineData("00:00:01")]
    [InlineData("not a duration")]
    public void A_retention_shorter_than_a_month_or_not_a_duration_is_refused(string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Retention", value))));

        Assert.False(result.IsValid);
        Assert.Contains("SubactId:Audit:Retention", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("ftp://siem.example.test/subactid")]
    [InlineData("/relative")]
    public void The_sink_url_must_be_an_absolute_http_or_https_url(string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:Sink:Url", value))));

        Assert.False(result.IsValid);
        Assert.Equal("SubactId:Audit:Sink:Url (environment variable SubactId__Audit__Sink__Url) must be an absolute http or https URL.", Assert.Single(result.Errors));
    }

    [Theory]
    [InlineData("00:00:00.5")]
    [InlineData("01:00:01")]
    [InlineData("00:00:00")]
    [InlineData("soon")]
    public void The_drain_interval_is_bounded(string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:DrainInterval", value))));

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.StartsWith("SubactId:Audit:DrainInterval (environment variable SubactId__Audit__DrainInterval)", result.Errors[0], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("00:00:01")]
    [InlineData("01:00:00")]
    public void The_drain_interval_bounds_are_inclusive(string value) =>
        Assert.True(SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:DrainInterval", value)))).IsValid);

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("many")]
    public void The_drain_batch_size_must_be_a_positive_whole_number(string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Audit:DrainBatchSize", value))));

        Assert.False(result.IsValid);
        Assert.Equal("SubactId:Audit:DrainBatchSize (environment variable SubactId__Audit__DrainBatchSize) must be a positive whole number.", Assert.Single(result.Errors));
    }

    private static Dictionary<string, string?> With(params (string Key, string Value)[] values)
    {
        var all = new Dictionary<string, string?>(Complete);
        foreach (var (key, value) in values)
        {
            all[key] = value;
        }

        return all;
    }

    private static IConfiguration Build(IEnumerable<KeyValuePair<string, string?>> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();
}
