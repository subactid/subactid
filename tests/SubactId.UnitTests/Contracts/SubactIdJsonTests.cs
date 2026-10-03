using System.Text.Json;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class SubactIdJsonTests
{
    private static readonly JsonSerializerOptions Options = SubactIdJson.CreateOptions();

    [Fact]
    public void Writes_snake_case_names_explicit_nulls_utc_timestamps_and_snake_case_enums()
    {
        var sample = new Sample(
            "task_01HQZX9K4M",
            new DateTimeOffset(2026, 9, 9, 16, 3, 41, 882, TimeSpan.FromHours(2)),
            new DateTimeOffset(2026, 9, 9, 14, 32, 0, TimeSpan.Zero),
            null,
            SampleDecision.Allow);

        var json = JsonSerializer.Serialize(sample, Options);

        Assert.Equal(
            "{\"task_id\":\"task_01HQZX9K4M\",\"ts\":\"2026-09-09T14:03:41.882Z\",\"task_expires_at\":\"2026-09-09T14:32:00Z\",\"reason\":null,\"decision\":\"allow\"}",
            json);
    }

    [Theory]
    [InlineData("\"2026-09-09T14:32:00Z\"")]
    [InlineData("\"2026-09-09T16:32:00+02:00\"")]
    [InlineData("\"2026-09-09T14:32:00.000Z\"")]
    public void Reads_timestamps_with_any_explicit_offset_as_the_same_instant(string json)
    {
        var value = JsonSerializer.Deserialize<DateTimeOffset>(json, Options);

        Assert.Equal(new DateTimeOffset(2026, 9, 9, 14, 32, 0, TimeSpan.Zero), value);
        Assert.Equal(TimeSpan.Zero, value.Offset);
    }

    [Theory]
    [InlineData("\"yesterday\"")]
    [InlineData("1757426520")]
    public void Rejects_timestamps_that_are_not_iso_8601(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<DateTimeOffset>(json, Options));
    }

    [Fact]
    public void Configure_is_idempotent_on_the_same_options_instance_shape()
    {
        var options = new JsonSerializerOptions();
        SubactIdJson.Configure(options);

        Assert.Equal(JsonNamingPolicy.SnakeCaseLower, options.PropertyNamingPolicy);
        Assert.Contains(options.Converters, c => c is Iso8601DurationConverter);
        Assert.Contains(options.Converters, c => c is UtcTimestampConverter);
    }

    private enum SampleDecision
    {
        Allow,
        Deny,
    }

    private sealed record Sample(string TaskId, DateTimeOffset Ts, DateTimeOffset TaskExpiresAt, string? Reason, SampleDecision Decision);
}
