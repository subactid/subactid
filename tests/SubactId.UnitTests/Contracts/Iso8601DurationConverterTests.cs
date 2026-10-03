using System.Text.Json;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class Iso8601DurationConverterTests
{
    [Theory]
    [InlineData("PT5M", 0, 0, 5, 0)]
    [InlineData("PT30M", 0, 0, 30, 0)]
    [InlineData("PT1H30M", 0, 1, 30, 0)]
    [InlineData("P1D", 1, 0, 0, 0)]
    [InlineData("P1DT12H", 1, 12, 0, 0)]
    [InlineData("PT90S", 0, 0, 1, 30)]
    [InlineData("PT0S", 0, 0, 0, 0)]
    public void Parses_day_time_durations(string text, int days, int hours, int minutes, int seconds)
    {
        Assert.True(Iso8601DurationConverter.TryParse(text, out var value));
        Assert.Equal(new TimeSpan(days, hours, minutes, seconds), value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("P")]
    [InlineData("PT")]
    [InlineData("5M")]
    [InlineData("-PT5M")]
    [InlineData("PT5M\n")]
    [InlineData("PT\u0665M")]
    [InlineData("PT-5M")]
    [InlineData("P1M")]
    [InlineData("P1Y")]
    [InlineData("P1W")]
    [InlineData("PT5M ")]
    [InlineData("00:05:00")]
    [InlineData("PT5.5M")]
    [InlineData("PT999999999999D")]
    public void Rejects_anything_else(string text)
    {
        Assert.False(Iso8601DurationConverter.TryParse(text, out _));
    }

    [Theory]
    [InlineData(0, 0, 5, 0, "PT5M")]
    [InlineData(0, 0, 30, 0, "PT30M")]
    [InlineData(0, 6, 0, 0, "PT6H")]
    [InlineData(1, 0, 0, 0, "P1D")]
    [InlineData(1, 12, 30, 15, "P1DT12H30M15S")]
    [InlineData(0, 0, 0, 0, "PT0S")]
    public void Formats_as_iso_8601(int days, int hours, int minutes, int seconds, string expected)
    {
        Assert.Equal(expected, Iso8601DurationConverter.Format(new TimeSpan(days, hours, minutes, seconds)));
    }

    [Fact]
    public void Formatting_keeps_milliseconds_and_refuses_negative_durations()
    {
        Assert.Equal("PT1.5S", Iso8601DurationConverter.Format(TimeSpan.FromMilliseconds(1500)));
        Assert.Throws<ArgumentOutOfRangeException>(() => Iso8601DurationConverter.Format(TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void Round_trips_through_the_shared_json_options()
    {
        var options = SubactIdJson.CreateOptions();
        var sample = new Sample(TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5));

        var json = JsonSerializer.Serialize(sample, options);
        var back = JsonSerializer.Deserialize<Sample>(json, options);

        Assert.Equal("{\"max_task_ttl\":\"PT30M\",\"max_token_ttl\":\"PT5M\"}", json);
        Assert.Equal(sample, back);
    }

    [Fact]
    public void Deserializing_a_bad_duration_is_a_json_error_not_a_crash()
    {
        var options = SubactIdJson.CreateOptions();

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Sample>("{\"max_task_ttl\":\"30 minutes\",\"max_token_ttl\":\"PT5M\"}", options));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Sample>("{\"max_task_ttl\":1800,\"max_token_ttl\":\"PT5M\"}", options));
    }

    private sealed record Sample(TimeSpan MaxTaskTtl, TimeSpan MaxTokenTtl);
}
