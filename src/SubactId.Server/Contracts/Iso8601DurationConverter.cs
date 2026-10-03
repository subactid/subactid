using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SubactId.Server.Contracts;

/// <summary>
/// Reads and writes <see cref="TimeSpan"/> as an ISO 8601 duration limited to days,
/// hours, minutes and seconds, for example <c>PT30M</c> or <c>P1DT12H</c>. Years, months
/// and negative durations are rejected.
/// </summary>
public sealed partial class Iso8601DurationConverter : JsonConverter<TimeSpan>
{
    /// <inheritdoc />
    public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("Expected an ISO 8601 duration string such as PT5M.");
        }

        return TryParse(reader.GetString(), out var value)
            ? value
            : throw new JsonException("Expected an ISO 8601 duration string such as PT5M.");
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);

        writer.WriteStringValue(Format(value));
    }

    /// <summary>Parses a duration such as <c>PT5M</c>. Returns <c>false</c> for anything else.</summary>
    /// <param name="text">The text to parse.</param>
    /// <param name="value">The parsed duration.</param>
    public static bool TryParse(string? text, out TimeSpan value)
    {
        value = default;
        if (text is null)
        {
            return false;
        }

        var match = Duration().Match(text);
        if (!match.Success)
        {
            return false;
        }

        var days = Component(match.Groups["d"]);
        var hours = Component(match.Groups["h"]);
        var minutes = Component(match.Groups["m"]);
        var seconds = Component(match.Groups["s"]);
        if (days + hours + minutes + seconds == 0 && !match.Groups["d"].Success && !match.Groups["h"].Success
            && !match.Groups["m"].Success && !match.Groups["s"].Success)
        {
            return false;
        }

        try
        {
            value = TimeSpan.FromDays(days) + TimeSpan.FromHours(hours) + TimeSpan.FromMinutes(minutes) + TimeSpan.FromSeconds(seconds);
        }
        catch (OverflowException)
        {
            return false;
        }

        return true;
    }

    /// <summary>Formats a non-negative duration as ISO 8601, for example <c>PT30M</c>.</summary>
    /// <param name="value">The duration.</param>
    /// <exception cref="ArgumentOutOfRangeException">The duration is negative.</exception>
    public static string Format(TimeSpan value)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);

        if (value == TimeSpan.Zero)
        {
            return "PT0S";
        }

        var text = "P";
        if (value.Days > 0)
        {
            text += $"{value.Days}D";
        }

        var time = string.Empty;
        if (value.Hours > 0)
        {
            time += $"{value.Hours}H";
        }

        if (value.Minutes > 0)
        {
            time += $"{value.Minutes}M";
        }

        var seconds = value.Seconds + value.Milliseconds / 1000.0;
        if (seconds > 0)
        {
            time += $"{seconds.ToString("0.###", CultureInfo.InvariantCulture)}S";
        }

        return time.Length > 0 ? $"{text}T{time}" : text;
    }

    private static double Component(Group group) =>
        group.Success ? double.Parse(group.Value, CultureInfo.InvariantCulture) : 0;

    // [0-9], not \d, which in .NET matches every Unicode digit; \z, not $, which also matches
    // before a final newline.
    [GeneratedRegex(@"^P(?:(?<d>[0-9]+)D)?(?:T(?:(?<h>[0-9]+)H)?(?:(?<m>[0-9]+)M)?(?:(?<s>[0-9]+(?:\.[0-9]{1,3})?)S)?)?\z", RegexOptions.CultureInvariant)]
    private static partial Regex Duration();
}
