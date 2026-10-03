using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>
/// Writes <see cref="DateTimeOffset"/> as UTC ISO 8601 with a <c>Z</c> suffix and at most
/// millisecond precision, for example <c>2026-09-09T14:03:41.882Z</c>, and reads any ISO 8601
/// timestamp with an explicit offset or <c>Z</c>.
/// </summary>
public sealed class UtcTimestampConverter : JsonConverter<DateTimeOffset>
{
    private const string WriteFormat = "yyyy-MM-dd'T'HH:mm:ss.FFF'Z'";

    /// <inheritdoc />
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String
            && DateTimeOffset.TryParse(reader.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var value))
        {
            return value;
        }

        throw new JsonException("Expected an ISO 8601 timestamp such as 2026-09-09T14:32:00Z.");
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);

        writer.WriteStringValue(value.ToUniversalTime().ToString(WriteFormat, CultureInfo.InvariantCulture));
    }
}
