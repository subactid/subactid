using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SubactId.Core.Audit;

namespace SubactId.Server.Contracts;

/// <summary>
/// Writes a ledger record's <c>ts</c> exactly as <see cref="AuditHash"/> hashed it: UTC ISO 8601
/// with a <c>Z</c> and always three fractional digits, for example
/// <c>2026-09-09T14:03:41.330Z</c>.
/// </summary>
/// <remarks>
/// Uses <see cref="AuditHash.TimestampFormat"/> so readers can recompute the record hash (spec
/// section 7). <see cref="UtcTimestampConverter"/> trims trailing zeros and would break that.
/// </remarks>
public sealed class AuditTimestampConverter : JsonConverter<DateTimeOffset>
{
    /// <inheritdoc />
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String
            && DateTimeOffset.TryParse(reader.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var value))
        {
            return value;
        }

        throw new JsonException("Expected an ISO 8601 timestamp such as 2026-09-09T14:03:41.882Z.");
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);

        writer.WriteStringValue(value.ToUniversalTime().ToString(AuditHash.TimestampFormat, CultureInfo.InvariantCulture));
    }
}
