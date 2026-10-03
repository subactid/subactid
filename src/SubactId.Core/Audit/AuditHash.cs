using System.Globalization;
using System.Text.Json;

namespace SubactId.Core.Audit;

/// <summary>
/// The canonical form of a record, the pre-image of its checkpoint leaf: the fields of
/// <see cref="AuditEvent"/> with keys in lexicographic order, no whitespace, explicit nulls, the
/// timestamp as UTC ISO 8601 with millisecond precision, and the decision in lowercase. The
/// sequence number is not included.
/// </summary>
/// <remarks>
/// <para>
/// This format is a contract, published in spec section 7. A leaf is
/// <c>sha256(0x00 || canonical_json(record))</c>, so anyone holding a record can verify it.
/// </para>
/// <para>
/// <c>count</c> and <c>detail</c> are written only when they have a value. Writing them as null
/// would change the pre-image of records that do not carry them.
/// </para>
/// </remarks>
public static class AuditHash
{
    /// <summary>Length of a SHA-256 hash in bytes.</summary>
    public const int Length = 32;

    /// <summary>
    /// The canonical timestamp format: UTC ISO 8601 with three fractional digits. A published
    /// <c>ts</c> must use it so the leaf can be rebuilt.
    /// </summary>
    public const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    /// <summary>The canonical JSON of <paramref name="record"/> as UTF-8.</summary>
    /// <param name="record">The record.</param>
    public static byte[] CanonicalJson(AuditEvent record)
    {
        ArgumentNullException.ThrowIfNull(record);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            writer.WriteStartObject();
            WriteString(writer, "agent_id", record.AgentId);
            WriteString(writer, "audience", record.Audience);
            if (record.Count is { } count)
            {
                // Only when present. See the remarks above.
                writer.WriteNumber("count", count);
            }

            WriteString(writer, "decision", AuditDecisionCodes.ToCode(record.Decision));
            if (record.DelegationDepth is { } depth)
            {
                writer.WriteNumber("delegation_depth", depth);
            }
            else
            {
                writer.WriteNull("delegation_depth");
            }

            if (record.Detail is { } detail)
            {
                // Only when present, like count.
                writer.WriteString("detail", detail);
            }

            writer.WriteString("event", record.Event);
            WriteString(writer, "jti", record.Jti);
            WriteString(writer, "reason", record.Reason);
            WriteString(writer, "scope", record.Scope);
            WriteString(writer, "sponsor", record.Sponsor);
            WriteString(writer, "task_id", record.TaskId);
            writer.WriteString("ts", record.Ts.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static void WriteString(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(name);
        }
        else
        {
            writer.WriteString(name, value);
        }
    }
}
