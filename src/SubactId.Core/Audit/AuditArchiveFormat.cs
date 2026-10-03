using System.Globalization;
using System.Text;

namespace SubactId.Core.Audit;

/// <summary>
/// The line format of an export, and how it is read back (spec section 7.5). One record or
/// checkpoint per line, tab-separated, null as <c>\N</c>, and control characters and backslash
/// escaped as Postgres bulk export does. The records section matches <c>COPY … TO STDOUT</c> byte for byte.
/// <para>
/// Exports are verified by rebuilding each checkpoint's root from the parsed records, so parsing
/// must be exact. The writer, verifier and command all share this one definition.
/// </para>
/// </summary>
public static class AuditArchiveFormat
{
    /// <summary>The first line of every export. Files without it are refused.</summary>
    public const string Magic = "subactid-audit-archive/1";

    /// <summary>
    /// The export timestamp format: UTC ISO 8601 with six fractional digits, the precision the
    /// ledger stores. Finer than the hashed millisecond form, so no rounding happens on export.
    /// </summary>
    public const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";

    /// <summary>The marker for a null field, as the bulk exporter writes it.</summary>
    public const string Null = @"\N";

    /// <summary>The ledger's columns, in the order a record's line carries them.</summary>
    public static readonly IReadOnlyList<string> Columns =
    [
        "seq", "ts", "event", "task_id", "agent_id", "sponsor", "audience", "scope",
        "jti", "delegation_depth", "decision", "reason", "count", "detail",
    ];

    /// <summary>Fields a checkpoint's line carries.</summary>
    private const int CheckpointFields = 9;

    /// <summary>One checkpoint as a line, in the order <see cref="TryReadCheckpoint"/> reads it.</summary>
    /// <param name="checkpoint">The checkpoint.</param>
    public static string WriteCheckpoint(AuditCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        return string.Join(
            '\t',
            checkpoint.CheckpointId.ToString(CultureInfo.InvariantCulture),
            checkpoint.FirstSeq.ToString(CultureInfo.InvariantCulture),
            checkpoint.LastSeq.ToString(CultureInfo.InvariantCulture),
            checkpoint.TreeSize.ToString(CultureInfo.InvariantCulture),
            Convert.ToHexStringLower(checkpoint.RootHash.Span),
            checkpoint.PrevCheckpointHash is { } previous ? Convert.ToHexStringLower(previous.Span) : Null,
            checkpoint.ClosedAt.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture),
            Escape(checkpoint.Kid),
            Convert.ToHexStringLower(checkpoint.Signature.Span));
    }

    /// <summary>Reads a checkpoint written by <see cref="WriteCheckpoint"/>.</summary>
    /// <param name="line">The line.</param>
    /// <param name="checkpoint">The checkpoint.</param>
    public static bool TryReadCheckpoint(string line, out AuditCheckpoint? checkpoint)
    {
        checkpoint = null;
        var fields = Split(line, CheckpointFields);
        if (fields is null
            || !TryParseLong(fields[0], out var id)
            || !TryParseLong(fields[1], out var firstSeq)
            || !TryParseLong(fields[2], out var lastSeq)
            || !TryParseLong(fields[3], out var treeSize)
            || !TryParseTimestamp(fields[6], out var closedAt)
            || fields[7] is not { } kid)
        {
            return false;
        }

        var root = ParseHash(fields[4]);
        var signature = ParseHash(fields[8]);
        var linked = fields[5] is null ? null : ParseHash(fields[5]);
        if (root is null || signature is null || (fields[5] is not null && linked is null))
        {
            return false;
        }

        // The first checkpoint links to nothing. Keep that as null, not as an empty hash.
        ReadOnlyMemory<byte>? previous = null;
        if (linked is not null)
        {
            previous = linked;
        }

        checkpoint = new AuditCheckpoint(id, firstSeq, lastSeq, treeSize, root, previous, closedAt, kid, signature);
        return true;
    }

    /// <summary>
    /// One record as a line, in the order <see cref="TryReadRecord"/> reads it. Matches the
    /// database's bulk export byte for byte. For producing or checking lines without a database.
    /// </summary>
    /// <param name="record">The record.</param>
    public static string WriteRecord(AuditLedgerRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        var written = record.Event;
        return string.Join(
            '\t',
            record.Seq.ToString(CultureInfo.InvariantCulture),
            written.Ts.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture),
            Escape(written.Event),
            Escape(written.TaskId),
            Escape(written.AgentId),
            Escape(written.Sponsor),
            Escape(written.Audience),
            Escape(written.Scope),
            Escape(written.Jti),
            written.DelegationDepth is { } depth ? depth.ToString(CultureInfo.InvariantCulture) : Null,
            Escape(AuditDecisionCodes.ToCode(written.Decision)),
            Escape(written.Reason),
            written.Count is { } count ? count.ToString(CultureInfo.InvariantCulture) : Null,
            Escape(written.Detail));
    }

    /// <summary>Reads a record written as one line of the records section.</summary>
    /// <param name="line">The line.</param>
    /// <param name="record">The record.</param>
    public static bool TryReadRecord(string line, out AuditLedgerRecord? record)
    {
        record = null;
        var fields = Split(line, Columns.Count);
        if (fields is null
            || !TryParseLong(fields[0], out var seq)
            || !TryParseTimestamp(fields[1], out var ts)
            || fields[2] is not { } name
            || !TryParseInt(fields[9], out var depth)
            || fields[10] is not (null or "allow" or "deny")
            || !TryParseInt(fields[12], out var count))
        {
            return false;
        }

        record = new AuditLedgerRecord(
            seq,
            new AuditEvent(
                ts,
                name,
                fields[3],
                fields[4],
                fields[5],
                fields[6],
                fields[7],
                fields[8],
                depth,
                AuditDecisionCodes.FromCode(fields[10]),
                fields[11],
                count,
                fields[13]));
        return true;
    }

    /// <summary>
    /// One field as the bulk exporter writes it: <c>\N</c> for null, and a backslash before each
    /// of the characters a tab-separated line cannot carry literally.
    /// </summary>
    /// <param name="value">The value.</param>
    public static string Escape(string? value)
    {
        if (value is null)
        {
            return Null;
        }

        var escaped = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            switch (character)
            {
                case '\\': escaped.Append(@"\\"); break;
                case '\b': escaped.Append(@"\b"); break;
                case '\f': escaped.Append(@"\f"); break;
                case '\n': escaped.Append(@"\n"); break;
                case '\r': escaped.Append(@"\r"); break;
                case '\t': escaped.Append(@"\t"); break;
                case '\v': escaped.Append(@"\v"); break;
                default: escaped.Append(character); break;
            }
        }

        return escaped.ToString();
    }

    /// <summary>
    /// The fields of one line, unescaped, or <c>null</c> when the line does not hold exactly
    /// <paramref name="count"/> of them.
    /// </summary>
    /// <param name="line">The line.</param>
    /// <param name="count">How many fields the line must hold.</param>
    public static string?[]? Split(string line, int count)
    {
        ArgumentNullException.ThrowIfNull(line);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(count, 0);

        var fields = new string?[count];
        var found = 0;
        var start = 0;
        for (var at = 0; at <= line.Length; at++)
        {
            if (at < line.Length && line[at] != '\t')
            {
                continue;
            }

            if (found == count)
            {
                return null;
            }

            fields[found++] = Unescape(line.AsSpan(start, at - start));
            start = at + 1;
        }

        return found == count ? fields : null;
    }

    /// <summary>The value one escaped field holds, or <c>null</c> for the null marker.</summary>
    private static string? Unescape(ReadOnlySpan<char> field)
    {
        if (field.SequenceEqual(Null))
        {
            return null;
        }

        if (field.IndexOf('\\') < 0)
        {
            return field.ToString();
        }

        var value = new StringBuilder(field.Length);
        for (var at = 0; at < field.Length; at++)
        {
            if (field[at] != '\\')
            {
                value.Append(field[at]);
                continue;
            }

            at++;
            if (at == field.Length)
            {
                // A trailing backslash is kept as is, so the rebuilt leaf fails verification.
                value.Append('\\');
                break;
            }

            switch (field[at])
            {
                case 'b': value.Append('\b'); break;
                case 'f': value.Append('\f'); break;
                case 'n': value.Append('\n'); break;
                case 'r': value.Append('\r'); break;
                case 't': value.Append('\t'); break;
                case 'v': value.Append('\v'); break;
                default: value.Append(field[at]); break;
            }
        }

        return value.ToString();
    }

    private static bool TryParseLong(string? text, out long value)
    {
        value = 0;
        return text is not null && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>An optional integer: <c>true</c> with no value when the field is null.</summary>
    private static bool TryParseInt(string? text, out int? value)
    {
        value = null;
        if (text is null)
        {
            return true;
        }

        if (!int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    private static bool TryParseTimestamp(string? text, out DateTimeOffset value)
    {
        value = default;
        return text is not null
            && DateTimeOffset.TryParseExact(
                text,
                TimestampFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out value);
    }

    /// <summary>The bytes a lowercase hex field holds, or <c>null</c> when it is not one.</summary>
    private static byte[]? ParseHash(string? text)
    {
        if (text is null || text.Length == 0 || text.Length % 2 != 0)
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(text);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
