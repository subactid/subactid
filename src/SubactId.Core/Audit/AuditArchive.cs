using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SubactId.Core.Audit;

/// <summary>
/// One month of the ledger that was exported and removed (spec section 7.5). Written before the
/// partition is detached. Records older than <see cref="ArchivedBefore"/> are no longer online,
/// and checkpoints up to <see cref="LastCheckpointId"/> cannot be verified from the database.
/// </summary>
/// <param name="Month">First instant of the archived month, UTC.</param>
/// <param name="Partition">The partition that was detached and dropped.</param>
/// <param name="FirstCheckpointId">First checkpoint in the export.</param>
/// <param name="LastCheckpointId">Last checkpoint in the export, or <see cref="FirstCheckpointId"/> minus one when the export holds no checkpoints.</param>
/// <param name="FirstSeq">First sequence number in the export.</param>
/// <param name="LastSeq">Last sequence number in the export, or <see cref="FirstSeq"/> minus one when the export holds no records.</param>
/// <param name="Records">Records in the export.</param>
/// <param name="Location">Where the export was written.</param>
/// <param name="Digest">SHA-256 of the export, exactly as it was written.</param>
/// <param name="ArchivedAt">When the export was taken.</param>
public sealed record AuditArchive(
    DateTimeOffset Month,
    string Partition,
    long FirstCheckpointId,
    long LastCheckpointId,
    long FirstSeq,
    long LastSeq,
    long Records,
    string Location,
    ReadOnlyMemory<byte> Digest,
    DateTimeOffset ArchivedAt)
{
    /// <summary>
    /// Longest <c>detail</c> a record holds (the column width). The escaped JSON must fit, so check
    /// a location with <see cref="LocationFits"/>, not by its own length.
    /// </summary>
    public const int MaxDetailLength = 2048;

    /// <summary>
    /// The first instant still online after this month was archived. Returned by <c>GET /audit</c>
    /// as <c>archived_before</c>.
    /// </summary>
    public DateTimeOffset ArchivedBefore => Month.AddMonths(1);

    /// <summary>
    /// Whether the export holds no checkpoints, because an earlier export already carried them.
    /// </summary>
    public bool IsEmpty => LastCheckpointId < FirstCheckpointId;

    /// <summary>
    /// The <c>detail</c> of the <c>audit.archived</c> record: partition, checkpoint and sequence
    /// ranges, export location and digest, as one line of JSON with keys in lexicographic order.
    /// </summary>
    public string ToDetail()
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            writer.WriteStartObject();
            writer.WriteString("digest", Convert.ToHexStringLower(Digest.Span));
            writer.WriteNumber("first_checkpoint", FirstCheckpointId);
            writer.WriteNumber("first_seq", FirstSeq);
            writer.WriteNumber("last_checkpoint", LastCheckpointId);
            writer.WriteNumber("last_seq", LastSeq);
            writer.WriteString("location", Location);
            writer.WriteString("month", MonthName(Month));
            writer.WriteString("partition", Partition);
            writer.WriteNumber("records", Records);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Whether an <c>audit.archived</c> detail naming <paramref name="location"/>, with every other
    /// field at its widest, fits in <see cref="MaxDetailLength"/>. Checked before exporting.
    /// </summary>
    /// <param name="location">Where the export would be written.</param>
    public static bool LocationFits(string location)
    {
        ArgumentNullException.ThrowIfNull(location);

        // Every other field at its widest.
        var widest = new AuditArchive(
            new DateTimeOffset(9999, 12, 1, 0, 0, 0, TimeSpan.Zero),
            "audit_events_p999912",
            long.MaxValue,
            long.MaxValue,
            long.MaxValue,
            long.MaxValue,
            long.MaxValue,
            location,
            new byte[AuditHash.Length],
            DateTimeOffset.MinValue);

        return widest.ToDetail().Length <= MaxDetailLength;
    }

    /// <summary>The month as <c>YYYY-MM</c>, as used on the command line and in export names.</summary>
    /// <param name="month">Any instant in the month.</param>
    public static string MonthName(DateTimeOffset month) =>
        month.ToUniversalTime().ToString("yyyy-MM", CultureInfo.InvariantCulture);

    /// <summary>The first instant of the UTC month holding <paramref name="at"/>.</summary>
    /// <param name="at">The instant.</param>
    public static DateTimeOffset StartOfMonth(DateTimeOffset at)
    {
        var utc = at.UtcDateTime;
        return new DateTimeOffset(utc.Year, utc.Month, 1, 0, 0, 0, TimeSpan.Zero);
    }

    /// <summary>
    /// Parses a strict <c>YYYY-MM</c> as the first instant of that month in UTC.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="month">The first instant of the month.</param>
    public static bool TryParseMonth(string? text, out DateTimeOffset month)
    {
        month = default;
        if (text is null
            || text.Length != 7
            || text[4] != '-'
            || !int.TryParse(text.AsSpan(0, 4), NumberStyles.None, CultureInfo.InvariantCulture, out var year)
            || !int.TryParse(text.AsSpan(5, 2), NumberStyles.None, CultureInfo.InvariantCulture, out var ordinal)
            || year is < 1 or > 9999
            || ordinal is < 1 or > 12)
        {
            return false;
        }

        month = new DateTimeOffset(year, ordinal, 1, 0, 0, 0, TimeSpan.Zero);
        return true;
    }
}

/// <summary>
/// The archived months. Append-only: each month is archived once.
/// </summary>
public interface IAuditArchiveRepository
{
    /// <summary>
    /// The most recently archived month, or <c>null</c> when nothing has been archived.
    /// Verification starts after its <see cref="AuditArchive.LastCheckpointId"/>.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<AuditArchive?> LastAsync(CancellationToken cancellationToken = default);

    /// <summary>The archive of <paramref name="month"/>, or <c>null</c> when it has not been archived.</summary>
    /// <param name="month">First instant of the month.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<AuditArchive?> FindAsync(DateTimeOffset month, CancellationToken cancellationToken = default);

    /// <summary>Records <paramref name="archive"/>. Called in the transaction that writes the <c>audit.archived</c> record.</summary>
    /// <param name="archive">The archive.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AppendAsync(AuditArchive archive, CancellationToken cancellationToken = default);
}

/// <summary>
/// Exports a month of the ledger and removes the partition that held it.
/// <para>
/// Removal detaches the partition, which leaves the <c>UPDATE</c>, <c>DELETE</c> and
/// <c>TRUNCATE</c> guard intact. It runs only as an explicit, audited command. Providers without
/// partitioning do not support it.
/// </para>
/// </summary>
public interface IAuditLedgerArchive
{
    /// <summary>
    /// Writes every record with a sequence number in <c>[firstSeq, lastSeq]</c> to
    /// <paramref name="destination"/> in sequence order, one line each, and returns how many were
    /// written. The format is the provider's bulk-export text.
    /// </summary>
    /// <param name="firstSeq">First sequence number, inclusive.</param>
    /// <param name="lastSeq">Last sequence number, inclusive.</param>
    /// <param name="destination">Where the lines go.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<long> ExportAsync(long firstSeq, long lastSeq, TextWriter destination, CancellationToken cancellationToken = default);

    /// <summary>The highest sequence number in <paramref name="partition"/>, or <c>null</c> when it holds no records.</summary>
    /// <param name="partition">The partition's table name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<long?> HighestSeqAsync(string partition, CancellationToken cancellationToken = default);

    /// <summary>
    /// Detaches <paramref name="partition"/> and drops it, provided it holds no record above
    /// <paramref name="exportedThrough"/>. The check runs after detaching, so late appends are
    /// caught. If one is found, the partition is left attached and its sequence number returned.
    /// <para>
    /// Refuses any name that is not a control-plane partition name.
    /// </para>
    /// </summary>
    /// <param name="partition">The partition's table name.</param>
    /// <param name="exportedThrough">The last sequence number the export of this month carries.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>null</c> once the partition is gone; otherwise the highest sequence number it holds, which is above <paramref name="exportedThrough"/>, with the partition still attached.</returns>
    Task<long?> DropAsync(string partition, long exportedThrough, CancellationToken cancellationToken = default);
}
