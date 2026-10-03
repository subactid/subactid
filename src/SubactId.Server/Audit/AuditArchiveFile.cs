using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SubactId.Core.Audit;

namespace SubactId.Server.Audit;

/// <summary>The header of an export, in the order its lines are written.</summary>
/// <param name="Month">The month it holds.</param>
/// <param name="Partition">The partition it was taken from.</param>
/// <param name="FirstCheckpointId">First checkpoint in it.</param>
/// <param name="LastCheckpointId">Last checkpoint in it. One below the first when it holds none.</param>
/// <param name="FirstSeq">First sequence number in it.</param>
/// <param name="LastSeq">Last sequence number in it. One below the first when it holds no records.</param>
/// <param name="Checkpoints">How many checkpoint lines follow the header.</param>
public sealed record AuditArchiveHeader(
    DateTimeOffset Month,
    string Partition,
    long FirstCheckpointId,
    long LastCheckpointId,
    long FirstSeq,
    long LastSeq,
    int Checkpoints);

/// <summary>
/// One month of the ledger as a gzip-compressed text file: the records a run of checkpoints
/// sealed, plus those checkpoints. It verifies on its own against the published key set.
/// The line format is <see cref="AuditArchiveFormat"/>'s.
/// </summary>
public static class AuditArchiveFile
{
    /// <summary>The file extension of an export.</summary>
    public const string Extension = ".subactid-archive.gz";

    /// <summary>The suffix a half-written export carries until it is complete.</summary>
    public const string PartialExtension = ".partial";

    /// <summary>The line the checkpoints section starts on.</summary>
    internal const string CheckpointsMarker = "[checkpoints]";

    /// <summary>The line the records section starts on. Every line after it is a record.</summary>
    internal const string RecordsMarker = "[records]";

    /// <summary>UTF-8 without a byte order mark.</summary>
    internal static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>The name an export of <paramref name="month"/> is written under.</summary>
    /// <param name="month">Any instant in the month.</param>
    public static string NameOf(DateTimeOffset month) => $"audit-{AuditArchive.MonthName(month)}{Extension}";

    /// <summary>
    /// Writes the export at <paramref name="path"/> and returns how many records it holds.
    /// It is written under a partial name and moved into place at the end, so an interrupted run
    /// never leaves a truncated archive.
    /// </summary>
    /// <param name="path">Where the export goes. Must not already exist.</param>
    /// <param name="header">What the export says about itself.</param>
    /// <param name="checkpoints">The checkpoints it carries, in id order.</param>
    /// <param name="records">Writes the records section, one line each, and returns how many it wrote.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<long> WriteAsync(
        string path,
        AuditArchiveHeader header,
        IReadOnlyList<AuditCheckpoint> checkpoints,
        Func<TextWriter, CancellationToken, Task<long>> records,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(checkpoints);
        ArgumentNullException.ThrowIfNull(records);

        if (header.Checkpoints != checkpoints.Count)
        {
            throw new ArgumentException("The header must say how many checkpoints the export carries.", nameof(header));
        }

        var partial = path + PartialExtension;
        try
        {
            long written;
            await using (var file = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 64 * 1024, useAsync: true))
            await using (var gzip = new GZipStream(file, CompressionLevel.Optimal))
            await using (var writer = new StreamWriter(gzip, Utf8) { NewLine = "\n" })
            {
                await writer.WriteLineAsync(AuditArchiveFormat.Magic.AsMemory(), cancellationToken);
                foreach (var line in HeaderLines(header))
                {
                    await writer.WriteLineAsync(line.AsMemory(), cancellationToken);
                }

                await writer.WriteLineAsync(CheckpointsMarker.AsMemory(), cancellationToken);
                foreach (var checkpoint in checkpoints)
                {
                    await writer.WriteLineAsync(AuditArchiveFormat.WriteCheckpoint(checkpoint).AsMemory(), cancellationToken);
                }

                await writer.WriteLineAsync(RecordsMarker.AsMemory(), cancellationToken);
                written = await records(writer, cancellationToken);
            }

            File.Move(partial, path);
            return written;
        }
        catch
        {
            Delete(partial);
            throw;
        }
    }

    /// <summary>SHA-256 of the export as it is on disk. This is what the ledger records.</summary>
    /// <param name="path">The export.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<byte[]> DigestAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 64 * 1024, useAsync: true);
        return await SHA256.HashDataAsync(file, cancellationToken);
    }

    /// <summary>Deletes an export. Best effort: IO and permission errors are swallowed.</summary>
    /// <param name="path">The export.</param>
    public static void Delete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Best effort. The caller reports where the file is.
        }
    }

    /// <summary>The header lines, in the order they are written and read.</summary>
    private static IEnumerable<string> HeaderLines(AuditArchiveHeader header)
    {
        yield return $"month={AuditArchive.MonthName(header.Month)}";
        yield return $"partition={header.Partition}";
        yield return Line("first_checkpoint", header.FirstCheckpointId);
        yield return Line("last_checkpoint", header.LastCheckpointId);
        yield return Line("first_seq", header.FirstSeq);
        yield return Line("last_seq", header.LastSeq);
        yield return Line("checkpoints", header.Checkpoints);

        static string Line(string key, long value) => $"{key}={value.ToString(CultureInfo.InvariantCulture)}";
    }
}

/// <summary>
/// Reads an export back: its header and checkpoints up front, then its records one at a time.
/// Records are streamed, not held in memory.
/// </summary>
public sealed class AuditArchiveReader : IAsyncDisposable
{
    private readonly string path;
    private readonly FileStream file;
    private readonly GZipStream gzip;
    private readonly StreamReader reader;

    private AuditArchiveReader(string path, FileStream file, GZipStream gzip, StreamReader reader, AuditArchiveHeader header, IReadOnlyList<AuditCheckpoint> checkpoints)
    {
        this.path = path;
        this.file = file;
        this.gzip = gzip;
        this.reader = reader;
        Header = header;
        Checkpoints = checkpoints;
    }

    /// <summary>What the export says about itself.</summary>
    public AuditArchiveHeader Header { get; }

    /// <summary>The checkpoints it carries, in id order.</summary>
    public IReadOnlyList<AuditCheckpoint> Checkpoints { get; }

    /// <summary>Opens an export and reads its header and checkpoints.</summary>
    /// <param name="path">The export.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidDataException">The file is not an export of this kind, or is malformed.</exception>
    public static async Task<AuditArchiveReader> OpenAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 64 * 1024, useAsync: true);
        GZipStream? gzip = null;
        StreamReader? reader = null;
        try
        {
            gzip = new GZipStream(file, CompressionMode.Decompress);
            reader = new StreamReader(gzip, AuditArchiveFile.Utf8, detectEncodingFromByteOrderMarks: false);

            if (await reader.ReadLineAsync(cancellationToken) != AuditArchiveFormat.Magic)
            {
                throw new InvalidDataException($"'{path}' does not start with {AuditArchiveFormat.Magic} and is not an audit ledger export.");
            }

            var header = await ReadHeaderAsync(path, reader, cancellationToken);
            if (await reader.ReadLineAsync(cancellationToken) != AuditArchiveFile.CheckpointsMarker)
            {
                throw new InvalidDataException($"'{path}' does not carry a checkpoints section where one is expected.");
            }

            var checkpoints = new List<AuditCheckpoint>(Math.Min(header.Checkpoints, 1024));
            for (var read = 0; read < header.Checkpoints; read++)
            {
                var text = await reader.ReadLineAsync(cancellationToken);
                if (text is null || !AuditArchiveFormat.TryReadCheckpoint(text, out var checkpoint) || checkpoint is null)
                {
                    throw new InvalidDataException($"'{path}' carries a checkpoint that could not be read.");
                }

                checkpoints.Add(checkpoint);
            }

            if (await reader.ReadLineAsync(cancellationToken) != AuditArchiveFile.RecordsMarker)
            {
                throw new InvalidDataException($"'{path}' does not carry a records section where one is expected.");
            }

            return new AuditArchiveReader(path, file, gzip, reader, header, checkpoints);
        }
        catch
        {
            // Each wrapper closes the stream under it, so only the outermost one is disposed.
            if (reader is not null)
            {
                reader.Dispose();
            }
            else if (gzip is not null)
            {
                await gzip.DisposeAsync();
            }
            else
            {
                await file.DisposeAsync();
            }

            throw;
        }
    }

    /// <summary>The next record, or <c>null</c> at the end of the export.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidDataException">A line of the records section is not a record.</exception>
    public async Task<AuditLedgerRecord?> ReadRecordAsync(CancellationToken cancellationToken)
    {
        var text = await reader.ReadLineAsync(cancellationToken);
        if (text is null)
        {
            return null;
        }

        if (!AuditArchiveFormat.TryReadRecord(text, out var record))
        {
            throw new InvalidDataException($"'{path}' carries a record that could not be read.");
        }

        return record;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        reader.Dispose();
        await gzip.DisposeAsync();
        await file.DisposeAsync();
    }

    /// <summary>Reads the seven header lines, in the order they are written.</summary>
    private static async Task<AuditArchiveHeader> ReadHeaderAsync(string path, StreamReader reader, CancellationToken cancellationToken)
    {
        var month = await ValueAsync(path, reader, "month", cancellationToken);
        var partition = await ValueAsync(path, reader, "partition", cancellationToken);
        var firstCheckpoint = await NumberAsync(path, reader, "first_checkpoint", cancellationToken);
        var lastCheckpoint = await NumberAsync(path, reader, "last_checkpoint", cancellationToken);
        var firstSeq = await NumberAsync(path, reader, "first_seq", cancellationToken);
        var lastSeq = await NumberAsync(path, reader, "last_seq", cancellationToken);
        var checkpoints = await NumberAsync(path, reader, "checkpoints", cancellationToken);

        if (!AuditArchive.TryParseMonth(month, out var parsed))
        {
            throw new InvalidDataException($"'{path}' names a month '{month}' that is not a YYYY-MM month.");
        }

        if (checkpoints is < 0 or > int.MaxValue)
        {
            throw new InvalidDataException($"'{path}' says it carries a number of checkpoints that cannot be read.");
        }

        return new AuditArchiveHeader(parsed, partition, firstCheckpoint, lastCheckpoint, firstSeq, lastSeq, (int)checkpoints);
    }

    private static async Task<string> ValueAsync(string path, StreamReader reader, string key, CancellationToken cancellationToken)
    {
        var line = await reader.ReadLineAsync(cancellationToken);
        var prefix = key + "=";
        if (line is null || !line.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"'{path}' does not carry '{key}' in its header where it is expected.");
        }

        return line[prefix.Length..];
    }

    private static async Task<long> NumberAsync(string path, StreamReader reader, string key, CancellationToken cancellationToken)
    {
        var value = await ValueAsync(path, reader, key, cancellationToken);
        return long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : throw new InvalidDataException($"'{path}' carries a header value for '{key}' that is not a whole number.");
    }
}
