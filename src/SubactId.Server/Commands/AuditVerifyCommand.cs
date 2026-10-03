using System.Globalization;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef.Repositories;
using SubactId.Tokens.Signing;
using PostgresContext = SubactId.Storage.Postgres.SubactIdDbContextFactory;
using SqliteContext = SubactId.Storage.Sqlite.SubactIdSqliteDbContextFactory;

namespace SubactId.Server.Commands;

/// <summary>
/// <c>SubactId.Server audit-verify [checkpoint_id:root,...] [--archive &lt;export&gt;]</c>: checks every
/// checkpoint of the audit ledger: its signature against the published key set, its link to the
/// previous checkpoint, and its root against the tree rebuilt from its records. Prints the counts,
/// the last checkpoint, and where the seal broke, if it did. Given marks from an earlier run, also
/// confirms those checkpoints still sign the same roots, which catches a cut or rewritten tail.
/// Never prints a record's content.
/// <para>
/// If old months have been archived, the walk starts at the first checkpoint after the last
/// archived one and checks its link across the boundary. With <c>--archive</c>, it verifies an
/// export on its own without reading the database.
/// </para>
/// </summary>
public static class AuditVerifyCommand
{
    /// <summary>The command word on the command line.</summary>
    public const string Name = "audit-verify";

    /// <summary>Exit code when the seal is broken.</summary>
    public const int BrokenExitCode = 3;

    /// <summary>Checkpoints read per query.</summary>
    public const int PageSize = 100;

    /// <summary>Exit code for an unusable argument.</summary>
    public const int UsageExitCode = 2;

    /// <summary>The <c>--archive</c> option: verify an export instead of the online ledger.</summary>
    public const string ArchiveOption = "--archive";

    /// <summary>Runs the command.</summary>
    /// <param name="options">Validated configuration.</param>
    /// <param name="args">The command's own arguments: the <c>checkpoint_id:root</c> list printed by an earlier run, and <c>--archive &lt;export&gt;</c>.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>0 when the seal is intact, <see cref="BrokenExitCode"/> when it is not, 1 when the ledger could not be read, <see cref="UsageExitCode"/> for a malformed argument.</returns>
    public static async Task<int> RunAsync(SubactIdOptions options, string[] args, TextWriter? output = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(args);
        output ??= Console.Out;

        string? expectedMarks = null;
        string? export = null;
        for (var at = 0; at < args.Length; at++)
        {
            if (args[at] == ArchiveOption && at + 1 < args.Length && export is null)
            {
                export = args[++at];
            }
            else if (expectedMarks is null && !args[at].StartsWith('-'))
            {
                expectedMarks = args[at];
            }
            else
            {
                await Console.Error.WriteLineAsync($"Usage: {Name} [<checkpoint_id>:<root>,...] [{ArchiveOption} <export>].");
                return UsageExitCode;
            }
        }

        if (export is not null && expectedMarks is not null)
        {
            await Console.Error.WriteLineAsync($"{ArchiveOption} verifies one export on its own; a list of checkpoints from an earlier run is about the online ledger and is not read against it.");
            return UsageExitCode;
        }

        IReadOnlyList<AuditCheckpointMark>? expected = null;
        if (expectedMarks is not null && !TryParseMarks(expectedMarks, out expected))
        {
            await Console.Error.WriteLineAsync("Every expected checkpoint must be <checkpoint_id>:<64 hex characters>, separated by commas, as printed by an earlier run.");
            return UsageExitCode;
        }

        SigningKeySet? signingKeys = null;
        try
        {
            // The server's configured key set. Never the ephemeral development key, which cannot
            // verify anything signed before it existed.
            signingKeys = SigningKeyBootstrap.Load(options.Signing, isDevelopment: false, out _);
            var signatures = new SigningKeyCheckpointSignatures(signingKeys);
            if (export is not null)
            {
                return await VerifyExportAsync(export, signatures, output, cancellationToken);
            }

            await using var db = options.Database.Provider == StorageProvider.Sqlite
                ? SqliteContext.Create(options.Database.Path!)
                : PostgresContext.Create(options.Database.ConnectionString!);

            var query = new EfAuditCheckpointQuery(db);
            var (floor, boundary) = await FloorAsync(new EfAuditArchiveRepository(db), query, cancellationToken);
            if (boundary is not null)
            {
                await output.WriteLineAsync(boundary);
            }

            var (report, mark) = await VerifyAsync(
                query,
                new EfAuditLedgerReader(db),
                signatures,
                expected,
                floor,
                cancellationToken);

            if (report.IsIntact)
            {
                await output.WriteLineAsync(
                    $"Audit ledger intact: {report.Verified} checkpoint(s) verified sealing {report.SealedRecords} record(s) up to seq {report.LastSeq}, last checkpoint {Format(mark)}.");
                return 0;
            }

            await output.WriteLineAsync(
                $"Audit ledger BROKEN at checkpoint {report.FaultCheckpointId}: {Describe(report.Fault)}. {report.Verified} checkpoint(s) verified before it, last good seq {report.LastSeq}.");
            return BrokenExitCode;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Exception messages from Npgsql and EF Core name hosts and objects, never credentials.
            await Console.Error.WriteLineAsync($"Audit verification failed: {exception.GetType().Name}: {exception.Message}");
            return 1;
        }
        finally
        {
            signingKeys?.Dispose();
        }
    }

    /// <summary>
    /// Reads the checkpoints in id order, rebuilds each one's tree from the records it covers, and
    /// confirms <paramref name="expected"/> if given.
    /// </summary>
    /// <param name="checkpoints">The checkpoints.</param>
    /// <param name="ledger">The records they seal.</param>
    /// <param name="signatures">Where a checkpoint's signature is checked.</param>
    /// <param name="expected">Marks from an earlier run, or <c>null</c>.</param>
    /// <param name="floor">Where the walk begins when the ledger's oldest months have been archived; <c>null</c> for a ledger that still holds everything it wrote.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The report and the last checkpoint, which is what to pass next time.</returns>
    public static async Task<(AuditCheckpointReport Report, AuditCheckpointMark? Mark)> VerifyAsync(
        IAuditCheckpointQuery checkpoints,
        IAuditLedgerReader ledger,
        IAuditCheckpointSignatures signatures,
        IReadOnlyList<AuditCheckpointMark>? expected = null,
        AuditCheckpointFloor? floor = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoints);
        ArgumentNullException.ThrowIfNull(ledger);
        ArgumentNullException.ThrowIfNull(signatures);

        var verifier = new AuditCheckpointVerifier(signatures, floor);
        foreach (var mark in expected ?? [])
        {
            verifier.Watch(mark.CheckpointId);
        }

        // A mark below the floor names a checkpoint whose records are archived. Checkpoint rows
        // stay in the table, so it is read by id and confirmed without a walk. A mark with no row
        // stays unnoted, which Confirm reports as a cut tail.
        var afterId = 0L;
        if (floor is { } start)
        {
            // Skip archived checkpoints, whose records are no longer in the database.
            afterId = start.CheckpointId - 1;
            foreach (var mark in (expected ?? []).Where(mark => mark.CheckpointId < start.CheckpointId))
            {
                var stored = await checkpoints.ReadAsync(mark.CheckpointId - 1, 1, cancellationToken);
                if (stored.Count == 1 && stored[0].CheckpointId == mark.CheckpointId && !verifier.Note(stored[0]))
                {
                    break;
                }
            }
        }

        var walking = true;
        while (walking)
        {
            var page = await checkpoints.ReadAsync(afterId, PageSize, cancellationToken);
            foreach (var checkpoint in page)
            {
                if (!verifier.Feed(checkpoint, await SealedAsync(ledger, checkpoint, cancellationToken)))
                {
                    walking = false;
                    break;
                }
            }

            if (!walking || page.Count < PageSize)
            {
                break;
            }

            afterId = page[^1].CheckpointId;
        }

        foreach (var mark in expected ?? [])
        {
            verifier.Confirm(mark);
        }

        return (verifier.Report, verifier.Mark);
    }

    /// <summary>
    /// Where the walk begins, and a line to print about it: the first checkpoint, or after
    /// archiving, the one after the last archived checkpoint (which is read to check the link).
    /// </summary>
    private static async Task<(AuditCheckpointFloor? Floor, string? Boundary)> FloorAsync(
        IAuditArchiveRepository archives,
        IAuditCheckpointQuery checkpoints,
        CancellationToken cancellationToken)
    {
        if (await archives.LastAsync(cancellationToken) is not { LastCheckpointId: > 0 } last)
        {
            return (null, null);
        }

        var sealedBefore = await checkpoints.SealingAsync(last.LastSeq, cancellationToken);
        if (sealedBefore is null || sealedBefore.CheckpointId != last.LastCheckpointId)
        {
            return (
                new AuditCheckpointFloor(last.LastCheckpointId + 1),
                $"The ledger holds nothing before {AuditArchive.MonthName(last.ArchivedBefore)}, and checkpoint {last.LastCheckpointId}, which the archive of {AuditArchive.MonthName(last.Month)} ended at, is no longer in the ledger: the boundary link is NOT checked. Verify the export with {ArchiveOption}.");
        }

        return (
            new AuditCheckpointFloor(last.LastCheckpointId + 1, sealedBefore),
            $"The ledger holds nothing before {AuditArchive.MonthName(last.ArchivedBefore)}; walking from checkpoint {last.LastCheckpointId + 1}, which must follow on from archived checkpoint {last.LastCheckpointId}.");
    }

    /// <summary>Verifies one export on its own, reading nothing from the database.</summary>
    private static async Task<int> VerifyExportAsync(string path, IAuditCheckpointSignatures signatures, TextWriter output, CancellationToken cancellationToken)
    {
        await using var archive = await AuditArchiveReader.OpenAsync(path, cancellationToken);
        var report = await AuditArchiveVerification.VerifyAsync(archive, signatures, sealedBefore: null, cancellationToken);
        var month = AuditArchive.MonthName(archive.Header.Month);
        if (report.IsIntact)
        {
            await output.WriteLineAsync(
                $"Audit ledger export intact: {month}, {report.Seal.Verified} checkpoint(s) verified sealing {report.Records} record(s); checkpoints {archive.Header.FirstCheckpointId} to {archive.Header.LastCheckpointId}, sequence numbers {archive.Header.FirstSeq} to {archive.Header.LastSeq}.");
            return 0;
        }

        await output.WriteLineAsync(
            report.Seal.IsIntact
                ? $"Audit ledger export BROKEN: {month} carries {report.Records} sealed record(s) and at least one more that none of its checkpoints seals."
                : $"Audit ledger export BROKEN at checkpoint {report.Seal.FaultCheckpointId}: {Describe(report.Seal.Fault)}. {report.Seal.Verified} checkpoint(s) verified before it in {month}.");
        return BrokenExitCode;
    }

    /// <summary>
    /// Every record in the checkpoint's range, plus one more than the sealed count, so an inserted
    /// record shows up as an extra leaf.
    /// </summary>
    private static Task<IReadOnlyList<AuditLedgerRecord>> SealedAsync(IAuditLedgerReader ledger, AuditCheckpoint checkpoint, CancellationToken cancellationToken) =>
        ledger.ReadRangeAsync(checkpoint.FirstSeq - 1, checkpoint.LastSeq, checked((int)checkpoint.TreeSize) + 1, cancellationToken);

    /// <summary>The <c>checkpoint_id:root</c> form of a mark, as printed and accepted.</summary>
    /// <param name="mark">The last verified checkpoint, or <c>null</c> for an unsealed ledger.</param>
    public static string Format(AuditCheckpointMark? mark) =>
        mark is null
            ? "none (nothing sealed yet)"
            : $"{mark.CheckpointId}:{Convert.ToHexStringLower(mark.RootHash.Span)}";

    /// <summary>Parses the <c>checkpoint_id:root,...</c> form.</summary>
    /// <param name="text">The text.</param>
    /// <param name="marks">The marks.</param>
    public static bool TryParseMarks(string text, out IReadOnlyList<AuditCheckpointMark>? marks)
    {
        ArgumentNullException.ThrowIfNull(text);

        marks = null;
        var parsed = new List<AuditCheckpointMark>();
        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParseMark(part, out var mark))
            {
                return false;
            }

            parsed.Add(mark!);
        }

        if (parsed.Count == 0)
        {
            return false;
        }

        marks = parsed;
        return true;
    }

    /// <summary>Parses one <c>checkpoint_id:root</c>.</summary>
    /// <param name="text">The text.</param>
    /// <param name="mark">The mark.</param>
    public static bool TryParseMark(string text, out AuditCheckpointMark? mark)
    {
        mark = null;
        var parts = text.Split(':', 2);
        if (parts.Length != 2
            || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var checkpointId)
            || checkpointId < 1
            || parts[1].Length != 2 * MerkleTree.HashLength)
        {
            return false;
        }

        try
        {
            mark = new AuditCheckpointMark(checkpointId, Convert.FromHexString(parts[1]));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string Describe(AuditCheckpointFault fault) => fault switch
    {
        AuditCheckpointFault.BadSignature => "the signature does not verify, or the key it names is not published (checkpoint forged or key missing)",
        AuditCheckpointFault.BrokenChain => "it does not follow on from the checkpoint before it (a checkpoint is missing, was inserted, or was replaced)",
        AuditCheckpointFault.TamperedRecords => "the records it covers no longer build the root it signed (a record was edited, removed or inserted)",
        AuditCheckpointFault.Truncated => "a checkpoint recorded earlier no longer signs the same root (tail cut or rewritten)",
        _ => "unknown fault",
    };
}
