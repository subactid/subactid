using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Commands;

/// <summary>
/// <c>SubactId.Server audit-archive --before &lt;YYYY-MM&gt; --to &lt;directory&gt;</c>: exports each ledger
/// month older than the cutoff, verifies the export against its checkpoints, records the archive
/// in the ledger, then detaches and drops the partition.
/// <para>
/// The only command that removes records. It refuses a month with an unsealed record, a
/// checkpoint whose signature or link fails, an export that does not read back as what was
/// sealed, or a record added after the check. A refusal leaves the ledger unchanged, and nothing
/// is dropped that the export does not hold.
/// </para>
/// <para>
/// Months go oldest first, and each export is a contiguous run of checkpoints, so exports plus the
/// online ledger cover every checkpoint with no gap. A checkpoint that spans the boundary is
/// archived whole, so an export may hold a few records that are also still online.
/// </para>
/// </summary>
public static class AuditArchiveCommand
{
    /// <summary>The command word on the command line.</summary>
    public const string Name = "audit-archive";

    /// <summary>Exit code for an unusable argument.</summary>
    public const int UsageExitCode = 2;

    /// <summary>Exit code when a month was refused: it does not verify, or its export does not read back.</summary>
    public const int RefusedExitCode = 3;

    /// <summary>The <c>--before</c> option: the first month to keep.</summary>
    public const string BeforeOption = "--before";

    /// <summary>The <c>--to</c> option: the directory exports are written to.</summary>
    public const string ToOption = "--to";

    /// <summary>Runs the command.</summary>
    /// <param name="options">Validated configuration.</param>
    /// <param name="args">The command's own arguments, without the command word.</param>
    /// <param name="now">The instant the run is taken at; also where a cutoff derived from the configured retention is measured back from.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>0 when the run finished, <see cref="RefusedExitCode"/> when a month was refused, 1 when the ledger could not be read or written, <see cref="UsageExitCode"/> for a malformed argument.</returns>
    public static async Task<int> RunAsync(
        SubactIdOptions options,
        string[] args,
        DateTimeOffset now,
        TextWriter? output = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(args);
        output ??= Console.Out;

        if (!TryParse(args, options.Audit.Retention, now, out var cutoff, out var destination, out var usage))
        {
            await Console.Error.WriteLineAsync(usage);
            return UsageExitCode;
        }

        if (options.Database.Provider == StorageProvider.Sqlite)
        {
            await Console.Error.WriteLineAsync(
                "The embedded database has no partitioning, so there is nothing to detach and no way to take a month out of the ledger without weakening the guard that makes it append-only. Retention needs the Postgres provider.");
            return 1;
        }

        SigningKeySet? signingKeys = null;
        try
        {
            // The server's configured key set. Never the ephemeral development key.
            signingKeys = SigningKeyBootstrap.Load(options.Signing, isDevelopment: false, out _);

            // Uses the migration connection, since detaching and dropping a partition is DDL.
            var connectionString = options.Database.MigrationConnectionString ?? options.Database.ConnectionString!;
            await using var dataSource = SubactIdDataSourceFactory.Create(connectionString);
            await using var db = SubactIdDbContextFactory.Create(connectionString);

            var dialect = new PostgresDialect();
            var unitOfWork = new EfUnitOfWork(db, dialect);
            var run = new AuditArchiveRun(
                new PostgresAuditLedgerPartitions(dataSource),
                new PostgresAuditLedgerArchive(dataSource),
                new EfAuditCheckpointQuery(db),
                new EfAuditArchiveRepository(db),
                new EfAuditWriter(db, unitOfWork, dialect, new AuditOutboxSettings(options.Audit.DeliveryEnabled)),
                unitOfWork,
                new SigningKeyCheckpointSignatures(signingKeys),
                destination,
                output);

            return await run.ExecuteAsync(cutoff, now, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Exception messages from Npgsql and EF Core name hosts and objects, never credentials.
            await Console.Error.WriteLineAsync($"Audit archive failed: {exception.GetType().Name}: {exception.Message}");
            return 1;
        }
        finally
        {
            signingKeys?.Dispose();
        }
    }

    /// <summary>
    /// Reads <c>--before</c> and <c>--to</c>. The cutoff defaults to the configured retention.
    /// <c>--to</c> has no default.
    /// </summary>
    /// <param name="args">The command's own arguments.</param>
    /// <param name="retention">The configured retention, or <c>null</c>.</param>
    /// <param name="now">The current instant.</param>
    /// <param name="cutoff">First month to keep.</param>
    /// <param name="destination">Directory the exports go in.</param>
    /// <param name="usage">What to say when the arguments are unusable.</param>
    public static bool TryParse(
        string[] args,
        TimeSpan? retention,
        DateTimeOffset now,
        out DateTimeOffset cutoff,
        out string destination,
        out string usage)
    {
        ArgumentNullException.ThrowIfNull(args);

        cutoff = default;
        destination = string.Empty;
        usage = $"Usage: {Name} {BeforeOption} <YYYY-MM> {ToOption} <directory>. {BeforeOption} is the first month to keep, and may be left out when SubactId:Audit:Retention is set.";

        string? before = null;
        for (var at = 0; at < args.Length; at++)
        {
            switch (args[at])
            {
                case BeforeOption when at + 1 < args.Length && before is null:
                    before = args[++at];
                    break;

                case ToOption when at + 1 < args.Length && destination.Length == 0:
                    destination = args[++at];
                    break;

                default:
                    return false;
            }
        }

        if (destination.Length == 0)
        {
            return false;
        }

        if (before is not null)
        {
            if (!AuditArchive.TryParseMonth(before, out cutoff))
            {
                usage = $"{BeforeOption} must be a month as YYYY-MM, such as 2026-07.";
                return false;
            }
        }
        else if (retention is { } window)
        {
            cutoff = AuditArchive.StartOfMonth(now - window);
        }
        else
        {
            usage = $"{BeforeOption} must be given, or SubactId:Audit:Retention set, so that this command knows which months to keep.";
            return false;
        }

        // The current month and future months cannot be archived.
        if (cutoff > AuditArchive.StartOfMonth(now))
        {
            usage = $"{BeforeOption} must not be after the current month: the ledger is still being written into it.";
            return false;
        }

        // The export's location is stored escaped in the audit record, so check it fits before
        // doing any work. All export names are the same length, so the cutoff's name stands in.
        if (!AuditArchive.LocationFits(Path.Combine(destination, AuditArchiveFile.NameOf(cutoff))))
        {
            usage = $"{ToOption} names a path too long for the ledger to record where an export went; archive to a shorter one.";
            return false;
        }

        if (!Directory.Exists(destination))
        {
            usage = $"{ToOption} must name a directory that already exists.";
            return false;
        }

        return true;
    }
}

/// <summary>
/// One run of <see cref="AuditArchiveCommand"/> over the given storage: verify, export, read back,
/// record, detach. Separate from the command so it can be tested against fakes.
/// </summary>
/// <param name="partitions">The ledger's partitions.</param>
/// <param name="ledger">The export, and the detach and drop.</param>
/// <param name="checkpoints">The checkpoints.</param>
/// <param name="archives">What has already been archived.</param>
/// <param name="audit">Where the <c>audit.archived</c> record goes.</param>
/// <param name="unitOfWork">Transactions, so the record and the row commit together.</param>
/// <param name="signatures">Where a checkpoint's signature is checked.</param>
/// <param name="destination">Directory the exports go in.</param>
/// <param name="output">Where the report goes.</param>
public sealed class AuditArchiveRun(
    IAuditLedgerPartitions partitions,
    IAuditLedgerArchive ledger,
    IAuditCheckpointQuery checkpoints,
    IAuditArchiveRepository archives,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    IAuditCheckpointSignatures signatures,
    string destination,
    TextWriter output)
{
    /// <summary>Checkpoints read per query.</summary>
    private const int PageSize = 1000;

    /// <summary>Archives every month before <paramref name="cutoff"/>, oldest first.</summary>
    /// <param name="cutoff">First month to keep.</param>
    /// <param name="now">The instant the run is taken at.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> ExecuteAsync(DateTimeOffset cutoff, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var layout = await partitions.InspectAsync(cancellationToken);
        if (!layout.Partitioned)
        {
            return await RefuseAsync(
                "the audit ledger is not partitioned in this database, so no month can be detached. Run 'SubactId.Server migrate' first.",
                1);
        }

        var candidates = layout.Partitions
            .Where(partition => partition.Month is { } month && MonthOf(month) < cutoff)
            .OrderBy(partition => partition.Month)
            .ToList();

        if (candidates.Count == 0)
        {
            await output.WriteLineAsync($"Nothing to archive: the ledger holds no month before {AuditArchive.MonthName(cutoff)}.");
            return 0;
        }

        var last = await archives.LastAsync(cancellationToken);
        var floorCheckpointId = (last?.LastCheckpointId ?? 0) + 1;
        var floorSeq = (last?.LastSeq ?? 0) + 1;
        AuditCheckpoint? sealedBefore = null;
        if (last is { LastCheckpointId: > 0 })
        {
            sealedBefore = await checkpoints.SealingAsync(last.LastSeq, cancellationToken);
            if (sealedBefore is null || sealedBefore.CheckpointId != last.LastCheckpointId)
            {
                return await RefuseAsync(
                    $"checkpoint {last.LastCheckpointId}, which the archive of {AuditArchive.MonthName(last.Month)} ended at, is not the one sealing sequence number {last.LastSeq} any more. The checkpoints are not what they were when that month left; run 'SubactId.Server audit-verify' before archiving anything else.",
                    AuditArchiveCommand.RefusedExitCode);
            }
        }

        var archived = 0;
        foreach (var partition in candidates)
        {
            var month = MonthOf(partition.Month!.Value);

            // A run that stopped after recording a month but before dropping it is finished here,
            // under the same condition: the partition holds nothing the export does not.
            if (await archives.FindAsync(month, cancellationToken) is { } recorded)
            {
                await output.WriteLineAsync(
                    $"{partition.Name} was already recorded as archived to {recorded.Location}; detaching and dropping it now.");
                if (await ledger.DropAsync(partition.Name, recorded.LastSeq, cancellationToken) is { } beyond)
                {
                    return await RefuseAsync(RecordedButHolding(partition.Name, month, recorded.Location, beyond), AuditArchiveCommand.RefusedExitCode);
                }

                archived++;
                continue;
            }

            if (last is not null && month <= last.Month)
            {
                return await RefuseAsync(
                    $"{partition.Name} holds {AuditArchive.MonthName(month)}, which is not after {AuditArchive.MonthName(last.Month)}, the last month archived. A partition made for a month that has already left holds records this command cannot take out by sequence number; deal with it by hand.",
                    AuditArchiveCommand.RefusedExitCode);
            }

            var step = await ArchiveAsync(partition.Name, month, floorCheckpointId, floorSeq, sealedBefore, now, cancellationToken);
            if (step.ExitCode != 0)
            {
                return step.ExitCode;
            }

            last = step.Archive!;
            floorCheckpointId = last.LastCheckpointId + 1;
            floorSeq = last.LastSeq + 1;
            sealedBefore = step.SealedThrough;
            archived++;
        }

        await output.WriteLineAsync(
            $"Archived {archived} month(s); the online ledger now starts at checkpoint {floorCheckpointId} and holds nothing before {AuditArchive.MonthName(last!.ArchivedBefore)}.");
        return 0;
    }

    /// <summary>One month: the checks, the export, the read-back, the record and the drop, in that order.</summary>
    private async Task<ArchiveStep> ArchiveAsync(
        string partition,
        DateTimeOffset month,
        long floorCheckpointId,
        long floorSeq,
        AuditCheckpoint? sealedBefore,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Every record in the partition must be sealed. Checkpoints are contiguous, so checking the
        // highest sequence number is enough.
        var highest = await ledger.HighestSeqAsync(partition, cancellationToken);
        var lastCheckpointId = floorCheckpointId - 1;
        var sealedThrough = sealedBefore;
        if (highest is { } top)
        {
            var sealing = await checkpoints.SealingAsync(top, cancellationToken);
            if (sealing is null)
            {
                return await RefusedAsync(
                    $"{partition} holds record {top}, which no checkpoint has sealed yet. Let the sealing pass reach it and run this again.");
            }

            if (sealing.CheckpointId >= floorCheckpointId)
            {
                lastCheckpointId = sealing.CheckpointId;
                sealedThrough = sealing;
            }
        }

        var run = new List<AuditCheckpoint>();
        if (lastCheckpointId >= floorCheckpointId)
        {
            var afterId = floorCheckpointId - 1;
            while (true)
            {
                var page = await checkpoints.ReadAsync(afterId, PageSize, cancellationToken);
                foreach (var checkpoint in page)
                {
                    if (checkpoint.CheckpointId > lastCheckpointId)
                    {
                        break;
                    }

                    run.Add(checkpoint);
                }

                if (page.Count < PageSize || run.Count == 0 || run[^1].CheckpointId >= lastCheckpointId)
                {
                    break;
                }

                afterId = page[^1].CheckpointId;
            }

            if (run.Count == 0 || run[0].CheckpointId != floorCheckpointId || run[^1].CheckpointId != lastCheckpointId)
            {
                return await RefusedAsync(
                    $"the checkpoints {floorCheckpointId} to {lastCheckpointId}, which seal {partition}, are not all in the ledger.");
            }
        }

        // Check signatures and links before writing anything. Roots are checked later, from the
        // export.
        var floor = sealedBefore is null && floorCheckpointId == 1 ? null : new AuditCheckpointFloor(floorCheckpointId, sealedBefore);
        var chain = new AuditCheckpointVerifier(signatures, floor);
        foreach (var checkpoint in run)
        {
            if (!chain.Feed(checkpoint))
            {
                return await RefusedAsync(
                    $"checkpoint {chain.Report.FaultCheckpointId}, which seals part of {partition}, does not hold: {chain.Report.Fault}. Run 'SubactId.Server audit-verify'.");
            }
        }

        var lastSeq = run.Count == 0 ? floorSeq - 1 : run[^1].LastSeq;
        var path = Path.Combine(destination, AuditArchiveFile.NameOf(month));
        if (File.Exists(path))
        {
            return await RefusedAsync($"'{path}' already exists. An export is never written over; move it aside or archive somewhere else.");
        }

        var header = new AuditArchiveHeader(month, partition, floorCheckpointId, lastCheckpointId, floorSeq, lastSeq, run.Count);
        var records = await AuditArchiveFile.WriteAsync(
            path,
            header,
            run,
            (writer, token) => ledger.ExportAsync(floorSeq, lastSeq, writer, token),
            cancellationToken);

        var digest = await AuditArchiveFile.DigestAsync(path, cancellationToken);
        if (await ProblemWithExportAsync(path, run, sealedBefore, records, cancellationToken) is { } problem)
        {
            // An export that does not match what was sealed is deleted, and nothing is detached.
            AuditArchiveFile.Delete(path);
            return await RefusedAsync(
                $"the export of {AuditArchive.MonthName(month)} did not read back: {problem}. Nothing has been detached. Run 'SubactId.Server audit-verify'.");
        }

        // Recheck the highest sequence number: a late append (slow commit, clock skew) can land
        // after the first check and be in no export. If so, delete the export and stop. The detach
        // below repeats this check under a lock.
        if (await ledger.HighestSeqAsync(partition, cancellationToken) is { } appended && appended > lastSeq)
        {
            AuditArchiveFile.Delete(path);
            return await RefusedAsync(
                $"{partition} holds record {appended}, appended into {AuditArchive.MonthName(month)} after the month was checked and beyond what its export would carry. Nothing has been detached; let the sealing pass reach it and run this again.");
        }

        var archive = new AuditArchive(month, partition, floorCheckpointId, lastCheckpointId, floorSeq, lastSeq, records, path, digest, now);

        // Record the archive in the ledger, in the same transaction as the row that marks the
        // online ledger's new start.
        await unitOfWork.RunAsync(
            async token =>
            {
                await audit.AppendAsync(new AuditEvent(now, AuditEvents.AuditArchived, Detail: archive.ToDetail()), token);
                await archives.AppendAsync(archive, token);
                return true;
            },
            cancellationToken);

        // Detach only if the partition holds nothing past the export's last sequence number. If a
        // record slipped in, report it and keep the partition, even though the archive row is
        // already written.
        if (await ledger.DropAsync(partition, lastSeq, cancellationToken) is { } late)
        {
            return await RefusedAsync(RecordedButHolding(partition, month, path, late));
        }

        await output.WriteLineAsync(
            $"Archived {AuditArchive.MonthName(month)}: {records} record(s) sealed by checkpoints {floorCheckpointId}-{lastCheckpointId}, to {path} (sha256 {Convert.ToHexStringLower(digest)}).");
        return new ArchiveStep(0, archive, sealedThrough);
    }

    /// <summary>
    /// Reads the export back and rebuilds every root from its records. Returns <c>null</c> when it
    /// matches what was sealed, otherwise what is wrong.
    /// </summary>
    private async Task<string?> ProblemWithExportAsync(
        string path,
        IReadOnlyList<AuditCheckpoint> run,
        AuditCheckpoint? sealedBefore,
        long records,
        CancellationToken cancellationToken)
    {
        await using var archive = await AuditArchiveReader.OpenAsync(path, cancellationToken);
        if (archive.Checkpoints.Count != run.Count)
        {
            return $"it carries {archive.Checkpoints.Count} checkpoint(s) where {run.Count} were written";
        }

        for (var at = 0; at < run.Count; at++)
        {
            var written = archive.Checkpoints[at];
            if (!AuditCheckpointHash.SignedBytes(written).AsSpan().SequenceEqual(AuditCheckpointHash.SignedBytes(run[at]))
                || !written.Signature.Span.SequenceEqual(run[at].Signature.Span))
            {
                return $"checkpoint {run[at].CheckpointId} does not read back as the one the ledger holds";
            }
        }

        var report = await AuditArchiveVerification.VerifyAsync(archive, signatures, sealedBefore, cancellationToken);
        if (!report.Seal.IsIntact)
        {
            return $"checkpoint {report.Seal.FaultCheckpointId} does not verify from it ({report.Seal.Fault})";
        }

        if (!report.Complete)
        {
            return "it carries records that none of its checkpoints seals";
        }

        var sealedRecords = run.Sum(checkpoint => checkpoint.TreeSize);
        return report.Records == records && report.Records == sealedRecords
            ? null
            : $"it reads back as {report.Records} record(s) where {records} were exported and the checkpoints seal {sealedRecords}";
    }

    /// <summary>The first instant of the month a partition holds.</summary>
    private static DateTimeOffset MonthOf(DateOnly month) => new(month.Year, month.Month, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The message for a month recorded as archived that, at detach, holds a record its export
    /// does not. Explains the state and how to recover.
    /// </summary>
    private static string RecordedButHolding(string partition, DateTimeOffset month, string location, long beyond) =>
        $"{partition} is recorded as archived to {location}, but holds record {beyond}, appended after the month was checked and beyond what that export carries, so it has been left attached and nothing has been dropped. "
        + $"Once the sealing pass has reached that record, delete the audit_archives row for {AuditArchive.MonthName(month)}, move the export aside, and run this again: the month is exported afresh with that record in it, and a second audit.archived record says so.";

    private static async Task<ArchiveStep> RefusedAsync(string reason) =>
        new(await RefuseAsync(reason, AuditArchiveCommand.RefusedExitCode), null, null);

    private static async Task<int> RefuseAsync(string reason, int exitCode)
    {
        await Console.Error.WriteLineAsync($"Refused: {reason}");
        return exitCode;
    }

    /// <summary>What archiving one month ended with.</summary>
    /// <param name="ExitCode">0 when the month was archived.</param>
    /// <param name="Archive">What was recorded, when it was.</param>
    /// <param name="SealedThrough">The last checkpoint the export carried, which the next month links to.</param>
    private sealed record ArchiveStep(int ExitCode, AuditArchive? Archive, AuditCheckpoint? SealedThrough);
}
