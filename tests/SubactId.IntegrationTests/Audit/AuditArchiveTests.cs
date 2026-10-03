using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Commands;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using SubactId.Tokens.Signing;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

/// <summary>
/// Archiving a month: the export verifies on its own, the partition is dropped, an
/// <c>audit.archived</c> record says where it went, and what is left online verifies from its
/// floor. Uses its own database, because it drops partitions.
/// </summary>
public sealed class AuditArchiveTests : IAsyncLifetime
{
    private readonly PostgresDatabaseFixture postgres = new();
    private readonly string signingPem = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportPkcs8PrivateKeyPem();
    private readonly DirectoryInfo archive = Directory.CreateTempSubdirectory("subactid-archive-run");

    /// <summary>The month being archived: the oldest partition in this database, so there is exactly one candidate.</summary>
    private DateTimeOffset old;

    /// <summary>The first month kept, which is the one after <see cref="old"/>.</summary>
    private DateTimeOffset Cutoff => old.AddMonths(1);

    public async Task InitializeAsync()
    {
        await postgres.InitializeAsync();
        await postgres.EnsureMigratedAsync();

        var layout = await InspectAsync();
        var earliest = layout.Partitions.Select(partition => partition.Month).FirstOrDefault(month => month is not null)
            ?? throw new InvalidOperationException("The ledger has no partition to archive.");
        old = new DateTimeOffset(earliest.Year, earliest.Month, 1, 0, 0, 0, TimeSpan.Zero);
    }

    public async Task DisposeAsync()
    {
        archive.Delete(recursive: true);
        await postgres.DisposeAsync();
    }

    [Fact]
    public async Task A_month_is_exported_verified_recorded_and_only_then_detached_and_dropped()
    {
        await AppendAsync(old.AddDays(2), 4);
        await SealAsync();
        await AppendAsync(DateTimeOffset.UtcNow, 3);
        await SealAsync();

        var output = new StringWriter();
        Assert.Equal(0, await RunAsync(output));

        // Gone from the database, and no other month with it.
        var layout = await InspectAsync();
        Assert.Null(layout.Covering(old));
        Assert.NotNull(layout.Covering(DateTimeOffset.UtcNow));

        await using var db = postgres.CreateDbContext();
        var recorded = await new EfAuditArchiveRepository(db).LastAsync();
        Assert.NotNull(recorded);
        Assert.Equal(old, recorded!.Month);
        Assert.Equal(Cutoff, recorded.ArchivedBefore);
        Assert.Equal(4L, recorded.Records);
        Assert.Equal(PostgresAuditLedgerPartitions.NamePrefix + old.UtcDateTime.ToString("yyyyMM", CultureInfo.InvariantCulture), recorded.Partition);

        // The record of what left is in the ledger, and it names the export and its digest.
        var archived = await new EfAuditQuery(db, postgres.Dialect).QueryAsync(new AuditQuery(Limit: 100));
        var written = Assert.Single(archived, record => record.Event.Event == AuditEvents.AuditArchived);
        Assert.Equal(recorded.ToDetail(), written.Event.Detail);
        Assert.Contains(Convert.ToHexStringLower(recorded.Digest.Span), written.Event.Detail!, StringComparison.Ordinal);

        // The export is the copy, and it verifies against the key set and nothing else.
        Assert.True(File.Exists(recorded.Location));
        Assert.Equal(await AuditArchiveFile.DigestAsync(recorded.Location, CancellationToken.None), recorded.Digest.ToArray());
        using var keys = SigningKeys();
        await using (var export = await AuditArchiveReader.OpenAsync(recorded.Location, CancellationToken.None))
        {
            var report = await AuditArchiveVerification.VerifyAsync(export, new SigningKeyCheckpointSignatures(keys), sealedBefore: null);
            Assert.True(report.IsIntact, $"the export of {AuditArchive.MonthName(old)} did not verify: {report.Seal.Fault}");
            Assert.Equal(4L, report.Records);
        }

        // What is left online verifies from the checkpoint after the last archived one.
        var checkpoints = new EfAuditCheckpointQuery(db);
        var sealedBefore = await checkpoints.SealingAsync(recorded.LastSeq);
        Assert.NotNull(sealedBefore);
        var (online, _) = await AuditVerifyCommand.VerifyAsync(
            checkpoints,
            new EfAuditLedgerReader(db),
            new SigningKeyCheckpointSignatures(keys),
            expected: null,
            floor: new AuditCheckpointFloor(recorded.LastCheckpointId + 1, sealedBefore));

        Assert.True(online.IsIntact, $"the online ledger did not verify from its floor: {online.Fault} at {online.FaultCheckpointId}");
        Assert.True(online.Verified >= 1);

        // A mark from a run before the month left names a checkpoint below the floor. It still
        // confirms, since checkpoints stay in the table, and it still catches a wrong root.
        var floor = new AuditCheckpointFloor(recorded.LastCheckpointId + 1, sealedBefore);
        var (confirmed, _) = await AuditVerifyCommand.VerifyAsync(
            checkpoints,
            new EfAuditLedgerReader(db),
            new SigningKeyCheckpointSignatures(keys),
            expected: [new AuditCheckpointMark(sealedBefore.CheckpointId, sealedBefore.RootHash)],
            floor: floor);
        Assert.True(confirmed.IsIntact, $"a mark from before the archive did not confirm: {confirmed.Fault} at {confirmed.FaultCheckpointId}");

        var (rewritten, _) = await AuditVerifyCommand.VerifyAsync(
            checkpoints,
            new EfAuditLedgerReader(db),
            new SigningKeyCheckpointSignatures(keys),
            expected: [new AuditCheckpointMark(sealedBefore.CheckpointId, new byte[AuditCheckpointHash.Length])],
            floor: floor);
        Assert.Equal((AuditCheckpointFault.Truncated, sealedBefore.CheckpointId), (rewritten.Fault, rewritten.FaultCheckpointId));

        // The archived range reads as an empty page, not as an error.
        var gone = await new EfAuditQuery(db, postgres.Dialect).QueryAsync(new AuditQuery(From: old, To: Cutoff, Limit: 100));
        Assert.Empty(gone);
        Assert.Contains(AuditArchive.MonthName(old), output.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A checkpoint that straddles the boundary is archived whole, so the export holds a few records
    /// that are still online. What stays online begins at the next checkpoint. Nothing is dropped
    /// that is not in an export.
    /// </summary>
    [Fact]
    public async Task A_checkpoint_that_straddles_the_boundary_is_archived_whole()
    {
        await AppendAsync(old.AddDays(2), 2);
        await AppendAsync(DateTimeOffset.UtcNow, 2);
        await SealAsync();

        Assert.Equal(0, await RunAsync(new StringWriter()));

        await using var db = postgres.CreateDbContext();
        var recorded = await new EfAuditArchiveRepository(db).LastAsync();
        Assert.NotNull(recorded);
        Assert.Equal(4L, recorded!.Records);

        using var keys = SigningKeys();
        await using var export = await AuditArchiveReader.OpenAsync(recorded.Location, CancellationToken.None);
        var report = await AuditArchiveVerification.VerifyAsync(export, new SigningKeyCheckpointSignatures(keys), sealedBefore: null);
        Assert.True(report.IsIntact, $"the straddling export did not verify: {report.Seal.Fault}");

        // The two records of the month that stayed are still there and still readable, beside
        // the record of what left.
        var online = await new EfAuditQuery(db, postgres.Dialect).QueryAsync(new AuditQuery(From: Cutoff, Limit: 100));
        Assert.Equal(2, online.Count(record => record.Event.Event == AuditEvents.TokenIssued));
        Assert.Single(online, record => record.Event.Event == AuditEvents.AuditArchived);
    }

    /// <summary>A month holding a record the sealing pass has not reached is not archived yet.</summary>
    [Fact]
    public async Task A_month_with_a_record_no_checkpoint_has_sealed_is_refused_and_nothing_is_detached()
    {
        await AppendAsync(old.AddDays(2), 2);

        Assert.Equal(AuditArchiveCommand.RefusedExitCode, await RunAsync(new StringWriter()));

        Assert.NotNull((await InspectAsync()).Covering(old));
        Assert.False(File.Exists(Path.Combine(archive.FullName, AuditArchiveFile.NameOf(old))));
        await using var db = postgres.CreateDbContext();
        Assert.Null(await new EfAuditArchiveRepository(db).FindAsync(old));
    }

    /// <summary>
    /// A record can land in a month after the month was read, from a slow commit or a clock behind
    /// the others. It is outside the export, so the month is refused, its export deleted, and
    /// nothing is recorded or detached.
    /// </summary>
    [Fact]
    public async Task A_record_appended_into_the_month_after_it_was_checked_is_refused_rather_than_dropped()
    {
        await AppendAsync(old.AddDays(2), 2);
        await SealAsync();

        // Lands one more record in the month between the check and the export, as a slow commit would.
        Assert.Equal(AuditArchiveCommand.RefusedExitCode, await RunAsync(new StringWriter(), ledger => new AppendingDuringExport(ledger, () => AppendAsync(old.AddDays(3), 1))));

        Assert.NotNull((await InspectAsync()).Covering(old));
        Assert.False(File.Exists(Path.Combine(archive.FullName, AuditArchiveFile.NameOf(old))));
        await using var db = postgres.CreateDbContext();
        Assert.Null(await new EfAuditArchiveRepository(db).FindAsync(old));
        var still = await new EfAuditQuery(db, postgres.Dialect).QueryAsync(new AuditQuery(From: old, To: Cutoff, Limit: 100));
        Assert.Equal(3, still.Count);

        // Sealed, the late record is in the export of the next run, and the month leaves.
        await SealAsync();
        Assert.Equal(0, await RunAsync(new StringWriter()));
        Assert.Null((await InspectAsync()).Covering(old));
        Assert.Equal(3L, (await new EfAuditArchiveRepository(db).FindAsync(old))!.Records);
    }

    /// <summary>
    /// A detached partition can take no more appends, so the final check happens after the detach.
    /// A partition holding a record above what was exported is reattached, not dropped.
    /// </summary>
    [Fact]
    public async Task The_drop_puts_a_partition_back_that_holds_a_record_above_what_was_exported()
    {
        await AppendAsync(old.AddDays(2), 2);
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        var ledger = new PostgresAuditLedgerArchive(dataSource);
        var partition = (await InspectAsync()).Covering(old)!.Name;
        var highest = (await ledger.HighestSeqAsync(partition))!.Value;

        Assert.Equal(highest, await ledger.DropAsync(partition, highest - 1));
        Assert.NotNull((await InspectAsync()).Covering(old));
        await using (var db = postgres.CreateDbContext())
        {
            Assert.Equal(2, (await new EfAuditQuery(db, postgres.Dialect).QueryAsync(new AuditQuery(From: old, To: Cutoff, Limit: 100))).Count);
        }

        Assert.Null(await ledger.DropAsync(partition, highest));
        Assert.Null((await InspectAsync()).Covering(old));
    }

    /// <summary>A second run over the same months has nothing to do, and reports that instead of failing.</summary>
    [Fact]
    public async Task A_run_with_nothing_older_than_the_cutoff_archives_nothing()
    {
        await AppendAsync(DateTimeOffset.UtcNow, 2);
        await SealAsync();
        Assert.Equal(0, await RunAsync(new StringWriter()));

        var output = new StringWriter();
        Assert.Equal(0, await RunAsync(output));

        Assert.Contains("Nothing to archive", output.ToString(), StringComparison.Ordinal);
    }

    /// <summary>One run of the command over this database, writing its exports to the test's directory.</summary>
    /// <param name="output">Where the run's report goes.</param>
    /// <param name="wrap">Wraps the ledger the run uses, to make things happen in the middle of it.</param>
    private async Task<int> RunAsync(TextWriter output, Func<IAuditLedgerArchive, IAuditLedgerArchive>? wrap = null)
    {
        using var keys = SigningKeys();
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        await using var db = postgres.CreateDbContext();
        var unitOfWork = new EfUnitOfWork(db, postgres.Dialect);

        IAuditLedgerArchive ledger = new PostgresAuditLedgerArchive(dataSource);
        var run = new AuditArchiveRun(
            new PostgresAuditLedgerPartitions(dataSource),
            wrap is null ? ledger : wrap(ledger),
            new EfAuditCheckpointQuery(db),
            new EfAuditArchiveRepository(db),
            new EfAuditWriter(db, unitOfWork, postgres.Dialect),
            unitOfWork,
            new SigningKeyCheckpointSignatures(keys),
            archive.FullName,
            output);

        return await run.ExecuteAsync(Cutoff, DateTimeOffset.UtcNow);
    }

    /// <summary>Appends <paramref name="count"/> records timestamped in the month holding <paramref name="at"/>.</summary>
    private async Task AppendAsync(DateTimeOffset at, int count)
    {
        await using var db = postgres.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
        for (var i = 0; i < count; i++)
        {
            await writer.AppendAsync(new AuditEvent(
                at.AddSeconds(i),
                AuditEvents.TokenIssued,
                $"task_{i}",
                UniqueId("archive"),
                Sponsor,
                Decision: AuditDecision.Allow));
        }
    }

    /// <summary>One sealing pass, as the hosted service runs it.</summary>
    private async Task SealAsync()
    {
        using var keys = SigningKeys();
        await using var services = postgres.Services();
        var sealer = new AuditCheckpointSealer(
            services.GetRequiredService<IServiceScopeFactory>(),
            Options(),
            keys,
            TimeProvider.System,
            NullLogger<AuditCheckpointSealer>.Instance);

        await sealer.SealAsync();
    }

    private async Task<AuditLedgerLayout> InspectAsync()
    {
        await using var dataSource = SubactIdDataSourceFactory.Create(postgres.ApplicationConnectionString);
        return await new PostgresAuditLedgerPartitions(dataSource).InspectAsync();
    }

    private SigningKeySet SigningKeys() => SigningKeySetLoader.Load([new SigningKeySource(Kid: "archive-test", Pem: signingPem, Path: null)], activeKid: "archive-test");

    /// <summary>The ledger, except that something else happens first when the export is taken.</summary>
    private sealed class AppendingDuringExport(IAuditLedgerArchive inner, Func<Task> append) : IAuditLedgerArchive
    {
        public async Task<long> ExportAsync(long firstSeq, long lastSeq, TextWriter destination, CancellationToken cancellationToken = default)
        {
            await append();
            return await inner.ExportAsync(firstSeq, lastSeq, destination, cancellationToken);
        }

        public Task<long?> HighestSeqAsync(string partition, CancellationToken cancellationToken = default) => inner.HighestSeqAsync(partition, cancellationToken);

        public Task<long?> DropAsync(string partition, long exportedThrough, CancellationToken cancellationToken = default) => inner.DropAsync(partition, exportedThrough, cancellationToken);
    }

    private SubactIdOptions Options() => new()
    {
        Issuer = new Uri("https://subactid.internal.example.com"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = postgres.ApplicationConnectionString },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromMinutes(30), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 20 },
        Signing = new SigningOptions { Keys = [new ConfiguredSigningKey(0, new SigningKeySource(Kid: "archive-test", Pem: signingPem, Path: null))], ActiveKid = "archive-test" },
        Admin = new AdminOptions(),
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
    };
}
