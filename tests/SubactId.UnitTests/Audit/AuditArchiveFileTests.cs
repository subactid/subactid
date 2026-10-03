using System.IO.Compression;
using System.Text;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// An export as a file: what it holds, that it reads back as what was sealed, and that any
/// tampering is caught. After the month is detached the export is the only copy.
/// </summary>
public sealed class AuditArchiveFileTests : IDisposable
{
    private static readonly DateTimeOffset At = new(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero);
    private static readonly DateTimeOffset Month = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("subactid-archive-tests");

    public void Dispose() => directory.Delete(recursive: true);

    [Fact]
    public async Task An_export_reads_back_as_the_checkpoints_and_records_that_were_written()
    {
        var (checkpoints, records) = Sealed(2, 3);
        var path = await WriteAsync(checkpoints, records);

        await using var archive = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);

        Assert.Equal(Month, archive.Header.Month);
        Assert.Equal("audit_events_p202609", archive.Header.Partition);
        Assert.Equal(2, archive.Header.Checkpoints);
        Assert.Equal(
            checkpoints.Select(AuditCheckpointHash.SignedBytes),
            archive.Checkpoints.Select(AuditCheckpointHash.SignedBytes));
        Assert.Equal(records, await ReadAllAsync(archive));
    }

    [Fact]
    public async Task An_export_of_a_month_that_had_nothing_left_to_export_holds_no_checkpoints_and_no_records()
    {
        var path = Path.Combine(directory.FullName, AuditArchiveFile.NameOf(Month));
        var written = await AuditArchiveFile.WriteAsync(
            path,
            new AuditArchiveHeader(Month, "audit_events_p202609", 8, 7, 41, 40, 0),
            [],
            (_, _) => Task.FromResult(0L),
            CancellationToken.None);

        Assert.Equal(0L, written);
        await using var archive = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);
        Assert.Empty(archive.Checkpoints);
        Assert.Null(await archive.ReadRecordAsync(CancellationToken.None));

        var report = await AuditArchiveVerification.VerifyAsync(archive, new AlwaysValid(), sealedBefore: null, CancellationToken.None);
        Assert.True(report.IsIntact);
    }

    [Fact]
    public async Task An_export_verifies_against_the_key_set_and_the_roots_rebuilt_from_its_own_records()
    {
        var (checkpoints, records) = Sealed(2, 3);
        var path = await WriteAsync(checkpoints, records);

        await using var archive = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);
        var report = await AuditArchiveVerification.VerifyAsync(archive, new AlwaysValid(), sealedBefore: null, CancellationToken.None);

        Assert.True(report.IsIntact);
        Assert.Equal(6L, report.Records);
        Assert.Equal(2L, report.Seal.Verified);
    }

    [Fact]
    public async Task An_export_whose_signature_does_not_verify_is_broken()
    {
        var (checkpoints, records) = Sealed(1, 2);
        var path = await WriteAsync(checkpoints, records);

        await using var archive = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);
        var report = await AuditArchiveVerification.VerifyAsync(archive, new NeverValid(), sealedBefore: null, CancellationToken.None);

        Assert.False(report.IsIntact);
        Assert.Equal(AuditCheckpointFault.BadSignature, report.Seal.Fault);
    }

    /// <summary>A record edited inside the export no longer builds the root its checkpoint signed.</summary>
    [Fact]
    public async Task A_record_edited_in_the_export_no_longer_builds_the_root()
    {
        var (checkpoints, records) = Sealed(1, 3);
        var edited = records.ToList();
        edited[1] = new AuditLedgerRecord(edited[1].Seq, edited[1].Event with { Reason = "edited" });
        var path = await WriteAsync(checkpoints, edited);

        await using var archive = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);
        var report = await AuditArchiveVerification.VerifyAsync(archive, new AlwaysValid(), sealedBefore: null, CancellationToken.None);

        Assert.Equal(AuditCheckpointFault.TamperedRecords, report.Seal.Fault);
    }

    /// <summary>
    /// A record appended after the last checkpoint's range is sealed by nothing in the file. Every
    /// checkpoint still verifies, so only counting leftover records catches it.
    /// </summary>
    [Fact]
    public async Task A_record_the_export_carries_that_no_checkpoint_seals_is_not_complete()
    {
        var (checkpoints, records) = Sealed(1, 2);
        var extra = records.Append(new AuditLedgerRecord(records[^1].Seq + 1, new AuditEvent(At, AuditEvents.TokenIssued))).ToList();
        var path = await WriteAsync(checkpoints, extra);

        await using var archive = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);
        var report = await AuditArchiveVerification.VerifyAsync(archive, new AlwaysValid(), sealedBefore: null, CancellationToken.None);

        Assert.True(report.Seal.IsIntact);
        Assert.False(report.Complete);
        Assert.False(report.IsIntact);
    }

    /// <summary>
    /// Every export but the first starts partway through the ledger, so it is verified against the
    /// checkpoint the previous export ended at. Without one, the walk takes the export's own start
    /// as its floor and skips the link it cannot check.
    /// </summary>
    [Fact]
    public async Task A_later_export_is_checked_against_the_checkpoint_the_one_before_it_ended_at()
    {
        var (first, firstRecords) = Sealed(1, 2);
        var (second, secondRecords) = Sealed(1, 2, from: first[^1], firstSeq: firstRecords[^1].Seq + 1, firstId: first[^1].CheckpointId + 1);
        var path = await WriteAsync(second, secondRecords, firstCheckpointId: second[0].CheckpointId);

        await using (var linked = await AuditArchiveReader.OpenAsync(path, CancellationToken.None))
        {
            Assert.True((await AuditArchiveVerification.VerifyAsync(linked, new AlwaysValid(), first[^1], CancellationToken.None)).IsIntact);
        }

        await using var wrong = await AuditArchiveReader.OpenAsync(path, CancellationToken.None);
        var report = await AuditArchiveVerification.VerifyAsync(wrong, new AlwaysValid(), first[0] with { CheckpointId = second[0].CheckpointId - 1, LastSeq = 99 }, CancellationToken.None);
        Assert.Equal(AuditCheckpointFault.BrokenChain, report.Seal.Fault);
    }

    [Fact]
    public async Task An_export_is_never_written_over()
    {
        var (checkpoints, records) = Sealed(1, 1);
        var path = await WriteAsync(checkpoints, records);

        await Assert.ThrowsAnyAsync<IOException>(() => WriteAsync(checkpoints, records));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task A_half_written_export_is_not_left_under_the_name_of_a_finished_one()
    {
        var path = Path.Combine(directory.FullName, AuditArchiveFile.NameOf(Month));

        await Assert.ThrowsAsync<InvalidOperationException>(() => AuditArchiveFile.WriteAsync(
            path,
            new AuditArchiveHeader(Month, "audit_events_p202609", 1, 1, 1, 1, 0),
            [],
            (_, _) => throw new InvalidOperationException("the database went away"),
            CancellationToken.None));

        Assert.False(File.Exists(path));
        Assert.False(File.Exists(path + AuditArchiveFile.PartialExtension));
    }

    [Fact]
    public async Task A_file_that_is_not_an_export_is_refused_rather_than_read()
    {
        var path = Path.Combine(directory.FullName, "not-an-export.gz");
        await using (var file = new FileStream(path, FileMode.Create, FileAccess.Write))
        await using (var gzip = new GZipStream(file, CompressionLevel.Optimal))
        {
            await gzip.WriteAsync(Encoding.UTF8.GetBytes("hello\n"), CancellationToken.None);
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => AuditArchiveReader.OpenAsync(path, CancellationToken.None));
    }

    [Fact]
    public async Task The_digest_is_of_the_file_as_it_sits_on_disk()
    {
        var (checkpoints, records) = Sealed(1, 2);
        var path = await WriteAsync(checkpoints, records);

        var digest = await AuditArchiveFile.DigestAsync(path, CancellationToken.None);

        Assert.Equal(32, digest.Length);
        Assert.Equal(digest, await AuditArchiveFile.DigestAsync(path, CancellationToken.None));
    }

    /// <summary>Writes an export holding <paramref name="checkpoints"/> and <paramref name="records"/>.</summary>
    private async Task<string> WriteAsync(IReadOnlyList<AuditCheckpoint> checkpoints, IReadOnlyList<AuditLedgerRecord> records, long? firstCheckpointId = null)
    {
        var path = Path.Combine(directory.FullName, AuditArchiveFile.NameOf(Month));
        var header = new AuditArchiveHeader(
            Month,
            "audit_events_p202609",
            firstCheckpointId ?? 1,
            checkpoints[^1].CheckpointId,
            checkpoints[0].FirstSeq,
            checkpoints[^1].LastSeq,
            checkpoints.Count);

        await AuditArchiveFile.WriteAsync(
            path,
            header,
            checkpoints,
            async (writer, token) =>
            {
                foreach (var record in records)
                {
                    await writer.WriteLineAsync(AuditArchiveFormat.WriteRecord(record).AsMemory(), token);
                }

                return records.Count;
            },
            CancellationToken.None);

        return path;
    }

    private static async Task<List<AuditLedgerRecord>> ReadAllAsync(AuditArchiveReader archive)
    {
        var records = new List<AuditLedgerRecord>();
        while (await archive.ReadRecordAsync(CancellationToken.None) is { } record)
        {
            records.Add(record);
        }

        return records;
    }

    /// <summary>A run of checkpoints over their own records, as the sealing pass would have written them.</summary>
    private static (List<AuditCheckpoint> Checkpoints, List<AuditLedgerRecord> Records) Sealed(
        int count,
        int perCheckpoint,
        AuditCheckpoint? from = null,
        long firstSeq = 1,
        long firstId = 1)
    {
        var checkpoints = new List<AuditCheckpoint>();
        var records = new List<AuditLedgerRecord>();
        var previous = from;
        var seq = firstSeq;
        for (var at = 0; at < count; at++)
        {
            var leaves = new List<AuditLedgerRecord>();
            for (var written = 0; written < perCheckpoint; written++)
            {
                leaves.Add(new AuditLedgerRecord(
                    seq,
                    new AuditEvent(At.AddSeconds(seq), AuditEvents.TokenIssued, $"task_{seq}", "jira-triage", "human", Decision: AuditDecision.Allow)));
                seq++;
            }

            var checkpoint = new AuditCheckpoint(
                firstId + at,
                leaves[0].Seq,
                leaves[^1].Seq,
                perCheckpoint,
                MerkleTree.Root(leaves.Select(record => AuditCheckpointHash.Leaf(record.Event)).ToList()),
                previous is null ? null : (ReadOnlyMemory<byte>?)AuditCheckpointHash.LinkHash(previous),
                At.AddMinutes(at),
                "key-2026-09",
                Enumerable.Repeat((byte)0xff, 32).ToArray());

            checkpoints.Add(checkpoint);
            records.AddRange(leaves);
            previous = checkpoint;
        }

        return (checkpoints, records);
    }

    private sealed class AlwaysValid : IAuditCheckpointSignatures
    {
        public bool Verify(string kid, ReadOnlySpan<byte> signedBytes, ReadOnlySpan<byte> signature) => true;
    }

    private sealed class NeverValid : IAuditCheckpointSignatures
    {
        public bool Verify(string kid, ReadOnlySpan<byte> signedBytes, ReadOnlySpan<byte> signature) => false;
    }
}
