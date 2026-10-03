using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SubactId.Core.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// What a checkpoint is signed over, and how the verifier treats a tampered seal. The signed bytes
/// are rebuilt from a published checkpoint, so their shape is a public contract.
/// </summary>
public class AuditCheckpointTests
{
    private static readonly DateTimeOffset ClosedAt = new(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero);

    [Fact]
    public void The_signed_bytes_are_the_canonical_json_of_every_field_but_the_signature()
    {
        var checkpoint = new AuditCheckpoint(
            CheckpointId: 42,
            FirstSeq: 101,
            LastSeq: 240,
            TreeSize: 138,
            RootHash: Bytes(0x4e),
            PrevCheckpointHash: Bytes(0x9c),
            ClosedAt: ClosedAt,
            Kid: "key-2026-09",
            Signature: Bytes(0xff));

        var json = Encoding.UTF8.GetString(AuditCheckpointHash.SignedBytes(checkpoint));

        Assert.Equal(
            $$"""{"checkpoint_id":42,"closed_at":"2026-09-09T14:03:41.882Z","first_seq":101,"kid":"key-2026-09","last_seq":240,"prev_checkpoint_hash":"{{Hex(0x9c)}}","root_hash":"{{Hex(0x4e)}}","tree_size":138}""",
            json);
    }

    [Fact]
    public void The_first_checkpoint_signs_a_null_previous_hash_rather_than_an_empty_one()
    {
        var first = Checkpoint(1, 1, 3, 3, previous: null);

        using var document = JsonDocument.Parse(AuditCheckpointHash.SignedBytes(first));
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("prev_checkpoint_hash").ValueKind);
    }

    /// <summary>The signature is not inside its own pre-image, so a checkpoint can be verified from what is published.</summary>
    [Fact]
    public void The_signature_is_not_part_of_what_was_signed()
    {
        var checkpoint = Checkpoint(1, 1, 3, 3, previous: null);

        Assert.Equal(
            AuditCheckpointHash.SignedBytes(checkpoint),
            AuditCheckpointHash.SignedBytes(checkpoint with { Signature = Bytes(0x01) }));
    }

    [Theory]
    [InlineData("CheckpointId")]
    [InlineData("FirstSeq")]
    [InlineData("LastSeq")]
    [InlineData("TreeSize")]
    [InlineData("RootHash")]
    [InlineData("ClosedAt")]
    [InlineData("Kid")]
    public void Every_other_field_is_inside_the_signature(string field)
    {
        var checkpoint = Checkpoint(1, 1, 3, 3, previous: null);
        var changed = field switch
        {
            "CheckpointId" => checkpoint with { CheckpointId = 2 },
            "FirstSeq" => checkpoint with { FirstSeq = 2 },
            "LastSeq" => checkpoint with { LastSeq = 4 },
            "TreeSize" => checkpoint with { TreeSize = 4 },
            "RootHash" => checkpoint with { RootHash = Bytes(0x02) },
            "ClosedAt" => checkpoint with { ClosedAt = ClosedAt.AddMilliseconds(1) },
            _ => checkpoint with { Kid = "another" },
        };

        Assert.NotEqual(AuditCheckpointHash.SignedBytes(checkpoint), AuditCheckpointHash.SignedBytes(changed));
    }

    [Fact]
    public void The_link_hash_is_sha256_of_the_signed_bytes()
    {
        var checkpoint = Checkpoint(1, 1, 3, 3, previous: null);

        Assert.Equal(SHA256.HashData(AuditCheckpointHash.SignedBytes(checkpoint)), AuditCheckpointHash.LinkHash(checkpoint));
    }

    /// <summary>A record's leaf is taken over the canonical JSON the ledger hashes, so a published record is enough to rebuild it.</summary>
    [Fact]
    public void A_records_leaf_is_the_rfc_leaf_over_its_canonical_json()
    {
        var record = new AuditEvent(ClosedAt, AuditEvents.TokenIssued, "task_1", "jira-triage", "human", Decision: AuditDecision.Allow);

        Assert.Equal(MerkleTree.Leaf(AuditHash.CanonicalJson(record)), AuditCheckpointHash.Leaf(record));
    }

    [Fact]
    public void A_chain_of_checkpoints_over_their_own_records_verifies()
    {
        var (first, firstRecords) = Sealed(1, 1, previous: null, count: 3);
        var (second, secondRecords) = Sealed(2, first.LastSeq + 1, first, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());

        Assert.True(verifier.Feed(first, firstRecords));
        Assert.True(verifier.Feed(second, secondRecords));

        var report = verifier.Report;
        Assert.True(report.IsIntact);
        Assert.Equal((2L, 5L, 2L, second.LastSeq), (report.Verified, report.SealedRecords, report.LastCheckpointId, report.LastSeq));
        Assert.Equal(2L, verifier.Mark!.CheckpointId);
    }

    [Fact]
    public void A_checkpoint_whose_signature_does_not_verify_is_a_bad_signature()
    {
        var (first, records) = Sealed(1, 1, previous: null, count: 2);
        var verifier = new AuditCheckpointVerifier(new NeverValid());

        Assert.False(verifier.Feed(first, records));
        Assert.Equal((AuditCheckpointFault.BadSignature, 1L), (verifier.Report.Fault, verifier.Report.FaultCheckpointId));
    }

    [Fact]
    public void A_checkpoint_that_does_not_link_to_the_one_before_it_breaks_the_chain()
    {
        var (first, firstRecords) = Sealed(1, 1, previous: null, count: 2);
        var (second, secondRecords) = Sealed(2, first.LastSeq + 1, first, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());
        verifier.Feed(first, firstRecords);

        Assert.False(verifier.Feed(second with { PrevCheckpointHash = Bytes(0x00) }, secondRecords));
        Assert.Equal((AuditCheckpointFault.BrokenChain, 2L), (verifier.Report.Fault, verifier.Report.FaultCheckpointId));
    }

    [Fact]
    public void The_first_checkpoint_may_link_to_nothing_and_to_nothing_else()
    {
        var (first, records) = Sealed(1, 1, previous: null, count: 2);
        var claiming = new AuditCheckpointVerifier(new AlwaysValid());

        Assert.False(claiming.Feed(first with { PrevCheckpointHash = Bytes(0x11) }, records));
        Assert.Equal(AuditCheckpointFault.BrokenChain, claiming.Report.Fault);
    }

    /// <summary>
    /// A gap or an overlap does not show in a root. Only the ranges show that the ledger is covered end to end.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(-1)]
    public void A_range_that_does_not_begin_where_the_last_one_ended_breaks_the_chain(int drift)
    {
        var (first, firstRecords) = Sealed(1, 1, previous: null, count: 2);
        var (second, secondRecords) = Sealed(2, first.LastSeq + 1, first, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());
        verifier.Feed(first, firstRecords);

        Assert.False(verifier.Feed(second with { FirstSeq = second.FirstSeq + drift }, secondRecords));
        Assert.Equal(AuditCheckpointFault.BrokenChain, verifier.Report.Fault);
    }

    [Fact]
    public void An_edited_record_no_longer_builds_the_root_that_was_signed()
    {
        var (checkpoint, records) = Sealed(1, 1, previous: null, count: 4);
        var edited = records.ToList();
        edited[2] = new AuditLedgerRecord(edited[2].Seq, edited[2].Event with { Reason = "edited" });
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());

        Assert.False(verifier.Feed(checkpoint, edited));
        Assert.Equal((AuditCheckpointFault.TamperedRecords, 1L), (verifier.Report.Fault, verifier.Report.FaultCheckpointId));
    }

    [Fact]
    public void A_removed_or_inserted_record_changes_the_leaf_count_the_checkpoint_signed()
    {
        var (checkpoint, records) = Sealed(1, 1, previous: null, count: 4);

        var removed = new AuditCheckpointVerifier(new AlwaysValid());
        Assert.False(removed.Feed(checkpoint, records.Take(3).ToList()));
        Assert.Equal(AuditCheckpointFault.TamperedRecords, removed.Report.Fault);

        // Into a hole inside the sealed range: a sequence number the range covers but the tree does not.
        var inserted = records.ToList();
        inserted.Insert(2, new AuditLedgerRecord(records[1].Seq + 1, new AuditEvent(ClosedAt, AuditEvents.TokenIssued, "task_x", "agent", "human", Decision: AuditDecision.Allow)));
        var reinserted = new AuditCheckpointVerifier(new AlwaysValid());
        Assert.False(reinserted.Feed(checkpoint with { LastSeq = checkpoint.LastSeq + 1 }, inserted));
        Assert.Equal(AuditCheckpointFault.TamperedRecords, reinserted.Report.Fault);
    }

    [Fact]
    public void Records_outside_the_range_or_out_of_order_are_not_what_was_sealed()
    {
        var (checkpoint, records) = Sealed(1, 1, previous: null, count: 3);

        var outside = records.ToList();
        outside[^1] = new AuditLedgerRecord(checkpoint.LastSeq + 1, outside[^1].Event);
        Assert.False(new AuditCheckpointVerifier(new AlwaysValid()).Feed(checkpoint, outside));

        var reordered = new List<AuditLedgerRecord> { records[1], records[0], records[2] };
        Assert.False(new AuditCheckpointVerifier(new AlwaysValid()).Feed(checkpoint, reordered));
    }

    /// <summary>The cheap walk: signature and chain only, for a run that is not reading the whole ledger back.</summary>
    [Fact]
    public void Without_records_the_walk_checks_the_signature_and_the_chain_and_says_nothing_about_the_leaves()
    {
        var (first, _) = Sealed(1, 1, previous: null, count: 3);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());

        Assert.True(verifier.Feed(first));
        Assert.True(verifier.Report.IsIntact);
        Assert.Equal(3L, verifier.Report.SealedRecords);
    }

    [Fact]
    public void A_cut_tail_walks_clean_and_only_a_mark_from_an_earlier_run_exposes_it()
    {
        var (first, firstRecords) = Sealed(1, 1, previous: null, count: 2);
        var (second, secondRecords) = Sealed(2, first.LastSeq + 1, first, count: 2);

        var earlier = new AuditCheckpointVerifier(new AlwaysValid());
        earlier.Watch(2);
        earlier.Feed(first, firstRecords);
        earlier.Feed(second, secondRecords);
        var mark = earlier.Mark!;

        // The same ledger with its last checkpoint gone: nothing left in it is wrong.
        var cut = new AuditCheckpointVerifier(new AlwaysValid());
        cut.Watch(mark.CheckpointId);
        Assert.True(cut.Feed(first, firstRecords));
        Assert.True(cut.Report.IsIntact);

        Assert.False(cut.Confirm(mark));
        Assert.Equal((AuditCheckpointFault.Truncated, 2L), (cut.Report.Fault, cut.Report.FaultCheckpointId));
    }

    [Fact]
    public void A_mark_whose_root_no_longer_matches_is_a_rewritten_tail()
    {
        var (first, records) = Sealed(1, 1, previous: null, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());
        verifier.Watch(1);
        verifier.Feed(first, records);

        Assert.False(verifier.Confirm(new AuditCheckpointMark(1, Bytes(0x00))));
        Assert.Equal(AuditCheckpointFault.Truncated, verifier.Report.Fault);
    }

    [Fact]
    public void Checkpoints_must_be_fed_in_id_order()
    {
        var (first, firstRecords) = Sealed(1, 1, previous: null, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid());
        Assert.True(verifier.Feed(first, firstRecords));

        Assert.Throws<ArgumentException>(() => verifier.Feed(first, firstRecords));
    }

    [Fact]
    public void Nothing_after_the_first_fault_is_examined()
    {
        var (first, records) = Sealed(1, 1, previous: null, count: 2);
        var (second, secondRecords) = Sealed(2, first.LastSeq + 1, first, count: 2);
        var verifier = new AuditCheckpointVerifier(new NeverValid());

        Assert.False(verifier.Feed(first, records));
        Assert.False(verifier.Feed(second, secondRecords));
        Assert.Equal((1L, 0L), (verifier.Report.FaultCheckpointId, verifier.Report.Verified));
    }

    /// <summary>
    /// Once the oldest months are archived, the walk starts at the checkpoint after the last archived
    /// one. That first link is still checked, so an emptied ledger does not pass as an archived one.
    /// </summary>
    [Fact]
    public void A_walk_from_a_floor_checks_the_first_checkpoint_against_the_archived_one()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(2, archived.LastSeq + 1, archived, count: 3);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));

        Assert.True(verifier.Feed(online, onlineRecords));
        Assert.True(verifier.Report.IsIntact);
        Assert.Equal((1L, 3L, online.LastSeq), (verifier.Report.Verified, verifier.Report.SealedRecords, verifier.Report.LastSeq));
    }

    [Fact]
    public void A_first_online_checkpoint_that_does_not_follow_on_from_the_archived_one_breaks_the_chain()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(2, archived.LastSeq + 1, archived, count: 2);

        var unlinked = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));
        Assert.False(unlinked.Feed(online with { PrevCheckpointHash = Bytes(0x00) }, onlineRecords));
        Assert.Equal((AuditCheckpointFault.BrokenChain, 2L), (unlinked.Report.Fault, unlinked.Report.FaultCheckpointId));

        var adrift = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));
        Assert.False(adrift.Feed(online with { FirstSeq = online.FirstSeq + 1 }, onlineRecords));
        Assert.Equal(AuditCheckpointFault.BrokenChain, adrift.Report.Fault);
    }

    /// <summary>A checkpoint missing between what was archived and what is online is the gap the floor's id catches.</summary>
    [Fact]
    public void A_walk_that_does_not_start_at_the_checkpoint_after_the_archived_one_breaks_the_chain()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(3, archived.LastSeq + 1, archived, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));

        Assert.False(verifier.Feed(online, onlineRecords));
        Assert.Equal((AuditCheckpointFault.BrokenChain, 3L), (verifier.Report.Fault, verifier.Report.FaultCheckpointId));
    }

    /// <summary>
    /// Without the archived checkpoint the link names something this walk cannot see, so it is taken
    /// as the floor. Everything after it is checked as usual.
    /// </summary>
    [Fact]
    public void A_floor_with_no_archived_checkpoint_takes_the_first_link_as_given_and_checks_the_rest()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(2, archived.LastSeq + 1, archived, count: 2);
        var (next, nextRecords) = Sealed(3, online.LastSeq + 1, online, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2));

        Assert.True(verifier.Feed(online, onlineRecords));
        Assert.True(verifier.Feed(next, nextRecords));
        Assert.True(verifier.Report.IsIntact);

        var broken = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2));
        broken.Feed(online, onlineRecords);
        Assert.False(broken.Feed(next with { PrevCheckpointHash = Bytes(0x00) }, nextRecords));
        Assert.Equal(AuditCheckpointFault.BrokenChain, broken.Report.Fault);
    }

    /// <summary>
    /// A mark printed before a month left names a checkpoint below the floor. That checkpoint is still
    /// in the table, so it is checked as it stands rather than walked, and the mark still confirms.
    /// </summary>
    [Fact]
    public void A_mark_below_the_floor_confirms_against_the_checkpoint_as_it_stands()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(2, archived.LastSeq + 1, archived, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));
        verifier.Watch(1);

        Assert.True(verifier.Note(archived));
        Assert.True(verifier.Feed(online, onlineRecords));
        Assert.True(verifier.Confirm(new AuditCheckpointMark(1, archived.RootHash)));
        Assert.True(verifier.Report.IsIntact);
        Assert.Equal(1L, verifier.Report.Verified);
    }

    /// <summary>A noted checkpoint that no longer signs the root the mark recorded is the rewritten tail a mark exists to catch.</summary>
    [Fact]
    public void A_mark_below_the_floor_whose_root_no_longer_matches_is_a_rewritten_tail()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));
        verifier.Watch(1);
        verifier.Note(archived with { RootHash = Bytes(0x00) });

        Assert.False(verifier.Confirm(new AuditCheckpointMark(1, archived.RootHash)));
        Assert.Equal((AuditCheckpointFault.Truncated, 1L), (verifier.Report.Fault, verifier.Report.FaultCheckpointId));
    }

    /// <summary>A mark below the floor that was never noted names a checkpoint that is not in the table: a cut tail.</summary>
    [Fact]
    public void A_mark_below_the_floor_at_a_checkpoint_that_is_gone_is_a_cut_tail()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));
        verifier.Watch(1);

        Assert.False(verifier.Confirm(new AuditCheckpointMark(1, archived.RootHash)));
        Assert.Equal(AuditCheckpointFault.Truncated, verifier.Report.Fault);
    }

    [Fact]
    public void A_noted_checkpoint_whose_signature_does_not_verify_is_a_bad_signature_and_stops_the_walk()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(2, archived.LastSeq + 1, archived, count: 2);
        var verifier = new AuditCheckpointVerifier(new NeverValid(), new AuditCheckpointFloor(2, archived));

        Assert.False(verifier.Note(archived));
        Assert.False(verifier.Feed(online, onlineRecords));
        Assert.Equal((AuditCheckpointFault.BadSignature, 1L, 0L), (verifier.Report.Fault, verifier.Report.FaultCheckpointId, verifier.Report.Verified));
    }

    /// <summary>Only what is below the floor is taken as it stands; everything at or above it is walked.</summary>
    [Fact]
    public void Only_a_checkpoint_below_the_floor_is_noted_and_only_before_the_walk()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var (online, onlineRecords) = Sealed(2, archived.LastSeq + 1, archived, count: 2);

        Assert.Throws<ArgumentException>(() => new AuditCheckpointVerifier(new AlwaysValid()).Note(archived));
        Assert.Throws<ArgumentException>(() => new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived)).Note(online));

        var walking = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));
        walking.Feed(online, onlineRecords);
        Assert.Throws<InvalidOperationException>(() => walking.Note(archived));
    }

    /// <summary>A ledger every month of which has been archived has nothing online left to verify, and that is not a fault.</summary>
    [Fact]
    public void A_floor_with_nothing_after_it_is_intact()
    {
        var (archived, _) = Sealed(1, 1, previous: null, count: 2);
        var verifier = new AuditCheckpointVerifier(new AlwaysValid(), new AuditCheckpointFloor(2, archived));

        Assert.True(verifier.Report.IsIntact);
        Assert.Equal(0L, verifier.Report.Verified);
        Assert.Null(verifier.Mark);
    }

    /// <summary>A checkpoint over a run of records, and the records themselves, as the sealing pass would write them.</summary>
    private static (AuditCheckpoint Checkpoint, IReadOnlyList<AuditLedgerRecord> Records) Sealed(long id, long firstSeq, AuditCheckpoint? previous, int count)
    {
        var records = Enumerable.Range(0, count)
            .Select(i => new AuditLedgerRecord(
                firstSeq + i,
                new AuditEvent(ClosedAt.AddSeconds(i), AuditEvents.TokenIssued, $"task_{firstSeq + i}", "jira-triage", "human", Decision: AuditDecision.Allow)))
            .ToList();

        var root = MerkleTree.Root(records.Select(r => AuditCheckpointHash.Leaf(r.Event)).ToList());
        var checkpoint = new AuditCheckpoint(
            id,
            firstSeq,
            records[^1].Seq,
            count,
            root,
            previous is null ? null : (ReadOnlyMemory<byte>?)AuditCheckpointHash.LinkHash(previous),
            ClosedAt.AddMinutes(id),
            "key-2026-09",
            Bytes(0xff));

        return (checkpoint, records);
    }

    private static AuditCheckpoint Checkpoint(long id, long firstSeq, long lastSeq, long treeSize, AuditCheckpoint? previous) =>
        new(id, firstSeq, lastSeq, treeSize, Bytes(0x4e), previous is null ? null : (ReadOnlyMemory<byte>?)AuditCheckpointHash.LinkHash(previous), ClosedAt, "key-2026-09", Bytes(0xff));

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();

    private static string Hex(byte value) => string.Concat(Enumerable.Repeat(value.ToString("x2", System.Globalization.CultureInfo.InvariantCulture), 32));

    private sealed class AlwaysValid : IAuditCheckpointSignatures
    {
        public bool Verify(string kid, ReadOnlySpan<byte> signedBytes, ReadOnlySpan<byte> signature) => true;
    }

    private sealed class NeverValid : IAuditCheckpointSignatures
    {
        public bool Verify(string kid, ReadOnlySpan<byte> signedBytes, ReadOnlySpan<byte> signature) => false;
    }
}
