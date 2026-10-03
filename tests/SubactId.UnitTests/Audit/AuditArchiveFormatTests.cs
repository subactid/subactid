using SubactId.Core.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// The lines an export is made of. An export is verified by rebuilding each checkpoint's root
/// from the parsed records, so every field must read back exactly as written.
/// </summary>
public class AuditArchiveFormatTests
{
    private static readonly DateTimeOffset At = new(2026, 9, 9, 14, 3, 41, 882, TimeSpan.Zero);

    [Fact]
    public void A_record_with_every_field_set_reads_back_as_itself()
    {
        var record = new AuditLedgerRecord(
            10428,
            new AuditEvent(
                At,
                AuditEvents.TokenIssued,
                "task_01HQZX9K4M",
                "jira-triage",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "https://jira.internal",
                "jira:read jira:comment",
                "tok_01HQZX9K5P",
                1,
                AuditDecision.Allow,
                "rate_limited",
                7,
                "{\"month\":\"2026-09\"}"));

        Assert.True(AuditArchiveFormat.TryReadRecord(AuditArchiveFormat.WriteRecord(record), out var read));
        Assert.Equal(record, read!);
    }

    [Fact]
    public void A_record_with_nothing_but_a_timestamp_and_an_event_reads_back_as_itself()
    {
        var record = new AuditLedgerRecord(1, new AuditEvent(At, AuditEvents.SignalDenied));

        Assert.True(AuditArchiveFormat.TryReadRecord(AuditArchiveFormat.WriteRecord(record), out var read));
        Assert.Equal(record, read!);
    }

    /// <summary>
    /// Fields are tab-separated and newline-terminated, so a value holding either must still read
    /// back as one field.
    /// </summary>
    [Theory]
    [InlineData("a\tb")]
    [InlineData("a\nb")]
    [InlineData("a\\b")]
    [InlineData("a\\Nb")]
    [InlineData("\\N")]
    [InlineData("a\r\nb")]
    [InlineData("\b\f\v")]
    [InlineData("")]
    [InlineData("héllo ☃ \U0001F600")]
    public void A_value_that_could_end_a_field_or_a_line_survives_the_round_trip(string value)
    {
        var record = new AuditLedgerRecord(5, new AuditEvent(At, AuditEvents.TokenDenied, Reason: value, Sponsor: value));

        Assert.True(AuditArchiveFormat.TryReadRecord(AuditArchiveFormat.WriteRecord(record), out var read));
        Assert.Equal(record, read!);
    }

    /// <summary>A null field and an empty one are different values, and the export keeps them apart.</summary>
    [Fact]
    public void An_empty_string_is_not_a_null()
    {
        var empty = new AuditLedgerRecord(5, new AuditEvent(At, AuditEvents.TokenDenied, Reason: string.Empty));
        var absent = new AuditLedgerRecord(5, new AuditEvent(At, AuditEvents.TokenDenied));

        Assert.NotEqual(AuditArchiveFormat.WriteRecord(empty), AuditArchiveFormat.WriteRecord(absent));
        Assert.True(AuditArchiveFormat.TryReadRecord(AuditArchiveFormat.WriteRecord(empty), out var read));
        Assert.Equal(string.Empty, read!.Event.Reason);
    }

    /// <summary>The escapes a Postgres bulk export writes, which the records section uses.</summary>
    [Theory]
    [InlineData("\\", @"\\")]
    [InlineData("\b", @"\b")]
    [InlineData("\f", @"\f")]
    [InlineData("\n", @"\n")]
    [InlineData("\r", @"\r")]
    [InlineData("\t", @"\t")]
    [InlineData("\v", @"\v")]
    [InlineData("/", "/")]
    public void Escaping_is_the_bulk_exporters_own(string value, string escaped)
    {
        Assert.Equal(escaped, AuditArchiveFormat.Escape(value));
        Assert.Equal(new string?[] { value }, AuditArchiveFormat.Split(escaped, 1));
    }

    [Fact]
    public void A_null_field_is_the_null_marker_and_reads_back_as_null()
    {
        Assert.Equal(AuditArchiveFormat.Null, AuditArchiveFormat.Escape(null));
        Assert.Equal(new string?[] { null }, AuditArchiveFormat.Split(AuditArchiveFormat.Null, 1));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void A_line_with_the_wrong_number_of_fields_is_a_corrupted_export_rather_than_a_record(int fields)
    {
        Assert.Null(AuditArchiveFormat.Split(string.Join('\t', Enumerable.Repeat("x", fields)), 2));
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData("")]
    public void A_record_line_whose_sequence_number_is_not_one_is_refused(string seq)
    {
        var line = Fields(AuditArchiveFormat.WriteRecord(Record()), 0, seq);

        Assert.False(AuditArchiveFormat.TryReadRecord(line, out _));
    }

    /// <summary>
    /// A decision this server never wrote is refused, not read as "no decision", because the two
    /// give different leaves.
    /// </summary>
    [Fact]
    public void A_decision_that_is_neither_allow_nor_deny_is_refused()
    {
        Assert.False(AuditArchiveFormat.TryReadRecord(Fields(AuditArchiveFormat.WriteRecord(Record()), 10, "maybe"), out _));
    }

    [Theory]
    [InlineData("2026-09-09T14:03:41.882Z")]
    [InlineData("2026-09-09 14:03:41.882000Z")]
    [InlineData("nonsense")]
    public void A_timestamp_that_is_not_the_export_form_is_refused(string ts)
    {
        Assert.False(AuditArchiveFormat.TryReadRecord(Fields(AuditArchiveFormat.WriteRecord(Record()), 1, ts), out _));
    }

    /// <summary>
    /// The export keeps microseconds, as the ledger stores them, and a record's leaf is taken over
    /// three fractional digits. Both must hold for a record read back to match what was sealed.
    /// </summary>
    [Fact]
    public void A_timestamp_keeps_the_microseconds_the_ledger_stored()
    {
        var precise = At.AddTicks(4567);
        var record = new AuditLedgerRecord(1, new AuditEvent(precise, AuditEvents.TokenIssued));

        Assert.True(AuditArchiveFormat.TryReadRecord(AuditArchiveFormat.WriteRecord(record), out var read));
        Assert.Equal(precise.AddTicks(-(precise.Ticks % 10)), read!.Event.Ts);
        Assert.Equal(AuditHash.CanonicalJson(record.Event), AuditHash.CanonicalJson(read.Event));
    }

    [Fact]
    public void A_checkpoint_reads_back_as_the_one_that_was_written()
    {
        var checkpoint = new AuditCheckpoint(42, 101, 240, 138, Bytes(0x4e), (ReadOnlyMemory<byte>?)Bytes(0x9c), At, "key-2026-09", Bytes(0xff));

        Assert.True(AuditArchiveFormat.TryReadCheckpoint(AuditArchiveFormat.WriteCheckpoint(checkpoint), out var read));
        Assert.Equal(AuditCheckpointHash.SignedBytes(checkpoint), AuditCheckpointHash.SignedBytes(read!));
        Assert.Equal(checkpoint.Signature.ToArray(), read!.Signature.ToArray());
    }

    /// <summary>The first checkpoint of a ledger links to nothing, and an empty hash is not that.</summary>
    [Fact]
    public void A_checkpoint_that_links_to_nothing_reads_back_linking_to_nothing()
    {
        var first = new AuditCheckpoint(1, 1, 3, 3, Bytes(0x4e), null, At, "key-2026-09", Bytes(0xff));

        Assert.True(AuditArchiveFormat.TryReadCheckpoint(AuditArchiveFormat.WriteCheckpoint(first), out var read));
        Assert.Null(read!.PrevCheckpointHash);
        Assert.Equal(AuditCheckpointHash.SignedBytes(first), AuditCheckpointHash.SignedBytes(read));
    }

    [Theory]
    [InlineData(4, "not-hex")]
    [InlineData(8, "abc")]
    [InlineData(0, "x")]
    public void A_checkpoint_line_that_is_not_one_is_refused(int field, string value)
    {
        Assert.False(AuditArchiveFormat.TryReadCheckpoint(
            Fields(AuditArchiveFormat.WriteCheckpoint(new AuditCheckpoint(1, 1, 3, 3, Bytes(0x4e), null, At, "kid", Bytes(0xff))), field, value),
            out _));
    }

    private static AuditLedgerRecord Record() =>
        new(1, new AuditEvent(At, AuditEvents.TokenIssued, "task_1", "jira-triage", "human", Decision: AuditDecision.Allow));

    /// <summary>The same line with one field replaced.</summary>
    private static string Fields(string line, int field, string value)
    {
        var parts = line.Split('\t');
        parts[field] = value;
        return string.Join('\t', parts);
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
}
