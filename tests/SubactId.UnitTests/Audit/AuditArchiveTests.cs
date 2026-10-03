using System.Text.Json;
using SubactId.Core.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// What an archived month is, and what its ledger record says. The detail is sealed by the next
/// checkpoint, so the ledger keeps the digest of an export that has left the database.
/// </summary>
public class AuditArchiveTests
{
    private static readonly DateTimeOffset Month = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ArchivedAt = new(2026, 12, 1, 9, 30, 0, TimeSpan.Zero);

    [Fact]
    public void The_detail_names_the_partition_the_ranges_the_export_and_its_digest()
    {
        var detail = Archive().ToDetail();

        using var document = JsonDocument.Parse(detail);
        Assert.Equal(
            ["digest", "first_checkpoint", "first_seq", "last_checkpoint", "last_seq", "location", "month", "partition", "records"],
            document.RootElement.EnumerateObject().Select(property => property.Name));
        Assert.Equal("2026-09", document.RootElement.GetProperty("month").GetString());
        Assert.Equal("audit_events_p202609", document.RootElement.GetProperty("partition").GetString());
        Assert.Equal(412, document.RootElement.GetProperty("last_checkpoint").GetInt64());
        Assert.Equal(339726, document.RootElement.GetProperty("records").GetInt64());
        Assert.Equal("/var/lib/subactid/archive/audit-2026-09.subactid-archive.gz", document.RootElement.GetProperty("location").GetString());
        Assert.Equal(string.Concat(Enumerable.Repeat("ab", 32)), document.RootElement.GetProperty("digest").GetString());
    }

    /// <summary>The detail is one line, because it is a field of a record.</summary>
    [Fact]
    public void The_detail_is_one_line()
    {
        Assert.DoesNotContain('\n', Archive().ToDetail());
    }

    [Fact]
    public void The_first_instant_still_online_is_the_month_after_the_one_archived()
    {
        Assert.Equal(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), Archive().ArchivedBefore);
    }

    /// <summary>
    /// A month whose records an earlier export already carried has an empty range, not no range,
    /// so the floor still moves on.
    /// </summary>
    [Fact]
    public void A_month_with_nothing_left_to_export_carries_an_empty_range()
    {
        var empty = Archive() with { FirstCheckpointId = 8, LastCheckpointId = 7, FirstSeq = 41, LastSeq = 40, Records = 0 };

        Assert.True(empty.IsEmpty);
        Assert.False(Archive().IsEmpty);
    }

    /// <summary>
    /// The location is written into the detail escaped, so the length limit applies to the escaped
    /// form. An escaped character costs six.
    /// </summary>
    [Fact]
    public void A_location_fits_only_while_its_escaped_form_leaves_room_for_the_rest_of_the_detail()
    {
        Assert.True(AuditArchive.LocationFits("/var/lib/subactid/archive/audit-2026-09.subactid-archive.gz"));
        Assert.True(AuditArchive.LocationFits(new string('a', 1500)));
        Assert.False(AuditArchive.LocationFits(new string('a', 2000)));
        Assert.False(AuditArchive.LocationFits(new string('+', 400)));

        var widest = Archive() with { Location = new string('a', 1500), FirstCheckpointId = long.MaxValue, LastCheckpointId = long.MaxValue, FirstSeq = long.MaxValue, LastSeq = long.MaxValue, Records = long.MaxValue };
        Assert.True(widest.ToDetail().Length <= AuditArchive.MaxDetailLength);
    }

    [Theory]
    [InlineData("2026-09", 2026, 9)]
    [InlineData("0001-01", 1, 1)]
    [InlineData("9999-12", 9999, 12)]
    public void A_month_on_the_command_line_is_four_digits_a_hyphen_and_two(string text, int year, int month)
    {
        Assert.True(AuditArchive.TryParseMonth(text, out var parsed));
        Assert.Equal(new DateTimeOffset(year, month, 1, 0, 0, 0, TimeSpan.Zero), parsed);
    }

    [Theory]
    [InlineData((string?)null)]
    [InlineData("")]
    [InlineData("2026-9")]
    [InlineData("2026-091")]
    [InlineData("2026/09")]
    [InlineData("2026-00")]
    [InlineData("2026-13")]
    [InlineData("+026-09")]
    [InlineData(" 2026-09")]
    public void Anything_else_is_not_a_month(string? text)
    {
        Assert.False(AuditArchive.TryParseMonth(text, out _));
    }

    private static AuditArchive Archive() =>
        new(
            Month,
            "audit_events_p202609",
            1,
            412,
            1,
            339726,
            339726,
            "/var/lib/subactid/archive/audit-2026-09.subactid-archive.gz",
            Enumerable.Repeat((byte)0xab, 32).ToArray(),
            ArchivedAt);
}
