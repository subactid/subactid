using SubactId.Core.Audit;
using SubactId.Storage.Postgres.Repositories;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class AuditLedgerLayoutTests
{
    private static readonly DateTimeOffset September = new(2026, 9, 19, 14, 30, 0, TimeSpan.Zero);

    [Fact]
    public void The_month_a_record_belongs_to_is_its_month_in_UTC()
    {
        // An instant that is October where the caller is and September in UTC belongs to the
        // September partition, because the partition bounds are UTC instants and so is ts.
        var lastMomentOfSeptemberInUtc = new DateTimeOffset(2026, 10, 1, 8, 0, 0, TimeSpan.FromHours(10));

        Assert.Equal(new DateOnly(2026, 9, 1), AuditLedgerLayout.MonthOf(lastMomentOfSeptemberInUtc));
        Assert.Equal(new DateOnly(2026, 9, 1), AuditLedgerLayout.MonthOf(September));
    }

    [Fact]
    public void A_month_with_no_partition_is_uncovered_and_has_no_runway()
    {
        var layout = new AuditLedgerLayout(true, [Partition("audit_events_p202608")]);

        Assert.Null(layout.Covering(September));
        Assert.Null(layout.MonthsAhead(September));
    }

    [Fact]
    public void The_runway_is_the_unbroken_run_of_months_after_this_one()
    {
        var layout = new AuditLedgerLayout(true,
        [
            Partition("audit_events_p202608"),
            Partition("audit_events_p202609"),
            Partition("audit_events_p202610"),
            Partition("audit_events_p202611"),

            // December is missing, so January is not runway: a record written then is refused.
            Partition("audit_events_p202701"),
        ]);

        Assert.NotNull(layout.Covering(September));
        Assert.Equal(2, layout.MonthsAhead(September));
    }

    [Fact]
    public void A_partition_is_guarded_only_when_it_carries_both_guards_and_a_name_this_control_plane_gave()
    {
        Assert.True(Partition("audit_events_p202609").Guarded);
        Assert.False((Partition("audit_events_p202609") with { RefusesTruncate = false }).Guarded);
        Assert.False((Partition("audit_events_p202609") with { PrivilegesRevoked = false }).Guarded);

        // A partition made by hand is reported, not counted as one of ours.
        Assert.False(new AuditLedgerPartition("audit_events_archive", null, true, true).Guarded);
    }

    [Theory]
    [InlineData("audit_events_p202609", 2026, 9)]
    [InlineData("audit_events_p000101", 1, 1)]
    [InlineData("audit_events_p202612", 2026, 12)]
    public void A_partition_name_says_which_month_it_holds(string name, int year, int month)
    {
        Assert.Equal(new DateOnly(year, month, 1), PostgresAuditLedgerPartitions.MonthOf(name));
    }

    [Theory]
    [InlineData("audit_events")]
    [InlineData("audit_events_archive")]
    [InlineData("audit_events_p2026")]
    [InlineData("audit_events_p2026090")]
    [InlineData("audit_events_p202613")]
    [InlineData("audit_events_p202600")]
    [InlineData("audit_events_p 2026")]
    [InlineData("audit_events_p+20269")]
    [InlineData("audit_events_p-20269")]
    public void A_name_this_control_plane_did_not_give_names_no_month(string name)
    {
        Assert.Null(PostgresAuditLedgerPartitions.MonthOf(name));
    }

    private static AuditLedgerPartition Partition(string name) =>
        new(name, PostgresAuditLedgerPartitions.MonthOf(name), RefusesTruncate: true, PrivilegesRevoked: true);
}
