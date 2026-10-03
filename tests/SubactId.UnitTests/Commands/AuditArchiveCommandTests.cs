using SubactId.Core.Audit;
using SubactId.Server.Commands;
using Xunit;

namespace SubactId.UnitTests.Commands;

/// <summary>
/// What the one command that removes records accepts. Every refusal here happens before anything
/// is read: a cutoff that would take the current month, a missing destination, or no cutoff.
/// </summary>
public sealed class AuditArchiveCommandTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 11, 30, 0, TimeSpan.Zero);

    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("subactid-archive-args");

    public void Dispose() => directory.Delete(recursive: true);

    [Fact]
    public void The_cutoff_is_the_month_named_and_the_destination_the_directory_given()
    {
        Assert.True(AuditArchiveCommand.TryParse(["--before", "2026-07", "--to", directory.FullName], null, Now, out var cutoff, out var destination, out _));

        Assert.Equal(new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero), cutoff);
        Assert.Equal(directory.FullName, destination);
    }

    [Fact]
    public void The_options_may_come_in_either_order()
    {
        Assert.True(AuditArchiveCommand.TryParse(["--to", directory.FullName, "--before", "2026-07"], null, Now, out var cutoff, out _, out _));

        Assert.Equal(new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero), cutoff);
    }

    /// <summary>The configured retention is only a cutoff: the command must still be run to act on it.</summary>
    [Fact]
    public void Without_a_cutoff_the_configured_retention_supplies_one()
    {
        Assert.True(AuditArchiveCommand.TryParse(["--to", directory.FullName], TimeSpan.FromDays(90), Now, out var cutoff, out _, out _));

        Assert.Equal(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero), cutoff);
    }

    [Fact]
    public void Without_a_cutoff_and_without_a_retention_the_run_is_refused()
    {
        Assert.False(AuditArchiveCommand.TryParse(["--to", directory.FullName], null, Now, out _, out _, out var usage));

        Assert.Contains("SubactId:Audit:Retention", usage, StringComparison.Ordinal);
    }

    /// <summary>There is no default destination for an export.</summary>
    [Fact]
    public void A_run_with_nowhere_to_write_the_export_is_refused()
    {
        Assert.False(AuditArchiveCommand.TryParse(["--before", "2026-07"], TimeSpan.FromDays(90), Now, out _, out _, out _));
    }

    [Fact]
    public void A_destination_that_does_not_exist_is_refused_rather_than_created()
    {
        var missing = Path.Combine(directory.FullName, "not-here");

        Assert.False(AuditArchiveCommand.TryParse(["--before", "2026-07", "--to", missing], null, Now, out _, out _, out var usage));

        Assert.Contains("already exists", usage, StringComparison.Ordinal);
        Assert.False(Directory.Exists(missing));
    }

    /// <summary>
    /// The location is written escaped into the record's detail. A path that fits the column as bytes
    /// but not as an escaped field is refused before any month is read.
    /// </summary>
    [Fact]
    public void A_destination_the_ledger_could_not_record_an_export_at_is_refused()
    {
        // Each '+' is written as six characters; two components keep each under a file system's limit.
        var unrecordable = Path.Combine(directory.FullName, new string('+', 200), new string('+', 200));
        Directory.CreateDirectory(unrecordable);

        Assert.False(AuditArchiveCommand.TryParse(["--before", "2026-07", "--to", unrecordable], null, Now, out _, out _, out var usage));

        Assert.Contains("too long", usage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("2026-7")]
    [InlineData("2026")]
    [InlineData("2026-13")]
    [InlineData("2026-00")]
    [InlineData("July 2026")]
    public void A_cutoff_that_is_not_a_month_is_refused(string before)
    {
        Assert.False(AuditArchiveCommand.TryParse(["--before", before, "--to", directory.FullName], null, Now, out _, out _, out _));
    }

    /// <summary>The month being written into is not a month to archive, and neither is one that has not happened.</summary>
    [Theory]
    [InlineData("2026-10")]
    [InlineData("2027-01")]
    public void A_cutoff_after_the_current_month_is_refused(string before)
    {
        Assert.False(AuditArchiveCommand.TryParse(["--before", before, "--to", directory.FullName], null, Now, out _, out _, out var usage));

        Assert.Contains("current month", usage, StringComparison.Ordinal);
    }

    /// <summary>This month is allowed as a cutoff: it keeps the current month and takes everything before it.</summary>
    [Fact]
    public void The_current_month_is_an_allowed_cutoff()
    {
        Assert.True(AuditArchiveCommand.TryParse(["--before", "2026-09", "--to", directory.FullName], null, Now, out var cutoff, out _, out _));

        Assert.Equal(new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero), cutoff);
    }

    [Fact]
    public void An_argument_this_command_does_not_take_is_refused()
    {
        Assert.False(Parse("--before", "2026-07", "--to"));
        Assert.False(Parse("--to", directory.FullName, "--before"));
        Assert.False(Parse("--unknown", "x", "--to", directory.FullName));
        Assert.False(Parse("2026-07", "--to", directory.FullName));
    }

    [Fact]
    public void An_option_given_twice_is_refused_rather_than_taking_the_last_one()
    {
        Assert.False(Parse("--to", directory.FullName, "--to", directory.FullName, "--before", "2026-07"));
        Assert.False(Parse("--before", "2026-07", "--before", "2026-06", "--to", directory.FullName));
    }

    /// <summary>One parse with a retention configured, so a refusal is about the arguments only.</summary>
    private static bool Parse(params string[] args) =>
        AuditArchiveCommand.TryParse(args, TimeSpan.FromDays(90), Now, out _, out _, out _);

    [Fact]
    public void A_month_is_named_and_parsed_the_same_way_everywhere()
    {
        Assert.Equal("2026-09", AuditArchive.MonthName(new DateTimeOffset(2026, 9, 19, 23, 59, 0, TimeSpan.Zero)));
        Assert.Equal(new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero), AuditArchive.StartOfMonth(Now));
        Assert.True(AuditArchive.TryParseMonth("2026-09", out var parsed));
        Assert.Equal(AuditArchive.StartOfMonth(Now), parsed);
    }
}
