using SubactId.Server.Commands;
using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Commands;

public sealed class KeysCommandTests : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("subactid-keys-").FullName;

    public void Dispose() => Directory.Delete(directory, recursive: true);

    [Fact]
    public void Generate_writes_a_key_the_server_loads_back_without_changes()
    {
        var path = Path.Combine(directory, "active.pem");
        var output = new StringWriter();

        var exit = KeysCommand.RunGenerate(["--out", path], output);

        Assert.Equal(0, exit);
        using var loaded = SigningKeySetLoader.Load([new SigningKeySource(null, null, path)], activeKid: null);
        Assert.Contains(loaded.Active.Kid, output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Generate_prints_the_thumbprint_kid_and_the_setting_that_configures_it()
    {
        var path = Path.Combine(directory, "active.pem");
        var output = new StringWriter();

        Assert.Equal(0, KeysCommand.RunGenerate(["--out", path], output));

        var printed = output.ToString();
        Assert.Contains("(RFC 7638 thumbprint)", printed, StringComparison.Ordinal);
        Assert.Contains($"SubactId__Signing__Keys__0__Path={path}", printed, StringComparison.Ordinal);
        Assert.DoesNotContain("SubactId__Signing__Keys__0__Kid", printed, StringComparison.Ordinal);
    }

    [Fact]
    public void Generate_with_an_explicit_kid_uses_it_and_prints_the_setting_that_selects_it()
    {
        var path = Path.Combine(directory, "active.pem");
        var output = new StringWriter();

        Assert.Equal(0, KeysCommand.RunGenerate(["--out", path, "--kid", "payroll-2026"], output));

        var printed = output.ToString();
        Assert.Contains("Key id: payroll-2026", printed, StringComparison.Ordinal);
        Assert.Contains("SubactId__Signing__Keys__0__Kid=payroll-2026", printed, StringComparison.Ordinal);

        using var loaded = SigningKeySetLoader.Load([new SigningKeySource("payroll-2026", null, path)], activeKid: null);
        Assert.Equal("payroll-2026", loaded.Active.Kid);
    }

    [Fact]
    public void Generate_never_prints_private_key_material()
    {
        var path = Path.Combine(directory, "active.pem");
        var output = new StringWriter();

        Assert.Equal(0, KeysCommand.RunGenerate(["--out", path], output));

        var printed = output.ToString();
        Assert.DoesNotContain("PRIVATE KEY", printed, StringComparison.Ordinal);

        // No base64 line of the file appears in the output.
        var body = File.ReadAllLines(path).Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal));
        foreach (var line in body)
        {
            Assert.DoesNotContain(line, printed, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Generate_writes_the_key_readable_by_its_owner_alone()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(directory, "active.pem");

        Assert.Equal(0, KeysCommand.RunGenerate(["--out", path], new StringWriter()));

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [Fact]
    public void Generate_refuses_to_overwrite_an_existing_file_and_leaves_it_alone()
    {
        var path = Path.Combine(directory, "active.pem");
        File.WriteAllText(path, "not a key");
        var error = new StringWriter();

        var exit = KeysCommand.RunGenerate(["--out", path], new StringWriter(), error);

        Assert.Equal(1, exit);
        Assert.Equal("not a key", File.ReadAllText(path));
        Assert.Contains("refusing to overwrite", error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--kid", "only")]
    [InlineData("--out")]
    [InlineData("--out", "--kid")]
    [InlineData("--out", "a.pem", "--out", "b.pem")]
    [InlineData("--kid", "one", "--kid", "two", "--out", "a.pem")]
    [InlineData("generate", "--out", "a.pem")]
    public void Generate_reports_a_bad_argument_list(params string[] args)
    {
        var error = new StringWriter();

        var exit = KeysCommand.RunGenerate(args, new StringWriter(), error);

        Assert.Equal(KeysCommand.UsageExitCode, exit);
        Assert.NotEqual(string.Empty, error.ToString());
    }

    [Fact]
    public void Generate_with_no_arguments_asks_for_the_one_it_needs()
    {
        var error = new StringWriter();

        var exit = KeysCommand.RunGenerate([], new StringWriter(), error);

        Assert.Equal(KeysCommand.UsageExitCode, exit);
        Assert.Contains("--out is required", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Generate_writes_no_key_when_an_argument_is_rejected()
    {
        var path = Path.Combine(directory, "active.pem");

        var exit = KeysCommand.RunGenerate(["--out", path, "--unknown", "x"], new StringWriter(), new StringWriter());

        Assert.Equal(KeysCommand.UsageExitCode, exit);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Rotate_of_a_single_key_adds_the_next_number_and_retires_the_one_in_use()
    {
        var output = new StringWriter();

        KeysCommand.WriteRollout(
            output,
            [new PublishedKey(0, "old-kid")],
            activeKid: "old-kid",
            newKid: "new-kid",
            newPath: "/run/secrets/next.pem",
            explicitKid: null,
            new KeyRetirement(TimeSpan.FromMinutes(15), "the longest max_token_ttl of any registered agent."),
            new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));

        var printed = output.ToString();
        Assert.Contains("SubactId__Signing__Keys__1__Path=/run/secrets/next.pem", printed, StringComparison.Ordinal);

        // Step 1 keeps the old signer. With a second key configured the active kid is required, so it
        // must go out in the same deploy or the server will not start.
        Assert.Contains("SubactId__Signing__ActiveKid=old-kid", printed, StringComparison.Ordinal);
        Assert.Contains("SubactId__Signing__ActiveKid=new-kid", printed, StringComparison.Ordinal);
        Assert.Contains("remove SubactId__Signing__Keys__0__* (the entry for 'old-kid')", printed, StringComparison.Ordinal);
        Assert.Contains("00:15:00 after step 2", printed, StringComparison.Ordinal);
        Assert.Contains("2026-09-12T10:15:00Z", printed, StringComparison.Ordinal);
    }

    [Fact]
    public void Rotate_of_several_keys_takes_a_number_past_the_highest_and_retires_only_the_signer()
    {
        var output = new StringWriter();

        KeysCommand.WriteRollout(
            output,
            [new PublishedKey(0, "oldest"), new PublishedKey(2, "signing-now"), new PublishedKey(10, "staged")],
            activeKid: "signing-now",
            newKid: "new-kid",
            newPath: "/run/secrets/next.pem",
            explicitKid: "next",
            new KeyRetirement(TimeSpan.FromHours(2), "the longest max_token_ttl of any registered agent."),
            new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));

        var printed = output.ToString();

        // 11, not 1 or 3: an operator may reuse a gap, and after a rotation the count is not the next
        // free number.
        Assert.Contains("SubactId__Signing__Keys__11__Path=/run/secrets/next.pem", printed, StringComparison.Ordinal);
        Assert.Contains("SubactId__Signing__Keys__11__Kid=next", printed, StringComparison.Ordinal);
        Assert.Contains("Currently configured: 3 key(s), signing with 'signing-now'.", printed, StringComparison.Ordinal);
        Assert.Contains("remove SubactId__Signing__Keys__2__* (the entry for 'signing-now')", printed, StringComparison.Ordinal);
        Assert.DoesNotContain("Keys__0__*", printed, StringComparison.Ordinal);
        Assert.DoesNotContain("Keys__10__*", printed, StringComparison.Ordinal);
        Assert.Contains("02:00:00 after step 2", printed, StringComparison.Ordinal);
        Assert.Contains("2026-09-12T12:00:00Z", printed, StringComparison.Ordinal);
    }

    [Fact]
    public void Rotate_of_a_set_whose_numbers_start_past_zero_still_names_the_retiring_entry()
    {
        var output = new StringWriter();

        KeysCommand.WriteRollout(
            output,
            [new PublishedKey(7, "only-kid")],
            activeKid: "only-kid",
            newKid: "new-kid",
            newPath: "next.pem",
            explicitKid: null,
            new KeyRetirement(TimeSpan.FromMinutes(5), "SubactId:Tokens:DefaultTokenTtl, because no agent is registered."),
            DateTimeOffset.UnixEpoch);

        var printed = output.ToString();
        Assert.Contains("SubactId__Signing__Keys__8__Path=next.pem", printed, StringComparison.Ordinal);
        Assert.Contains("remove SubactId__Signing__Keys__7__* (the entry for 'only-kid')", printed, StringComparison.Ordinal);
    }

    [Fact]
    public void Rotate_says_where_the_wait_came_from_when_the_registry_could_not_be_read()
    {
        var output = new StringWriter();

        KeysCommand.WriteRollout(
            output,
            [new PublishedKey(0, "old-kid")],
            activeKid: "old-kid",
            newKid: "new-kid",
            newPath: "next.pem",
            explicitKid: null,
            new KeyRetirement(TimeSpan.FromHours(1), "SubactId:Agents:MaxTokenTtl, the longest any agent could hold, because the registry could not be read; check it against your registered agents."),
            DateTimeOffset.UnixEpoch);

        Assert.Contains("because the registry could not be read", output.ToString(), StringComparison.Ordinal);
    }
}
