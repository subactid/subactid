using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;
using SubactId.Server.Commands;
using SubactId.Server.Configuration;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Http;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Commands;

public sealed class DoctorCommandTests : IDisposable
{
    private const string MetadataUrl = "https://idp.example.test/realms/main/.well-known/openid-configuration";
    private const string JwksUrl = "https://idp.example.test/realms/main/protocol/openid-connect/certs";
    private const string PathSentinel = "SENTINEL-DB-PATH";
    private const string UrlPasswordSentinel = "SENTINEL-URL-PASSWORD";

    private readonly string directory = Directory.CreateTempSubdirectory("subactid-doctor-").FullName;

    public void Dispose() => Directory.Delete(directory, recursive: true);

    [Fact]
    public async Task An_invalid_configuration_is_the_whole_report_and_lists_every_error()
    {
        var checks = await DoctorCommand.CollectAsync(SubactIdOptionsLoader.Load(new ConfigurationBuilder().Build()), isDevelopment: false);

        var only = Assert.Single(checks);
        Assert.Equal("configuration", only.Name);
        Assert.Equal(DoctorStatus.Fail, only.Status);
        Assert.NotEmpty(only.Notes!);
        Assert.Contains(only.Notes!, n => n.Contains("SubactId__UpstreamIdp__Issuer", StringComparison.Ordinal));
    }

    [Fact]
    public async Task With_nothing_reachable_every_dependency_reports_a_failure_rather_than_throwing()
    {
        var checks = await DoctorCommand.CollectAsync(
            Configuration(),
            isDevelopment: false,
            clientFactory: new FakeIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        Assert.Equal(DoctorStatus.Fail, Find(checks, "upstream").Status);
        Assert.Equal(DoctorStatus.Fail, Find(checks, "database").Status);

        // A key that is configured and present still loads when every other check fails.
        Assert.Equal(DoctorStatus.Ok, Find(checks, "signing key").Status);
        Assert.Equal(DoctorStatus.Ok, Find(checks, "admin API").Status);
    }

    [Fact]
    public async Task The_embedded_provider_reports_a_ledger_that_is_one_table_and_sheds_nothing()
    {
        var checks = await DoctorCommand.CollectAsync(
            Configuration(),
            isDevelopment: false,
            clientFactory: new FakeIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        var partitions = Find(checks, "audit partitions");
        Assert.Equal(DoctorStatus.Ok, partitions.Status);
        Assert.Contains("one table", partitions.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_mismatched_upstream_issuer_names_the_frontend_url_as_the_likely_cause()
    {
        var idp = new FakeIdp
        {
            [MetadataUrl] = $"{{\"issuer\":\"https://sso.example.com/realms/main\",\"jwks_uri\":\"{JwksUrl}\"}}",
        };

        var checks = await DoctorCommand.CollectAsync(Configuration(), isDevelopment: false, clientFactory: idp.CreateClient, clock: new FakeTimeProvider(Now));

        var upstream = Find(checks, "upstream");
        Assert.Equal(DoctorStatus.Fail, upstream.Status);
        Assert.Contains(upstream.Notes!, n => n.Contains("frontend URL", StringComparison.Ordinal));
        Assert.Contains(upstream.Notes!, n => n.Contains(Issuer, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_downgraded_jwks_uri_names_the_downgrade_as_the_likely_cause()
    {
        var idp = new FakeIdp
        {
            [MetadataUrl] = $"{{\"issuer\":\"{Issuer}\",\"jwks_uri\":\"http://idp.example.test/realms/main/certs\"}}",
        };

        var checks = await DoctorCommand.CollectAsync(Configuration(), isDevelopment: false, clientFactory: idp.CreateClient, clock: new FakeTimeProvider(Now));

        Assert.Contains(Find(checks, "upstream").Notes!, n => n.Contains("http jwks_uri", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_reachable_upstream_reports_its_issuer_and_key_count()
    {
        var checks = await DoctorCommand.CollectAsync(Configuration(), isDevelopment: false, clientFactory: WorkingIdp().CreateClient, clock: new FakeTimeProvider(Now));

        var upstream = Find(checks, "upstream");
        Assert.Equal(DoctorStatus.Ok, upstream.Status);
        Assert.Contains(Issuer, upstream.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_valid_subject_token_is_accepted_and_the_principal_is_named()
    {
        var checks = await CheckTokenAsync(Mint("RS256", "rsa1", Claims()));

        var check = Find(checks, "subject token");
        Assert.Equal(DoctorStatus.Ok, check.Status);
        Assert.Contains("f47ac10b-58cc-4372-a567-0e02b2c3d479", check.Detail, StringComparison.Ordinal);
        Assert.Contains(Issuer, check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_token_without_the_audience_is_diagnosed_as_the_missing_keycloak_mapper()
    {
        var checks = await CheckTokenAsync(Mint("RS256", "rsa1", Claims(("aud", "account"))));

        var check = Find(checks, "subject token");
        Assert.Equal(DoctorStatus.Fail, check.Status);
        Assert.Contains(nameof(UpstreamRejection.AudienceMismatch), check.Detail, StringComparison.Ordinal);
        Assert.Contains("audience mapper", Assert.Single(check.Notes!), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_subject_token_is_held_to_the_configured_token_types_as_the_server_holds_it()
    {
        // Minted with typ "JWT", which is what Keycloak puts on an access token by default.
        var checks = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:UpstreamIdp:SubjectTokenTypes", "at+jwt")),
            isDevelopment: false,
            subjectToken: Mint("RS256", "rsa1", Claims()),
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        var check = Find(checks, "subject token");
        Assert.Equal(DoctorStatus.Fail, check.Status);
        Assert.Contains(nameof(UpstreamRejection.UnacceptedType), check.Detail, StringComparison.Ordinal);
        var advice = Assert.Single(check.Notes!);
        Assert.Contains("SubactId:UpstreamIdp:SubjectTokenTypes", advice, StringComparison.Ordinal);
        Assert.Contains("at+jwt", advice, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_subject_token_of_a_configured_type_is_accepted()
    {
        var checks = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:UpstreamIdp:SubjectTokenTypes", "at+jwt")),
            isDevelopment: false,
            subjectToken: Mint("RS256", "rsa1", Claims(), headerJson: "{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"rsa1\"}"),
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        Assert.Equal(DoctorStatus.Ok, Find(checks, "subject token").Status);
    }

    [Fact]
    public async Task A_token_from_another_issuer_is_diagnosed_as_the_wrong_realm()
    {
        var checks = await CheckTokenAsync(Mint("RS256", "rsa1", Claims(("iss", "https://other.example.test/realms/main"))));

        var check = Find(checks, "subject token");
        Assert.Equal(DoctorStatus.Fail, check.Status);
        Assert.Contains(nameof(UpstreamRejection.UntrustedIssuer), check.Detail, StringComparison.Ordinal);
        Assert.Contains("different realm", Assert.Single(check.Notes!), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_subject_token_is_read_from_standard_input_when_asked_for()
    {
        var token = Mint("RS256", "rsa1", Claims());
        var checks = await DoctorCommand.CollectAsync(
            Configuration(),
            isDevelopment: false,
            subjectToken: DoctorCommand.StdinToken,
            clientFactory: WorkingIdp().CreateClient,
            stdin: new StringReader(token + "\n"),
            clock: new FakeTimeProvider(Now));

        Assert.Equal(DoctorStatus.Ok, Find(checks, "subject token").Status);
    }

    [Fact]
    public async Task The_report_never_prints_the_token_or_a_configured_secret()
    {
        var token = Mint("RS256", "rsa1", Claims());
        var checks = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:Admin:ApiKey", "SENTINEL-ADMIN-KEY-that-is-long-enough-to-pass")),
            isDevelopment: false,
            subjectToken: token,
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        var written = new StringWriter();
        DoctorCommand.Write(written, checks);
        var printed = written.ToString();

        Assert.DoesNotContain(token, printed, StringComparison.Ordinal);
        Assert.DoesNotContain("SENTINEL-ADMIN-KEY", printed, StringComparison.Ordinal);

        // The database failure line names only the exception, never what it was given to connect
        // with, which for Postgres holds a password.
        Assert.DoesNotContain(PathSentinel, printed, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_url_that_carries_credentials_is_a_configuration_error_and_is_never_printed()
    {
        var output = new StringWriter();

        var exit = await DoctorCommand.RunAsync(
            Configuration(("SubactId:UpstreamIdp:SponsorCheck:UsersUrl", $"https://reader:{UrlPasswordSentinel}@idp.example.test/admin/realms/main/users")),
            isDevelopment: false,
            [],
            output,
            new StringWriter());

        Assert.Equal(DoctorCommand.FailedExitCode, exit);
        var printed = output.ToString();
        Assert.Contains("SubactId:UpstreamIdp:SponsorCheck:UsersUrl (environment variable SubactId__UpstreamIdp__SponsorCheck__UsersUrl) must not carry credentials.", printed, StringComparison.Ordinal);
        Assert.DoesNotContain(UrlPasswordSentinel, printed, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_redirect_from_the_identity_provider_is_reported_and_not_followed_as_the_server_does_not_follow_it()
    {
        await using var target = new LoopbackServer("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        await using var idp = new LoopbackServer($"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target.Port}/realms/main/.well-known/openid-configuration\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        // No client factory: the report fetches with the client it uses outside a test.
        var checks = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:UpstreamIdp:Issuer", $"http://127.0.0.1:{idp.Port}/realms/main")),
            isDevelopment: false,
            clock: new FakeTimeProvider(Now));

        var upstream = Find(checks, "upstream");
        Assert.Equal(DoctorStatus.Fail, upstream.Status);
        Assert.Contains("redirect (302)", upstream.Detail, StringComparison.Ordinal);
        Assert.Contains(upstream.Notes!, n => n.Contains("SubactId__UpstreamIdp__Issuer", StringComparison.Ordinal));
        Assert.Equal(1, idp.Connections);
        Assert.Equal(0, target.Connections);
    }

    [Fact]
    public async Task The_admin_api_is_stated_either_way()
    {
        var disabled = await DoctorCommand.CollectAsync(Configuration(), isDevelopment: false, clientFactory: WorkingIdp().CreateClient, clock: new FakeTimeProvider(Now));
        Assert.Contains("Disabled", Find(disabled, "admin API").Detail, StringComparison.Ordinal);

        var enabled = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:Admin:ApiKey", "SENTINEL-ADMIN-KEY-that-is-long-enough-to-pass")),
            isDevelopment: false,
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));
        Assert.Contains("Enabled", Find(enabled, "admin API").Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Settings_that_loosen_outbound_fetches_are_warnings_and_their_absence_is_a_pass()
    {
        var defaults = await DoctorCommand.CollectAsync(Configuration(), isDevelopment: false, clientFactory: WorkingIdp().CreateClient, clock: new FakeTimeProvider(Now));
        var loose = Find(defaults, "outbound");
        Assert.Equal(DoctorStatus.Warn, loose.Status);
        Assert.Contains(loose.Notes!, n => n.Contains("BlockPrivateNetworks is off", StringComparison.Ordinal));
        Assert.DoesNotContain(loose.Notes!, n => n.Contains("AllowInsecureHttp", StringComparison.Ordinal));

        var insecure = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:AllowInsecureHttp", "true")),
            isDevelopment: false,
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));
        Assert.Equal(2, Find(insecure, "outbound").Notes!.Count);

        var strict = await DoctorCommand.CollectAsync(
            Configuration(("SubactId:AgentKeys:BlockPrivateNetworks", "true")),
            isDevelopment: false,
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));
        Assert.Equal(DoctorStatus.Ok, Find(strict, "outbound").Status);
    }

    [Fact]
    public async Task An_ephemeral_development_key_is_a_warning_not_a_pass()
    {
        var settings = Settings();
        settings.Remove("SubactId:Signing:Keys:0:Path");

        var checks = await DoctorCommand.CollectAsync(
            SubactIdOptionsLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(settings).Build()),
            isDevelopment: true,
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        var key = Find(checks, "signing key");
        Assert.Equal(DoctorStatus.Warn, key.Status);
        Assert.Contains(key.Notes!, n => n.Contains("SubactId__Signing__Keys__0__Path", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("--what")]
    [InlineData("--subject-token=SENTINEL-TOKEN")]
    [InlineData("--SubactId:Admin:ApiKey=SENTINEL-ADMIN-KEY-that-is-long-enough-to-pass")]
    public async Task An_unusable_argument_is_named_by_position_never_repeated_and_no_checks_are_run(string argument)
    {
        var error = new StringWriter();
        var output = new StringWriter();

        var exit = await DoctorCommand.RunAsync(Configuration(), isDevelopment: false, ["--subject-token", "-", argument], output, error, stdin: new StringReader(string.Empty));

        Assert.Equal(DoctorCommand.UsageExitCode, exit);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Contains("Argument 3 ", error.ToString(), StringComparison.Ordinal);

        // It may be a token given the wrong way, or a setting that holds a secret.
        Assert.DoesNotContain(argument, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_exit_code_is_zero_only_when_nothing_failed()
    {
        var output = new StringWriter();

        var failed = await DoctorCommand.RunAsync(
            SubactIdOptionsLoader.Load(new ConfigurationBuilder().Build()), isDevelopment: false, [], output, new StringWriter());

        Assert.Equal(DoctorCommand.FailedExitCode, failed);
        Assert.Contains("1 failed", output.ToString(), StringComparison.Ordinal);
    }

    private async Task<IReadOnlyList<DoctorCheck>> CheckTokenAsync(string token) =>
        await DoctorCommand.CollectAsync(
            Configuration(),
            isDevelopment: false,
            subjectToken: token,
            clientFactory: WorkingIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

    private static FakeIdp WorkingIdp() => new()
    {
        [MetadataUrl] = $"{{\"issuer\":\"{Issuer}\",\"jwks_uri\":\"{JwksUrl}\"}}",
        [JwksUrl] = Jwks(RsaJwk(Rsa1, "rsa1"), EcJwk(Ec1, "ec1")),
    };

    private static DoctorCheck Find(IReadOnlyList<DoctorCheck> checks, string name) =>
        Assert.Single(checks, c => c.Name == name);

    [Fact]
    public async Task Signals_receiver_warns_that_a_non_sub_sponsor_key_must_be_named_by_the_transmitter()
    {
        var checks = await DoctorCommand.CollectAsync(
            Configuration(
                ("SubactId:UpstreamIdp:SponsorKeyClaim", "email"),
                ("SubactId:Ssf:Issuer", "https://transmitter.example.test"),
                ("SubactId:Ssf:Audience", "https://subactid.example.test/ssf"),
                ("SubactId:Ssf:BearerToken", "0123456789abcdef0123456789abcdef")),
            isDevelopment: false,
            clientFactory: new FakeIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        var signals = Find(checks, "signals receiver");
        Assert.Contains(signals.Notes!, n => n.Contains("not 'sub'", StringComparison.Ordinal));
        Assert.Contains(signals.Notes!, n => n.Contains("'email' claim", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Signals_receiver_does_not_warn_when_the_sponsor_key_claim_is_sub()
    {
        var checks = await DoctorCommand.CollectAsync(
            Configuration(
                ("SubactId:Ssf:Issuer", "https://transmitter.example.test"),
                ("SubactId:Ssf:Audience", "https://subactid.example.test/ssf"),
                ("SubactId:Ssf:BearerToken", "0123456789abcdef0123456789abcdef")),
            isDevelopment: false,
            clientFactory: new FakeIdp().CreateClient,
            clock: new FakeTimeProvider(Now));

        var signals = Find(checks, "signals receiver");
        Assert.DoesNotContain(signals.Notes!, n => n.Contains("not 'sub'", StringComparison.Ordinal));
    }

    private SubactIdOptionsResult Configuration(params (string Key, string Value)[] extra)
    {
        var settings = Settings();
        foreach (var (key, value) in extra)
        {
            settings[key] = value;
        }

        return SubactIdOptionsLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
    }

    private Dictionary<string, string?> Settings()
    {
        // A signing key that is on disk, and a database path under a missing directory, so the
        // database check fails as an unreachable one would.
        var keyPath = Path.Combine(directory, "active.pem");
        if (!File.Exists(keyPath))
        {
            using var key = SubactId.Tokens.Signing.SigningKeyFile.Create(keyPath);
        }

        return new Dictionary<string, string?>
        {
            ["SubactId:Issuer"] = "https://subactid.example.test",
            ["SubactId:UpstreamIdp:Issuer"] = Issuer,
            ["SubactId:UpstreamIdp:Audience"] = Audience,
            ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
            ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = $"{Issuer}/protocol/openid-connect/token",
            ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
            ["SubactId:Database:Provider"] = "Sqlite",
            ["SubactId:Database:Path"] = Path.Combine(directory, PathSentinel, "subactid.db"),
            ["SubactId:Signing:Keys:0:Path"] = keyPath,
        };
    }
}
