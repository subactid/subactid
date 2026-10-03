using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SubactId.Core.Agents;
using SubactId.Server.Commands;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Commands;

public sealed class AgentCommandTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    // Real coordinates: the registration contract checks that the key set is usable, so made-up
    // base64 would be refused first.
    private static readonly (string X, string Y) Coordinates = NewCoordinates();

    private readonly string directory = Directory.CreateTempSubdirectory("subactid-agent-").FullName;

    public void Dispose() => Directory.Delete(directory, recursive: true);

    [Fact]
    public void Init_writes_a_registration_a_key_and_a_key_set()
    {
        var output = new StringWriter();

        var exit = AgentCommand.RunInit(["jira-triage", "--out", directory], output);

        Assert.Equal(0, exit);
        Assert.True(File.Exists(Path.Combine(directory, "jira-triage.yaml")));
        Assert.True(File.Exists(Path.Combine(directory, "jira-triage.jwks.json")));
        Assert.True(File.Exists(Path.Combine(directory, "jira-triage.key.pem")));
        Assert.Contains("RFC 7638 thumbprint", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Init_writes_the_private_key_readable_by_its_owner_alone_and_never_prints_it()
    {
        var output = new StringWriter();
        Assert.Equal(0, AgentCommand.RunInit(["jira-triage", "--out", directory], output));

        var keyPath = Path.Combine(directory, "jira-triage.key.pem");
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyPath));
        }

        var printed = output.ToString();
        Assert.DoesNotContain("PRIVATE KEY", printed, StringComparison.Ordinal);
        foreach (var line in File.ReadAllLines(keyPath).Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal)))
        {
            Assert.DoesNotContain(line, printed, StringComparison.Ordinal);
        }

        // The public half is committed, so it is not owner-only; the private half is the secret.
        Assert.DoesNotContain(File.ReadAllText(keyPath), File.ReadAllText(Path.Combine(directory, "jira-triage.yaml")), StringComparison.Ordinal);
    }

    [Fact]
    public void What_init_writes_is_read_back_as_a_valid_registration_once_the_two_lists_are_filled()
    {
        Assert.Equal(0, AgentCommand.RunInit(["jira-triage", "--out", directory], new StringWriter()));

        var path = Path.Combine(directory, "jira-triage.yaml");
        var yaml = File.ReadAllText(path)
            .Replace("allowed_scopes: []", "allowed_scopes:\n  - jira:read", StringComparison.Ordinal)
            .Replace("allowed_audiences: []", "allowed_audiences:\n  - https://jira.internal", StringComparison.Ordinal);

        Assert.Empty(AgentRegistrationFile.TryRead(path, yaml, out var file));
        Assert.Empty(file!.Request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));

        Assert.NotNull(agent);
        Assert.Equal("jira-triage", agent.AgentId);
        Assert.True(agent.SponsorRequired);
        Assert.Equal(1, agent.MaxDelegationDepth);
        Assert.Equal(["jira:read"], agent.AllowedScopes);
        Assert.Null(agent.JwksUri);
        Assert.Single(agent.Jwks!.Keys);
    }

    [Fact]
    public void The_defaults_init_writes_are_the_tight_ones()
    {
        Assert.Equal(0, AgentCommand.RunInit(["jira-triage", "--out", directory], new StringWriter()));

        var yaml = File.ReadAllText(Path.Combine(directory, "jira-triage.yaml"));

        // An agent that can be granted nothing until somebody says otherwise.
        Assert.Contains("sponsor_required: true", yaml, StringComparison.Ordinal);
        Assert.Contains("allowed_scopes: []", yaml, StringComparison.Ordinal);
        Assert.Contains("allowed_audiences: []", yaml, StringComparison.Ordinal);
        Assert.Contains("max_delegation_depth: 1", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Init_refuses_to_overwrite_anything_it_would_have_written()
    {
        Assert.Equal(0, AgentCommand.RunInit(["jira-triage", "--out", directory], new StringWriter()));
        var before = File.ReadAllText(Path.Combine(directory, "jira-triage.key.pem"));
        var error = new StringWriter();

        var exit = AgentCommand.RunInit(["jira-triage", "--out", directory], new StringWriter(), error);

        Assert.Equal(AgentCommand.FailedExitCode, exit);
        Assert.Contains("refusing to overwrite", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllText(Path.Combine(directory, "jira-triage.key.pem")));
    }

    [Theory]
    [InlineData("Jira-Triage")]
    [InlineData("-leading")]
    [InlineData("with space")]
    public void Init_refuses_an_agent_id_the_admin_api_would_refuse_before_writing_a_key(string agentId)
    {
        var error = new StringWriter();

        var exit = AgentCommand.RunInit([agentId, "--out", directory], new StringWriter(), error);

        Assert.Equal(AgentCommand.UsageExitCode, exit);
        Assert.Contains("agent_id", error.ToString(), StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(directory));
    }

    [Theory]
    [InlineData("--out")]
    [InlineData("jira-triage")]
    [InlineData("jira-triage", "--out")]
    [InlineData("jira-triage", "--wat", "x")]
    public void Init_reports_a_bad_argument_list(params string[] args)
    {
        var error = new StringWriter();

        Assert.Equal(AgentCommand.UsageExitCode, AgentCommand.RunInit(args, new StringWriter(), error));
        Assert.NotEqual(string.Empty, error.ToString());
    }

    [Fact]
    public async Task Apply_creates_an_agent_that_is_not_there_yet()
    {
        var admin = new FakeAdminApi();
        var results = await ApplyAsync(admin, Registration());

        Assert.Equal(AgentApplyOutcome.Created, Assert.Single(results).Outcome);
        Assert.Equal(["GET /admin/agents/jira-triage", "POST /admin/agents/"], admin.Calls);
    }

    [Fact]
    public async Task A_lifetime_the_file_does_not_state_never_drives_a_change()
    {
        // The server applied its own default lifetime at creation, and this command cannot know it.
        // A file that states no lifetime asserts none, so nothing is compared or sent.
        var admin = new FakeAdminApi();
        await ApplyAsync(admin, Registration());
        await ApplyAsync(admin, Registration().Replace("max_token_ttl: PT5M", "max_token_ttl: PT2M", StringComparison.Ordinal));
        admin.Calls.Clear();

        var withoutLifetimes = Registration()
            .Replace("max_task_ttl: PT30M\n", string.Empty, StringComparison.Ordinal)
            .Replace("max_token_ttl: PT5M\n", string.Empty, StringComparison.Ordinal);
        var results = await ApplyAsync(admin, withoutLifetimes);

        Assert.Equal(AgentApplyOutcome.Unchanged, Assert.Single(results).Outcome);
        Assert.Equal(["GET /admin/agents/jira-triage"], admin.Calls);
    }

    [Fact]
    public async Task Apply_is_idempotent_and_makes_no_admin_call_when_nothing_differs()
    {
        var admin = new FakeAdminApi();
        await ApplyAsync(admin, Registration());
        admin.Calls.Clear();

        var results = await ApplyAsync(admin, Registration());

        Assert.Equal(AgentApplyOutcome.Unchanged, Assert.Single(results).Outcome);

        // Only the read happens; nothing is written.
        Assert.Equal(["GET /admin/agents/jira-triage"], admin.Calls);
    }

    [Fact]
    public async Task Apply_patches_only_what_differs_and_says_what_changed()
    {
        var admin = new FakeAdminApi();
        await ApplyAsync(admin, Registration());
        admin.Calls.Clear();

        var results = await ApplyAsync(admin, Registration(tokenTtl: "PT2M"));

        var result = Assert.Single(results);
        Assert.Equal(AgentApplyOutcome.Updated, result.Outcome);
        Assert.Equal("max_token_ttl: PT5M -> PT2M", Assert.Single(result.Changes));
        Assert.Equal(["GET /admin/agents/jira-triage", "PATCH /admin/agents/jira-triage"], admin.Calls);

        // Only the field that differed, so the audit record names that field and no other.
        Assert.Contains("max_token_ttl", admin.LastBody, StringComparison.Ordinal);
        Assert.DoesNotContain("allowed_scopes", admin.LastBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_file_the_admin_api_would_refuse_is_refused_before_anything_is_sent()
    {
        var admin = new FakeAdminApi();

        // max_token_ttl above max_task_ttl: the domain rule, applied locally.
        var results = await ApplyAsync(admin, Registration(tokenTtl: "PT40M"));

        var result = Assert.Single(results);
        Assert.Equal(AgentApplyOutcome.Failed, result.Outcome);
        Assert.Contains(result.Changes, c => c.StartsWith("max_token_ttl:", StringComparison.Ordinal));
        Assert.Empty(admin.Calls);
    }

    [Fact]
    public async Task A_dry_run_sends_nothing_and_needs_no_admin_key()
    {
        var admin = new FakeAdminApi();
        var path = Write(Registration());
        var output = new StringWriter();

        var exit = await AgentCommand.RunApplyAsync(
            [path, "--dry-run"], AgentRegistrationLimits.Default, Now,
            adminKey: null, clientFactory: admin.CreateClient, output: output, error: new StringWriter());

        Assert.Equal(0, exit);
        Assert.Empty(admin.Calls);
        Assert.Contains("would create", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_an_admin_key_it_says_where_to_put_one_and_never_offers_a_flag()
    {
        var error = new StringWriter();

        var exit = await AgentCommand.RunApplyAsync(
            [Write(Registration()), "--server", "https://subactid.example.com"], AgentRegistrationLimits.Default, Now,
            adminKey: null, clientFactory: new FakeAdminApi().CreateClient, stdin: new StringReader(string.Empty),
            output: new StringWriter(), error: error);

        Assert.Equal(AgentCommand.UsageExitCode, exit);
        var message = error.ToString();
        Assert.Contains(AgentCommand.AdminKeyVariable, message, StringComparison.Ordinal);
        Assert.Contains("process list", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://subactid.internal:8080")]
    [InlineData("http://10.0.0.5:5100")]
    public async Task Plain_http_to_a_host_that_is_not_loopback_is_refused_before_the_key_is_sent(string server)
    {
        var admin = new FakeAdminApi();
        var error = new StringWriter();

        var exit = await AgentCommand.RunApplyAsync(
            [Write(Registration()), "--server", server], AgentRegistrationLimits.Default, Now,
            adminKey: "an-admin-key-that-must-not-cross-a-network", clientFactory: admin.CreateClient,
            output: new StringWriter(), error: error);

        Assert.Equal(AgentCommand.UsageExitCode, exit);
        Assert.Empty(admin.Calls);
        Assert.Contains("https", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("an-admin-key", error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://127.0.0.1:5100")]
    [InlineData("http://localhost:5100")]
    [InlineData("http://[::1]:5100")]
    [InlineData("https://subactid.example.com")]
    public async Task Https_or_plain_http_on_loopback_is_accepted(string server)
    {
        var admin = new FakeAdminApi();

        var exit = await AgentCommand.RunApplyAsync(
            [Write(Registration()), "--server", server], AgentRegistrationLimits.Default, Now,
            adminKey: "an-admin-key", clientFactory: admin.CreateClient,
            output: new StringWriter(), error: new StringWriter());

        Assert.Equal(0, exit);
        Assert.NotEmpty(admin.Calls);
    }

    [Fact]
    public async Task A_refused_admin_key_is_reported_as_that_rather_than_as_a_status_code()
    {
        var admin = new FakeAdminApi { Status = HttpStatusCode.Unauthorized };

        var results = await ApplyAsync(admin, Registration());

        Assert.Contains(Assert.Single(results).Changes, c => c.Contains("admin key was refused", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_unreachable_control_plane_is_reported_rather_than_thrown()
    {
        var admin = new FakeAdminApi { Throw = true };

        var results = await ApplyAsync(admin, Registration());

        Assert.Equal(AgentApplyOutcome.Failed, Assert.Single(results).Outcome);
    }

    [Fact]
    public void The_diff_is_by_field_and_compares_a_key_set_by_its_canonical_form()
    {
        var jwks = Keys("a");
        var current = Agent(jwks: jwks);
        var reordered = Keys("a");

        Assert.Empty(AgentCommand.Diff(Agent(jwks: reordered), current));
        Assert.Equal("max_delegation_depth: 2 -> 3", Assert.Single(AgentCommand.Diff(Agent(depth: 3, jwks: jwks), current)));
        Assert.Contains("jwks: a -> b", AgentCommand.Diff(Agent(jwks: Keys("b")), current));
    }

    private static (string X, string Y) NewCoordinates()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = key.ExportParameters(false).Q;
        return (Base64Url.EncodeToString(q.X!), Base64Url.EncodeToString(q.Y!));
    }

    private static AgentJwks Keys(string kid) =>
        new([new AgentJwk { Kid = kid, Kty = "EC", Crv = "P-256", X = Coordinates.X, Y = Coordinates.Y, Alg = "ES256", Use = "sig" }]);

    private static Agent Agent(int depth = 2, AgentJwks? jwks = null) => new(
        "jira-triage", "Jira triage agent", true, ["jira:read"], ["https://jira.internal"],
        TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5), depth, [], null, jwks, true, Now, Now);

    private static string Registration(string tokenTtl = "PT5M") => $$"""
        agent_id: jira-triage
        display_name: Jira triage agent
        sponsor_required: true
        allowed_scopes:
          - jira:read
        allowed_audiences:
          - https://jira.internal
        max_task_ttl: PT30M
        max_token_ttl: {{tokenTtl}}
        max_delegation_depth: 1
        high_risk_audiences: []
        jwks:
          keys:
            - kid: a
              kty: EC
              crv: P-256
              x: {{Coordinates.X}}
              y: {{Coordinates.Y}}
              alg: ES256
              use: sig
        """;

    private string Write(string yaml)
    {
        var path = Path.Combine(directory, $"{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    private async Task<IReadOnlyList<AgentApplyResult>> ApplyAsync(FakeAdminApi admin, string yaml)
    {
        using var client = admin.CreateClient();
        client.BaseAddress = new Uri("https://subactid.example.com");
        return await AgentCommand.ApplyAsync([Write(yaml)], client, AgentRegistrationLimits.Default, Now);
    }

    /// <summary>An admin API that holds one agent in memory and records what was asked of it.</summary>
    private sealed class FakeAdminApi : HttpMessageHandler
    {
        private AgentResponse? stored;

        public List<string> Calls { get; } = [];

        public HttpStatusCode? Status { get; init; }

        public bool Throw { get; init; }

        public string LastBody { get; private set; } = string.Empty;

        public HttpClient CreateClient() => new(this, disposeHandler: false);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Throw)
            {
                throw new HttpRequestException("nothing is listening there");
            }

            var path = request.RequestUri!.AbsolutePath;
            Calls.Add($"{request.Method} {path}");

            if (Status is { } refuse)
            {
                return new HttpResponseMessage(refuse);
            }

            if (request.Content is not null)
            {
                LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            if (request.Method == HttpMethod.Get)
            {
                return stored is null
                    ? new HttpResponseMessage(HttpStatusCode.NotFound)
                    : Json(stored);
            }

            var body = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(LastBody);
            stored = Merge(stored, body);
            return Json(stored!);
        }

        private static AgentResponse Merge(AgentResponse? existing, System.Text.Json.JsonElement body)
        {
            var request = System.Text.Json.JsonSerializer.Deserialize<RegisterAgentRequest>(body.GetRawText(), SubactIdJson.Options)!;
            if (existing is null)
            {
                request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);
                return AgentResponse.From(agent!);
            }

            var patch = System.Text.Json.JsonSerializer.Deserialize<UpdateAgentRequest>(body.GetRawText(), SubactIdJson.Options)!;
            patch.TryApplyTo(existing.ToAgent(), AgentRegistrationLimits.Default, Now, out var updated);
            return AgentResponse.From(updated!);
        }

        private static HttpResponseMessage Json(AgentResponse agent) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(agent, SubactIdJson.Options), Encoding.UTF8, "application/json"),
        };
    }
}
