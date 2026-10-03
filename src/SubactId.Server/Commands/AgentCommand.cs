using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SubactId.Core.Agents;
using SubactId.Core.Validation;
using SubactId.Server.Contracts;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Commands;

/// <summary>What reconciling one registration did.</summary>
public enum AgentApplyOutcome
{
    /// <summary>The registration matched what the server already held.</summary>
    Unchanged,

    /// <summary>The agent did not exist and was registered.</summary>
    Created,

    /// <summary>The agent existed and differed, so it was patched.</summary>
    Updated,

    /// <summary>The file or the server refused it.</summary>
    Failed,
}

/// <summary>One file's outcome.</summary>
/// <param name="Path">The file.</param>
/// <param name="AgentId">The agent it registers, when the file named one.</param>
/// <param name="Outcome">What happened.</param>
/// <param name="Changes">The fields that differed, or the problems that stopped it.</param>
public sealed record AgentApplyResult(string Path, string? AgentId, AgentApplyOutcome Outcome, IReadOnlyList<string> Changes);

/// <summary>
/// <c>SubactId.Server agent init</c> and <c>agent apply</c>: manage agent registrations as files.
/// <para>
/// <c>init</c> writes an agent's key, its public key set and a registration with tight defaults.
/// <c>apply</c> reconciles those files with a running control plane through the admin API, so every
/// change is audited. Neither prints a private key or the admin key, and the admin key is never a
/// command-line argument.
/// </para>
/// </summary>
public static class AgentCommand
{
    /// <summary>The command word on the command line.</summary>
    public const string Name = "agent";

    /// <summary>Verb that writes a key and a registration for a new agent.</summary>
    public const string InitVerb = "init";

    /// <summary>Verb that reconciles registration files against a running control plane.</summary>
    public const string ApplyVerb = "apply";

    /// <summary>Environment variable the admin key is read from.</summary>
    public const string AdminKeyVariable = "SUBACTID_ADMIN_KEY";

    /// <summary>Exit code for an unusable argument.</summary>
    public const int UsageExitCode = 2;

    /// <summary>Exit code when a file was refused or the server rejected it.</summary>
    public const int FailedExitCode = 1;

    /// <summary>
    /// JSON options for requests. Same as the API's, but null fields are omitted, since a patch
    /// names only what it changes.
    /// </summary>
    private static readonly JsonSerializerOptions Outbound = new(SubactIdJson.Options)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private const string OutFlag = "--out";
    private const string ServerFlag = "--server";
    private const string DryRunFlag = "--dry-run";

    /// <summary>
    /// <c>agent init &lt;agent-id&gt; --out &lt;dir&gt;</c>: writes the agent's private key, its public key
    /// set, and a registration that embeds the set. Reads no configuration.
    /// </summary>
    /// <param name="args">Arguments after the verb.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="error">Where failures go; standard error by default.</param>
    /// <returns>0 on success, <see cref="FailedExitCode"/> when a file could not be written, <see cref="UsageExitCode"/> for a bad argument.</returns>
    public static int RunInit(IReadOnlyList<string> args, TextWriter? output = null, TextWriter? error = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        output ??= Console.Out;
        error ??= Console.Error;

        if (!TryReadInit(args, error, out var agentId, out var directory))
        {
            return UsageExitCode;
        }

        var keyPath = Path.Combine(directory, $"{agentId}.key.pem");
        var jwksPath = Path.Combine(directory, $"{agentId}.jwks.json");
        var registrationPath = Path.Combine(directory, $"{agentId}.yaml");

        foreach (var existing in new[] { keyPath, jwksPath, registrationPath })
        {
            if (File.Exists(existing))
            {
                error.WriteLine($"'{existing}' already exists; refusing to overwrite it.");
                return FailedExitCode;
            }
        }

        try
        {
            Directory.CreateDirectory(directory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"'{directory}' could not be created: {exception.GetType().Name}.");
            return FailedExitCode;
        }

        SigningKey key;
        try
        {
            // Owner-only, never overwrites, and clears the encoded key from memory after writing.
            key = SigningKeyFile.Create(keyPath);
        }
        catch (SigningKeyException exception)
        {
            error.WriteLine(exception.Message);
            return FailedExitCode;
        }

        using (key)
        {
            var jwks = new AgentJwks([new AgentJwk
            {
                Kid = key.Kid,
                Kty = "EC",
                Crv = "P-256",
                X = key.PublicJwk.X,
                Y = key.PublicJwk.Y,
                Alg = SigningKey.Algorithm,
                Use = "sig",
            }]);

            try
            {
                File.WriteAllText(jwksPath, jwks.ToJson() + '\n');
                File.WriteAllText(registrationPath, AgentRegistrationFile.Write(agentId, jwks));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                error.WriteLine($"the registration could not be written: {exception.GetType().Name}.");
                return FailedExitCode;
            }

            output.WriteLine($"Wrote a registration for '{agentId}':");
            output.WriteLine($"    {registrationPath}  the registration; fill in allowed_scopes and allowed_audiences");
            output.WriteLine($"    {jwksPath}  its public keys, the same set the registration embeds");
            output.WriteLine($"    {keyPath}  its private key, readable by its owner only");
            output.WriteLine();
            output.WriteLine($"Key id: {key.Kid} (RFC 7638 thumbprint)");
            output.WriteLine();
            output.WriteLine("The private key belongs in a secret store, not in the repository. Everything else here");
            output.WriteLine("is public and is meant to be committed.");
        }

        return 0;
    }

    /// <summary>
    /// <c>agent apply &lt;files&gt; --server &lt;url&gt;</c>: validates each registration locally, then
    /// creates, patches or leaves it alone. Idempotent: a second run makes no admin call.
    /// </summary>
    /// <param name="args">Arguments after the verb.</param>
    /// <param name="limits">Server-wide lifetime bounds used for local validation.</param>
    /// <param name="now">The current time, used only for local validation.</param>
    /// <param name="adminKey">The admin key; read from the environment or standard input when <c>null</c>.</param>
    /// <param name="clientFactory">Provides the <see cref="HttpClient"/> used to reach the admin API.</param>
    /// <param name="stdin">Where the admin key is read from when it is not in the environment.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="error">Where failures go; standard error by default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>0 when every file is applied, <see cref="FailedExitCode"/> when one was refused, <see cref="UsageExitCode"/> for a bad argument.</returns>
    public static async Task<int> RunApplyAsync(
        IReadOnlyList<string> args,
        AgentRegistrationLimits limits,
        DateTimeOffset now,
        string? adminKey = null,
        Func<HttpClient>? clientFactory = null,
        TextReader? stdin = null,
        TextWriter? output = null,
        TextWriter? error = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(limits);
        output ??= Console.Out;
        error ??= Console.Error;

        if (!TryReadApply(args, error, out var paths, out var server, out var dryRun))
        {
            return UsageExitCode;
        }

        adminKey ??= ReadAdminKey(stdin);
        if (!dryRun && string.IsNullOrWhiteSpace(adminKey))
        {
            error.WriteLine($"No admin key. Set {AdminKeyVariable}, or pipe the key to this command on standard input.");
            error.WriteLine("It is never taken as an argument: an argument is visible in the process list and in CI logs.");
            return UsageExitCode;
        }

        using var client = clientFactory?.Invoke() ?? new HttpClient();
        client.BaseAddress = server;
        if (!dryRun)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminKey);
        }

        var results = await ApplyAsync(paths, client, limits, now, dryRun, cancellationToken);
        Write(output, results, dryRun);
        return results.Any(r => r.Outcome == AgentApplyOutcome.Failed) ? FailedExitCode : 0;
    }

    /// <summary>Reconciles each file and returns what happened, without printing anything.</summary>
    /// <param name="paths">The registration files.</param>
    /// <param name="client">A client whose base address is the control plane and which carries the admin key.</param>
    /// <param name="limits">Server-wide lifetime bounds used for local validation.</param>
    /// <param name="now">The current time, used only for local validation.</param>
    /// <param name="dryRun">When set, nothing is sent.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<IReadOnlyList<AgentApplyResult>> ApplyAsync(
        IReadOnlyList<string> paths,
        HttpClient client,
        AgentRegistrationLimits limits,
        DateTimeOffset now,
        bool dryRun = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(limits);

        var results = new List<AgentApplyResult>();
        foreach (var path in paths)
        {
            results.Add(await ApplyOneAsync(path, client, limits, now, dryRun, cancellationToken));
        }

        return results;
    }

    /// <summary>Writes the report: one line per file, then what differed beneath it.</summary>
    /// <param name="output">Where the report goes.</param>
    /// <param name="results">What each file did.</param>
    /// <param name="dryRun">Whether nothing was actually sent.</param>
    public static void Write(TextWriter output, IReadOnlyList<AgentApplyResult> results, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(results);

        foreach (var result in results)
        {
            var label = result.Outcome switch
            {
                AgentApplyOutcome.Unchanged => "unchanged",
                AgentApplyOutcome.Created => dryRun ? "would create" : "created",
                AgentApplyOutcome.Updated => dryRun ? "would update" : "updated",
                _ => "FAILED",
            };

            output.WriteLine($"{label}  {result.AgentId ?? result.Path}");
            foreach (var change in result.Changes)
            {
                output.WriteLine($"    {change}");
            }
        }

        var failed = results.Count(r => r.Outcome == AgentApplyOutcome.Failed);
        var changed = results.Count(r => r.Outcome is AgentApplyOutcome.Created or AgentApplyOutcome.Updated);
        output.WriteLine();
        output.WriteLine(failed == 0
            ? $"{results.Count} file(s), {changed.ToString(CultureInfo.InvariantCulture)} changed."
            : $"{results.Count} file(s), {changed.ToString(CultureInfo.InvariantCulture)} changed, {failed.ToString(CultureInfo.InvariantCulture)} failed.");
    }

    /// <summary>The fields in which a desired registration differs from what the server holds.</summary>
    /// <param name="desired">The registration from the file.</param>
    /// <param name="current">The agent the server currently holds.</param>
    public static IReadOnlyList<string> Diff(Agent desired, Agent current)
    {
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(current);

        var changes = new List<string>();
        Compare("display_name", current.DisplayName, desired.DisplayName, changes);
        Compare("sponsor_required", current.SponsorRequired, desired.SponsorRequired, changes);
        CompareList("allowed_scopes", current.AllowedScopes, desired.AllowedScopes, changes);
        CompareList("allowed_audiences", current.AllowedAudiences, desired.AllowedAudiences, changes);
        Compare("max_task_ttl", Iso8601DurationConverter.Format(current.MaxTaskTtl), Iso8601DurationConverter.Format(desired.MaxTaskTtl), changes);
        Compare("max_token_ttl", Iso8601DurationConverter.Format(current.MaxTokenTtl), Iso8601DurationConverter.Format(desired.MaxTokenTtl), changes);
        Compare("max_delegation_depth", current.MaxDelegationDepth, desired.MaxDelegationDepth, changes);
        CompareList("high_risk_audiences", current.HighRiskAudiences, desired.HighRiskAudiences, changes);
        Compare("jwks_uri", current.JwksUri?.ToString() ?? "(none)", desired.JwksUri?.ToString() ?? "(none)", changes);

        // Compared in canonical form, so reordered members are not a change.
        if (current.Jwks != desired.Jwks)
        {
            changes.Add($"jwks: {Keys(current.Jwks)} -> {Keys(desired.Jwks)}");
        }

        return changes;
    }

    private static string Keys(AgentJwks? jwks) =>
        jwks is null ? "(none)" : string.Join(", ", jwks.Keys.Select(k => k.Kid));

    private static async Task<AgentApplyResult> ApplyOneAsync(
        string path,
        HttpClient client,
        AgentRegistrationLimits limits,
        DateTimeOffset now,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        string yaml;
        try
        {
            yaml = await File.ReadAllTextAsync(path, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new AgentApplyResult(path, null, AgentApplyOutcome.Failed, [$"could not be read: {exception.GetType().Name}."]);
        }

        var fileErrors = AgentRegistrationFile.TryRead(path, yaml, out var file);
        if (fileErrors.Count > 0)
        {
            return new AgentApplyResult(path, null, AgentApplyOutcome.Failed, Describe(fileErrors));
        }

        // Run the admin API's validation locally before sending anything.
        var errors = file!.Request.TryToAgent(limits, now, out var desired);
        if (errors.Count > 0)
        {
            return new AgentApplyResult(path, file.Request.AgentId, AgentApplyOutcome.Failed, Describe(errors));
        }

        var agentId = desired!.AgentId;
        if (dryRun)
        {
            return new AgentApplyResult(path, agentId, AgentApplyOutcome.Created, ["not sent: this is a dry run."]);
        }

        try
        {
            var current = await GetAsync(client, agentId, cancellationToken);
            if (current is null)
            {
                await SendAsync(client, HttpMethod.Post, "/admin/agents/", file.Request, cancellationToken);
                return new AgentApplyResult(path, agentId, AgentApplyOutcome.Created, []);
            }

            // A lifetime the file leaves unset is not compared: the local default may differ from
            // the one the server applied.
            var comparable = desired with
            {
                MaxTaskTtl = file.Request.MaxTaskTtl ?? current.MaxTaskTtl,
                MaxTokenTtl = file.Request.MaxTokenTtl ?? current.MaxTokenTtl,
            };

            var changes = Diff(comparable, current);
            if (changes.Count == 0)
            {
                return new AgentApplyResult(path, agentId, AgentApplyOutcome.Unchanged, []);
            }

            await SendAsync(client, HttpMethod.Patch, $"/admin/agents/{Uri.EscapeDataString(agentId)}", ToPatch(file.Request, comparable, current), cancellationToken);
            return new AgentApplyResult(path, agentId, AgentApplyOutcome.Updated, changes);
        }
        catch (AdminCallException exception)
        {
            return new AgentApplyResult(path, agentId, AgentApplyOutcome.Failed, exception.Problems);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new AgentApplyResult(path, agentId, AgentApplyOutcome.Failed, [$"the control plane could not be reached: {exception.GetType().Name}."]);
        }
    }

    /// <summary>
    /// Builds a patch with only the fields that differ, so the audit record lists just those.
    /// </summary>
    private static UpdateAgentRequest ToPatch(RegisterAgentRequest request, Agent desired, Agent current) => new(
        desired.DisplayName == current.DisplayName ? null : request.DisplayName,
        desired.SponsorRequired == current.SponsorRequired ? null : desired.SponsorRequired,
        desired.AllowedScopes.SequenceEqual(current.AllowedScopes, StringComparer.Ordinal) ? null : request.AllowedScopes,
        desired.AllowedAudiences.SequenceEqual(current.AllowedAudiences, StringComparer.Ordinal) ? null : request.AllowedAudiences,
        desired.MaxTaskTtl == current.MaxTaskTtl ? null : request.MaxTaskTtl,
        desired.MaxTokenTtl == current.MaxTokenTtl ? null : request.MaxTokenTtl,
        desired.MaxDelegationDepth == current.MaxDelegationDepth ? null : request.MaxDelegationDepth,
        desired.HighRiskAudiences.SequenceEqual(current.HighRiskAudiences, StringComparer.Ordinal) ? null : desired.HighRiskAudiences,
        desired.JwksUri == current.JwksUri ? null : request.JwksUri,
        desired.Jwks == current.Jwks ? null : request.Jwks,
        Enabled: null);

    private static async Task<Agent?> GetAsync(HttpClient client, string agentId, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"/admin/agents/{Uri.EscapeDataString(agentId)}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        await EnsureAcceptedAsync(response, cancellationToken);

        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var current = JsonSerializer.Deserialize<AgentResponse>(body, SubactIdJson.Options)
            ?? throw new AdminCallException(["the control plane returned an agent that could not be read."]);
        return current.ToAgent();
    }

    private static async Task SendAsync<T>(HttpClient client, HttpMethod method, string path, T body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path)
        {
            Content = new StringContent(JsonSerializer.Serialize(body, Outbound), Encoding.UTF8, "application/json"),
        };

        using var response = await client.SendAsync(request, cancellationToken);
        await EnsureAcceptedAsync(response, cancellationToken);
    }

    private static async Task EnsureAcceptedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var status = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            throw new AdminCallException([$"the admin key was refused ({status}). Check {AdminKeyVariable}."]);
        }

        if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
        {
            throw new AdminCallException([$"the admin API is disabled on that server ({status}); it has no admin key configured."]);
        }

        // The body holds the server's per-field errors. It never contains a credential.
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        throw new AdminCallException([$"the control plane refused it ({status}).", .. Truncate(body)]);
    }

    private static IEnumerable<string> Truncate(string body) =>
        string.IsNullOrWhiteSpace(body) ? [] : [body.Length > 2000 ? body[..2000] + "..." : body];

    private static IReadOnlyList<string> Describe(IReadOnlyList<ValidationError> errors) =>
        [.. errors.Select(e => $"{e.Field}: {e.Message}")];

    private static void Compare<T>(string field, T current, T desired, List<string> changes)
    {
        if (!EqualityComparer<T>.Default.Equals(current, desired))
        {
            changes.Add($"{field}: {current} -> {desired}");
        }
    }

    private static void CompareList(string field, IReadOnlyList<string> current, IReadOnlyList<string> desired, List<string> changes)
    {
        if (!current.SequenceEqual(desired, StringComparer.Ordinal))
        {
            changes.Add($"{field}: [{string.Join(", ", current)}] -> [{string.Join(", ", desired)}]");
        }
    }

    private static string? ReadAdminKey(TextReader? stdin)
    {
        if (Environment.GetEnvironmentVariable(AdminKeyVariable) is { Length: > 0 } fromEnvironment)
        {
            return fromEnvironment;
        }

        // Read only when input is redirected, so an interactive run does not hang.
        if (stdin is not null)
        {
            return stdin.ReadToEnd().Trim();
        }

        return Console.IsInputRedirected ? Console.In.ReadToEnd().Trim() : null;
    }

    private static bool TryReadInit(IReadOnlyList<string> args, TextWriter error, out string agentId, out string directory)
    {
        agentId = string.Empty;
        directory = string.Empty;
        string? outDirectory = null;

        if (args.Count == 0 || args[0].StartsWith("--", StringComparison.Ordinal))
        {
            error.WriteLine($"Usage: {Name} {InitVerb} <agent-id> {OutFlag} <directory>.");
            return false;
        }

        agentId = args[0];
        for (var i = 1; i < args.Count; i++)
        {
            if (args[i] != OutFlag)
            {
                error.WriteLine($"'{args[i]}' is not an argument of '{Name} {InitVerb}'. Usage: {Name} {InitVerb} <agent-id> {OutFlag} <directory>.");
                return false;
            }

            if (i + 1 >= args.Count || outDirectory is not null || args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                error.WriteLine($"{OutFlag} needs exactly one value.");
                return false;
            }

            outDirectory = args[++i];
        }

        if (outDirectory is null)
        {
            error.WriteLine($"{OutFlag} is required. Usage: {Name} {InitVerb} <agent-id> {OutFlag} <directory>.");
            return false;
        }

        // Validate the id before any key is written.
        var candidate = new Agent(agentId, agentId, true, [], [], AgentRegistrationFile.DefaultTaskTtl, AgentRegistrationFile.DefaultTokenTtl, 1, [], null, null, true, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        if (AgentValidator.Validate(candidate, AgentRegistrationLimits.Default).FirstOrDefault(e => e.Field == "agent_id") is { } problem)
        {
            error.WriteLine($"agent_id {problem.Message}");
            return false;
        }

        directory = outDirectory;
        return true;
    }

    /// <summary><c>localhost</c>, an address in <c>127.0.0.0/8</c>, or <c>::1</c>: a host that never leaves this machine.</summary>
    private static bool IsLoopback(Uri url) =>
        url.IsLoopback || (System.Net.IPAddress.TryParse(url.IdnHost, out var address) && System.Net.IPAddress.IsLoopback(address));

    private static bool TryReadApply(IReadOnlyList<string> args, TextWriter error, out IReadOnlyList<string> paths, out Uri server, out bool dryRun)
    {
        paths = [];
        server = null!;
        dryRun = false;
        var files = new List<string>();
        string? serverArgument = null;

        for (var i = 0; i < args.Count; i++)
        {
            switch (args[i])
            {
                case ServerFlag when i + 1 < args.Count && serverArgument is null:
                    serverArgument = args[++i];
                    break;

                case DryRunFlag:
                    dryRun = true;
                    break;

                case var flag when flag.StartsWith("--", StringComparison.Ordinal):
                    error.WriteLine($"'{flag}' is not an argument of '{Name} {ApplyVerb}'. Usage: {Name} {ApplyVerb} <files> {ServerFlag} <url> [{DryRunFlag}].");
                    return false;

                default:
                    files.Add(args[i]);
                    break;
            }
        }

        if (files.Count == 0)
        {
            error.WriteLine($"Usage: {Name} {ApplyVerb} <files> {ServerFlag} <url> [{DryRunFlag}].");
            return false;
        }

        if (serverArgument is null && !dryRun)
        {
            error.WriteLine($"{ServerFlag} is required: the URL of the control plane to apply to.");
            return false;
        }

        if (serverArgument is not null && (!Uri.TryCreate(serverArgument, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp)))
        {
            error.WriteLine($"{ServerFlag} must be an absolute http or https URL.");
            return false;
        }
        else if (serverArgument is not null)
        {
            server = new Uri(serverArgument, UriKind.Absolute);

            // The admin key goes with every request, so it must not cross a network in the clear.
            // Plain http stays allowed for a loopback host, such as a port-forward.
            if (server.Scheme == Uri.UriSchemeHttp && !IsLoopback(server))
            {
                error.WriteLine($"{ServerFlag} must use https unless it is on a loopback host: the admin key is sent with every request.");
                return false;
            }
        }
        else
        {
            server = new Uri("http://localhost", UriKind.Absolute);
        }

        paths = files;
        return true;
    }

    private sealed class AdminCallException(IReadOnlyList<string> problems) : Exception("The admin API refused the registration.")
    {
        public IReadOnlyList<string> Problems { get; } = problems;
    }
}
