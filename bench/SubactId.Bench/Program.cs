using System.Globalization;
using System.Net;
using System.Text.Json;
using SubactId.Bench;

// The sizing rig's load generator. Commands: setup (create users and agents), load (fixed-rate
// load and a report), soak (the ledger growth run) and stress (a changing rate, per second).
//
// No dependencies beyond the platform, and kept small, since it shares CPU with the server.

var arguments = Arguments.Parse(args);
if (arguments.Command is null)
{
    Console.Error.WriteLine("usage: SubactId.Bench <setup|load|soak|stress> [--key value ...]");
    return 2;
}

var rig = Rig.FromEnvironment();
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

try
{
    return arguments.Command switch
    {
        "setup" => await SetupAsync(),
        "load" => await LoadAsync(),
        "soak" => await SoakAsync(),
        "stress" => await StressAsync(),
        _ => Unknown(arguments.Command),
    };
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("interrupted");
    return 130;
}

static int Unknown(string command)
{
    Console.Error.WriteLine($"unknown command: {command}");
    return 2;
}

async Task<int> SetupAsync()
{
    var users = arguments.Int("users", 64);
    await WaitForReadyAsync(rig, cancellation.Token);

    Console.WriteLine($"creating {users} humans in the realm");
    var created = await rig.Keycloak.EnsureUsersAsync(users, cancellation.Token);
    Console.WriteLine($"signing them in");
    var subjects = await Subjects.SignInAsync(rig.Keycloak, created, cancellation.Token);
    Console.WriteLine($"{subjects.Count} subject tokens held");

    // Optional lifetimes for the registrations. The growth model depends only on the ratio of
    // task to token lifetime, so the soak can use shorter ones than the defaults.
    var taskTtl = arguments.Optional("task-ttl");
    var tokenTtl = arguments.Optional("token-ttl");
    foreach (var agentId in Rig.Agents)
    {
        var key = rig.AgentKey(agentId);
        var isNew = await rig.ControlPlane.RegisterAsync(key, Rig.Audience, Rig.Scopes, taskTtl, tokenTtl, cancellation.Token);
        Console.WriteLine($"agent {agentId}: {(isNew ? "registered" : "already registered")}"
            + (taskTtl is null && tokenTtl is null ? string.Empty : $" (task {taskTtl ?? "default"}, token {tokenTtl ?? "default"})"));
    }

    return 0;
}

async Task<int> LoadAsync()
{
    var shape = arguments.Text("shape", "exchange");
    var rate = arguments.Double("rate", 10);
    var warmup = TimeSpan.FromSeconds(arguments.Double("warmup", 15));
    var measure = TimeSpan.FromSeconds(arguments.Double("duration", 60));
    var poolSize = arguments.Int("pool", 200);
    var label = arguments.Text("label", $"{shape}-{rate:0.##}");

    await WaitForReadyAsync(rig, cancellation.Token);
    var users = await rig.Keycloak.EnsureUsersAsync(arguments.Int("users", 64), cancellation.Token);
    var subjects = await Subjects.SignInAsync(rig.Keycloak, users, cancellation.Token);
    var agent = rig.AgentKey(Rig.BusyAgent);

    var operation = await OperationAsync(shape, poolSize, subjects, agent);
    if (operation is null)
    {
        Console.Error.WriteLine($"unknown shape: {shape}");
        return 2;
    }

    Console.WriteLine($"{label}: offering {rate}/s for {measure.TotalSeconds:0}s after {warmup.TotalSeconds:0}s of warmup");
    var recorder = await OpenModel.RunAsync(rate, warmup, measure, operation, cancellation.Token);
    var summary = recorder.Summarize(label, rate);
    Report(summary);
    Write(arguments.Optional("out"), summary);
    return 0;
}

// Builds the operation for a shape. Pools of grants and tokens are created before the clock starts.
async Task<Func<CancellationToken, Task<Outcome>>?> OperationAsync(string shape, int poolSize, Subjects subjects, AgentKey agent)
{
    switch (shape)
    {
        case "exchange":
            return async token => await rig.ControlPlane.ExchangeAsync(
                await subjects.NextAsync(token), agent.Assertion(rig.ControlPlane.TokenEndpoint), Rig.Audience, Rig.ScopeText, token);

        case "refresh":
            {
                var grants = await PoolAsync(poolSize, subjects, agent, static outcome => outcome.Grant, cancellation.Token);
                var cursor = -1;
                return token =>
                {
                    var grant = grants[(int)((uint)Interlocked.Increment(ref cursor) % (uint)grants.Length)];
                    return rig.ControlPlane.RefreshAsync(grant, agent.Assertion(rig.ControlPlane.TokenEndpoint), Rig.Audience, Rig.ScopeText, token);
                };
            }

        case "introspect":
            {
                var tokens = await PoolAsync(poolSize, subjects, agent, static outcome => outcome.AccessToken, cancellation.Token);
                var cursor = -1;
                return token =>
                {
                    var access = tokens[(int)((uint)Interlocked.Increment(ref cursor) % (uint)tokens.Length)];
                    return rig.ControlPlane.IntrospectAsync(access, agent.Assertion(rig.ControlPlane.TokenEndpoint), token);
                };
            }

        case "jwks":
            return token => rig.ControlPlane.GetAsync("/.well-known/jwks.json", token);

        case "discovery":
            return token => rig.ControlPlane.GetAsync("/.well-known/openid-configuration", token);

        case "denied":
            return rig.ControlPlane.DeniedAsync;

        case "mixed":
            return await MixedAsync(poolSize, subjects, agent);

        default:
            return null;
    }
}

// A weighted mix of shapes, set with --mix. The default is mostly introspection, with some
// exchanges, refreshes and key fetches.
async Task<Func<CancellationToken, Task<Outcome>>> MixedAsync(int poolSize, Subjects subjects, AgentKey agent)
{
    var weights = arguments.Text("mix", "exchange=10,refresh=10,introspect=70,jwks=10")
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(part => part.Split('=', 2))
        .Select(pair => (Shape: pair[0], Weight: int.Parse(pair[1], CultureInfo.InvariantCulture)))
        .Where(pair => pair.Weight > 0)
        .ToArray();

    var parts = new List<(int Upto, Func<CancellationToken, Task<Outcome>> Operation)>();
    var total = 0;
    foreach (var (part, weight) in weights)
    {
        if (part == "mixed" || await OperationAsync(part, poolSize, subjects, agent) is not { } operation)
        {
            throw new ArgumentException($"'{part}' is not a shape a mix can hold.");
        }

        total += weight;
        parts.Add((total, operation));
    }

    if (total == 0)
    {
        throw new ArgumentException("The mix has no weight in it.");
    }

    var turn = -1;
    return token =>
    {
        // Deterministic interleaving, so runs of the same mix send the same sequence.
        var slot = (int)((uint)Interlocked.Increment(ref turn) % (uint)total);
        foreach (var (upto, operation) in parts)
        {
            if (slot < upto)
            {
                return operation(token);
            }
        }

        return parts[^1].Operation(token);
    };
}

// The growth-model run. Issues tasks for two agents, one never renewed and one renewed until the
// task ends, then holds until the sweeper has written every terminal record. The ledger counts by
// agent then give rows per exchange for each pattern.
async Task<int> SoakAsync()
{
    var rate = arguments.Double("rate", 10);
    var issueFor = TimeSpan.FromSeconds(arguments.Double("issue-seconds", 600));
    var holdFor = TimeSpan.FromSeconds(arguments.Double("hold-seconds", 3600));
    var refreshEvery = TimeSpan.FromSeconds(arguments.Double("refresh-seconds", 270));

    await WaitForReadyAsync(rig, cancellation.Token);
    var users = await rig.Keycloak.EnsureUsersAsync(arguments.Int("users", 64), cancellation.Token);
    var subjects = await Subjects.SignInAsync(rig.Keycloak, users, cancellation.Token);
    var idle = rig.AgentKey(Rig.IdleAgent);
    var busy = rig.AgentKey(Rig.BusyAgent);

    var renewals = new System.Collections.Concurrent.ConcurrentQueue<Renewal>();
    long idleIssued = 0;
    long busyIssued = 0;
    long refreshed = 0;
    long refreshRefused = 0;
    var turn = -1;

    var markStarted = DateTimeOffset.UtcNow;
    Console.WriteLine($"soak: {rate}/s for {issueFor.TotalSeconds:0}s, then holding {holdFor.TotalSeconds:0}s; renewing every {refreshEvery.TotalSeconds:0}s");

    // Renews the busy agent's live tasks in the background. A refusal is counted, not retried,
    // since it usually means the task ended.
    var renewing = Task.Run(async () =>
    {
        while (!cancellation.Token.IsCancellationRequested)
        {
            var now = DateTimeOffset.UtcNow;
            var carried = new List<Renewal>();
            while (renewals.TryDequeue(out var renewal))
            {
                if (renewal.DueAt > now)
                {
                    carried.Add(renewal);
                    continue;
                }

                var outcome = await rig.ControlPlane.RefreshAsync(renewal.Grant, busy.Assertion(rig.ControlPlane.TokenEndpoint), Rig.Audience, Rig.ScopeText, cancellation.Token);
                if (outcome.Status is >= 200 and < 300 && outcome.Grant is { } next)
                {
                    Interlocked.Increment(ref refreshed);
                    carried.Add(renewal with { Grant = next, DueAt = now + refreshEvery });
                }
                else
                {
                    Interlocked.Increment(ref refreshRefused);
                }
            }

            foreach (var renewal in carried)
            {
                renewals.Enqueue(renewal);
            }

            await Task.Delay(TimeSpan.FromSeconds(5), cancellation.Token);
        }
    }, cancellation.Token);

    var recorder = await OpenModel.RunAsync(rate, TimeSpan.Zero, issueFor, async token =>
    {
        var subject = await subjects.NextAsync(token);
        var toBusy = ((uint)Interlocked.Increment(ref turn) & 1) == 1;
        var key = toBusy ? busy : idle;
        var outcome = await rig.ControlPlane.ExchangeAsync(subject, key.Assertion(rig.ControlPlane.TokenEndpoint), Rig.Audience, Rig.ScopeText, token);
        if (outcome.Status is >= 200 and < 300)
        {
            if (toBusy)
            {
                Interlocked.Increment(ref busyIssued);
                if (outcome.Grant is { } grant)
                {
                    renewals.Enqueue(new Renewal(grant, DateTimeOffset.UtcNow + refreshEvery));
                }
            }
            else
            {
                Interlocked.Increment(ref idleIssued);
            }
        }

        return outcome;
    }, cancellation.Token);

    var lastExchange = DateTimeOffset.UtcNow;
    Console.WriteLine($"issuing finished at {lastExchange:O}: {idleIssued} never-renewed, {busyIssued} renewed");
    Console.WriteLine($"holding for {holdFor.TotalSeconds:0}s so every task's terminal record is written");

    var holdUntil = lastExchange + holdFor;
    while (DateTimeOffset.UtcNow < holdUntil && !cancellation.Token.IsCancellationRequested)
    {
        var left = holdUntil - DateTimeOffset.UtcNow;
        Console.WriteLine($"  {left.TotalMinutes:0.0} minutes left; {Interlocked.Read(ref refreshed)} renewals, {Interlocked.Read(ref refreshRefused)} refused");
        await Task.Delay(TimeSpan.FromMinutes(Math.Min(5, Math.Max(1, left.TotalMinutes))), cancellation.Token);
    }

    await cancellation.CancelAsync();
    try
    {
        await renewing;
    }
    catch (OperationCanceledException)
    {
        // Expected: the renewer runs until the soak stops it.
    }

    var summary = recorder.Summarize("soak", rate);
    var soak = new SoakSummary(
        markStarted,
        lastExchange,
        DateTimeOffset.UtcNow,
        idleIssued,
        busyIssued,
        Interlocked.Read(ref refreshed),
        Interlocked.Read(ref refreshRefused),
        refreshEvery.TotalSeconds,
        summary);

    Report(summary);
    Console.WriteLine($"never-renewed tasks: {idleIssued}; renewed tasks: {busyIssued}; renewals: {soak.Refreshes}; refused: {soak.RefreshesRefused}");
    Write(arguments.Optional("out"), soak);
    return 0;
}

// Runs a changing rate and reports each second. stress.sh injects the faults. This only offers
// load and records responses.
async Task<int> StressAsync()
{
    var shape = arguments.Text("shape", "exchange");
    var stages = Stress.ParseProfile(arguments.Text("profile", "30@50"));
    var poolSize = arguments.Int("pool", 200);
    var label = arguments.Text("label", $"stress-{shape}");

    await WaitForReadyAsync(rig, cancellation.Token);
    var users = await rig.Keycloak.EnsureUsersAsync(arguments.Int("users", 8), cancellation.Token);
    var subjects = await Subjects.SignInAsync(rig.Keycloak, users, cancellation.Token);
    var agent = rig.AgentKey(Rig.BusyAgent);

    var operation = await OperationAsync(shape, poolSize, subjects, agent);
    if (operation is null)
    {
        Console.Error.WriteLine($"unknown shape: {shape}");
        return 2;
    }

    // Written before the first request, so stress.sh can time its faults against the run.
    if (arguments.Optional("started-file") is { } startedFile)
    {
        File.WriteAllText(startedFile, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture));
    }

    Console.WriteLine($"{label}: {shape}, {string.Join(", ", stages.Select(stage => $"{stage.Seconds:0}s at {stage.Rate:0.##}/s"))}");
    var timeline = await Stress.RunAsync(stages, operation, cancellation.Token);
    timeline.TokenAnswers = rig.ControlPlane.TokenAnswers;
    var summary = timeline.Summarize(label);

    Console.WriteLine($"  completed {summary.Completed}, succeeded {summary.Succeeded}; p50 {summary.P50:0.00} ms  p99 {summary.P99:0.00} ms  max {summary.Max:0.0} ms"
        + (summary.Abandoned > 0 ? $"; {summary.Abandoned} never returned" : string.Empty));
    foreach (var (outcome, count) in summary.Outcomes)
    {
        Console.WriteLine($"  {outcome}: {count}");
    }

    Console.WriteLine("   sec  offered   ok/s  fail/s    p50 ms    p99 ms  in-flight  outcomes");
    foreach (var row in summary.Seconds)
    {
        var failures = string.Join(" ", row.Outcomes.Where(pair => !pair.Key.StartsWith('2')).Select(pair => $"{pair.Key}={pair.Value}"));
        Console.WriteLine($"  {row.Second,4} {row.Offered,8} {row.Succeeded,6} {row.Failed,7} {row.P50,9:0.0} {row.P99,9:0.0} {row.PeakInFlight,10}  {failures}");
    }

    Write(arguments.Optional("out"), summary);
    return 0;
}

// A fixed set of live grants or tokens for a run, created before the clock starts.
async Task<string[]> PoolAsync(int size, Subjects subjects, AgentKey agent, Func<Outcome, string?> select, CancellationToken token)
{
    var pool = new List<string>(size);
    while (pool.Count < size)
    {
        var outcome = await rig.ControlPlane.ExchangeAsync(
            await subjects.NextAsync(token), agent.Assertion(rig.ControlPlane.TokenEndpoint), Rig.Audience, Rig.ScopeText, token);
        if (select(outcome) is { } value)
        {
            pool.Add(value);
            continue;
        }

        throw new InvalidOperationException($"Could not build the pool: the control plane answered {outcome.Status} ({outcome.Error}).");
    }

    return [.. pool];
}

static async Task WaitForReadyAsync(Rig rig, CancellationToken token)
{
    for (var attempt = 0; attempt < 120; attempt++)
    {
        if (await rig.ControlPlane.IsReadyAsync(token))
        {
            return;
        }

        await Task.Delay(TimeSpan.FromSeconds(2), token);
    }

    throw new InvalidOperationException("The control plane never became ready.");
}

static void Report(RunSummary summary)
{
    Console.WriteLine($"  offered {summary.Offered} at {summary.OfferedRate}/s, completed {summary.Completed}, succeeded {summary.Succeeded} ({summary.CompletedPerSecond:0.0}/s)");
    Console.WriteLine($"  p50 {summary.P50:0.00} ms  p90 {summary.P90:0.00} ms  p99 {summary.P99:0.00} ms  max {summary.Max:0.0} ms");
    Console.WriteLine($"  peak in flight {summary.PeakInFlight}{(summary.Abandoned > 0 ? $", {summary.Abandoned} never returned" : string.Empty)}");
    foreach (var (outcome, count) in summary.Outcomes)
    {
        Console.WriteLine($"  {outcome}: {count}");
    }
}

static void Write<T>(string? path, T payload)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        return;
    }

    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    File.WriteAllText(path, JsonSerializer.Serialize(payload, BenchJson.Options));
    Console.WriteLine($"  written to {path}");
}

internal sealed record Renewal(string Grant, DateTimeOffset DueAt);

internal sealed record SoakSummary(
    DateTimeOffset StartedAt,
    DateTimeOffset LastExchangeAt,
    DateTimeOffset FinishedAt,
    long TasksNeverRenewed,
    long TasksRenewed,
    long Refreshes,
    long RefreshesRefused,
    double RefreshIntervalSeconds,
    RunSummary Load);

internal static class BenchJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

internal sealed class Arguments
{
    private readonly Dictionary<string, string> values = new(StringComparer.Ordinal);

    public string? Command { get; private init; }

    public static Arguments Parse(string[] args)
    {
        var parsed = new Arguments { Command = args.Length > 0 && !args[0].StartsWith("--", StringComparison.Ordinal) ? args[0] : null };
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var key = args[i][2..];
            var value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "true";
            parsed.values[key] = value;
        }

        return parsed;
    }

    public string Text(string key, string fallback) => values.TryGetValue(key, out var value) ? value : fallback;

    public string? Optional(string key) => values.TryGetValue(key, out var value) ? value : null;

    public int Int(string key, int fallback) => values.TryGetValue(key, out var value) ? int.Parse(value, CultureInfo.InvariantCulture) : fallback;

    public double Double(string key, double fallback) => values.TryGetValue(key, out var value) ? double.Parse(value, CultureInfo.InvariantCulture) : fallback;
}

// The rig's configuration from the environment, and the clients built from it.
internal sealed class Rig
{
    public const string Audience = "https://bench.internal";
    public const string ScopeText = "bench:read bench:write";
    public const string IdleAgent = "bench-idle";
    public const string BusyAgent = "bench-busy";

    public static readonly string[] Scopes = ["bench:read", "bench:write"];
    public static readonly string[] Agents = [IdleAgent, BusyAgent];

    private readonly Dictionary<string, AgentKey> keys = new(StringComparer.Ordinal);
    private readonly string keyDirectory;

    private Rig(ControlPlane controlPlane, Keycloak keycloak, string keyDirectory)
    {
        ControlPlane = controlPlane;
        Keycloak = keycloak;
        this.keyDirectory = keyDirectory;
    }

    public ControlPlane ControlPlane { get; }

    public Keycloak Keycloak { get; }

    public static Rig FromEnvironment()
    {
        var issuer = new Uri(Required("SUBACTID_ISSUER"));
        var adminKey = Required("SUBACTID_ADMIN_API_KEY");
        var keycloakUrl = new Uri(Required("KEYCLOAK_URL"));
        var realm = Required("KEYCLOAK_REALM");
        var clientId = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_ID") ?? "bench-cli";
        var adminUser = Environment.GetEnvironmentVariable("KEYCLOAK_ADMIN_USERNAME") ?? "admin";
        var adminPassword = Required("KEYCLOAK_ADMIN_PASSWORD");
        var keyDirectory = Environment.GetEnvironmentVariable("BENCH_KEY_DIR") ?? "/results/keys";

        return new Rig(
            new ControlPlane(Client(), issuer, adminKey),
            new Keycloak(Client(), keycloakUrl, realm, clientId, adminUser, adminPassword),
            keyDirectory);
    }

    public AgentKey AgentKey(string agentId)
    {
        lock (keys)
        {
            if (!keys.TryGetValue(agentId, out var key))
            {
                key = SubactId.Bench.AgentKey.LoadOrCreate(Path.Combine(keyDirectory, $"{agentId}.pem"), agentId);
                keys[agentId] = key;
            }

            return key;
        }
    }

    private static HttpClient Client()
    {
        var handler = new SocketsHttpHandler
        {
            // High, so a saturating run is not queued inside the generator.
            MaxConnectionsPerServer = 4096,
            PooledConnectionLifetime = TimeSpan.FromMinutes(30),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.None,
            UseProxy = false,
            AllowAutoRedirect = false,
        };

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(120) };
    }

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"{name} is not set.");
}
