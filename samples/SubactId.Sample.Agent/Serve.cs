using System.Collections.Concurrent;
using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>
/// The demo agent run as a service driven by the portal. The portal passes the human's access
/// token, which is exchanged for a task token and not kept. Tool calls carry only the task token.
/// </summary>
/// <remarks>
/// Tasks are kept in memory and lost on restart.
/// </remarks>
internal static class Serve
{
    /// <summary>How long before a token expires the refresher renews it.</summary>
    private static readonly TimeSpan RenewWithin = TimeSpan.FromSeconds(8);

    /// <summary>How often a long-running task calls a tool, so there is work to see between renewals.</summary>
    private static readonly TimeSpan WorkEvery = TimeSpan.FromSeconds(20);

    /// <summary>Runs the agent as a service until it is stopped.</summary>
    public static async Task<int> RunAsync(string[] args)
    {
        var issuer = new Uri(Env("SUBACTID_ISSUER", "http://subactid:5100"), UriKind.Absolute);
        var adminKey = File.ReadAllText(Env("SUBACTID_ADMIN_KEY_FILE", "/etc/subactid-quickstart/admin-key")).Trim();
        var audience = Env("TOOL_AUDIENCE", "https://jira.internal");
        var keyPath = Env("SUBACTID_AGENT_KEY_FILE", "/var/lib/portal-agent/agent-key.pem");

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var subactid = new ControlPlane(http, issuer, adminKey);
        var tools = new ToolServer(http, new Uri(Env("TOOL_SERVER_URL", "http://tool-server:8080"), UriKind.Absolute));

        // One registration per profile, since max_task_ttl is set per agent.
        var profiles = new Dictionary<string, TaskProfile>(StringComparer.Ordinal)
        {
            ["short"] = new("portal-agent-short", "Portal agent (short tasks)", "PT2M"),
            ["long"] = new("portal-agent-long", "Portal agent (long tasks)", "PT10M"),
        };

        // One private key shared by both registrations, so both publish the same JWKS. Each
        // assertion's iss and sub must name the registration the task runs under.
        var keys = profiles.ToDictionary(p => p.Key, p => AgentKey.LoadOrCreate(keyPath, p.Value.AgentId), StringComparer.Ordinal);
        var jwksUri = Env("SUBACTID_AGENT_JWKS_URI", "https://portal-agent:8443/jwks.json");

        // Serve the JWKS before registering.
        var builder = WebApplication.CreateBuilder(args);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        var app = builder.Build();
        app.MapGet("/jwks.json", () => Results.Content(keys["short"].Jwks, "application/json"));
        await app.StartAsync();

        Console.WriteLine($"portal-agent: waiting for the control plane at {issuer}");
        if (!await WaitUntilAsync(() => subactid.IsReadyAsync(CancellationToken.None)))
        {
            Console.Error.WriteLine("portal-agent: the control plane never became ready.");
            return 1;
        }

        foreach (var profile in profiles.Values)
        {
            await EnsureRegisteredAsync(subactid, profile, audience, jwksUri, CancellationToken.None);
            Console.WriteLine($"portal-agent: registered {profile.AgentId} (max_task_ttl {profile.MaxTaskTtl}, max_token_ttl {TaskProfile.MaxTokenTtl})");
        }

        var tasks = new ConcurrentDictionary<string, LiveTask>(StringComparer.Ordinal);

        app.MapGet("/healthz", () => Results.Text("ok"));

        // The task profiles the portal offers.
        app.MapGet("/profiles", () => Results.Json(profiles.ToDictionary(
            p => p.Key,
            p => new { agent_id = p.Value.AgentId, display_name = p.Value.DisplayName, max_task_ttl = p.Value.MaxTaskTtl, max_token_ttl = TaskProfile.MaxTokenTtl })));

        app.MapGet("/tools", async (CancellationToken cancellationToken) =>
            await tools.DescribeAsync(cancellationToken) is { } described ? Results.Content(described, "application/json") : Results.StatusCode(503));

        // The exchange. The human's token is used once and not kept.
        app.MapPost("/tasks", async (StartTaskBody body, CancellationToken cancellationToken) =>
        {
            if (string.IsNullOrWhiteSpace(body.SubjectToken))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "No subject token." });
            }

            if (!profiles.TryGetValue(body.Kind ?? "short", out var profile))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Unknown task kind." });
            }

            var requested = string.IsNullOrWhiteSpace(body.Scope) ? "jira:read jira:comment" : body.Scope!;
            var key = keys[body.Kind ?? "short"];
            var result = await subactid.ExchangeAsync(body.SubjectToken!, key.Assertion(subactid.TokenEndpoint), audience, requested, cancellationToken);
            if (result.Session is not { } session)
            {
                return Results.Json(new { error = result.Error, error_description = result.Description }, statusCode: 403);
            }

            var task = new LiveTask(session.TaskId, body.Kind ?? "short", profile.AgentId, audience, requested, session);
            task.Log("ok", $"task {session.TaskId} started", $"scope {session.Scope}, token good for {session.ExpiresIn}s, task until {session.TaskExpiresAt:HH:mm:ss}Z");
            if (!string.Equals(requested, session.Scope, StringComparison.Ordinal))
            {
                task.Log("deny", $"asked for '{requested}', granted '{session.Scope}'", "The intersection of what the human holds, what this agent is allowed and what was asked for.");
            }

            tasks[session.TaskId] = task;
            return Results.Json(task.Snapshot());
        });

        app.MapGet("/tasks", () => Results.Json(tasks.Values
            .OrderByDescending(t => t.StartedAt)
            .Select(t => t.Snapshot())
            .ToArray()));

        app.MapGet("/tasks/{taskId}", (string taskId) =>
            tasks.TryGetValue(taskId, out var task) ? Results.Json(task.Snapshot()) : Results.NotFound());

        // One tool call. `credential` selects the task token, or the human's token to show that
        // the tool server refuses it.
        app.MapPost("/tasks/{taskId}/call", async (string taskId, CallBody body, CancellationToken cancellationToken) =>
        {
            if (!tasks.TryGetValue(taskId, out var task))
            {
                return Results.NotFound();
            }

            var tool = body.Tool ?? "search";
            var human = string.Equals(body.Credential, "human", StringComparison.Ordinal);
            if (human && string.IsNullOrWhiteSpace(body.SubjectToken))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "No subject token to try." });
            }

            // Used for this call only. Never stored on the task.
            var credential = human ? body.SubjectToken! : task.AccessToken;
            var call = await tools.CallAsync(tool, credential, cancellationToken);
            var what = human ? $"{tool} with the human's Keycloak token" : tool;
            if (call.Status < 300)
            {
                task.Log("ok", $"{what} -> {call.Status}", call.Result);
            }
            else
            {
                task.Log("deny", $"{what} -> {call.Status} {call.Error}", human
                    ? "The tool server takes task tokens from this control plane and nothing else. A token from the identity provider is not one."
                    : call.Description);
            }

            return Results.Json(new { status = call.Status, result = call.Result, error = call.Error, error_description = call.Description, task = task.Snapshot() });
        });

        app.MapPost("/tasks/{taskId}/refresh", async (string taskId, CancellationToken cancellationToken) =>
        {
            if (!tasks.TryGetValue(taskId, out var task))
            {
                return Results.NotFound();
            }

            await RenewAsync(subactid, keys[task.Kind], task, cancellationToken);
            return Results.Json(task.Snapshot());
        });

        // A refresh with a chosen scope. It may ask for any subset of the grant, never more.
        app.MapPost("/tasks/{taskId}/narrow", async (string taskId, NarrowBody body, CancellationToken cancellationToken) =>
        {
            if (!tasks.TryGetValue(taskId, out var task))
            {
                return Results.NotFound();
            }

            var wanted = body.Scope ?? string.Empty;
            var result = await subactid.RefreshAsync(task.Grant, keys[task.Kind].Assertion(subactid.TokenEndpoint), task.Audience, wanted, cancellationToken);
            if (result.Session is { } session)
            {
                task.Adopt(session);
                task.Log("ok", $"scope now '{session.Scope}'", "Every renewal is checked against the grant, which keeps the scope of the last renewal. Less than the grant is always allowed and it sticks; more than it never is, not even the scope it started with.");
            }
            else
            {
                task.Log("deny", $"{result.Error}", result.Description);
            }

            return Results.Json(task.Snapshot());
        });

        app.MapPost("/tasks/{taskId}/revoke", async (string taskId, CancellationToken cancellationToken) =>
        {
            if (!tasks.TryGetValue(taskId, out var task))
            {
                return Results.NotFound();
            }

            var revoked = await subactid.RevokeTaskAsync(taskId, cancellationToken);
            task.End("operator_kill_switch");
            task.Log("deny", $"task revoked ({revoked})", "The token in hand is still unexpired and still correctly signed. It is no longer live, and a high-risk tool finds that out on its next call.");
            return Results.Json(task.Snapshot());
        });

        // Background renewal and periodic work for long tasks.
        using var stopping = new CancellationTokenSource();
        var background = Task.Run(() => BackgroundAsync(subactid, tools, keys, tasks, stopping.Token));

        Console.WriteLine("portal-agent: ready on :8100");
        await app.WaitForShutdownAsync();
        await stopping.CancelAsync();
        try
        {
            await background;
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }

        return 0;
    }

    /// <summary>Renews every token that is about to run out, and gives long tasks something to do.</summary>
    private static async Task BackgroundAsync(ControlPlane subactid, ToolServer tools, IReadOnlyDictionary<string, AgentKey> keys, ConcurrentDictionary<string, LiveTask> tasks, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            foreach (var task in tasks.Values.Where(t => t.Running).ToArray())
            {
                // A failure in one task must not stop the loop for the others.
                try
                {
                    await TickAsync(subactid, tools, keys, task, cancellationToken);
                }
                catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or JsonException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
                {
                    task.Log("deny", "the agent could not reach the control plane or the tool server", exception.Message);
                }
            }
        }
    }

    /// <summary>One second of one task: end it if it is over, renew it if it is about to be, work if it is a long one.</summary>
    private static async Task TickAsync(ControlPlane subactid, ToolServer tools, IReadOnlyDictionary<string, AgentKey> keys, LiveTask task, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (now >= task.TaskExpiresAt)
        {
            task.End("task_expired");
            task.Log("deny", "the task reached max_task_ttl", "Its agent is still enabled and still entitled; this task is simply over, and no token can outlive it.");
            return;
        }

        // Token lifetime is capped by the task's remaining time, so skip renewal near the task's end.
        if (task.TokenExpiresAt - now <= RenewWithin && task.TaskExpiresAt - now > RenewWithin)
        {
            await RenewAsync(subactid, keys[task.Kind], task, cancellationToken);
        }

        if (task.Kind == "long" && task.Running && now - task.LastWorkedAt >= WorkEvery)
        {
            task.LastWorkedAt = now;
            var call = await tools.CallAsync("search", task.AccessToken, cancellationToken);
            task.Log(call.Status < 300 ? "ok" : "deny", $"working: search -> {call.Status}", call.Status < 300 ? call.Result : call.Description);
        }
    }

    /// <summary>One renewal, asking for exactly the scope the task already has.</summary>
    private static async Task RenewAsync(ControlPlane subactid, AgentKey key, LiveTask task, CancellationToken cancellationToken)
    {
        var result = await subactid.RefreshAsync(task.Grant, key.Assertion(subactid.TokenEndpoint), task.Audience, task.Scope, cancellationToken);
        if (result.Session is { } session)
        {
            task.Adopt(session);
            task.Log("ok", $"renewed #{task.Refreshes}", $"same task, new token, still {session.Scope}. The sponsor was re-checked with the identity provider.");
            return;
        }

        task.End(result.Error ?? "refresh_failed");
        task.Log("deny", $"renewal refused: {result.Error}", result.Description);
    }

    /// <summary>Registers a profile, or brings an existing registration up to what this build expects.</summary>
    private static async Task EnsureRegisteredAsync(ControlPlane subactid, TaskProfile profile, string audience, string jwksUri, CancellationToken cancellationToken)
    {
        var registration = new
        {
            agent_id = profile.AgentId,
            display_name = profile.DisplayName,
            sponsor_required = true,
            allowed_scopes = new[] { "jira:read", "jira:comment" },
            allowed_audiences = new[] { audience },
            max_task_ttl = profile.MaxTaskTtl,
            max_token_ttl = TaskProfile.MaxTokenTtl,
            max_delegation_depth = 1,
            jwks_uri = jwksUri,
        };

        if (await subactid.RegisterAsync(registration, cancellationToken))
        {
            return;
        }

        // Already registered. Update only if it differs, to avoid an agent.updated audit record
        // on every restart.
        var current = await subactid.GetAgentAsync(profile.AgentId, cancellationToken);
        if (current is { } existing && Matches(existing, profile, audience, jwksUri))
        {
            return;
        }

        await subactid.UpdateAsync(profile.AgentId, registration, cancellationToken);
    }

    /// <summary>Whether a registration already says what this build would register.</summary>
    private static bool Matches(JsonElement current, TaskProfile profile, string audience, string jwksUri) =>
        Text(current, "display_name") == profile.DisplayName
        && Text(current, "max_task_ttl") == profile.MaxTaskTtl
        && Text(current, "max_token_ttl") == TaskProfile.MaxTokenTtl
        && Text(current, "jwks_uri") == jwksUri
        && current.TryGetProperty("sponsor_required", out var sponsor) && sponsor.ValueKind == JsonValueKind.True
        && current.TryGetProperty("max_delegation_depth", out var depth) && depth.TryGetInt32(out var d) && d == 1
        && Strings(current, "allowed_scopes").SequenceEqual(new[] { "jira:read", "jira:comment" }, StringComparer.Ordinal)
        && Strings(current, "allowed_audiences").SequenceEqual([audience], StringComparer.Ordinal);

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string[] Strings(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToArray()
            : [];

    private static async Task<bool> WaitUntilAsync(Func<Task<bool>> probe)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await probe())
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        return false;
    }

    private static string Env(string name, string fallback) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;
}

/// <summary>A task profile the portal offers, and the registration it runs under.</summary>
/// <param name="AgentId">The registration this profile's tasks run under.</param>
/// <param name="DisplayName">How the registration names itself.</param>
/// <param name="MaxTaskTtl">The whole task's ceiling, as an ISO 8601 duration.</param>
internal sealed record TaskProfile(string AgentId, string DisplayName, string MaxTaskTtl)
{
    /// <summary>
    /// Token lifetime for both profiles. Short, so renewals are visible in the portal.
    /// </summary>
    public const string MaxTokenTtl = "PT30S";
}

/// <summary>Body of <c>POST /tasks</c>.</summary>
internal sealed record StartTaskBody(string? SubjectToken, string? Kind, string? Scope);

/// <summary>Body of <c>POST /tasks/{id}/call</c>. <c>Credential</c> is <c>task</c> or <c>human</c>.</summary>
internal sealed record CallBody(string? Tool, string? Credential, string? SubjectToken);

/// <summary>Body of <c>POST /tasks/{id}/narrow</c>.</summary>
internal sealed record NarrowBody(string? Scope);
