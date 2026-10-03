// The quickstart's demo agent. It publishes its keys, registers itself, and runs the demo: a
// human signs in, the agent gets a narrower, shorter-lived token, calls a tool server, renews
// with a narrower scope, is refused a wider one, the task is revoked, and the ledger is shown.
//
//   SUBACTID_ISSUER, SUBACTID_ADMIN_KEY_FILE, SUBACTID_AGENT_ID, SUBACTID_AGENT_JWKS_URI, SUBACTID_AGENT_KEY_FILE
//   KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, DEMO_USERNAME, DEMO_PASSWORD
//   TOOL_SERVER_URL, TOOL_AUDIENCE
using System.Text.Json;
using SubactId.Sample.Agent;

// `serve` runs the agent as a service driven by the portal, instead of the scripted demo below.
if (args is ["serve", ..])
{
    return await Serve.RunAsync(args[1..]);
}

const int Steps = 8;

// The agent's registration limits.
string[] allowedScopes = ["jira:read", "jira:comment"];
var maxTaskTtl = "PT30M";
var maxTokenTtl = "PT5M";

var issuer = new Uri(Env("SUBACTID_ISSUER", "http://subactid:5100"), UriKind.Absolute);
var adminKey = File.ReadAllText(Env("SUBACTID_ADMIN_KEY_FILE", "/etc/subactid-quickstart/admin-key")).Trim();
var agentId = Env("SUBACTID_AGENT_ID", "demo-agent");
var jwksUri = Env("SUBACTID_AGENT_JWKS_URI", "https://demo-agent:8443/jwks.json");
var audience = Env("TOOL_AUDIENCE", "https://jira.internal");
var username = Env("DEMO_USERNAME", "demo");

var key = AgentKey.LoadOrCreate(Env("SUBACTID_AGENT_KEY_FILE", "/var/lib/demo-agent/agent-key.pem"), agentId);

// Serves the JWKS the control plane fetches from jwks_uri, over https.
var builder = WebApplication.CreateBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
var jwks = builder.Build();
jwks.MapGet("/jwks.json", () => Results.Content(key.Jwks, "application/json"));
await jwks.StartAsync();

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
var subactid = new ControlPlane(http, issuer, adminKey);
var keycloak = new Keycloak(http, new Uri(Env("KEYCLOAK_URL", "http://keycloak:8080"), UriKind.Absolute), Env("KEYCLOAK_REALM", "subactid-demo"), Env("KEYCLOAK_CLIENT_ID", "demo-cli"));
var tools = new ToolServer(http, new Uri(Env("TOOL_SERVER_URL", "http://tool-server:8080"), UriKind.Absolute));
using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(10));
var token = cancellation.Token;

try
{
    await RunAsync();
}
catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or JsonException or TaskCanceledException)
{
    Narrate.Failed(exception.Message);
    return 1;
}

Narrate.Banner(
    "The stack stays up",
    "  The control plane answers on http://localhost:5100, the tool server on http://localhost:8082,",
    "  and the identity provider on http://localhost:8080. Ask the ledger anything:",
    "",
    "    ADMIN_KEY=$(docker compose exec -T subactid cat /etc/subactid/admin-key)",
    "    curl -s -H \"Authorization: Bearer $ADMIN_KEY\" 'http://localhost:5100/audit?limit=50'",
    "",
    "  quickstart/README.md has more to try. Stop it all with docker compose down -v.");

await jwks.WaitForShutdownAsync();
return 0;

async Task RunAsync()
{
    Narrate.Banner(
        "Subact ID quickstart",
        "  An agent is about to act for a human. Watch what it is allowed to do,",
        "  what it is refused, and what the ledger says afterwards.");
    var since = DateTimeOffset.UtcNow.AddMinutes(-1);

    await WaitUntilAsync("the control plane", () => subactid.IsReadyAsync(token));
    await WaitUntilAsync("the tool server", () => tools.IsUpAsync(token));

    // 1. The human.
    Narrate.Step(1, Steps, $"{username} signs in at the identity provider");
    var subjectToken = await WaitForAsync("the identity provider", async () =>
    {
        var signIn = await keycloak.SignInAsync(username, Env("DEMO_PASSWORD", "demo"), token);
        return signIn.Refusal is { } refusal
            ? throw new InvalidOperationException($"the identity provider refused to sign {username} in ({refusal})")
            : signIn.AccessToken;
    });
    var human = Jwt.Payload(subjectToken);
    var sponsor = Jwt.Claim(human, "sub");
    Narrate.Detail("sub", sponsor);
    Narrate.Detail("scope", Jwt.Claim(human, "scope"));
    Narrate.Note("This token is the human's, and it stays the human's; the agent never sends it to a tool.");

    // 2. The agent.
    Narrate.Step(2, Steps, $"the agent {agentId} is registered");
    var registered = await subactid.RegisterAsync(
        new
        {
            agent_id = agentId,
            display_name = "Quickstart demo agent",
            sponsor_required = true,
            allowed_scopes = allowedScopes,
            allowed_audiences = new[] { audience },
            max_task_ttl = maxTaskTtl,
            max_token_ttl = maxTokenTtl,
            max_delegation_depth = 1,
            jwks_uri = jwksUri,
        },
        token);
    Narrate.Detail("allowed_scopes", string.Join(' ', allowedScopes));
    Narrate.Detail("allowed_audiences", audience);
    Narrate.Detail("max_task_ttl", $"{maxTaskTtl}, and max_token_ttl {maxTokenTtl}: a half-hour task never holds a half-hour credential");
    Narrate.Detail("jwks_uri", jwksUri);
    Narrate.Note(registered ? "Registered just now." : "Already registered from an earlier run; the registration is unchanged.");

    // 3. The exchange.
    Narrate.Step(3, Steps, "the agent exchanges the human's token for a scoped task token");
    var exchange = await ExchangeAsync(subjectToken, string.Join(' ', allowedScopes));
    if (exchange.Session is not { } session)
    {
        throw new InvalidOperationException($"the exchange was refused with {exchange.Error}: {exchange.Description}");
    }

    var claims = Jwt.Payload(session.AccessToken);
    Narrate.Allowed($"task {session.TaskId} started");
    Narrate.Detail("sub", $"{Jwt.Claim(claims, "sub")}   <- the human, not the agent");
    Narrate.Detail("act.sub", $"{Jwt.Claim(claims.GetProperty("act"), "sub")}   <- the agent, as the actor");
    Narrate.Detail("scope", session.Scope);
    Narrate.Detail("aud", Jwt.Claim(claims, "aud"));
    Narrate.Detail("expires_in", $"{session.ExpiresIn}s, while the task runs until {session.TaskExpiresAt:u}");

    // 4. Using it.
    Narrate.Step(4, Steps, "the agent calls the tool server with that token");
    var search = await tools.CallAsync("search", session.AccessToken, token);
    Narrate.Allowed($"search -> {search.Status} {search.Result}");
    var comment = await tools.CallAsync("comment", session.AccessToken, token);
    Narrate.Allowed($"comment -> {comment.Status} {comment.Result}");
    Narrate.Note("comment is high risk, so the tool server introspected the token instead of trusting its own check.");

    // 5. Refresh with a narrower scope.
    Narrate.Step(5, Steps, "the token runs out long before the task does, so the agent renews it");
    var renewal = await subactid.RefreshAsync(session.Grant, key.Assertion(subactid.TokenEndpoint), audience, "jira:read", token);
    if (renewal.Session is not { } narrowed)
    {
        throw new InvalidOperationException($"the refresh was refused with {renewal.Error}: {renewal.Description}");
    }

    Narrate.Allowed($"refreshed task {narrowed.TaskId}: same task, new token, scope {narrowed.Scope}");
    Narrate.Note("The identity provider was asked again whether the human is still active; a disabled user ends the task here.");
    var narrowedComment = await tools.CallAsync("comment", narrowed.AccessToken, token);
    Narrate.Denied($"comment with the narrowed token -> {narrowedComment.Status} {narrowedComment.Error}: {narrowedComment.Description}");
    Narrate.Note("Asking for less is allowed and it sticks. Asking for more never is, at any hop.");

    // 6. A denial.
    Narrate.Step(6, Steps, "the agent asks for a scope it may not have");
    var widened = await subactid.ExchangeAsync(subjectToken, key.Assertion(subactid.TokenEndpoint), audience, "payroll:write", token);
    if (widened.Session is not null)
    {
        throw new InvalidOperationException("the control plane issued a token for payroll:write, which it must never do");
    }

    Narrate.Denied($"{widened.Error}: {widened.Description}");
    Narrate.Note("A token carries the user's scopes, and the agent's, and the ones asked for: whatever is in all three.");
    Narrate.Note("The human has no payroll:write and neither does the agent, so there is nothing left to issue.");

    // 7. The kill switch.
    Narrate.Step(7, Steps, "an operator kills the task while the token is still valid");
    var revoked = await subactid.RevokeTaskAsync(session.TaskId, token);
    Narrate.Detail("revoked_tasks", revoked.ToString(System.Globalization.CultureInfo.InvariantCulture));
    var afterKill = await tools.CallAsync("comment", session.AccessToken, token);
    Narrate.Denied($"comment -> {afterKill.Status} {afterKill.Error}: {afterKill.Description}");
    Narrate.Note("The same token, still unexpired and still correctly signed. The tool server asked, and the answer had changed.");

    // 8. The ledger.
    Narrate.Step(8, Steps, $"everything any agent did for {sponsor}");
    var from = since.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
    Narrate.Note($"GET /audit?sponsor={sponsor}&from={from}");
    Console.WriteLine();
    Console.WriteLine("         seq  event            decision  reason                       scope");
    foreach (var record in await subactid.AuditAsync(sponsor, from, 50, token))
    {
        Console.WriteLine($"        {record.Seq,4}  {Fit(record.Event, 15)}  {Fit(record.Decision, 8)}  {Fit(record.Reason, 27)}  {record.Scope}");
    }

    Narrate.Note("Every line is sealed by a signed checkpoint; `SubactId.Server audit-verify` checks them.");
}

// The control plane caches agent JWKS and refetches for an unknown kid at most every thirty
// seconds, so retry once after that if the key is not known yet.
async Task<ExchangeResult> ExchangeAsync(string subjectToken, string scope)
{
    var result = await subactid.ExchangeAsync(subjectToken, key.Assertion(subactid.TokenEndpoint), audience, scope, token);
    if (result.Error != "invalid_client")
    {
        return result;
    }

    Narrate.Note("The control plane does not know this key yet; waiting for it to refetch the JWKS.");
    await Task.Delay(TimeSpan.FromSeconds(31), token);
    return await subactid.ExchangeAsync(subjectToken, key.Assertion(subactid.TokenEndpoint), audience, scope, token);
}

// Polls a dependency until it answers, so start-up order does not matter.
Task WaitUntilAsync(string what, Func<Task<bool>> probe) =>
    WaitForAsync(what, async () => await probe() ? what : null);

async Task<T> WaitForAsync<T>(string what, Func<Task<T?>> probe)
    where T : class
{
    var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
    var announced = false;
    while (DateTimeOffset.UtcNow < deadline)
    {
        if (await probe() is { } result)
        {
            return result;
        }

        if (!announced)
        {
            Narrate.Note($"Waiting for {what} to come up.");
            announced = true;
        }

        await Task.Delay(TimeSpan.FromSeconds(2), token);
    }

    throw new InvalidOperationException($"{what} did not come up within five minutes");
}

static string Fit(string? value, int width) => (value ?? "-").PadRight(width)[..width];

static string Env(string name, string fallback) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;
