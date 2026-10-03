// The quickstart's portal, where a human signs in and watches an agent act for them. The human's
// access token stays on this server and is sent to the agent once, to exchange for a task token.
// The page then shows the token's claims, renewals, revocation, and what the tool server does
// with the human's token instead of the task token.
//
// Two sign-in modes. Keycloak sets `iss` from the hostname used to sign in, and the control plane
// only accepts its discovered issuer. In compose the browser uses localhost:8080 and the control
// plane uses keycloak:8080:
//
//   password  (default)  this page collects the password and requests the token from
//                        keycloak:8080 itself, so the issuer matches. Needs no setup.
//   redirect             Keycloak's login page with authorization code and PKCE. This page never
//                        sees the password. Needs `127.0.0.1 keycloak` in your hosts file and
//                        KEYCLOAK_PUBLIC_URL=http://keycloak:8080 (see quickstart/README.md).
//
//   PORTAL_LOGIN_MODE      password | redirect
//   PORTAL_BASE_URL        where the browser reaches this portal, for the redirect URI
//   KEYCLOAK_PUBLIC_URL    where the browser reaches Keycloak
//   KEYCLOAK_URL           where this process reaches Keycloak
//   KEYCLOAK_REALM, PORTAL_CLIENT_ID
//   AGENT_URL              the agent's service API
//   SUBACTID_ISSUER, SUBACTID_ADMIN_KEY_FILE   the control plane, for the ledger the page shows
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using SubactId.Sample.Portal;

var portalBase = Env("PORTAL_BASE_URL", "http://localhost:8090").TrimEnd('/');
var keycloakPublic = Env("KEYCLOAK_PUBLIC_URL", "http://localhost:8080").TrimEnd('/');
var keycloakInternal = Env("KEYCLOAK_URL", "http://keycloak:8080").TrimEnd('/');
var realm = Env("KEYCLOAK_REALM", "subactid-demo");
var clientId = Env("PORTAL_CLIENT_ID", "demo-portal");
var loginMode = Env("PORTAL_LOGIN_MODE", "password");
var agentUrl = new Uri(Env("AGENT_URL", "http://portal-agent:8100"), UriKind.Absolute);
var issuer = new Uri(Env("SUBACTID_ISSUER", "http://subactid:5100"), UriKind.Absolute);

var adminKeyFile = Env("SUBACTID_ADMIN_KEY_FILE", "/etc/subactid-quickstart/admin-key");
var adminKey = File.Exists(adminKeyFile) ? File.ReadAllText(adminKeyFile).Trim() : null;

var redirectUri = $"{portalBase}/callback";
var sessions = new Sessions();

var builder = WebApplication.CreateBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddHttpClient();
var app = builder.Build();

var http = app.Services.GetRequiredService<IHttpClientFactory>().CreateClient();
http.Timeout = TimeSpan.FromSeconds(20);

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/healthz", () => Results.Text("ok"));

// Which sign-in the page should offer.
app.MapGet("/api/login-mode", () => Results.Json(new { mode = loginMode }));

// Password grant sign-in. A real application should not collect passwords. See the top of this
// file for why the demo does.
app.MapPost("/login", async (HttpContext context, PasswordLogin body, CancellationToken cancellationToken) =>
{
    if (!string.Equals(loginMode, "password", StringComparison.Ordinal))
    {
        return Results.BadRequest(new { error = "unsupported", error_description = "This portal signs in through Keycloak's own page." });
    }

    using var form = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "password",
        ["client_id"] = clientId,
        ["username"] = body.Username ?? string.Empty,
        ["password"] = body.Password ?? string.Empty,
        ["scope"] = "openid jira:read jira:comment",
    });

    using var response = await http.PostAsync($"{keycloakInternal}/realms/{realm}/protocol/openid-connect/token", form, cancellationToken);
    if (!response.IsSuccessStatusCode)
    {
        // A generic message, so the response does not reveal whether the account exists.
        return Results.Json(new { error = "invalid_grant", error_description = "That username and password did not work." }, statusCode: 401);
    }

    using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
    SignIn(context, document.RootElement);
    return Results.Json(new { signed_in = true });
});

// Redirects to Keycloak's login page. The portal never sees the password.
app.MapGet("/login", (HttpContext context) =>
{
    var login = sessions.Begin();
    var query = new Dictionary<string, string?>
    {
        ["client_id"] = clientId,
        ["response_type"] = "code",
        ["redirect_uri"] = redirectUri,
        ["scope"] = "openid jira:read jira:comment",
        ["state"] = login.State,
        ["code_challenge"] = Sessions.Challenge(login.Verifier),
        ["code_challenge_method"] = "S256",
    };

    var url = QueryHelpers.AddQueryString($"{keycloakPublic}/realms/{realm}/protocol/openid-connect/auth", query);
    return Results.Redirect(url);
});

app.MapGet("/callback", async (HttpContext context, string? code, string? state, string? error, CancellationToken cancellationToken) =>
{
    if (error is not null)
    {
        return Results.Redirect($"/?error={Uri.EscapeDataString(error)}");
    }

    if (sessions.Claim(state) is not { } login || code is null)
    {
        return Results.Redirect("/?error=bad_state");
    }

    using var form = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["client_id"] = clientId,
        ["code"] = code,
        ["redirect_uri"] = redirectUri,
        ["code_verifier"] = login.Verifier,
    });

    using var response = await http.PostAsync($"{keycloakInternal}/realms/{realm}/protocol/openid-connect/token", form, cancellationToken);
    var body = await response.Content.ReadAsStringAsync(cancellationToken);
    if (!response.IsSuccessStatusCode)
    {
        // Never pass the identity provider's response to the page.
        return Results.Redirect("/?error=token_exchange_failed");
    }

    using var document = JsonDocument.Parse(body);
    SignIn(context, document.RootElement);
    return Results.Redirect("/");
});

app.MapPost("/logout", (HttpContext context) =>
{
    sessions.Remove(context.Request.Cookies[Sessions.CookieName]);
    context.Response.Cookies.Delete(Sessions.CookieName);
    return Results.Ok(new { signed_out = true });
});

app.MapGet("/api/session", (HttpContext context) =>
{
    if (Current(context) is not { } session)
    {
        return Results.Json(new { authenticated = false });
    }

    return Results.Json(new
    {
        authenticated = true,
        username = session.Username,
        sub = session.Subject,
        scopes = session.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(s => s != "openid").ToArray(),
        expires_in = (int)Math.Max(0, (session.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds),
        claims = session.Claims(),
    });
});

// Everything below requires a signed-in session.
app.MapGet("/api/profiles", async (HttpContext context, CancellationToken cancellationToken) =>
    Current(context) is null ? Results.Unauthorized() : await ForwardAsync(HttpMethod.Get, "/profiles", null, cancellationToken));

app.MapGet("/api/tools", async (HttpContext context, CancellationToken cancellationToken) =>
    Current(context) is null ? Results.Unauthorized() : await ForwardAsync(HttpMethod.Get, "/tools", null, cancellationToken));

app.MapGet("/api/tasks", async (HttpContext context, CancellationToken cancellationToken) =>
    Current(context) is null ? Results.Unauthorized() : await ForwardAsync(HttpMethod.Get, "/tasks", null, cancellationToken));

app.MapGet("/api/tasks/{taskId}", async (HttpContext context, string taskId, CancellationToken cancellationToken) =>
    Current(context) is null ? Results.Unauthorized() : await ForwardAsync(HttpMethod.Get, $"/tasks/{Uri.EscapeDataString(taskId)}", null, cancellationToken));

// Sends the human's token to the agent for the exchange.
app.MapPost("/api/tasks", async (HttpContext context, StartTask body, CancellationToken cancellationToken) =>
{
    if (Current(context) is not { } session)
    {
        return Results.Unauthorized();
    }

    return await ForwardAsync(HttpMethod.Post, "/tasks", new
    {
        subjectToken = session.AccessToken,
        kind = body.Kind,
        scope = body.Scope,
    }, cancellationToken);
});

app.MapPost("/api/tasks/{taskId}/call", async (HttpContext context, string taskId, CallTool body, CancellationToken cancellationToken) =>
{
    if (Current(context) is not { } session)
    {
        return Results.Unauthorized();
    }

    // The human's token is sent only when the caller asks to try it, for that one call.
    var human = string.Equals(body.Credential, "human", StringComparison.Ordinal);
    return await ForwardAsync(HttpMethod.Post, $"/tasks/{Uri.EscapeDataString(taskId)}/call", new
    {
        tool = body.Tool,
        credential = body.Credential,
        subjectToken = human ? session.AccessToken : null,
    }, cancellationToken);
});

app.MapPost("/api/tasks/{taskId}/{action}", async (HttpContext context, string taskId, string action, CancellationToken cancellationToken) =>
{
    if (Current(context) is null)
    {
        return Results.Unauthorized();
    }

    if (action is not ("refresh" or "revoke" or "narrow"))
    {
        return Results.NotFound();
    }

    object? body = null;
    if (action == "narrow")
    {
        using var document = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: cancellationToken);
        body = new { scope = document.RootElement.TryGetProperty("scope", out var s) ? s.GetString() : null };
    }

    return await ForwardAsync(HttpMethod.Post, $"/tasks/{Uri.EscapeDataString(taskId)}/{action}", body, cancellationToken);
});

// The human's audit records. A real application would not hold the admin key. The demo does so
// it can show the audit trail.
app.MapGet("/api/audit", async (HttpContext context, CancellationToken cancellationToken) =>
{
    if (Current(context) is not { } session)
    {
        return Results.Unauthorized();
    }

    if (adminKey is null)
    {
        return Results.Json(new { records = Array.Empty<object>(), unavailable = "No admin key is mounted." });
    }

    using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(issuer, $"/audit?sponsor={Uri.EscapeDataString(session.Subject)}&limit=100"));
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminKey);
    using var response = await http.SendAsync(request, cancellationToken);
    return Results.Content(await response.Content.ReadAsStringAsync(cancellationToken), "application/json", statusCode: (int)response.StatusCode);
});

app.Run();

PortalSession? Current(HttpContext context) => sessions.Find(context.Request.Cookies[Sessions.CookieName]);

// Records the signed-in human and sets an opaque session cookie. The token stays on the server.
void SignIn(HttpContext context, JsonElement token)
{
    var accessToken = token.GetProperty("access_token").GetString()!;
    var expiresIn = token.TryGetProperty("expires_in", out var e) ? e.GetInt64() : 300;
    var id = sessions.Create(PortalSession.FromToken(accessToken, expiresIn));
    context.Response.Cookies.Append(Sessions.CookieName, id, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
    });
}

// Forwards a request to the agent's service API and returns its response unchanged.
async Task<IResult> ForwardAsync(HttpMethod method, string path, object? body, CancellationToken cancellationToken)
{
    using var request = new HttpRequestMessage(method, new Uri(agentUrl, path));
    if (body is not null)
    {
        request.Content = JsonContent.Create(body);
    }

    try
    {
        using var response = await http.SendAsync(request, cancellationToken);
        var text = await response.Content.ReadAsStringAsync(cancellationToken);
        return Results.Content(text, "application/json", statusCode: (int)response.StatusCode);
    }
    catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
    {
        return Results.Json(new { error = "agent_unreachable", error_description = "The agent is not answering yet." }, statusCode: 503);
    }
}

static string Env(string name, string fallback) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;

/// <summary>Body of <c>POST /login</c> in password mode.</summary>
internal sealed record PasswordLogin(string? Username, string? Password);

/// <summary>Body of <c>POST /api/tasks</c>.</summary>
internal sealed record StartTask(string? Kind, string? Scope);

/// <summary>Body of <c>POST /api/tasks/{id}/call</c>.</summary>
internal sealed record CallTool(string? Tool, string? Credential);
