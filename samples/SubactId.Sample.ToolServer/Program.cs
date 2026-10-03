// A sample tool server: a fake Jira that only an agent acting for a human may call.
// It does what spec section 9 requires of a tool server: verify the task token against the
// control plane's keys, enforce the route's scope, introspect for high-risk tools and for every
// token that carries introspect_required, and log the human and the agent on every call. It uses
// only the platform, so every step is visible.
//
//   SUBACTID_ISSUER    the control plane, for example http://subactid:5100
//   TOOL_AUDIENCE  the audience this server answers for, for example https://jira.internal
using System.Net.Http.Headers;
using Microsoft.Extensions.Primitives;
using SubactId.Sample.ToolServer;

var issuer = new Uri(Environment.GetEnvironmentVariable("SUBACTID_ISSUER") ?? "http://subactid:5100", UriKind.Absolute);
var audience = Environment.GetEnvironmentVariable("TOOL_AUDIENCE") ?? "https://jira.internal";

// The policy. Unlisted tools do not exist.
var tools = new Dictionary<string, Tool>(StringComparer.Ordinal)
{
    ["search"] = new("jira:read", HighRisk: false),
    ["comment"] = new("jira:comment", HighRisk: true),
};

var builder = WebApplication.CreateBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddHttpClient();
var app = builder.Build();

var http = app.Services.GetRequiredService<IHttpClientFactory>().CreateClient();
http.Timeout = TimeSpan.FromSeconds(10);
var verifier = new TaskTokenVerifier(http, issuer, audience, maxDelegationDepth: 1, TimeProvider.System);
var introspection = new Introspection(http, issuer);

app.MapGet("/healthz", () => Results.Text("ok"));

app.MapGet("/", () => Results.Json(new
{
    audience,
    control_plane = issuer.AbsoluteUri,
    tools = tools.ToDictionary(t => t.Key, t => new { scope = t.Value.Scope, high_risk = t.Value.HighRisk }),
}));

app.MapPost("/tools/{tool}", async (string tool, HttpContext context, CancellationToken cancellationToken) =>
{
    if (!tools.TryGetValue(tool, out var policy))
    {
        CallLog.Write(tool, "refused", "unknown_tool", null);
        return Problem(context, StatusCodes.Status404NotFound, "invalid_request", "No such tool.");
    }

    var presented = Bearer(context.Request.Headers.Authorization);
    var (token, refusal) = await verifier.VerifyAsync(presented, cancellationToken);
    if (token is null)
    {
        CallLog.Write(tool, "refused", refusal, null);
        return Problem(context, StatusCodes.Status401Unauthorized, "invalid_token", "The task token was refused.");
    }

    if (!token.Scopes.Contains(policy.Scope))
    {
        CallLog.Write(tool, "refused", "insufficient_scope", token);
        return Problem(context, StatusCodes.Status403Forbidden, "insufficient_scope", $"This tool needs the {policy.Scope} scope.");
    }

    // High risk: also introspect, since only the control plane knows about a revocation. A token
    // carrying introspect_required is high risk whatever this server thinks of the tool.
    if (policy.HighRisk || token.IntrospectRequired)
    {
        var (active, reason) = await introspection.CheckAsync(presented!, cancellationToken);
        if (!active)
        {
            CallLog.Write(tool, "refused", reason, token);
            return Problem(context, StatusCodes.Status401Unauthorized, "invalid_token", "The control plane says this token is not live.");
        }
    }

    CallLog.Write(tool, "allowed", null, token);
    return Results.Json(new
    {
        tool,
        result = tool switch
        {
            "search" => "PROJ-1 Login fails on Firefox; PROJ-7 Flaky checkout test",
            _ => "Comment added to PROJ-1.",
        },
        on_behalf_of = token.Subject,
        acted_by = token.Agent,
    });
});

app.Run();

static string? Bearer(StringValues header) =>
    AuthenticationHeaderValue.TryParse(header.ToString(), out var value) && string.Equals(value.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
        ? value.Parameter
        : null;

// RFC 6750 section 3 error response. Never echoes the token.
static IResult Problem(HttpContext context, int status, string error, string description)
{
    if (status is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
    {
        context.Response.Headers.WWWAuthenticate = $"Bearer error=\"{error}\"";
    }

    return Results.Json(new { error, error_description = description }, statusCode: status);
}

internal sealed record Tool(string Scope, bool HighRisk);
