using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Server.Admin;
using SubactId.Server.Agents;
using SubactId.Server.Audit;
using SubactId.Server.ClientAuth;
using SubactId.Server.Commands;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Discovery;
using SubactId.Server.Health;
using SubactId.Server.Hosting;
using SubactId.Server.Introspection;
using SubactId.Server.Logging;
using SubactId.Server.Logout;
using SubactId.Server.Revocation;
using SubactId.Server.Scim;
using SubactId.Server.Signals;
using SubactId.Server.Tasks;
using SubactId.Server.Tokens;
using SubactId.Server.Upstream;
using SubactId.Storage.Postgres;
using SubactId.Storage.Sqlite;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;

// A leading bare word is a command (for example "migrate"); everything else goes to the host.
var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0] : null;
var verb = command is not null && args.Length > 1 && !args[1].StartsWith('-') ? args[1] : null;

// Key generation runs before any configuration is read, so it needs no deployment settings.
if (command == KeysCommand.Name && verb == KeysCommand.GenerateVerb)
{
    return KeysCommand.RunGenerate(args[2..]);
}

// The agent verbs work on registration files and the admin API, and read no server configuration.
if (command == AgentCommand.Name)
{
    switch (verb)
    {
        case AgentCommand.InitVerb:
            return AgentCommand.RunInit(args[2..]);

        case AgentCommand.ApplyVerb:
            return await AgentCommand.RunApplyAsync(args[2..], AgentRegistrationLimits.Default, DateTimeOffset.UtcNow);

        default:
            Console.Error.WriteLine($"Unknown '{AgentCommand.Name}' verb '{verb ?? "(none)"}'. Supported verbs: {AgentCommand.InitVerb}, {AgentCommand.ApplyVerb}.");
            return AgentCommand.UsageExitCode;
    }
}

// The doctor's arguments are kept out of the host's configuration, since one may be a token.
var hostArgs = command is null ? args : args[1..];
if (command == DoctorCommand.Name)
{
    hostArgs = DoctorCommand.WithoutSubjectToken(hostArgs);
}

var builder = WebApplication.CreateBuilder(hostArgs);

var configuration = SubactIdOptionsLoader.Load(builder.Configuration);

// The doctor runs even when the configuration is invalid, so it can report what is wrong.
if (command == DoctorCommand.Name)
{
    return await DoctorCommand.RunAsync(configuration, builder.Environment.IsDevelopment(), args[1..]);
}

if (!configuration.IsValid)
{
    Console.Error.WriteLine("Subact ID cannot start because its configuration is incomplete or invalid:");
    foreach (var error in configuration.Errors)
    {
        Console.Error.WriteLine($"  - {error}");
    }

    return 1;
}

var options = configuration.Options!;

if (command == MigrateCommand.Name)
{
    return await MigrateCommand.RunAsync(options);
}

if (command == AuditVerifyCommand.Name)
{
    return await AuditVerifyCommand.RunAsync(options, args[1..]);
}

// The only command that removes audit records. Never run on a timer or at startup.
if (command == AuditArchiveCommand.Name)
{
    return await AuditArchiveCommand.RunAsync(options, args[1..], DateTimeOffset.UtcNow);
}

// Signing keys are loaded first. Outside Development, a missing or unusable key stops the
// process. A key is never generated silently.
SigningKeySet signingKeys;
bool ephemeralSigningKey;
try
{
    signingKeys = SigningKeyBootstrap.Load(options.Signing, builder.Environment.IsDevelopment(), out ephemeralSigningKey);
}
catch (SigningKeyException exception)
{
    Console.Error.WriteLine($"Subact ID cannot start: {exception.Message}");
    return 1;
}

if (command is not null)
{
    using (signingKeys)
    {
        if (command == KeysCommand.Name)
        {
            if (verb == KeysCommand.RotateVerb)
            {
                return await KeysCommand.RunRotateAsync(options, signingKeys, ephemeralSigningKey, args[2..], DateTimeOffset.UtcNow);
            }

            if (verb is not null)
            {
                Console.Error.WriteLine($"Unknown '{KeysCommand.Name}' verb '{verb}'. Supported verbs: {KeysCommand.GenerateVerb}, {KeysCommand.RotateVerb}.");
                return KeysCommand.UsageExitCode;
            }

            return KeysCommand.Run(signingKeys, ephemeralSigningKey);
        }

        Console.Error.WriteLine($"Unknown command. Supported commands: {MigrateCommand.Name}, {KeysCommand.Name}, {AuditVerifyCommand.Name}, {AuditArchiveCommand.Name}, {DoctorCommand.Name}, {AgentCommand.Name}.");
        return 2;
    }
}

// Structured JSON to stdout. The optional "Serilog" configuration section (for example
// Serilog__MinimumLevel__Default=Debug) overrides these defaults.
builder.Host.UseSerilog((context, loggerConfiguration) => loggerConfiguration
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .ReadFrom.Configuration(context.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console(new CompactJsonFormatter()));

builder.Services.AddSingleton(options);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(options.Agents);
builder.Services.AddSingleton(_ => signingKeys);
builder.Services.ConfigureHttpJsonOptions(json => SubactIdJson.Configure(json.SerializerOptions));

// Binding failures throw in every environment, so UnhandledFaultMiddleware answers them with a
// problem document.
builder.Services.Configure<RouteHandlerOptions>(route => route.ThrowOnBadRequest = true);
if (options.Database.Provider == StorageProvider.Sqlite)
{
    builder.Services.AddSqliteStorage(options.Database.Path!, deliverAudit: options.Audit.DeliveryEnabled);
}
else
{
    builder.Services.AddPostgresStorage(options.Database.ConnectionString!, deliverAudit: options.Audit.DeliveryEnabled);
}
builder.Services.AddUpstreamIdp(options.UpstreamIdp);
builder.Services.AddSubactIdLogout(options.UpstreamIdp);
builder.Services.AddClientAuthentication(options.Issuer, options.AgentKeys.BlockPrivateNetworks);
builder.Services.AddSubactIdHealthChecks();
builder.Services.AddSubactIdAdmin();
builder.Services.AddSubactIdScim(options.Scim);
// The identity provider's issuer, which iss_sub subjects in events must name: the discovery URL
// without its well-known suffix.
builder.Services.AddSubactIdSecurityEvents(options.Ssf, options.UpstreamIdp.MetadataUrl.GetLeftPart(UriPartial.Path)[..^UpstreamKeyCache.DiscoverySuffix.Length].TrimEnd('/'));
builder.Services.AddSubactIdTokenEndpoint();
builder.Services.AddSubactIdRevocation();
builder.Services.AddSubactIdIntrospection();
builder.Services.AddHostedService<TaskExpirySweeper>();

// Removes sign-outs once no subject token they refuse can still be valid. Every replica runs one;
// removing a record twice is harmless.
builder.Services.AddHostedService<SignOutPruner>();
builder.Services.AddSubactIdAuditDelivery(options.Audit);

// Seals unsealed records into signed checkpoints on a timer. Every replica runs a sealer, and
// the claim is exclusive, so each range is sealed once.
builder.Services.AddSingleton<IAuditCheckpointSignatures, SigningKeyCheckpointSignatures>();
builder.Services.AddHostedService<AuditCheckpointSealer>();

// Keeps monthly ledger partitions created ahead of the current month. There is no catch-all
// partition, and readiness fails when the current month has none.
builder.Services.AddHostedService<AuditPartitionSweeper>();

// Denial aggregation: one counter per instance, drained on a timer.
builder.Services.AddSingleton(options.Audit.Aggregation);
builder.Services.AddSingleton<DenialAggregator>();
builder.Services.AddSingleton<RenewalSummary>();
builder.Services.AddHostedService<DenialAggregationFlusher>();
builder.Services.AddSubactIdRateLimiting(options.RateLimit);
builder.Services.AddSubactIdOverloadShedding(options.Overload);

var app = builder.Build();

if (options.Admin.ApiKey is null)
{
    app.Logger.LogWarning("The admin API is disabled because SubactId:Admin:ApiKey is not set; /admin endpoints answer 503.");
}

if (options.Database.Provider == StorageProvider.Sqlite)
{
    app.Logger.LogInformation(
        "State is stored in the embedded database. One instance writes it at a time: run a single replica, on local disk, and expect no failover.");
}

if (!options.Audit.DeliveryEnabled)
{
    app.Logger.LogInformation("Audit records stay in the ledger only; set SubactId:Audit:Sink:Url to deliver them to a sink.");
}

app.Logger.LogInformation(
    "The audit ledger is sealed every {Interval}: a record written since the last checkpoint is in the ledger and guarded by it, but not yet inside a signed root. SubactId:Audit:Checkpoint:Interval is that window.",
    options.Audit.CheckpointInterval);

// Tasks are keyed by the sponsor key claim. When that is not `sub`, a signal or a provisioning
// write must name the person by that claim's value. One that names them another way matches no
// task and is still accepted, which nothing else would show, so say it once here. Back-channel
// logout is unaffected: it matches a task by its session, or else by `sub`.
if (!string.Equals(options.UpstreamIdp.SponsorKeyClaim, UpstreamIdpOptions.DefaultSponsorKeyClaim, StringComparison.Ordinal))
{
    if (options.Ssf is not null)
    {
        app.Logger.LogInformation(
            "Tasks are keyed by the '{Claim}' claim, not 'sub'. A Shared Signals event must name the person by that claim's value, as an iss_sub subject's 'sub' or an opaque subject's 'id'. One that names them by their identity provider 'sub' ends no task.",
            options.UpstreamIdp.SponsorKeyClaim);
    }

    if (options.Scim is { } scim)
    {
        app.Logger.LogInformation(
            "Tasks are keyed by the '{Claim}' claim, not 'sub'. A SCIM user's '{Attribute}' must carry that claim's value. A deactivation that names the person any other way ends no task.",
            options.UpstreamIdp.SponsorKeyClaim,
            scim.SponsorKeyAttribute == ScimSponsorKeyAttribute.UserName ? "userName" : "externalId");
    }
}

// A guarded key fetch connects directly, so the address it checks is the address it reaches. Say
// so where this process has a proxy for https, since those fetches will not go through it.
if (options.AgentKeys.BlockPrivateNetworks)
{
    var probe = new Uri("https://agent.example/");
    if (!HttpClient.DefaultProxy.IsBypassed(probe) && HttpClient.DefaultProxy.GetProxy(probe) is not null)
    {
        app.Logger.LogWarning(
            "SubactId:AgentKeys:BlockPrivateNetworks is on, so agents' keys are fetched directly and not through the proxy this process is configured with: through a proxy, the address reached could not be checked. A host with no direct route out cannot fetch them; filter at the proxy instead and turn the setting off.");
    }
}

if (options.Database.Provider != StorageProvider.Sqlite)
{
    app.Logger.LogInformation(
        "The audit ledger is partitioned by month, with {Months} month(s) kept ahead of the current one. There is no catch-all partition, so this instance is not ready while the current month has none; 'SubactId.Server migrate' makes them where this server's role may not.",
        options.Audit.PartitionMonthsAhead);

    // The retention policy is logged either way. Records only leave through audit-archive.
    if (options.Audit.Retention is { } auditRetention)
    {
        app.Logger.LogInformation(
            "Audit ledger retention is {Retention}: months older than that are exported and dropped when 'SubactId.Server audit-archive' is run. Nothing leaves the ledger on a timer.",
            auditRetention);
    }
    else
    {
        app.Logger.LogInformation(
            "The audit ledger keeps everything: SubactId:Audit:Retention is not set, so it grows without bound. 'SubactId.Server audit-archive --before <YYYY-MM> --to <directory>' is what takes a month out of it.");
    }
}

if (!options.Audit.Aggregation.Enabled)
{
    app.Logger.LogWarning(
        "Denial aggregation is off: a caller with no credential appends one audit record per request, to a table that refuses DELETE. Leave SubactId:Audit:Aggregation:Enabled on unless something else bounds that.");
}

if (options.RateLimit.Enabled && options.RateLimit.TrustedProxies.Count == 0)
{
    // Without trusted proxies, callers behind a proxy all share one limit.
    app.Logger.LogInformation(
        "Requests are limited by their socket address. Behind a proxy or an ingress that is the proxy's address for every caller, and one limit is shared by all of them; set SubactId:RateLimit:TrustedProxies to the proxy's network so the caller is counted instead.");
}
else if (!options.RateLimit.Enabled)
{
    app.Logger.LogWarning("Requests are not limited; the endpoints reachable without a credential will answer as fast as they are asked.");
}

if (ephemeralSigningKey)
{
    app.Logger.LogWarning(
        "No signing key is configured; using an ephemeral Development key {Kid}. Tokens will not verify after a restart. Configure SubactId:Signing:Keys before deploying anywhere.",
        signingKeys.Active.Kid);
}

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseSerilogRequestLogging();
// After the correlation id and request logging, so faults carry an id and the logged status is
// the one answered.
app.UseSubactIdUnhandledFaults();
app.UseSubactIdRateLimiting(options.RateLimit);
// After the per-source limiter, so one source's flood is refused before it uses shared capacity.
app.UseSubactIdOverloadShedding(options.Overload);
// Before routing, so no body is read for a caller without the admin key.
app.UseSubactIdAdminApiKey();
// The same for the SCIM credential, when SCIM is enabled.
app.UseSubactIdScimBearer(options.Scim);

app.MapSubactIdHealthEndpoints();
app.MapSubactIdDiscoveryEndpoints();
app.MapSubactIdAgentJwksEndpoint();
app.MapSubactIdTokenEndpoints();
app.MapSubactIdRevocationEndpoints();
app.MapSubactIdIntrospectionEndpoints();
app.MapSubactIdAdminEndpoints();
app.MapSubactIdLogoutEndpoints(options.UpstreamIdp);
app.MapSubactIdScimEndpoints(options.Scim);
app.MapSubactIdSecurityEventEndpoints(options.Ssf);
app.MapSubactIdAuditEndpoints();

app.Run();

return 0;

/// <summary>Entry point marker so in-process tests can host the server.</summary>
public partial class Program;
