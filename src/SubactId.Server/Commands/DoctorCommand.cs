using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Http;
using SubactId.Server.Signals;
using SubactId.Storage.Postgres;
using SubactId.Storage.Postgres.Repositories;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using PostgresContext = SubactId.Storage.Postgres.SubactIdDbContextFactory;
using SqliteContext = SubactId.Storage.Sqlite.SubactIdSqliteDbContextFactory;

namespace SubactId.Server.Commands;

/// <summary>How a check came out.</summary>
public enum DoctorStatus
{
    /// <summary>The check passed.</summary>
    Ok,

    /// <summary>The check passed but something about it is not fit for production.</summary>
    Warn,

    /// <summary>The check failed.</summary>
    Fail,
}

/// <summary>
/// One line of a <c>doctor</c> report: what was checked, how it came out, and what to do about
/// it. Never contains a token or a secret.
/// </summary>
/// <param name="Name">The short name of the check.</param>
/// <param name="Status">How it came out.</param>
/// <param name="Detail">One sentence, in plain words.</param>
/// <param name="Notes">Further lines, such as a likely cause or a configuration error list.</param>
public sealed record DoctorCheck(string Name, DoctorStatus Status, string Detail, IReadOnlyList<string>? Notes = null);

/// <summary>
/// <c>SubactId.Server doctor</c>: runs the readiness checks plus some extra ones and prints one line
/// per check. Exits non-zero if any check fails, so it works as a Helm test or CI smoke step.
/// <para>
/// Checks report failures as lines, never by throwing. Nothing printed is a token or a secret:
/// not the token given to <c>--subject-token</c>, and not an argument it does not take.
/// Configuration refuses a URL that carries credentials, so the URLs it names carry none. Other
/// configured values, such as URLs and the audience, are printed, since they are what a failure
/// is about.
/// </para>
/// </summary>
public static class DoctorCommand
{
    /// <summary>The command word on the command line.</summary>
    public const string Name = "doctor";

    /// <summary>Exit code when a check failed.</summary>
    public const int FailedExitCode = 1;

    /// <summary>Exit code for an unusable argument.</summary>
    public const int UsageExitCode = 2;

    /// <summary>Value of <c>--subject-token</c> that means "read the token from standard input".</summary>
    public const string StdinToken = "-";

    private const string SubjectTokenFlag = "--subject-token";

    /// <summary>
    /// The arguments without <c>--subject-token</c> and its value, for the host's configuration,
    /// so the token never becomes a setting.
    /// </summary>
    /// <param name="args">Arguments after the command word.</param>
    public static string[] WithoutSubjectToken(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var kept = new List<string>(args.Count);
        for (var i = 0; i < args.Count; i++)
        {
            if (args[i] == SubjectTokenFlag)
            {
                i++;
                continue;
            }

            kept.Add(args[i]);
        }

        return [.. kept];
    }

    /// <summary>Runs every check and prints the report.</summary>
    /// <param name="configuration">The result of loading configuration, valid or not.</param>
    /// <param name="isDevelopment">Whether the host runs in the Development environment.</param>
    /// <param name="args">Arguments after the command word.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="error">Where argument failures go; standard error by default.</param>
    /// <param name="clientFactory">Provides the <see cref="HttpClient"/> used to reach the identity provider.</param>
    /// <param name="stdin">Where <c>--subject-token -</c> reads from; standard input by default.</param>
    /// <param name="clock">Time source.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>0 when every check passed, <see cref="FailedExitCode"/> when one failed, <see cref="UsageExitCode"/> for a bad argument.</returns>
    public static async Task<int> RunAsync(
        SubactIdOptionsResult configuration,
        bool isDevelopment,
        IReadOnlyList<string> args,
        TextWriter? output = null,
        TextWriter? error = null,
        Func<HttpClient>? clientFactory = null,
        TextReader? stdin = null,
        TimeProvider? clock = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(args);
        output ??= Console.Out;
        error ??= Console.Error;
        clock ??= TimeProvider.System;

        if (!TryReadArguments(args, error, out var subjectTokenArgument))
        {
            return UsageExitCode;
        }

        var checks = await CollectAsync(configuration, isDevelopment, subjectTokenArgument, clientFactory, stdin, clock, cancellationToken);
        Write(output, checks);
        return checks.Any(c => c.Status == DoctorStatus.Fail) ? FailedExitCode : 0;
    }

    /// <summary>Runs every check and returns the report without printing it.</summary>
    /// <param name="configuration">The result of loading configuration, valid or not.</param>
    /// <param name="isDevelopment">Whether the host runs in the Development environment.</param>
    /// <param name="subjectToken">A subject token to validate, <see cref="StdinToken"/> to read one from <paramref name="stdin"/>, or <c>null</c> to skip that check.</param>
    /// <param name="clientFactory">Provides the <see cref="HttpClient"/> used to reach the identity provider.</param>
    /// <param name="stdin">Where <see cref="StdinToken"/> reads from; standard input by default.</param>
    /// <param name="clock">Time source.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<IReadOnlyList<DoctorCheck>> CollectAsync(
        SubactIdOptionsResult configuration,
        bool isDevelopment,
        string? subjectToken = null,
        Func<HttpClient>? clientFactory = null,
        TextReader? stdin = null,
        TimeProvider? clock = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        clock ??= TimeProvider.System;

        var checks = new List<DoctorCheck>();
        if (!configuration.IsValid)
        {
            // Nothing else can be checked without valid settings, so stop at the error list.
            checks.Add(new DoctorCheck("configuration", DoctorStatus.Fail, $"{configuration.Errors.Count} setting(s) are missing or invalid.", configuration.Errors));
            return checks;
        }

        var options = configuration.Options!;
        checks.Add(new DoctorCheck("configuration", DoctorStatus.Ok, "Loaded."));

        SigningKeySet? signingKeys = null;
        try
        {
            signingKeys = SigningKeyBootstrap.Load(options.Signing, isDevelopment, out var ephemeral);
            checks.Add(ephemeral
                ? new DoctorCheck("signing key", DoctorStatus.Warn, $"Ephemeral Development key '{signingKeys.Active.Kid}'.",
                    ["Tokens stop verifying when this process restarts. Configure SubactId__Signing__Keys__0__Path before deploying anywhere."])
                : new DoctorCheck("signing key", DoctorStatus.Ok, $"Active kid '{signingKeys.Active.Kid}', {signingKeys.Keys.Count} key(s) published."));
        }
        catch (SigningKeyException exception)
        {
            checks.Add(new DoctorCheck("signing key", DoctorStatus.Fail, exception.Message));
        }

        using (signingKeys)
        {
            using var cache = new UpstreamKeyCache(clientFactory ?? DefaultClient, options.UpstreamIdp.MetadataUrl, clock);
            var snapshot = await CheckUpstreamAsync(cache, checks, cancellationToken);
            await CheckDatabaseAsync(options, checks, cancellationToken);
            await CheckAuditPartitionsAsync(options, checks, clock, cancellationToken);
            checks.Add(options.Admin.ApiKey is null
                ? new DoctorCheck("admin API", DoctorStatus.Ok, "Disabled; /admin answers 503.")
                : new DoctorCheck("admin API", DoctorStatus.Ok, "Enabled; /admin requires the configured key."));
            checks.Add(SponsorCheckReport(options));
            checks.Add(TransportReport(options));
            checks.Add(ScimReport(options));
            checks.Add(SecurityEventReport(options));

            var token = ReadSubjectToken(subjectToken, stdin);
            if (token is not null)
            {
                await CheckSubjectTokenAsync(options, cache, token, snapshot is not null, checks, clock, cancellationToken);
            }
        }

        return checks;
    }

    /// <summary>Writes a report. One line per check, then any notes indented beneath it.</summary>
    /// <param name="output">Where the report goes.</param>
    /// <param name="checks">The checks to write.</param>
    public static void Write(TextWriter output, IReadOnlyList<DoctorCheck> checks)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(checks);

        var width = checks.Count == 0 ? 0 : checks.Max(c => c.Name.Length);
        foreach (var check in checks)
        {
            var label = check.Status switch
            {
                DoctorStatus.Ok => "ok  ",
                DoctorStatus.Warn => "warn",
                _ => "FAIL",
            };

            output.WriteLine($"{label}  {check.Name.PadRight(width)}  {check.Detail}");
            foreach (var note in check.Notes ?? [])
            {
                output.WriteLine($"{new string(' ', label.Length + width + 4)}{note}");
            }
        }

        var failed = checks.Count(c => c.Status == DoctorStatus.Fail);
        output.WriteLine();
        output.WriteLine(failed == 0
            ? $"{checks.Count} check(s), none failed."
            : $"{checks.Count} check(s), {failed.ToString(CultureInfo.InvariantCulture)} failed.");
    }

    /// <summary>
    /// Reports how this deployment learns a human may no longer be acted for. Poll mode depends on
    /// the identity provider; signals mode depends on something sending signals.
    /// </summary>
    private static DoctorCheck SponsorCheckReport(SubactIdOptions options)
    {
        if (options.UpstreamIdp.SponsorCheckMode == SponsorCheckMode.Poll)
        {
            var check = options.UpstreamIdp.SponsorCheck!;
            return new DoctorCheck("sponsor check", DoctorStatus.Ok, $"Mode 'poll'; the identity provider is asked at {check.UsersUrl}, reusing an answer for at most {check.CacheTtl}.",
                [$"This control plane authenticates there as '{check.ClientId}' with a signed assertion, whose service account needs to be able to read users."]);
        }

        return new DoctorCheck("sponsor check", DoctorStatus.Ok, "Mode 'signals'; the identity provider is not asked.",
            [
                "A human is acted for until something tells this control plane otherwise, so a task whose sponsor is disabled at the provider runs to its own expiry unless a signal arrives.",
                $"Tasks are keyed by the '{options.UpstreamIdp.SponsorKeyClaim}' claim, which is what a signal about a person must name them by.",
            ]);
    }

    /// <summary>
    /// Warns about the two settings that loosen how this control plane reaches other hosts. Neither
    /// is a failure: both have deployments that need them.
    /// </summary>
    private static DoctorCheck TransportReport(SubactIdOptions options)
    {
        var notes = new List<string>();
        if (options.AllowInsecureHttp)
        {
            notes.Add("SubactId__AllowInsecureHttp is on: the issuer, the identity provider, the Shared Signals transmitter or the audit sink may be plain http on a network. Turn it off outside a demo or a network you trust.");
        }

        if (!options.AgentKeys.BlockPrivateNetworks)
        {
            notes.Add("SubactId__AgentKeys__BlockPrivateNetworks is off: an agent registered with a jwks_uri on an internal or metadata address is fetched from it. Only the admin API can register one. Turn it on unless agents publish their keys on a private network, or filter at an egress proxy.");
        }

        return notes.Count == 0
            ? new DoctorCheck("outbound", DoctorStatus.Ok, "https only, and agents' keys are fetched from public addresses only.")
            : new DoctorCheck("outbound", DoctorStatus.Warn, $"{notes.Count} setting(s) loosen how other hosts are reached.", notes);
    }

    /// <summary>
    /// Reports whether the SCIM receiver is on and which attribute a deactivation is keyed by. A
    /// wrong attribute accepts every write and silently blocks nobody.
    /// </summary>
    private static DoctorCheck ScimReport(SubactIdOptions options)
    {
        if (options.Scim is not { } scim)
        {
            return new DoctorCheck("SCIM receiver", DoctorStatus.Ok, "Not configured; /scim answers 404.");
        }

        var attribute = scim.SponsorKeyAttribute == ScimSponsorKeyAttribute.UserName ? "userName" : "externalId";
        var notes = new List<string>
        {
            $"A provisioned user is matched to tasks by its '{attribute}', which must carry the same value as the '{options.UpstreamIdp.SponsorKeyClaim}' claim of that person's subject token.",
            $"At most {scim.MaxUsers.ToString(CultureInfo.InvariantCulture)} users are held; a create past that is refused.",
        };
        if (scim.PreviousBearerToken is not null)
        {
            notes.Add("Two credentials are accepted: a rotation is in progress, and the previous one still works. Remove it once the client has the new one.");
        }

        return new DoctorCheck("SCIM receiver", DoctorStatus.Ok, "Configured; /scim/v2/Users accepts a provisioning client with the configured bearer credential.", notes);
    }

    /// <summary>
    /// Reports whether the Shared Signals receiver is on and whose signature it expects. The
    /// transmitter has its own issuer and keys, distinct from the identity provider's.
    /// </summary>
    private static DoctorCheck SecurityEventReport(SubactIdOptions options)
    {
        if (options.Ssf is not { } ssf)
        {
            return new DoctorCheck("signals receiver", DoctorStatus.Ok, $"Not configured; {SecurityEventEndpoints.EventsPath} answers 404.");
        }

        var notes = new List<string>
        {
            $"Events must be signed by a key published at {ssf.MetadataUrl} and carry '{ssf.Audience}' as their audience.",
            "A subject in iss_sub form must name the identity provider above; one in opaque form carries the key tasks are stored under.",
            $"Either way, the subject value is matched against the '{options.UpstreamIdp.SponsorKeyClaim}' claim tasks are keyed by.",
        };
        if (!string.Equals(options.UpstreamIdp.SponsorKeyClaim, UpstreamIdpOptions.DefaultSponsorKeyClaim, StringComparison.Ordinal))
        {
            notes.Add(
                $"The sponsor key claim is '{options.UpstreamIdp.SponsorKeyClaim}', not 'sub': the transmitter must put that value in the subject (an iss_sub 'sub', or an opaque 'id'). An event that names the person by their raw IdP 'sub' will end no task.");
        }
        if (ssf.PreviousBearerToken is not null)
        {
            notes.Add("Two push credentials are accepted: a rotation is in progress. Remove the previous one once the transmitter has the new one.");
        }

        return new DoctorCheck("signals receiver", DoctorStatus.Ok, $"Configured; {SecurityEventEndpoints.EventsPath} accepts a transmitter presenting the configured credential and a signed event.", notes);
    }

    private static async Task<UpstreamKeySnapshot?> CheckUpstreamAsync(UpstreamKeyCache cache, List<DoctorCheck> checks, CancellationToken cancellationToken)
    {
        try
        {
            var snapshot = await cache.GetAsync(cancellationToken);
            if (snapshot.Keys.Count == 0)
            {
                checks.Add(new DoctorCheck("upstream", DoctorStatus.Fail, $"The JWKS of '{snapshot.Issuer}' contains no usable signing key.",
                    ["Every key was rejected as unusable: an unsupported key type, or a missing kid."]));
                return null;
            }

            checks.Add(new DoctorCheck("upstream", DoctorStatus.Ok, $"Issuer '{snapshot.Issuer}', {snapshot.Keys.Count} signing key(s)."));
            return snapshot;
        }
        catch (UpstreamDiscoveryException exception)
        {
            checks.Add(new DoctorCheck("upstream", DoctorStatus.Fail, exception.Message, [LikelyCause(exception.Fault, cache.ExpectedIssuer)]));
            return null;
        }
        catch (HttpRequestException exception) when (exception.StatusCode is { } status && (int)status is >= 300 and < 400)
        {
            checks.Add(new DoctorCheck("upstream", DoctorStatus.Fail,
                $"The identity provider answered with a redirect ({((int)status).ToString(CultureInfo.InvariantCulture)}). The control plane never follows one, so it cannot fetch the keys.",
                ["Likely cause: a URL it is reached at is not the one it answers on, such as http where it redirects to https. Set SubactId__UpstreamIdp__Issuer to the realm URL it redirects to; if the jwks_uri it advertises is what redirects, fix its frontend URL instead."]));
            return null;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            checks.Add(new DoctorCheck("upstream", DoctorStatus.Fail, "The discovery document could not be fetched.",
            [
                $"Likely cause: nothing is serving {cache.ExpectedIssuer} from here, or the request timed out.",
                "Check the host is resolvable and reachable from this pod, and that SubactId__UpstreamIdp__Issuer is the realm URL.",
            ]));
            return null;
        }
    }

    private static string LikelyCause(UpstreamDiscoveryFault fault, string expectedIssuer) => fault switch
    {
        UpstreamDiscoveryFault.IssuerMismatch =>
            $"Likely cause: the identity provider's frontend URL differs from the URL it is reached on. It must declare '{expectedIssuer}' as its issuer; in Keycloak that is the realm's frontend URL or KC_HOSTNAME.",
        UpstreamDiscoveryFault.JwksNotHttps =>
            "Likely cause: the identity provider advertises an http jwks_uri while discovery was fetched over https. Fix its frontend URL rather than downgrading this.",
        UpstreamDiscoveryFault.NoIssuer or UpstreamDiscoveryFault.NoJwksUri =>
            "Likely cause: the URL is not an OIDC discovery document; a proxy or login page answered instead.",
        UpstreamDiscoveryFault.NotJson =>
            "Likely cause: a proxy, login page or error page answered instead of the discovery document.",
        UpstreamDiscoveryFault.NoKeysArray =>
            "Likely cause: the jwks_uri does not serve a JWKS.",
        UpstreamDiscoveryFault.TooLarge =>
            "Likely cause: the URL serves something other than a discovery document or JWKS.",
        _ => "Likely cause: the identity provider is not serving a usable discovery document.",
    };

    private static async Task CheckDatabaseAsync(SubactIdOptions options, List<DoctorCheck> checks, CancellationToken cancellationToken)
    {
        var provider = options.Database.Provider == StorageProvider.Sqlite ? "sqlite" : "postgres";
        try
        {
            await using var db = options.Database.Provider == StorageProvider.Sqlite
                ? SqliteContext.Create(options.Database.Path!)
                : PostgresContext.Create(options.Database.ConnectionString!);

            // Reads the migration history only. Only "migrate" applies migrations.
            var pending = (await db.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();
            checks.Add(pending.Count == 0
                ? new DoctorCheck("database", DoctorStatus.Ok, $"Reachable ({provider}), schema up to date.")
                : new DoctorCheck("database", DoctorStatus.Fail, $"Reachable ({provider}), but {pending.Count} migration(s) have not been applied.",
                    ["Run 'SubactId.Server migrate' with the migration credentials. This command never applies them."]));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            checks.Add(new DoctorCheck("database", DoctorStatus.Fail, $"The {provider} database could not be read ({exception.GetType().Name}).",
                ["Check the host, port and credentials, and that this pod may reach the database."]));
        }
    }

    /// <summary>
    /// Checks the ledger's partitions and that each carries its own append-only guard, since a
    /// <c>TRUNCATE</c> on a partition checks only that partition's privileges and triggers.
    /// <para>
    /// A missing partition for the current month is a failure: every append, and so every
    /// exchange, is refused.
    /// </para>
    /// </summary>
    private static async Task CheckAuditPartitionsAsync(SubactIdOptions options, List<DoctorCheck> checks, TimeProvider clock, CancellationToken cancellationToken)
    {
        const string CheckName = "audit partitions";

        if (options.Database.Provider == StorageProvider.Sqlite)
        {
            checks.Add(new DoctorCheck(CheckName, DoctorStatus.Ok, "Not partitioned; the embedded provider keeps the ledger in one table.",
                ["Records are never removed from it: detaching a partition is how a ledger sheds history without weakening the guard, and there is none to detach here."]));
            return;
        }

        AuditLedgerLayout layout;
        try
        {
            await using var dataSource = SubactIdDataSourceFactory.Create(options.Database.ConnectionString!);
            layout = await new PostgresAuditLedgerPartitions(dataSource).InspectAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            checks.Add(new DoctorCheck(CheckName, DoctorStatus.Fail, $"The ledger's partitions could not be read ({exception.GetType().Name})."));
            return;
        }

        if (!layout.Partitioned)
        {
            checks.Add(new DoctorCheck(CheckName, DoctorStatus.Fail, "The audit ledger is not a partitioned table.",
                ["Run 'SubactId.Server migrate' with the migration credentials. This command never applies migrations."]));
            return;
        }

        var now = clock.GetUtcNow();
        var unguarded = layout.Partitions.Where(p => !p.Guarded).ToList();
        var notes = new List<string>();
        foreach (var partition in unguarded)
        {
            notes.Add(partition switch
            {
                { Month: null } => $"'{partition.Name}' is a partition of the ledger that this control plane did not create, so nothing has checked the month it claims to hold.",
                { RefusesTruncate: false, PrivilegesRevoked: false } => $"'{partition.Name}' carries neither guard: a TRUNCATE naming it would destroy every record in it.",
                { RefusesTruncate: false } => $"'{partition.Name}' has no BEFORE TRUNCATE trigger, so only the revoked privilege stands between it and a TRUNCATE.",
                _ => $"'{partition.Name}' has not had UPDATE, DELETE and TRUNCATE revoked, so only the trigger stands between it and a TRUNCATE.",
            });
        }

        var ahead = layout.MonthsAhead(now);
        if (ahead is null)
        {
            notes.Insert(0, "Run 'SubactId.Server migrate' with the migration credentials, which creates this month and the runway after it that SubactId:Audit:Partitions:MonthsAhead asks for.");
            checks.Add(new DoctorCheck(CheckName, DoctorStatus.Fail,
                $"{layout.Partitions.Count} partition(s), but none for {now.ToString("yyyy-MM", CultureInfo.InvariantCulture)}: every append would be refused, and this instance would never become ready.",
                notes));
            return;
        }

        if (unguarded.Count > 0)
        {
            checks.Add(new DoctorCheck(CheckName, DoctorStatus.Fail,
                $"{layout.Partitions.Count} partition(s), {ahead.Value.ToString(CultureInfo.InvariantCulture)} month(s) ahead of this one, and {unguarded.Count.ToString(CultureInfo.InvariantCulture)} of them not guarded.",
                notes));
            return;
        }

        checks.Add(ahead.Value >= options.Audit.PartitionMonthsAhead
            ? new DoctorCheck(CheckName, DoctorStatus.Ok,
                $"{layout.Partitions.Count} partition(s), all guarded, {ahead.Value.ToString(CultureInfo.InvariantCulture)} month(s) ahead of this one.")
            : new DoctorCheck(CheckName, DoctorStatus.Warn,
                $"{layout.Partitions.Count} partition(s), all guarded, but only {ahead.Value.ToString(CultureInfo.InvariantCulture)} month(s) ahead of this one.",
                [$"The server tops this back up to {options.Audit.PartitionMonthsAhead.ToString(CultureInfo.InvariantCulture)} month(s), at start and hourly after. If it stays short, its role may not create partitions here; run 'SubactId.Server migrate' with the migration credentials, which does."]));
    }

    private static async Task CheckSubjectTokenAsync(
        SubactIdOptions options,
        UpstreamKeyCache cache,
        string token,
        bool upstreamReachable,
        List<DoctorCheck> checks,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!upstreamReachable)
        {
            checks.Add(new DoctorCheck("subject token", DoctorStatus.Fail, "Not checked: the upstream keys could not be fetched."));
            return;
        }

        var validation = await new UpstreamTokenValidator(cache, options.UpstreamIdp.Audience, clock, options.UpstreamIdp.SubjectTokenTypes).ValidateAsync(token, cancellationToken);
        if (validation.IsValid)
        {
            var principal = validation.Principal!;
            var keyClaim = options.UpstreamIdp.SponsorKeyClaim;
            if (principal.FindStringClaim(keyClaim) is null)
            {
                checks.Add(new DoctorCheck("subject token", DoctorStatus.Fail, $"Accepted, but it carries no usable '{keyClaim}' claim, so an exchange with it is invalid_grant.",
                    [$"SubactId:UpstreamIdp:SponsorKeyClaim names the claim each task is keyed by. Either the token needs a mapper emitting '{keyClaim}' as a string, or the setting names the wrong claim."]));
                return;
            }

            checks.Add(new DoctorCheck("subject token", DoctorStatus.Ok,
                $"Accepted: sub '{principal.Subject}' from '{principal.Issuer}', expiring {principal.ExpiresAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)}.",
                [principal.Scopes.Count == 0 ? "The token carries no scope claim." : $"Scopes: {string.Join(' ', principal.Scopes)}."]));
            return;
        }

        checks.Add(new DoctorCheck("subject token", DoctorStatus.Fail, $"Rejected: {validation.Reason}.", [RejectionAdvice(validation.Reason, options)]));
    }

    private static string RejectionAdvice(UpstreamRejection reason, SubactIdOptions options) => reason switch
    {
        UpstreamRejection.AudienceMismatch =>
            $"The token's aud does not include '{options.UpstreamIdp.Audience}'. Keycloak issues the client itself and 'account' by default, so the client needs an audience mapper emitting '{options.UpstreamIdp.Audience}'.",
        UpstreamRejection.UntrustedIssuer =>
            "The token's iss is not the configured upstream issuer. It was issued by a different realm, or the realm's frontend URL differs from the one configured here.",
        UpstreamRejection.UnknownKey =>
            "The token names a kid the identity provider does not publish. It was signed by a realm other than the configured one, or by a key that has since been removed.",
        UpstreamRejection.Expired =>
            "The token has expired. Get a fresh one; this is not a configuration problem.",
        UpstreamRejection.NotYetValid =>
            "The token is not valid yet, beyond 60 seconds of skew. Check the clocks on both hosts.",
        UpstreamRejection.Malformed =>
            "The value is not a canonical compact JWS, or a claim has the wrong shape. Check that a whole access token was passed, not a refresh token or an id token fragment.",
        UpstreamRejection.UnsupportedAlgorithm =>
            "The token's alg is not RS256, PS256 or ES256. Change the realm's token signature algorithm.",
        UpstreamRejection.UnacceptedType =>
            $"The token's typ header is missing or is not one SubactId:UpstreamIdp:SubjectTokenTypes accepts ({string.Join(", ", options.UpstreamIdp.SubjectTokenTypes)}). Keycloak marks access tokens 'JWT' unless the client is set to issue RFC 9068 'at+jwt' access tokens; see docs/keycloak.md.",
        UpstreamRejection.MissingSubject or UpstreamRejection.SubTooLong =>
            "The token's sub is missing or too long. A subject token must identify a human; a service account token does not.",
        UpstreamRejection.InvalidSignature =>
            "The signature does not verify against the published key of that kid.",
        _ => "See docs/spec/v0.1.md for what a subject token must carry.",
    };

    private static string? ReadSubjectToken(string? argument, TextReader? stdin)
    {
        if (argument is null)
        {
            return null;
        }

        if (argument != StdinToken)
        {
            return argument;
        }

        // Standard input keeps the token out of the process list. It is never written back out.
        var read = (stdin ?? Console.In).ReadToEnd().Trim();
        return read.Length == 0 ? null : read;
    }

    // Built as the server's identity provider client is, so the report says what the server would
    // see: a redirect is not followed.
    private static HttpClient DefaultClient()
    {
        var client = new HttpClient(HardenedHttpHandler.Create(blockPrivateNetworks: false)) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    private static bool TryReadArguments(IReadOnlyList<string> args, TextWriter error, out string? subjectToken)
    {
        subjectToken = null;

        for (var i = 0; i < args.Count; i++)
        {
            // Named by position, never repeated: it may be a token given the wrong way, such as
            // --subject-token=<jwt>, or a setting that holds a secret.
            if (args[i] != SubjectTokenFlag)
            {
                error.WriteLine($"Argument {(i + 1).ToString(CultureInfo.InvariantCulture)} is not an argument of '{Name}', and is not repeated in case it holds a token or a secret. Usage: {Name} [{SubjectTokenFlag} <jwt>|{StdinToken}].");
                return false;
            }

            if (subjectToken is not null)
            {
                error.WriteLine($"{SubjectTokenFlag} was given more than once. Usage: {Name} [{SubjectTokenFlag} <jwt>|{StdinToken}].");
                return false;
            }

            if (i + 1 >= args.Count || args[i + 1].Length == 0)
            {
                error.WriteLine($"{SubjectTokenFlag} needs a value, or {StdinToken} to read one from standard input.");
                return false;
            }

            subjectToken = args[++i];
        }

        return true;
    }
}
