using System.Data.Common;
using System.Globalization;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef.Repositories;
using SubactId.Tokens.Signing;
using PostgresContext = SubactId.Storage.Postgres.SubactIdDbContextFactory;
using SqliteContext = SubactId.Storage.Sqlite.SubactIdSqliteDbContextFactory;

namespace SubactId.Server.Commands;

/// <summary>One published key: the number it is configured under and the id it resolved to.</summary>
/// <param name="Index">The <c>N</c> in <c>SubactId:Signing:Keys:N</c>.</param>
/// <param name="Kid">The key id in JWKS, explicit or the RFC 7638 thumbprint.</param>
public readonly record struct PublishedKey(int Index, string Kid);

/// <summary>How long a retired key must stay published after it stops signing, and why.</summary>
/// <param name="After">The longest a token signed by the retiring key can still be presented.</param>
/// <param name="Source">A sentence fragment naming where <see cref="After"/> was read from.</param>
public sealed record KeyRetirement(TimeSpan After, string Source);

/// <summary>
/// <c>SubactId.Server keys</c>: loads the signing keys as the server would, prints the public JWKS
/// and the active kid, then exits. Prints nothing private.
/// <para>
/// <c>keys generate</c> writes a new key and the setting that configures it. <c>keys rotate</c>
/// writes a new key and the three-step rollout that replaces the current one. See
/// <c>docs/keys.md</c>.
/// </para>
/// </summary>
public static class KeysCommand
{
    /// <summary>The command word on the command line.</summary>
    public const string Name = "keys";

    /// <summary>Verb that writes a new key and the setting to configure it under.</summary>
    public const string GenerateVerb = "generate";

    /// <summary>Verb that writes a new key and the rollout that retires the current one.</summary>
    public const string RotateVerb = "rotate";

    /// <summary>Exit code for an unusable argument.</summary>
    public const int UsageExitCode = 2;

    private const string OutFlag = "--out";
    private const string KidFlag = "--kid";

    /// <summary>Runs the command with no verb: prints the JWKS and the active kid.</summary>
    /// <param name="keys">The loaded key set.</param>
    /// <param name="ephemeral">Whether the set was generated rather than configured.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <returns>Process exit code.</returns>
    public static int Run(SigningKeySet keys, bool ephemeral, TextWriter? output = null)
    {
        ArgumentNullException.ThrowIfNull(keys);
        output ??= Console.Out;

        if (ephemeral)
        {
            output.WriteLine("No signing key is configured; this is an ephemeral Development key.");
        }

        output.WriteLine(keys.ToJwks().ToJson());
        output.WriteLine($"Active kid: {keys.Active.Kid}");
        return 0;
    }

    /// <summary>
    /// <c>keys generate --out &lt;path&gt; [--kid &lt;name&gt;]</c>: writes a new P-256 key and prints the
    /// setting that configures it. Reads no configuration.
    /// </summary>
    /// <param name="args">Arguments after the verb.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="error">Where failures go; standard error by default.</param>
    /// <returns>0 on success, 1 when the key could not be written, <see cref="UsageExitCode"/> for a bad argument.</returns>
    public static int RunGenerate(IReadOnlyList<string> args, TextWriter? output = null, TextWriter? error = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        output ??= Console.Out;
        error ??= Console.Error;

        if (!TryReadArguments(GenerateVerb, args, error, out var path, out var kid))
        {
            return UsageExitCode;
        }

        SigningKey key;
        try
        {
            key = SigningKeyFile.Create(path, kid);
        }
        catch (SigningKeyException exception)
        {
            error.WriteLine(exception.Message);
            return 1;
        }

        using (key)
        {
            WriteWrote(output, path, key, kid);
            output.WriteLine();
            output.WriteLine("Configure the server with:");
            foreach (var setting in Settings(0, path, kid))
            {
                output.WriteLine($"    {setting}");
            }
        }

        return 0;
    }

    /// <summary>
    /// <c>keys rotate --out &lt;path&gt; [--kid &lt;name&gt;]</c>: writes a new key beside the configured
    /// ones and prints the rollout that makes it the signer and retires the current one.
    /// </summary>
    /// <param name="options">Validated configuration.</param>
    /// <param name="keys">The key set as the server would load it.</param>
    /// <param name="ephemeral">Whether that set was generated rather than configured.</param>
    /// <param name="args">Arguments after the verb.</param>
    /// <param name="now">The current time.</param>
    /// <param name="output">Where the report goes; standard output by default.</param>
    /// <param name="error">Where failures go; standard error by default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>0 on success, 1 when there is nothing to rotate or the key could not be written, <see cref="UsageExitCode"/> for a bad argument.</returns>
    public static async Task<int> RunRotateAsync(
        SubactIdOptions options,
        SigningKeySet keys,
        bool ephemeral,
        IReadOnlyList<string> args,
        DateTimeOffset now,
        TextWriter? output = null,
        TextWriter? error = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(args);
        output ??= Console.Out;
        error ??= Console.Error;

        if (!TryReadArguments(RotateVerb, args, error, out var path, out var kid))
        {
            return UsageExitCode;
        }

        if (ephemeral)
        {
            error.WriteLine($"No signing key is configured, so there is nothing to rotate. Use '{Name} {GenerateVerb}' to make the first one.");
            return 1;
        }

        var retirement = await ReadRetirementAsync(options, cancellationToken);

        SigningKey key;
        try
        {
            key = SigningKeyFile.Create(path, kid);
        }
        catch (SigningKeyException exception)
        {
            error.WriteLine(exception.Message);
            return 1;
        }

        using (key)
        {
            WriteWrote(output, path, key, kid);
            output.WriteLine();
            WriteRollout(output, Published(options.Signing, keys), keys.Active.Kid, key.Kid, path, kid, retirement, now);
        }

        return 0;
    }

    /// <summary>
    /// Writes the three-step rollout: the settings to change at each step, and when the retired key
    /// may stop being published. Writes only to <paramref name="output"/>.
    /// </summary>
    /// <param name="output">Where the rollout goes.</param>
    /// <param name="published">The currently configured keys, in publication order.</param>
    /// <param name="activeKid">The key currently signing.</param>
    /// <param name="newKid">The id of the newly written key.</param>
    /// <param name="newPath">Where the newly written key is.</param>
    /// <param name="explicitKid">The <c>--kid</c> given for the new key, or <c>null</c> for its thumbprint.</param>
    /// <param name="retirement">How long the retiring key must stay published after step 2.</param>
    /// <param name="now">The current time, used to date step 3.</param>
    public static void WriteRollout(
        TextWriter output,
        IReadOnlyList<PublishedKey> published,
        string activeKid,
        string newKid,
        string newPath,
        string? explicitKid,
        KeyRetirement retirement,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(published);
        ArgumentException.ThrowIfNullOrWhiteSpace(activeKid);
        ArgumentNullException.ThrowIfNull(retirement);

        // The new key takes the index after the highest in use, never a gap, which an operator
        // may be about to reuse.
        var newIndex = published.Count == 0 ? 0 : published.Max(k => k.Index) + 1;
        int? retiringIndex = null;
        foreach (var key in published)
        {
            if (string.Equals(key.Kid, activeKid, StringComparison.Ordinal))
            {
                retiringIndex = key.Index;
                break;
            }
        }

        output.WriteLine($"Currently configured: {published.Count} key(s), signing with '{activeKid}'.");
        output.WriteLine();
        output.WriteLine("Roll it out in three steps, deploying after each one.");
        output.WriteLine();

        output.WriteLine("Step 1 - publish the new key without signing with it:");
        foreach (var setting in Settings(newIndex, newPath, explicitKid))
        {
            output.WriteLine($"    {setting}");
        }

        // With one key the active kid may be unset. A second key makes it required, so step 1
        // sets it.
        output.WriteLine($"    SubactId__Signing__ActiveKid={activeKid}");
        output.WriteLine($"  Both keys are then in JWKS. Tokens are still signed by '{activeKid}'.");
        output.WriteLine();

        output.WriteLine("Step 2 - start signing with the new key:");
        output.WriteLine($"    SubactId__Signing__ActiveKid={newKid}");
        output.WriteLine($"  Tokens signed by '{activeKid}' keep verifying: it is still published.");
        output.WriteLine();

        var retireAt = now.ToUniversalTime() + retirement.After;
        output.WriteLine($"Step 3 - stop publishing the retired key, no earlier than {retirement.After.ToString("c", CultureInfo.InvariantCulture)} after step 2 is deployed:");
        output.WriteLine(retiringIndex is { } number
            ? $"    remove SubactId__Signing__Keys__{number.ToString(CultureInfo.InvariantCulture)}__* (the entry for '{activeKid}')"
            : $"    remove the SubactId__Signing__Keys entry for '{activeKid}'");
        output.WriteLine($"  A token signed by '{activeKid}' can still be presented for that long, so");
        output.WriteLine("  removing the key any earlier breaks it.");
        output.WriteLine($"  The wait comes from {retirement.Source}");
        output.WriteLine($"  If step 2 is deployed now, step 3 is due after {retireAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)}.");
    }

    /// <summary>Pairs each configured key with the id it resolved to, in publication order.</summary>
    /// <param name="signing">The signing configuration.</param>
    /// <param name="keys">The set loaded from it.</param>
    private static IReadOnlyList<PublishedKey> Published(SigningOptions signing, SigningKeySet keys) =>
        [.. signing.Keys.Zip(keys.Keys, (configured, key) => new PublishedKey(configured.Index, key.Kid))];

    /// <summary>
    /// How long a retired key must stay published: the largest <c>max_token_ttl</c> in the
    /// registry, the default token TTL when no agent is registered, or the server-wide ceiling
    /// when the registry cannot be read.
    /// </summary>
    private static async Task<KeyRetirement> ReadRetirementAsync(SubactIdOptions options, CancellationToken cancellationToken)
    {
        try
        {
            await using var db = options.Database.Provider == StorageProvider.Sqlite
                ? SqliteContext.Create(options.Database.Path!)
                : PostgresContext.Create(options.Database.ConnectionString!);

            var longest = await new EfAgentQuery(db).LongestMaxTokenTtlAsync(cancellationToken);
            return longest is { } ttl
                ? new KeyRetirement(ttl, "the longest max_token_ttl of any registered agent.")
                : new KeyRetirement(options.Tokens.DefaultTokenTtl, "SubactId:Tokens:DefaultTokenTtl, because no agent is registered.");
        }
        catch (Exception exception) when (exception is DbException or InvalidOperationException or TimeoutException or IOException)
        {
            // Fall back to the ceiling. The note names neither the database nor the failure.
            return new KeyRetirement(
                options.Agents.MaxTokenTtl,
                "SubactId:Agents:MaxTokenTtl, the longest any agent could hold, because the registry could not be read; check it against your registered agents.");
        }
    }

    private static void WriteWrote(TextWriter output, string path, SigningKey key, string? explicitKid)
    {
        output.WriteLine($"Wrote a new P-256 signing key to {path}, readable by its owner only.");
        output.WriteLine(explicitKid is null
            ? $"Key id: {key.Kid} (RFC 7638 thumbprint)"
            : $"Key id: {key.Kid} (set with {KidFlag}; its RFC 7638 thumbprint is {SigningKey.Thumbprint(key.PublicJwk.X, key.PublicJwk.Y)})");
    }

    private static IEnumerable<string> Settings(int index, string path, string? explicitKid)
    {
        var number = index.ToString(CultureInfo.InvariantCulture);
        yield return $"SubactId__Signing__Keys__{number}__Path={path}";
        if (explicitKid is not null)
        {
            yield return $"SubactId__Signing__Keys__{number}__Kid={explicitKid}";
        }
    }

    private static bool TryReadArguments(string verb, IReadOnlyList<string> args, TextWriter error, out string path, out string? kid)
    {
        path = string.Empty;
        kid = null;
        string? readPath = null;

        for (var i = 0; i < args.Count; i++)
        {
            var flag = args[i];
            if (flag is not (OutFlag or KidFlag))
            {
                error.WriteLine($"'{flag}' is not an argument of '{Name} {verb}'. {Usage(verb)}");
                return false;
            }

            if (i + 1 >= args.Count)
            {
                error.WriteLine($"{flag} needs a value. {Usage(verb)}");
                return false;
            }

            var value = args[++i];
            if (value.Length == 0 || value.StartsWith("--", StringComparison.Ordinal))
            {
                error.WriteLine($"{flag} needs a value. {Usage(verb)}");
                return false;
            }

            if (flag == OutFlag)
            {
                if (readPath is not null)
                {
                    error.WriteLine($"{OutFlag} was given more than once. {Usage(verb)}");
                    return false;
                }

                readPath = value;
            }
            else
            {
                if (kid is not null)
                {
                    error.WriteLine($"{KidFlag} was given more than once. {Usage(verb)}");
                    return false;
                }

                kid = value;
            }
        }

        if (readPath is null)
        {
            error.WriteLine($"{OutFlag} is required. {Usage(verb)}");
            return false;
        }

        path = readPath;
        return true;
    }

    private static string Usage(string verb) => $"Usage: {Name} {verb} {OutFlag} <path> [{KidFlag} <name>].";
}
