using System.Globalization;
using System.Net;
using System.Xml;
using SubactId.Core.Agents;
using SubactId.Server.Audit;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Configuration;

/// <summary>
/// Reads the <c>SubactId</c> configuration section into a validated <see cref="SubactIdOptions"/> or a
/// list of every problem found. No error message includes a configured value.
/// </summary>
public static class SubactIdOptionsLoader
{
    /// <summary>Name of the configuration section all settings live under.</summary>
    public const string SectionName = "SubactId";

    /// <summary>Default lifetime of a task when <c>SubactId:Tokens:DefaultTaskTtl</c> is not set.</summary>
    public static readonly TimeSpan DefaultTaskTtl = TimeSpan.FromMinutes(30);

    /// <summary>Default lifetime of a token when <c>SubactId:Tokens:DefaultTokenTtl</c> is not set.</summary>
    public static readonly TimeSpan DefaultTokenTtl = TimeSpan.FromMinutes(5);

    private const string IssuerKey = "Issuer";
    private const string UpstreamIssuerKey = "UpstreamIdp:Issuer";
    private const string UpstreamMetadataUrlKey = "UpstreamIdp:MetadataUrl";
    private const string UpstreamAudienceKey = "UpstreamIdp:Audience";
    private const string UpstreamSubjectTokenTypesKey = "UpstreamIdp:SubjectTokenTypes";
    private const string AgentKeysBlockPrivateNetworksKey = "AgentKeys:BlockPrivateNetworks";
    private const string AllowInsecureHttpKey = "AllowInsecureHttp";
    private const string SponsorUsersUrlKey = "UpstreamIdp:SponsorCheck:UsersUrl";
    private const string SponsorTokenUrlKey = "UpstreamIdp:SponsorCheck:TokenUrl";
    private const string SponsorClientIdKey = "UpstreamIdp:SponsorCheck:ClientId";
    private const string SponsorCacheTtlKey = "UpstreamIdp:SponsorCheck:CacheTtl";
    private const string SponsorCheckModeKey = "UpstreamIdp:SponsorCheck:Mode";
    private const string SponsorKeyClaimKey = "UpstreamIdp:SponsorKeyClaim";
    private const string BackchannelLogoutAudienceKey = "UpstreamIdp:BackchannelLogout:Audience";
    private const string ProviderKey = "Database:Provider";
    private const string ConnectionStringKey = "Database:ConnectionString";
    private const string MigrationConnectionStringKey = "Database:MigrationConnectionString";
    private const string DatabasePathKey = "Database:Path";
    private const string DefaultTaskTtlKey = "Tokens:DefaultTaskTtl";
    private const string DefaultTokenTtlKey = "Tokens:DefaultTokenTtl";
    private const string MinTaskTtlKey = "Agents:MinTaskTtl";
    private const string MaxTaskTtlKey = "Agents:MaxTaskTtl";
    private const string MinTokenTtlKey = "Agents:MinTokenTtl";
    private const string MaxTokenTtlKey = "Agents:MaxTokenTtl";
    private const string SweepIntervalKey = "Tasks:SweepInterval";
    private const string SweepBatchSizeKey = "Tasks:SweepBatchSize";
    private const string RetentionKey = "Tasks:Retention";
    private const string SignOutRetentionKey = "Revocations:SignOutRetention";
    private const string SigningKeysKey = "Signing:Keys";
    private const string ActiveKidKey = "Signing:ActiveKid";
    private const string AdminApiKeyKey = "Admin:ApiKey";
    private const string ScimBearerTokenKey = "Scim:BearerToken";
    private const string ScimPreviousBearerTokenKey = "Scim:PreviousBearerToken";
    private const string ScimSponsorKeyAttributeKey = "Scim:SponsorKeyAttribute";
    private const string ScimMaxUsersKey = "Scim:MaxUsers";
    private const string SsfIssuerKey = "Ssf:Issuer";
    private const string SsfAudienceKey = "Ssf:Audience";
    private const string SsfBearerTokenKey = "Ssf:BearerToken";
    private const string SsfPreviousBearerTokenKey = "Ssf:PreviousBearerToken";
    private const string AuditSinkUrlKey = "Audit:Sink:Url";
    private const string AuditSinkBearerTokenKey = "Audit:Sink:BearerToken";
    private const string AuditDrainIntervalKey = "Audit:DrainInterval";
    private const string AuditDrainBatchSizeKey = "Audit:DrainBatchSize";
    private const string AuditCheckpointIntervalKey = "Audit:Checkpoint:Interval";
    private const string AuditRetentionKey = "Audit:Retention";
    private const string AuditPartitionMonthsAheadKey = "Audit:Partitions:MonthsAhead";
    private const string AuditAggregationEnabledKey = "Audit:Aggregation:Enabled";
    private const string AuditAggregationWindowKey = "Audit:Aggregation:Window";
    private const string RateLimitEnabledKey = "RateLimit:Enabled";
    private const string RateLimitPermitsPerMinuteKey = "RateLimit:PermitsPerMinute";
    private const string RateLimitBurstKey = "RateLimit:Burst";
    private const string RateLimitSignalPermitsPerMinuteKey = "RateLimit:Signals:PermitsPerMinute";
    private const string RateLimitSignalBurstKey = "RateLimit:Signals:Burst";
    private const string RateLimitIntrospectionPermitsPerMinuteKey = "RateLimit:Introspection:PermitsPerMinute";
    private const string RateLimitIntrospectionBurstKey = "RateLimit:Introspection:Burst";
    private const string RateLimitTrustedProxiesKey = "RateLimit:TrustedProxies";
    private const string OverloadEnabledKey = "Overload:Enabled";
    private const string OverloadConcurrencyLimitKey = "Overload:ConcurrencyLimit";
    private const string OverloadQueueLimitKey = "Overload:QueueLimit";
    private const string OverloadQueueTimeoutKey = "Overload:QueueTimeout";

    /// <summary>Loads and validates settings from the <c>SubactId</c> section of <paramref name="configuration"/>.</summary>
    /// <param name="configuration">Root configuration, typically built from environment variables.</param>
    /// <returns>The validated options, or the full list of errors.</returns>
    public static SubactIdOptionsResult Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(SectionName);
        var errors = new List<string>();

        var issuer = ReadRequiredUrl(section, IssuerKey, errors);
        var metadataUrl = ReadUpstreamMetadataUrl(section, errors);
        var upstreamAudience = ReadRequiredString(section, UpstreamAudienceKey, errors);
        var subjectTokenTypes = ReadList(UpstreamSubjectTokenTypesKey, errors);
        var blockPrivateNetworkKeyFetch = ReadOptionalBool(AgentKeysBlockPrivateNetworksKey, fallback: false, errors);
        var sponsorCheckMode = ReadSponsorCheckMode(section, errors);
        var sponsorKeyClaim = ReadSponsorKeyClaim(section, errors);
        var sponsorCacheTtl = ReadOptionalTtl(section, SponsorCacheTtlKey, SponsorCheckOptions.DefaultCacheTtl, errors);
        var sponsorCheck = ReadSponsorCheck(section, sponsorCheckMode, sponsorCacheTtl, errors);
        var backchannelLogoutAudience = ReadOptionalString(section, BackchannelLogoutAudienceKey);
        var database = ReadDatabase(section, errors);
        var taskTtl = ReadOptionalTtl(section, DefaultTaskTtlKey, DefaultTaskTtl, errors);
        var tokenTtl = ReadOptionalTtl(section, DefaultTokenTtlKey, DefaultTokenTtl, errors);
        var minTaskTtl = ReadOptionalTtl(section, MinTaskTtlKey, AgentRegistrationLimits.Default.MinTaskTtl, errors);
        var maxTaskTtl = ReadOptionalTtl(section, MaxTaskTtlKey, AgentRegistrationLimits.Default.MaxTaskTtl, errors);
        var minTokenTtl = ReadOptionalTtl(section, MinTokenTtlKey, AgentRegistrationLimits.Default.MinTokenTtl, errors);
        var maxTokenTtl = ReadOptionalTtl(section, MaxTokenTtlKey, AgentRegistrationLimits.Default.MaxTokenTtl, errors);
        var sweepInterval = ReadOptionalTtl(section, SweepIntervalKey, TaskSweepOptions.DefaultSweepInterval, errors);
        var sweepBatchSize = ReadOptionalPositiveInt(section, SweepBatchSizeKey, TaskSweepOptions.DefaultBatchSize, errors);
        var retention = ReadOptionalTtl(section, RetentionKey, TaskSweepOptions.DefaultRetention, errors);
        var signOutRetention = ReadOptionalTtl(section, SignOutRetentionKey, RevocationOptions.DefaultSignOutRetention, errors);
        if (signOutRetention is { } keptFor && keptFor > RevocationOptions.MaxSignOutRetention)
        {
            errors.Add($"{Describe(SignOutRetentionKey)} must be at most {RevocationOptions.MaxSignOutRetention}.");
        }
        var signingKeys = ReadSigningKeys(section, errors);
        var activeKid = ReadOptionalString(section, ActiveKidKey);
        var adminApiKey = ReadOptionalString(section, AdminApiKeyKey);
        if (adminApiKey is not null && adminApiKey.Length < AdminOptions.MinApiKeyLength)
        {
            errors.Add($"{Describe(AdminApiKeyKey)} must be at least {AdminOptions.MinApiKeyLength} characters.");
        }

        var scim = ReadScim(section, errors);
        var ssf = ReadSsf(section, errors);
        var auditSinkUrl = ReadOptionalUrl(section, AuditSinkUrlKey, errors, credentialsKey: AuditSinkBearerTokenKey);
        var auditSinkBearerToken = ReadOptionalString(section, AuditSinkBearerTokenKey);
        var auditDrainInterval = ReadOptionalTtl(section, AuditDrainIntervalKey, AuditOptions.DefaultDrainInterval, errors);
        var auditDrainBatchSize = ReadOptionalPositiveInt(section, AuditDrainBatchSizeKey, AuditOptions.DefaultDrainBatchSize, errors);
        var auditCheckpointInterval = ReadOptionalTtl(section, AuditCheckpointIntervalKey, AuditOptions.DefaultCheckpointInterval, errors);
        if (auditCheckpointInterval is { } checkpoint && (checkpoint < AuditOptions.MinCheckpointInterval || checkpoint > AuditOptions.MaxCheckpointInterval))
        {
            errors.Add($"{Describe(AuditCheckpointIntervalKey)} must be between {AuditOptions.MinCheckpointInterval} and {AuditOptions.MaxCheckpointInterval}.");
        }

        var auditPartitionMonthsAhead = ReadOptionalPositiveInt(section, AuditPartitionMonthsAheadKey, AuditOptions.DefaultPartitionMonthsAhead, errors);
        if (auditPartitionMonthsAhead is { } monthsAhead && (monthsAhead < AuditOptions.MinPartitionMonthsAhead || monthsAhead > AuditOptions.MaxPartitionMonthsAhead))
        {
            errors.Add($"{Describe(AuditPartitionMonthsAheadKey)} must be between {AuditOptions.MinPartitionMonthsAhead} and {AuditOptions.MaxPartitionMonthsAhead}.");
        }

        // Only the default cutoff for audit-archive. Unset means keep everything, so there is no
        // fallback value and ReadOptionalTtl does not fit.
        TimeSpan? auditRetention = null;
        if (ReadOptionalString(section, AuditRetentionKey) is { } configuredRetention)
        {
            if (!TryParseDuration(configuredRetention, out var parsedRetention))
            {
                errors.Add($"{Describe(AuditRetentionKey)} must be a duration such as 90.00:00:00 or P90D.");
            }
            else if (parsedRetention < AuditOptions.MinRetention)
            {
                errors.Add($"{Describe(AuditRetentionKey)} must be at least {AuditOptions.MinRetention}, because the ledger is archived a whole month at a time.");
            }
            else
            {
                auditRetention = parsedRetention;
            }
        }

        if (auditSinkBearerToken is not null && ReadOptionalString(section, AuditSinkUrlKey) is null)
        {
            errors.Add($"{Describe(AuditSinkBearerTokenKey)} requires {Describe(AuditSinkUrlKey)}.");
        }

        // Never send the bearer token over plain http.
        if (auditSinkBearerToken is not null && auditSinkUrl is not null && auditSinkUrl.Scheme != Uri.UriSchemeHttps)
        {
            errors.Add($"{Describe(AuditSinkUrlKey)} must use https when {Describe(AuditSinkBearerTokenKey)} is set.");
        }

        if (auditDrainInterval is { } drain && (drain < AuditOptions.MinDrainInterval || drain > AuditOptions.MaxDrainInterval))
        {
            errors.Add($"{Describe(AuditDrainIntervalKey)} must be between {AuditOptions.MinDrainInterval} and {AuditOptions.MaxDrainInterval}.");
        }

        var aggregationEnabled = ReadOptionalBool(AuditAggregationEnabledKey, fallback: true, errors);
        var aggregationWindow = ReadOptionalTtl(section, AuditAggregationWindowKey, DenialAggregationOptions.DefaultWindow, errors);
        if (aggregationWindow is { } window && (window < DenialAggregationOptions.MinWindow || window > DenialAggregationOptions.MaxWindow))
        {
            errors.Add($"{Describe(AuditAggregationWindowKey)} must be between {DenialAggregationOptions.MinWindow} and {DenialAggregationOptions.MaxWindow}.");
        }

        var rateLimitEnabled = ReadOptionalBool(RateLimitEnabledKey, fallback: true, errors);
        var rateLimitPermits = ReadOptionalPositiveInt(section, RateLimitPermitsPerMinuteKey, RateLimitOptions.DefaultPermitsPerMinute, errors);
        var rateLimitBurst = ReadOptionalPositiveInt(section, RateLimitBurstKey, RateLimitOptions.DefaultBurst, errors);
        var signalPermits = ReadOptionalPositiveInt(section, RateLimitSignalPermitsPerMinuteKey, RateLimitOptions.DefaultSignalPermitsPerMinute, errors);
        var signalBurst = ReadOptionalPositiveInt(section, RateLimitSignalBurstKey, RateLimitOptions.DefaultSignalBurst, errors);
        var introspectionPermits = ReadOptionalPositiveInt(section, RateLimitIntrospectionPermitsPerMinuteKey, RateLimitOptions.DefaultIntrospectionPermitsPerMinute, errors);
        var introspectionBurst = ReadOptionalPositiveInt(section, RateLimitIntrospectionBurstKey, RateLimitOptions.DefaultIntrospectionBurst, errors);
        var trustedProxies = ReadNetworks(RateLimitTrustedProxiesKey, errors);

        var overloadEnabled = ReadOptionalBool(OverloadEnabledKey, fallback: true, errors);
        var concurrencyLimit = ReadOptionalBoundedInt(OverloadConcurrencyLimitKey, OverloadOptions.DefaultConcurrencyLimit, 1, OverloadOptions.MaxConcurrencyLimit, errors);
        var queueLimit = ReadOptionalBoundedInt(
            OverloadQueueLimitKey,
            Math.Min((concurrencyLimit ?? OverloadOptions.DefaultConcurrencyLimit) * OverloadOptions.DefaultQueueFactor, OverloadOptions.MaxQueueLimit),
            0,
            OverloadOptions.MaxQueueLimit,
            errors);
        var queueTimeout = ReadOptionalTtl(section, OverloadQueueTimeoutKey, OverloadOptions.DefaultQueueTimeout, errors);
        if (queueTimeout is { } wait && wait > OverloadOptions.MaxQueueTimeout)
        {
            errors.Add($"{Describe(OverloadQueueTimeoutKey)} must not exceed {OverloadOptions.MaxQueueTimeout}; a longer wait is the unbounded queue this setting exists to prevent.");
        }

        // Each bucket refills every second, so a burst below one second's worth would silently cap
        // the sustained rate. Every bucket gets the same check.
        RequireBurstHoldsOneRefill(rateLimitPermits, rateLimitBurst, RateLimitPermitsPerMinuteKey, RateLimitBurstKey);
        RequireBurstHoldsOneRefill(signalPermits, signalBurst, RateLimitSignalPermitsPerMinuteKey, RateLimitSignalBurstKey);
        RequireBurstHoldsOneRefill(introspectionPermits, introspectionBurst, RateLimitIntrospectionPermitsPerMinuteKey, RateLimitIntrospectionBurstKey);

        void RequireBurstHoldsOneRefill(int? permitsPerMinute, int? bucket, string permitsKey, string burstKey)
        {
            if (permitsPerMinute is { } permits && bucket is { } burst)
            {
                var perSecond = (int)Math.Ceiling(permits / 60.0);
                if (burst < perSecond)
                {
                    errors.Add($"{Describe(burstKey)} must be at least {perSecond}, one second's worth of {Describe(permitsKey)}; a smaller bucket would hold the sustained rate down to it.");
                }
            }
        }

        IReadOnlyList<IPNetwork> ReadNetworks(string key, List<string> into)
        {
            var raw = section[key];
            if (string.IsNullOrWhiteSpace(raw))
            {
                return [];
            }

            var networks = new List<IPNetwork>();
            foreach (var entry in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!IPNetwork.TryParse(entry, out var network))
                {
                    into.Add($"{Describe(key)} must be a comma-separated list of CIDR networks such as 10.0.0.0/8.");
                    return [];
                }

                // Trusting every network would let any caller pick its own source address.
                if (network.PrefixLength == 0)
                {
                    into.Add($"{Describe(key)} must not contain a network that matches every address.");
                    return [];
                }

                networks.Add(network);
            }

            return networks;
        }

        int? ReadOptionalBoundedInt(string key, int fallback, int min, int max, List<string> into)
        {
            var raw = section[key];
            if (string.IsNullOrWhiteSpace(raw))
            {
                return fallback;
            }

            if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number < min || number > max)
            {
                into.Add($"{Describe(key)} must be a whole number from {min} to {max}.");
                return null;
            }

            return number;
        }

        bool? ReadOptionalBool(string key, bool fallback, List<string> into)
        {
            var raw = section[key];
            if (string.IsNullOrWhiteSpace(raw))
            {
                return fallback;
            }

            if (!bool.TryParse(raw, out var parsed))
            {
                into.Add($"{Describe(key)} must be true or false.");
                return null;
            }

            return parsed;
        }

        IReadOnlyList<string> ReadList(string key, List<string> into)
        {
            // A list is one comma-separated value. The numbered form a JSON array or a __0
            // variable makes is refused, not read as unset: a list that narrows what is accepted
            // must never go unenforced because of how it was written.
            if (section.GetSection(key).GetChildren().Any())
            {
                into.Add($"{Describe(key)} must be one comma-separated value, not a numbered list.");
                return [];
            }

            var raw = section[key];
            return string.IsNullOrWhiteSpace(raw)
                ? []
                : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        if (taskTtl is { } task && tokenTtl is { } token && token > task)
        {
            errors.Add($"{Describe(DefaultTokenTtlKey)} must not exceed {Describe(DefaultTaskTtlKey)}.");
        }

        // Registration bounds and default lifetimes, checked together so the defaults fall inside
        // the bounds.
        AgentRegistrationLimits? agentLimits = null;
        if (minTaskTtl is { } minTask && maxTaskTtl is { } maxTask && minTokenTtl is { } minToken && maxTokenTtl is { } maxToken && taskTtl is { } defaultTask && tokenTtl is { } defaultToken)
        {
            agentLimits = new AgentRegistrationLimits(minTask, maxTask, minToken, maxToken, defaultTask, defaultToken);
            foreach (var contradiction in agentLimits.Contradictions())
            {
                errors.Add($"{Describe(MinTaskTtlKey)}, {Describe(MaxTaskTtlKey)}, {Describe(MinTokenTtlKey)}, {Describe(MaxTokenTtlKey)}, {Describe(DefaultTaskTtlKey)} and {Describe(DefaultTokenTtlKey)} contradict each other: {contradiction}.");
            }
        }

        if (sweepInterval is { } interval && (interval < TaskSweepOptions.MinSweepInterval || interval > TaskSweepOptions.MaxSweepInterval))
        {
            errors.Add($"{Describe(SweepIntervalKey)} must be between {TaskSweepOptions.MinSweepInterval} and {TaskSweepOptions.MaxSweepInterval}.");
        }

        // A disabled user's tasks must end within one token lifetime, so the cache TTL is capped by
        // it. Only poll mode caches.
        if (sponsorCheckMode == SponsorCheckMode.Poll && sponsorCacheTtl is { } cache && tokenTtl is { } tokenLifetime && cache > tokenLifetime)
        {
            errors.Add($"{Describe(SponsorCacheTtlKey)} must not exceed {Describe(DefaultTokenTtlKey)}.");
        }

        // Tokens, keys and credentials travel over these. Plain http is accepted on a loopback host,
        // where nothing crosses a network, and elsewhere only when the deployment says it means it.
        var allowInsecureHttp = ReadOptionalBool(AllowInsecureHttpKey, fallback: false, errors);
        if (allowInsecureHttp is false)
        {
            RequireHttps(IssuerKey, issuer, errors);
            // Named by whichever of the two the deployment set; the other is derived from it.
            RequireHttps(string.IsNullOrWhiteSpace(section[UpstreamMetadataUrlKey]) ? UpstreamIssuerKey : UpstreamMetadataUrlKey, metadataUrl, errors);
            RequireHttps(SponsorUsersUrlKey, sponsorCheck?.UsersUrl, errors);
            RequireHttps(SponsorTokenUrlKey, sponsorCheck?.TokenUrl, errors);
            RequireHttps(SsfIssuerKey, ssf?.MetadataUrl, errors);
            // A sink with a bearer token is already held to https by a rule of its own.
            if (auditSinkBearerToken is null)
            {
                RequireHttps(AuditSinkUrlKey, auditSinkUrl, errors);
            }
        }

        if (errors.Count > 0)
        {
            return SubactIdOptionsResult.Invalid(errors);
        }

        return SubactIdOptionsResult.Valid(new SubactIdOptions
        {
            Issuer = issuer!,
            AllowInsecureHttp = allowInsecureHttp!.Value,
            UpstreamIdp = new UpstreamIdpOptions
            {
                MetadataUrl = metadataUrl!,
                Audience = upstreamAudience!,
                SubjectTokenTypes = subjectTokenTypes,
                SponsorKeyClaim = sponsorKeyClaim!,
                SponsorCheckMode = sponsorCheckMode,
                SponsorCheck = sponsorCheck,
                BackchannelLogout = backchannelLogoutAudience is null ? null : new BackchannelLogoutOptions { Audience = backchannelLogoutAudience },
            },
            Database = database!,
            Tokens = new TokenOptions { DefaultTaskTtl = taskTtl!.Value, DefaultTokenTtl = tokenTtl!.Value },
            Agents = agentLimits!,
            AgentKeys = new AgentKeyFetchOptions { BlockPrivateNetworks = blockPrivateNetworkKeyFetch!.Value },
            Tasks = new TaskSweepOptions { SweepInterval = sweepInterval!.Value, BatchSize = sweepBatchSize!.Value, Retention = retention!.Value },
            Revocations = new RevocationOptions { SignOutRetention = signOutRetention!.Value },
            Signing = new SigningOptions { Keys = signingKeys, ActiveKid = activeKid },
            Admin = new AdminOptions { ApiKey = adminApiKey },
            Scim = scim,
            Ssf = ssf,
            RateLimit = new RateLimitOptions
            {
                Enabled = rateLimitEnabled!.Value,
                PermitsPerMinute = rateLimitPermits!.Value,
                Burst = rateLimitBurst!.Value,
                SignalPermitsPerMinute = signalPermits!.Value,
                SignalBurst = signalBurst!.Value,
                IntrospectionPermitsPerMinute = introspectionPermits!.Value,
                IntrospectionBurst = introspectionBurst!.Value,
                TrustedProxies = trustedProxies,
            },
            Overload = new OverloadOptions
            {
                Enabled = overloadEnabled!.Value,
                ConcurrencyLimit = concurrencyLimit!.Value,
                QueueLimit = queueLimit!.Value,
                QueueTimeout = queueTimeout!.Value,
            },
            Audit = new AuditOptions
            {
                SinkUrl = auditSinkUrl,
                SinkBearerToken = auditSinkBearerToken,
                DrainInterval = auditDrainInterval!.Value,
                DrainBatchSize = auditDrainBatchSize!.Value,
                CheckpointInterval = auditCheckpointInterval!.Value,
                Retention = auditRetention,
                PartitionMonthsAhead = auditPartitionMonthsAhead!.Value,
                Aggregation = new DenialAggregationOptions { Enabled = aggregationEnabled!.Value, Window = aggregationWindow!.Value },
            },
        });
    }

    /// <summary>
    /// Reads the database settings for the configured provider. Postgres needs a connection string,
    /// SQLite a path, and settings for the other provider are refused. No message names a
    /// configured value.
    /// </summary>
    private static DatabaseOptions? ReadDatabase(IConfiguration section, List<string> errors)
    {
        var before = errors.Count;
        var name = ReadOptionalString(section, ProviderKey);
        StorageProvider provider;
        if (name is null)
        {
            provider = StorageProvider.Postgres;
        }
        else if (!Enum.TryParse(name, ignoreCase: true, out provider) || !Enum.IsDefined(provider))
        {
            var supported = string.Join(", ", Enum.GetNames<StorageProvider>().Select(n => n.ToLowerInvariant()));
            errors.Add($"{Describe(ProviderKey)} must be one of: {supported}.");
            return null;
        }

        var connectionString = ReadOptionalString(section, ConnectionStringKey);
        var migrationConnectionString = ReadOptionalString(section, MigrationConnectionStringKey);
        var path = ReadOptionalString(section, DatabasePathKey);

        if (provider == StorageProvider.Postgres)
        {
            if (connectionString is null)
            {
                errors.Add($"{Describe(ConnectionStringKey)} is required.");
            }

            if (path is not null)
            {
                errors.Add($"{Describe(DatabasePathKey)} is only used when {Describe(ProviderKey)} is sqlite.");
            }
        }
        else
        {
            if (path is null)
            {
                errors.Add($"{Describe(DatabasePathKey)} is required when {Describe(ProviderKey)} is sqlite.");
            }

            if (connectionString is not null)
            {
                errors.Add($"{Describe(ConnectionStringKey)} is only used when {Describe(ProviderKey)} is postgres.");
            }

            if (migrationConnectionString is not null)
            {
                errors.Add($"{Describe(MigrationConnectionStringKey)} is only used when {Describe(ProviderKey)} is postgres.");
            }
        }

        return errors.Count > before
            ? null
            : new DatabaseOptions
            {
                Provider = provider,
                ConnectionString = connectionString,
                MigrationConnectionString = migrationConnectionString,
                Path = path,
            };
    }

    /// <summary>
    /// Reads <c>Signing:Keys:N</c> in numeric order. Checks only the shape (numeric index, exactly
    /// one of Pem or Path). Key material is validated when loaded.
    /// </summary>
    private static IReadOnlyList<ConfiguredSigningKey> ReadSigningKeys(IConfiguration section, List<string> errors)
    {
        var entries = new List<(int Index, IConfigurationSection Entry)>();
        foreach (var entry in section.GetSection(SigningKeysKey).GetChildren())
        {
            if (!int.TryParse(entry.Key, NumberStyles.None, CultureInfo.InvariantCulture, out var index))
            {
                errors.Add($"{Describe(SigningKeysKey)} entries must be numbered from 0; '{entry.Key}' is not a number.");
                continue;
            }

            entries.Add((index, entry));
        }

        var sources = new List<ConfiguredSigningKey>();
        foreach (var (index, entry) in entries.OrderBy(e => e.Index))
        {
            var pem = ReadOptionalString(entry, "Pem");
            var path = ReadOptionalString(entry, "Path");
            if (pem is null == path is null)
            {
                errors.Add($"{Describe($"{SigningKeysKey}:{index}")} must set exactly one of Pem or Path.");
                continue;
            }

            sources.Add(new ConfiguredSigningKey(index, new SigningKeySource(ReadOptionalString(entry, "Kid"), pem, path)));
        }

        return sources;
    }

    private static string? ReadOptionalString(IConfiguration section, string key)
    {
        var value = section[key];
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string? ReadRequiredString(IConfiguration section, string key, List<string> errors)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"{Describe(key)} is required.");
            return null;
        }

        return value;
    }

    private static Uri? ReadRequiredUrl(IConfiguration section, string key, List<string> errors)
    {
        var value = ReadRequiredString(section, key, errors);
        return value is null ? null : ParseHttpUrl(value, key, errors);
    }

    private static Uri? ReadOptionalUrl(IConfiguration section, string key, List<string> errors, string? credentialsKey = null)
    {
        var value = ReadOptionalString(section, key);
        return value is null ? null : ParseHttpUrl(value, key, errors, credentialsKey);
    }

    /// <summary>
    /// The SCIM receiver's settings, or <c>null</c> when no credential is configured. Without a
    /// credential, any other setting in the section is refused.
    /// </summary>
    private static ScimOptions? ReadScim(IConfiguration section, List<string> errors)
    {
        var bearerToken = ReadOptionalString(section, ScimBearerTokenKey);
        var previousBearerToken = ReadOptionalString(section, ScimPreviousBearerTokenKey);
        var attribute = ReadScimSponsorKeyAttribute(section, errors);
        var maxUsers = ReadOptionalPositiveInt(section, ScimMaxUsersKey, ScimOptions.DefaultMaxUsers, errors);

        if (bearerToken is null)
        {
            foreach (var key in (string[])[ScimPreviousBearerTokenKey, ScimSponsorKeyAttributeKey, ScimMaxUsersKey])
            {
                if (ReadOptionalString(section, key) is not null)
                {
                    errors.Add($"{Describe(key)} must not be set without {Describe(ScimBearerTokenKey)}; the SCIM receiver does not exist without a credential.");
                }
            }

            return null;
        }

        if (bearerToken.Length < ScimOptions.MinBearerTokenLength)
        {
            errors.Add($"{Describe(ScimBearerTokenKey)} must be at least {ScimOptions.MinBearerTokenLength} characters.");
        }

        if (previousBearerToken is not null && previousBearerToken.Length < ScimOptions.MinBearerTokenLength)
        {
            errors.Add($"{Describe(ScimPreviousBearerTokenKey)} must be at least {ScimOptions.MinBearerTokenLength} characters.");
        }

        // The previous credential must differ from the current one.
        if (previousBearerToken is not null && string.Equals(previousBearerToken, bearerToken, StringComparison.Ordinal))
        {
            errors.Add($"{Describe(ScimPreviousBearerTokenKey)} must differ from {Describe(ScimBearerTokenKey)}.");
        }

        if (attribute is null || maxUsers is null)
        {
            return null;
        }

        return new ScimOptions
        {
            BearerToken = bearerToken,
            PreviousBearerToken = previousBearerToken,
            SponsorKeyAttribute = attribute.Value,
            MaxUsers = maxUsers.Value,
        };
    }

    /// <summary>
    /// The Shared Signals receiver's settings, or <c>null</c> when no transmitter is configured. The
    /// transmitter is the trust root, so without it any other setting in the section is refused.
    /// </summary>
    private static SsfOptions? ReadSsf(IConfiguration section, List<string> errors)
    {
        var issuer = ReadOptionalString(section, SsfIssuerKey);
        if (issuer is null)
        {
            foreach (var key in (string[])[SsfAudienceKey, SsfBearerTokenKey, SsfPreviousBearerTokenKey])
            {
                if (ReadOptionalString(section, key) is not null)
                {
                    errors.Add($"{Describe(key)} must not be set without {Describe(SsfIssuerKey)}; the Shared Signals receiver does not exist without a transmitter to trust.");
                }
            }

            return null;
        }

        var transmitter = ParseHttpUrl(issuer, SsfIssuerKey, errors);
        if (transmitter is not null && (transmitter.Query.Length > 0 || transmitter.Fragment.Length > 0))
        {
            errors.Add($"{Describe(SsfIssuerKey)} must be a plain issuer URL, with no query string or fragment.");
            transmitter = null;
        }

        // The audience and the credential are both required with a transmitter.
        var audience = ReadRequiredString(section, SsfAudienceKey, errors);
        var bearerToken = ReadRequiredString(section, SsfBearerTokenKey, errors);
        var previousBearerToken = ReadOptionalString(section, SsfPreviousBearerTokenKey);

        if (bearerToken is not null && bearerToken.Length < SsfOptions.MinBearerTokenLength)
        {
            errors.Add($"{Describe(SsfBearerTokenKey)} must be at least {SsfOptions.MinBearerTokenLength} characters.");
        }

        if (previousBearerToken is not null && previousBearerToken.Length < SsfOptions.MinBearerTokenLength)
        {
            errors.Add($"{Describe(SsfPreviousBearerTokenKey)} must be at least {SsfOptions.MinBearerTokenLength} characters.");
        }

        // The previous credential must differ from the current one.
        if (previousBearerToken is not null && string.Equals(previousBearerToken, bearerToken, StringComparison.Ordinal))
        {
            errors.Add($"{Describe(SsfPreviousBearerTokenKey)} must differ from {Describe(SsfBearerTokenKey)}.");
        }

        if (transmitter is null || audience is null || bearerToken is null)
        {
            return null;
        }

        return new SsfOptions
        {
            MetadataUrl = new Uri(transmitter.GetLeftPart(UriPartial.Path).TrimEnd('/') + UpstreamKeyCache.DiscoverySuffix),
            Audience = audience,
            BearerToken = bearerToken,
            PreviousBearerToken = previousBearerToken,
        };
    }

    /// <summary>
    /// Which attribute of a provisioned user identifies the person tasks are keyed by. Providers
    /// differ, so it is configured.
    /// </summary>
    private static ScimSponsorKeyAttribute? ReadScimSponsorKeyAttribute(IConfiguration section, List<string> errors)
    {
        var value = ReadOptionalString(section, ScimSponsorKeyAttributeKey);
        if (value is null)
        {
            return ScimSponsorKeyAttribute.ExternalId;
        }

        if (string.Equals(value, "externalId", StringComparison.OrdinalIgnoreCase))
        {
            return ScimSponsorKeyAttribute.ExternalId;
        }

        if (string.Equals(value, "userName", StringComparison.OrdinalIgnoreCase))
        {
            return ScimSponsorKeyAttribute.UserName;
        }

        errors.Add($"{Describe(ScimSponsorKeyAttributeKey)} must be 'externalId' or 'userName'.");
        return null;
    }

    /// <summary>
    /// How the sponsor is checked: <c>poll</c> (ask the identity provider's admin API) or
    /// <c>signals</c> (act only on received signals). Defaults to <c>poll</c>.
    /// </summary>
    private static SponsorCheckMode ReadSponsorCheckMode(IConfiguration section, List<string> errors)
    {
        var value = ReadOptionalString(section, SponsorCheckModeKey);
        if (value is null)
        {
            return SponsorCheckMode.Poll;
        }

        if (string.Equals(value, "poll", StringComparison.OrdinalIgnoreCase))
        {
            return SponsorCheckMode.Poll;
        }

        if (string.Equals(value, "signals", StringComparison.OrdinalIgnoreCase))
        {
            return SponsorCheckMode.Signals;
        }

        errors.Add($"{Describe(SponsorCheckModeKey)} must be 'poll' or 'signals'.");
        return SponsorCheckMode.Poll;
    }

    /// <summary>
    /// The claim that identifies the human for blocking. A name with whitespace is refused, since it
    /// would never match.
    /// </summary>
    private static string? ReadSponsorKeyClaim(IConfiguration section, List<string> errors)
    {
        var value = ReadOptionalString(section, SponsorKeyClaimKey);
        if (value is null)
        {
            return UpstreamIdpOptions.DefaultSponsorKeyClaim;
        }

        if (value.Length > UpstreamIdpOptions.MaxSponsorKeyClaimLength || value.Any(char.IsWhiteSpace))
        {
            errors.Add($"{Describe(SponsorKeyClaimKey)} must be a claim name of at most {UpstreamIdpOptions.MaxSponsorKeyClaimLength} characters with no whitespace.");
            return null;
        }

        return value;
    }

    /// <summary>
    /// The outbound check's settings. Under <c>poll</c> all three are required. Under
    /// <c>signals</c> setting any of them is refused.
    /// </summary>
    private static SponsorCheckOptions? ReadSponsorCheck(IConfiguration section, SponsorCheckMode mode, TimeSpan? cacheTtl, List<string> errors)
    {
        if (mode == SponsorCheckMode.Signals)
        {
            foreach (var key in (string[])[SponsorUsersUrlKey, SponsorTokenUrlKey, SponsorClientIdKey, SponsorCacheTtlKey])
            {
                if (ReadOptionalString(section, key) is not null)
                {
                    errors.Add($"{Describe(key)} must not be set when {Describe(SponsorCheckModeKey)} is 'signals'; the identity provider is not asked in that mode.");
                }
            }

            return null;
        }

        var usersUrl = ReadRequiredUrl(section, SponsorUsersUrlKey, errors);
        var tokenUrl = ReadRequiredUrl(section, SponsorTokenUrlKey, errors);
        var clientId = ReadRequiredString(section, SponsorClientIdKey, errors);
        if (usersUrl is null || tokenUrl is null || clientId is null || cacheTtl is null)
        {
            return null;
        }

        return new SponsorCheckOptions { UsersUrl = usersUrl, TokenUrl = tokenUrl, ClientId = clientId, CacheTtl = cacheTtl.Value };
    }

    /// <summary>
    /// The upstream discovery URL, derived from the realm URL in <c>UpstreamIdp:Issuer</c> (preferred)
    /// or read in full from <c>UpstreamIdp:MetadataUrl</c>. Setting both is an error.
    /// </summary>
    private static Uri? ReadUpstreamMetadataUrl(IConfiguration section, List<string> errors)
    {
        var issuer = ReadOptionalString(section, UpstreamIssuerKey);
        var metadataUrl = ReadOptionalString(section, UpstreamMetadataUrlKey);

        if (issuer is not null && metadataUrl is not null)
        {
            errors.Add($"{Describe(UpstreamIssuerKey)} and {Describe(UpstreamMetadataUrlKey)} must not both be set; set only {Describe(UpstreamIssuerKey)}.");
            return null;
        }

        if (issuer is null && metadataUrl is null)
        {
            errors.Add($"{Describe(UpstreamIssuerKey)} is required: the identity provider's realm URL, for example https://idp.example.com/realms/main.");
            return null;
        }

        if (issuer is not null)
        {
            var realm = ParseHttpUrl(issuer, UpstreamIssuerKey, errors);
            if (realm is null)
            {
                return null;
            }

            if (realm.Query.Length > 0 || realm.Fragment.Length > 0)
            {
                errors.Add($"{Describe(UpstreamIssuerKey)} must be a plain realm URL, with no query string or fragment.");
                return null;
            }

            return new Uri(realm.GetLeftPart(UriPartial.Path).TrimEnd('/') + UpstreamKeyCache.DiscoverySuffix);
        }

        var parsed = ParseHttpUrl(metadataUrl!, UpstreamMetadataUrlKey, errors);
        if (parsed is null)
        {
            return null;
        }

        // The key cache derives the expected issuer by removing this suffix, so it is required.
        if (!parsed.AbsolutePath.EndsWith(UpstreamKeyCache.DiscoverySuffix, StringComparison.Ordinal))
        {
            errors.Add($"{Describe(UpstreamMetadataUrlKey)} must end with {UpstreamKeyCache.DiscoverySuffix}; set {Describe(UpstreamIssuerKey)} to the realm URL instead and it is derived for you.");
            return null;
        }

        return parsed;
    }

    /// <summary>
    /// Refuses an http URL on a host that is not loopback. The URL is not repeated in the message.
    /// </summary>
    private static void RequireHttps(string key, Uri? url, List<string> errors)
    {
        if (url is null || url.Scheme != Uri.UriSchemeHttp || IsLoopback(url))
        {
            return;
        }

        errors.Add($"{Describe(key)} uses http on a host that is not loopback, so what travels over it would cross the network in the clear. Use https, or set {Describe(AllowInsecureHttpKey)} to true for a demo or a network you trust.");
    }

    private static bool IsLoopback(Uri url) =>
        url.IsLoopback || (System.Net.IPAddress.TryParse(url.IdnHost, out var address) && System.Net.IPAddress.IsLoopback(address));

    private static Uri? ParseHttpUrl(string value, string key, List<string> errors, string? credentialsKey = null)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            errors.Add($"{Describe(key)} must be an absolute http or https URL.");
            return null;
        }

        // Nothing sends a user name or password given in a URL, since the HTTP client drops them,
        // and URLs are printed where a secret must not be: doctor names the URLs it checks, and
        // SubactId:Issuer is in every token. So none may carry one.
        if (uri.UserInfo.Length > 0)
        {
            errors.Add(credentialsKey is null
                ? $"{Describe(key)} must not carry credentials."
                : $"{Describe(key)} must not carry credentials; use {Describe(credentialsKey)}.");
            return null;
        }

        return uri;
    }

    private static int? ReadOptionalPositiveInt(IConfiguration section, string key, int fallback, List<string> errors)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number <= 0)
        {
            errors.Add($"{Describe(key)} must be a positive whole number.");
            return null;
        }

        return number;
    }

    /// <summary>
    /// Reads a duration as either a .NET time span (<c>00:05:00</c>) or ISO 8601 (<c>PT5M</c>).
    /// </summary>
    private static TimeSpan? ReadOptionalTtl(IConfiguration section, string key, TimeSpan fallback, List<string> errors)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        if (!TryParseDuration(value, out var ttl))
        {
            errors.Add($"{Describe(key)} must be a duration such as 00:05:00 or PT5M.");
            return null;
        }

        if (ttl <= TimeSpan.Zero)
        {
            errors.Add($"{Describe(key)} must be greater than zero.");
            return null;
        }

        return ttl;
    }

    /// <summary>A duration as a .NET time span (<c>00:05:00</c>) or an ISO 8601 duration (<c>PT5M</c>).</summary>
    private static bool TryParseDuration(string value, out TimeSpan duration)
    {
        if (TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out duration))
        {
            return true;
        }

        // XmlConvert reads ISO 8601 durations but throws on failure and accepts years and months,
        // which have no fixed length. Reject Y or M in the date part (before the T, M is months).
        var separator = value.IndexOf('T', StringComparison.OrdinalIgnoreCase);
        var datePart = separator < 0 ? value : value[..separator];
        if (datePart.Contains('Y', StringComparison.OrdinalIgnoreCase)
            || datePart.Contains('M', StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            duration = XmlConvert.ToTimeSpan(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Names a setting by its configuration key and the environment variable that sets it.</summary>
    private static string Describe(string key)
    {
        var fullKey = $"{SectionName}:{key}";
        var envName = fullKey.Replace(":", "__", StringComparison.Ordinal);
        return $"{fullKey} (environment variable {envName})";
    }
}
