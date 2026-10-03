using SubactId.Core.Agents;
using SubactId.Server.Audit;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Configuration;

/// <summary>
/// Validated server configuration. Only <see cref="SubactIdOptionsLoader"/> creates instances.
/// </summary>
public sealed class SubactIdOptions
{
    /// <summary>
    /// Whether the issuer, the identity provider, the Shared Signals transmitter and the audit sink
    /// may be plain http on a host that is not loopback. Off by default; for demos and trusted networks.
    /// </summary>
    public bool AllowInsecureHttp { get; init; }

    /// <summary>Absolute URL this control plane uses as the OIDC <c>iss</c> value.</summary>
    public required Uri Issuer { get; init; }

    /// <summary>Upstream identity provider settings.</summary>
    public required UpstreamIdpOptions UpstreamIdp { get; init; }

    /// <summary>Database settings.</summary>
    public required DatabaseOptions Database { get; init; }

    /// <summary>Token lifetime defaults.</summary>
    public required TokenOptions Tokens { get; init; }

    /// <summary>Bounds for agent registrations, and default lifetimes for ones that set none.</summary>
    public required AgentRegistrationLimits Agents { get; init; }

    /// <summary>How the control plane fetches agents' published keys.</summary>
    public AgentKeyFetchOptions AgentKeys { get; init; } = new();

    /// <summary>The expiry sweeper's schedule.</summary>
    public required TaskSweepOptions Tasks { get; init; }

    /// <summary>How long the records that refuse signed-out subject tokens are kept.</summary>
    public RevocationOptions Revocations { get; init; } = new();

    /// <summary>Token signing keys.</summary>
    public required SigningOptions Signing { get; init; }

    /// <summary>Admin API settings.</summary>
    public required AdminOptions Admin { get; init; }

    /// <summary>Audit delivery settings.</summary>
    public required AuditOptions Audit { get; init; }

    /// <summary>Rate limits on the endpoints reachable without a credential.</summary>
    public RateLimitOptions RateLimit { get; init; } = new();

    /// <summary>How much work the instance runs at once, across all callers.</summary>
    public OverloadOptions Overload { get; init; } = new();

    /// <summary>The SCIM 2.0 receiver, or <c>null</c> when not configured (no routes are mapped).</summary>
    public ScimOptions? Scim { get; init; }

    /// <summary>The Shared Signals receiver, or <c>null</c> when not configured (no route is mapped).</summary>
    public SsfOptions? Ssf { get; init; }
}

/// <summary>
/// The inbound Shared Signals / CAEP receiver. Present only when a transmitter is configured.
/// </summary>
public sealed class SsfOptions
{
    /// <summary>Shortest push credential accepted, in characters.</summary>
    public const int MinBearerTokenLength = AdminOptions.MinApiKeyLength;

    /// <summary>
    /// Absolute URL of the transmitter's own OIDC discovery document, which gives its issuer and
    /// signing keys. Usually differs from the identity provider's (at Okta it is the organisation's).
    /// </summary>
    public required Uri MetadataUrl { get; init; }

    /// <summary>The stream audience every event must carry as its <c>aud</c>.</summary>
    public required string Audience { get; init; }

    /// <summary>
    /// The credential the transmitter presents when it pushes an event. Checked in addition to the
    /// event signature. A secret: never logged, never echoed.
    /// </summary>
    public required string BearerToken { get; init; }

    /// <summary>A second accepted credential for rotation, or <c>null</c>. A secret.</summary>
    public string? PreviousBearerToken { get; init; }

    /// <summary>Returns fixed placeholders so neither credential can leak through formatting.</summary>
    public override string ToString() =>
        $"SsfOptions {{ MetadataUrl = {MetadataUrl}, Audience = {Audience}, BearerToken = <redacted>, PreviousBearerToken = {(PreviousBearerToken is null ? "<none>" : "<redacted>")} }}";
}

/// <summary>Which SCIM attribute names the person for the purpose of blocking them.</summary>
public enum ScimSponsorKeyAttribute
{
    /// <summary>The provisioning client's identifier for the person. What most clients send.</summary>
    ExternalId,

    /// <summary>The <c>userName</c>, for clients whose <c>externalId</c> is missing or unsuitable.</summary>
    UserName,
}

/// <summary>
/// The inbound SCIM 2.0 receiver. Present only when a bearer credential is configured.
/// </summary>
public sealed class ScimOptions
{
    /// <summary>Shortest credential accepted, in characters.</summary>
    public const int MinBearerTokenLength = AdminOptions.MinApiKeyLength;

    /// <summary>Default for <see cref="MaxUsers"/>.</summary>
    public const int DefaultMaxUsers = 50_000;

    /// <summary>
    /// The credential a provisioning client presents. Separate from the admin key. A secret: never
    /// logged, never echoed.
    /// </summary>
    public required string BearerToken { get; init; }

    /// <summary>
    /// A second accepted credential, or <c>null</c>. Lets Okta and Entra ID rotate the secret in two
    /// steps. A secret, like <see cref="BearerToken"/>.
    /// </summary>
    public string? PreviousBearerToken { get; init; }

    /// <summary>Which attribute of a provisioned user names the person that tasks are keyed by.</summary>
    public required ScimSponsorKeyAttribute SponsorKeyAttribute { get; init; }

    /// <summary>Most user records this control plane holds, so a directory sync cannot fill the disk.</summary>
    public required int MaxUsers { get; init; }

    /// <summary>Returns fixed placeholders so neither credential can leak through formatting.</summary>
    public override string ToString() =>
        $"ScimOptions {{ BearerToken = <redacted>, PreviousBearerToken = {(PreviousBearerToken is null ? "<none>" : "<redacted>")}, SponsorKeyAttribute = {SponsorKeyAttribute}, MaxUsers = {MaxUsers} }}";
}

/// <summary>
/// Audit ledger and sink settings. Records are always written to the ledger. When a sink URL is
/// set they are also queued in the outbox and posted by the drain, so a slow sink never blocks
/// token issuance.
/// </summary>
public sealed class AuditOptions
{
    /// <summary>Default for <see cref="DrainInterval"/>.</summary>
    public static readonly TimeSpan DefaultDrainInterval = TimeSpan.FromSeconds(5);

    /// <summary>Shortest <see cref="DrainInterval"/> accepted.</summary>
    public static readonly TimeSpan MinDrainInterval = TimeSpan.FromSeconds(1);

    /// <summary>Longest <see cref="DrainInterval"/> accepted.</summary>
    public static readonly TimeSpan MaxDrainInterval = TimeSpan.FromHours(1);

    /// <summary>Default for <see cref="DrainBatchSize"/>.</summary>
    public const int DefaultDrainBatchSize = 100;

    /// <summary>Default for <see cref="CheckpointInterval"/>.</summary>
    public static readonly TimeSpan DefaultCheckpointInterval = TimeSpan.FromMinutes(1);

    /// <summary>Shortest <see cref="CheckpointInterval"/> accepted.</summary>
    public static readonly TimeSpan MinCheckpointInterval = TimeSpan.FromSeconds(1);

    /// <summary>Longest <see cref="CheckpointInterval"/> accepted.</summary>
    public static readonly TimeSpan MaxCheckpointInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// Shortest <see cref="Retention"/> accepted. The ledger is archived a whole month at a time,
    /// so retention is at least the longest month.
    /// </summary>
    public static readonly TimeSpan MinRetention = TimeSpan.FromDays(31);

    /// <summary>Default for <see cref="PartitionMonthsAhead"/>.</summary>
    public const int DefaultPartitionMonthsAhead = 2;

    /// <summary>Fewest months of partitions kept ahead, so a month never starts without one.</summary>
    public const int MinPartitionMonthsAhead = 1;

    /// <summary>Most months of partitions kept ahead.</summary>
    public const int MaxPartitionMonthsAhead = 12;

    /// <summary>Where records are posted, or <c>null</c> when no sink is configured (nothing is queued).</summary>
    public Uri? SinkUrl { get; init; }

    /// <summary>Bearer token presented to the sink, if it requires one. A secret: never logged, never echoed.</summary>
    public string? SinkBearerToken { get; init; }

    /// <summary>Time between drain passes, between <see cref="MinDrainInterval"/> and <see cref="MaxDrainInterval"/>.</summary>
    public required TimeSpan DrainInterval { get; init; }

    /// <summary>Most records posted to the sink in one request; a pass repeats until a batch comes back short.</summary>
    public required int DrainBatchSize { get; init; }

    /// <summary>How unattributable denials are collapsed into summary records.</summary>
    public DenialAggregationOptions Aggregation { get; init; } = new();

    /// <summary>
    /// Time between sealing passes, which is the longest a record goes before it is inside a signed
    /// root. Between <see cref="MinCheckpointInterval"/> and <see cref="MaxCheckpointInterval"/>.
    /// </summary>
    public required TimeSpan CheckpointInterval { get; init; }

    /// <summary>
    /// How much of the ledger stays online, or <c>null</c> (the default) for all of it. Only the
    /// default cutoff for <c>audit-archive</c>; nothing is removed until that command runs. At least
    /// <see cref="MinRetention"/>.
    /// </summary>
    public TimeSpan? Retention { get; init; }

    /// <summary>
    /// Months of ledger partitions kept ahead of the current one, between
    /// <see cref="MinPartitionMonthsAhead"/> and <see cref="MaxPartitionMonthsAhead"/>. Each extra
    /// partition adds planning cost to every <c>/audit</c> query.
    /// </summary>
    public int PartitionMonthsAhead { get; init; } = DefaultPartitionMonthsAhead;

    /// <summary>Whether records are queued and delivered.</summary>
    public bool DeliveryEnabled => SinkUrl is not null;

    /// <summary>Redacts the token and strips user info, query and fragment from the sink URL.</summary>
    public override string ToString() => $"AuditOptions {{ SinkUrl = {(SinkUrl is null ? "<none>" : $"{SinkUrl.Scheme}://{SinkUrl.Authority}{SinkUrl.AbsolutePath}")}, SinkBearerToken = {(SinkBearerToken is null ? "<none>" : "<redacted>")}, DrainInterval = {DrainInterval}, DrainBatchSize = {DrainBatchSize}, CheckpointInterval = {CheckpointInterval}, Retention = {(Retention is { } retention ? retention.ToString() : "<none>")}, PartitionMonthsAhead = {PartitionMonthsAhead} }}";
}

/// <summary>
/// Admin API authentication for v0.1: one shared API key presented as a bearer token. With no
/// key configured, the admin API answers 503.
/// </summary>
public sealed class AdminOptions
{
    /// <summary>Shortest key accepted, in characters.</summary>
    public const int MinApiKeyLength = 32;

    /// <summary>The API key, or <c>null</c> to disable the admin API. A secret: never logged, never echoed.</summary>
    public string? ApiKey { get; init; }

    /// <summary>Returns a fixed placeholder so the secret cannot leak through formatting.</summary>
    public override string ToString() => $"AdminOptions {{ ApiKey = {(ApiKey is null ? "<none>" : "<redacted>")} }}";
}

/// <summary>
/// One configured signing key and its index. Indexes can have gaps after a rotation.
/// </summary>
/// <param name="Index">The <c>N</c> in <c>SubactId:Signing:Keys:N</c>.</param>
/// <param name="Source">Where the key comes from.</param>
public sealed record ConfiguredSigningKey(int Index, SigningKeySource Source);

/// <summary>
/// Token signing keys from <c>SubactId:Signing:Keys:N</c> (each with <c>Kid</c>, and one of
/// <c>Pem</c> or <c>Path</c>) and the active key from <c>SubactId:Signing:ActiveKid</c>.
/// </summary>
public sealed class SigningOptions
{
    /// <summary>Configured keys in publication order. May be empty; the startup code decides what that means.</summary>
    public required IReadOnlyList<ConfiguredSigningKey> Keys { get; init; }

    /// <summary>The kid to sign with. Required when more than one key is configured.</summary>
    public string? ActiveKid { get; init; }

    /// <summary>Every key's source, in publication order.</summary>
    public IReadOnlyList<SigningKeySource> Sources => [.. Keys.Select(k => k.Source)];
}

/// <summary>Settings for the upstream identity provider that issues subject tokens.</summary>
public sealed class UpstreamIdpOptions
{
    /// <summary>Default for <see cref="SponsorKeyClaim"/>: the subject.</summary>
    public const string DefaultSponsorKeyClaim = "sub";

    /// <summary>Longest claim name accepted for <see cref="SponsorKeyClaim"/>.</summary>
    public const int MaxSponsorKeyClaimLength = 64;

    /// <summary>Absolute URL of the upstream OIDC discovery document.</summary>
    public required Uri MetadataUrl { get; init; }

    /// <summary>The <c>aud</c> value an upstream subject token must carry to be accepted by this control plane.</summary>
    public required string Audience { get; init; }

    /// <summary>
    /// The <c>typ</c> header values a subject token may carry, or empty to accept any (the default).
    /// The spec does not require a <c>typ</c>; setting this only tightens acceptance, for example to
    /// <c>at+jwt</c> where the identity provider marks its access tokens that way (RFC 9068).
    /// </summary>
    public IReadOnlyList<string> SubjectTokenTypes { get; init; } = [];

    /// <summary>
    /// The claim that identifies the human for blocking. Stored on each task next to the
    /// <c>sub</c>, so signals keyed by another identifier can find their tasks. Does not change
    /// the <c>sub</c>.
    /// </summary>
    public required string SponsorKeyClaim { get; init; }

    /// <summary>How this control plane learns that a human may no longer be acted for.</summary>
    public required SponsorCheckMode SponsorCheckMode { get; init; }

    /// <summary>
    /// How to query the identity provider. Set under <see cref="SponsorCheckMode.Poll"/>,
    /// <c>null</c> under <see cref="SponsorCheckMode.Signals"/>.
    /// </summary>
    public SponsorCheckOptions? SponsorCheck { get; init; }

    /// <summary>The back-channel logout receiver, or <c>null</c> when not configured (no endpoint is mapped).</summary>
    public BackchannelLogoutOptions? BackchannelLogout { get; init; }
}

/// <summary>
/// The OpenID Connect back-channel logout receiver. Present only when an audience is configured.
/// </summary>
public sealed class BackchannelLogoutOptions
{
    /// <summary>
    /// The client the logout URI is registered on, which a logout token carries as its <c>aud</c>.
    /// The human-facing client, distinct from <see cref="UpstreamIdpOptions.Audience"/>.
    /// </summary>
    public required string Audience { get; init; }
}

/// <summary>
/// How the control plane fetches an agent's published keys (its <c>jwks_uri</c>). Redirects are
/// never followed. Fetches from addresses that are not public are refused only when an operator
/// opts in, so the default preserves setups where agents publish on an internal host.
/// </summary>
public sealed class AgentKeyFetchOptions
{
    /// <summary>
    /// When <c>true</c>, a fetch of an agent's <c>jwks_uri</c> that resolves only to addresses that
    /// are not public (loopback, private, link-local and the other special-purpose ranges) is
    /// refused, and the fetch connects directly rather than through a proxy. Off by default. Turn
    /// it on when agents publish only on public hosts, to keep a registered <c>jwks_uri</c> from
    /// reaching internal infrastructure (SSRF).
    /// </summary>
    public bool BlockPrivateNetworks { get; init; }
}

/// <summary>How this control plane learns that a human may no longer be acted for.</summary>
public enum SponsorCheckMode
{
    /// <summary>
    /// Ask the identity provider's admin API (Keycloak's) on every refresh and exchange, behind a
    /// short cache. A failed or unreadable answer counts as a no.
    /// </summary>
    Poll,

    /// <summary>
    /// Ask nothing and act on received signals at once. Provider-neutral but weaker: without a
    /// signal, a task runs to its own expiry.
    /// </summary>
    Signals,
}

/// <summary>
/// How to ask the identity provider whether a user is still active. Authenticates with
/// <c>private_key_jwt</c> signed by the active signing key, so no shared secret is needed.
/// </summary>
public sealed class SponsorCheckOptions
{
    /// <summary>Default for <see cref="CacheTtl"/>.</summary>
    public static readonly TimeSpan DefaultCacheTtl = TimeSpan.FromSeconds(30);

    /// <summary>Absolute URL of the admin users collection, for example <c>https://idp/admin/realms/main/users</c>.</summary>
    public required Uri UsersUrl { get; init; }

    /// <summary>Absolute URL of the identity provider's token endpoint, where the service token is obtained.</summary>
    public required Uri TokenUrl { get; init; }

    /// <summary>The client id this control plane is registered under at the identity provider.</summary>
    public required string ClientId { get; init; }

    /// <summary>How long a sponsor's status is reused. Never longer than a token lifetime.</summary>
    public required TimeSpan CacheTtl { get; init; }
}

/// <summary>The databases the control plane can store its state in.</summary>
public enum StorageProvider
{
    /// <summary>Postgres, for a deployment of any size.</summary>
    Postgres,

    /// <summary>An embedded SQLite file, for a trial or a single node. One instance writes it at a time.</summary>
    Sqlite,
}

/// <summary>
/// Database settings. Which members are set depends on <see cref="Provider"/>.
/// </summary>
public sealed class DatabaseOptions
{
    /// <summary>Which database to store state in.</summary>
    public required StorageProvider Provider { get; init; }

    /// <summary>
    /// Postgres connection string, set when <see cref="Provider"/> is
    /// <see cref="StorageProvider.Postgres"/>. A secret: never logged, returned or put in an error.
    /// </summary>
    public string? ConnectionString { get; init; }

    /// <summary>
    /// Optional connection string for a schema-owning role, used only by <c>migrate</c>. Falls back
    /// to <see cref="ConnectionString"/>. A secret.
    /// </summary>
    public string? MigrationConnectionString { get; init; }

    /// <summary>
    /// Path to the database file, set when <see cref="Provider"/> is
    /// <see cref="StorageProvider.Sqlite"/>. Not echoed in errors.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>Returns the provider with every other value redacted.</summary>
    public override string ToString() => $"DatabaseOptions {{ Provider = {Provider}, ConnectionString = <redacted>, MigrationConnectionString = <redacted>, Path = <redacted> }}";
}

/// <summary>
/// Lifetimes for an agent registration that sets none of its own. Not a ceiling on ones that do.
/// </summary>
public sealed class TokenOptions
{
    /// <summary>Lifetime of a whole task for a registration with no <c>max_task_ttl</c>.</summary>
    public required TimeSpan DefaultTaskTtl { get; init; }

    /// <summary>Lifetime of a single token for a registration with no <c>max_token_ttl</c>. Never exceeds <see cref="DefaultTaskTtl"/>.</summary>
    public required TimeSpan DefaultTokenTtl { get; init; }
}

/// <summary>How long the records that refuse signed-out subject tokens are kept.</summary>
public sealed class RevocationOptions
{
    /// <summary>
    /// Default for <see cref="SignOutRetention"/>: a day, well above the access-token lifetime of
    /// common identity providers (minutes to an hour).
    /// </summary>
    public static readonly TimeSpan DefaultSignOutRetention = TimeSpan.FromHours(24);

    /// <summary>Longest <see cref="SignOutRetention"/> accepted.</summary>
    public static readonly TimeSpan MaxSignOutRetention = TimeSpan.FromDays(30);

    /// <summary>
    /// How long a sign-out (a back-channel logout, or a Shared Signals <c>session-revoked</c>) is
    /// kept after it was recorded, refusing the subject tokens it signed out. After that it is
    /// removed. It must be at least the identity provider's longest access-token lifetime, plus
    /// the clock skew allowed on subject tokens, or a subject token signed out at the start of its
    /// life could start a task once the record is gone.
    /// </summary>
    public TimeSpan SignOutRetention { get; init; } = DefaultSignOutRetention;
}

/// <summary>How often expired tasks are marked terminal and how many per pass.</summary>
public sealed class TaskSweepOptions
{
    /// <summary>Default for <see cref="SweepInterval"/>.</summary>
    public static readonly TimeSpan DefaultSweepInterval = TimeSpan.FromMinutes(1);

    /// <summary>Default for <see cref="BatchSize"/>: small, because each batch holds the audit chain lock for one append.</summary>
    public const int DefaultBatchSize = 20;

    /// <summary>Shortest <see cref="SweepInterval"/> accepted.</summary>
    public static readonly TimeSpan MinSweepInterval = TimeSpan.FromSeconds(1);

    /// <summary>Longest <see cref="SweepInterval"/> accepted.</summary>
    public static readonly TimeSpan MaxSweepInterval = TimeSpan.FromDays(1);

    /// <summary>Time between sweeps, between <see cref="MinSweepInterval"/> and <see cref="MaxSweepInterval"/>.</summary>
    public required TimeSpan SweepInterval { get; init; }

    /// <summary>Most tasks expired in one transaction; a sweep repeats until a pass comes back short.</summary>
    public required int BatchSize { get; init; }

    /// <summary>
    /// Default for <see cref="Retention"/>: a week, so recent tasks can still be looked up and a late
    /// refresh is refused with the task's own reason.
    /// </summary>
    public static readonly TimeSpan DefaultRetention = TimeSpan.FromDays(7);

    /// <summary>
    /// How long a task is kept after it expires before the sweeper removes it and its grants.
    /// </summary>
    public TimeSpan Retention { get; init; } = DefaultRetention;
}
