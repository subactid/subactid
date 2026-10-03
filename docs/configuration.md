# Configuration

Subact ID reads its configuration from environment variables. No `appsettings.json` ships with the
server.

Every setting has a key and an environment variable. `SubactId:RateLimit:Burst` is the key and
`SubactId__RateLimit__Burst` is the variable: replace each `:` with `__`. Startup errors name both,
so you can search this page for either:

    SubactId:Audit:Aggregation:Window (environment variable SubactId__Audit__Aggregation__Window) must be between 00:00:01 and 00:15:00.

This page lists every setting, its default and what it accepts. For why you would set one, see
[storage](storage.md), [signing keys](keys.md), [Keycloak](keycloak.md) and
[Kubernetes](kubernetes.md).

## How a value is read

- **Empty means unset.** A blank or whitespace-only value takes the default.
  `SubactId__Admin__ApiKey=` disables the admin API.
- **Durations** are ISO 8601 (`PT5M`) or .NET time spans (`00:05:00`). Years and months are
  refused because they have no fixed length. Every duration must be greater than zero.
- **Whole numbers** are plain digits, with no sign or separators.
- **Booleans** are `true` or `false`.
- **Lists** are one comma-separated value: `SubactId:RateLimit:TrustedProxies` and
  `SubactId:UpstreamIdp:SubjectTokenTypes`. A list in numbered form (`__0`, or a JSON array) is not
  read, and `SubjectTokenTypes` refuses it, so that setting never goes unenforced. Signing keys are
  numbered instead: `SubactId__Signing__Keys__0__Path`.
- **Command-line arguments override the environment**, for example `--SubactId:RateLimit:Burst=5`.
  Use this for trying things out, not in a deployment.
- **All errors are reported at once**, and no error message repeats a configured value.
- **Every URL** must be absolute `http` or `https`, with no user name or password in it
  (`https://user:password@host`). Nothing sends them, `doctor` prints the URLs it checks, and
  `SubactId:Issuer` is in every token.
- **Plain `http` is for loopback only.** `SubactId:Issuer`, the identity provider's URLs, the
  sponsor check's URLs, `SubactId:Ssf:Issuer` and `SubactId:Audit:Sink:Url` must be `https`
  unless their host is loopback (`localhost`, `127.0.0.0/8`, `::1`). Set
  `SubactId:AllowInsecureHttp` to `true` to allow `http` anywhere, as the quickstart and the kind
  install do; `doctor` warns while it is on.

## Required

The server does not start without these.

| Setting | What it is |
|---|---|
| `SubactId:Issuer` | Absolute URL the control plane issues tokens as. It is the `iss` of every token and the base of every URL in the discovery document. A trailing slash is dropped. |
| `SubactId:UpstreamIdp:Issuer` | The identity provider's realm URL, for example `https://idp.example.com/realms/main`. Or set `SubactId:UpstreamIdp:MetadataUrl` instead. |
| `SubactId:UpstreamIdp:Audience` | The `aud` an upstream subject token must carry. |
| `SubactId:UpstreamIdp:SponsorCheck:UsersUrl` | Required when `SubactId:UpstreamIdp:SponsorCheck:Mode` is `poll` (the default). |
| `SubactId:UpstreamIdp:SponsorCheck:TokenUrl` | Required under `poll`. |
| `SubactId:UpstreamIdp:SponsorCheck:ClientId` | Required under `poll`. |
| `SubactId:Database:ConnectionString` | Required for `postgres` (the default). For `sqlite`, set `SubactId:Database:Path` instead. |

## Database

See [Storage](storage.md).

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Database:Provider` | `postgres` | `postgres` or `sqlite`, case-insensitive. |
| `SubactId:Database:ConnectionString` | — | Required for `postgres`, refused for `sqlite`. A secret. |
| `SubactId:Database:MigrationConnectionString` | the connection string | Refused for `sqlite`. A role that may change the schema, used only by `migrate`. A secret. |
| `SubactId:Database:Path` | — | Path to the SQLite file. Required for `sqlite`, refused for `postgres`. |

Under `postgres`, readiness uses a separate pool of at most four connections with the same
credentials, so a busy request pool does not fail the readiness probe. Count those four per
instance when you size `max_connections`. The request pool's size is `Maximum Pool Size` in the
connection string (100 by default).

GSS encryption is off unless the connection string sets `GSS Encryption Mode` or the
`PGGSSENCMODE` environment variable is set and not empty; then Npgsql uses what was named, and
the connection string wins when both are. The default keeps Npgsql from looking for the system's
Kerberos library on every start, which the runtime image does not ship, and so from writing a
plain-text line to stderr among the JSON log lines.

## Upstream identity provider

See [Keycloak](keycloak.md) for these settings with Keycloak values filled in.

At every exchange and refresh, Subact ID checks whether the human may still be acted for. It always
checks its own block list. `SubactId:UpstreamIdp:SponsorCheck:Mode` decides what else happens:

- **`poll`** (default): Subact ID also asks the identity provider's admin API (Keycloak's shape). The
  human is refused if either says no. A provider that cannot answer counts as no.
- **`signals`**: Subact ID asks nothing and acts only on signals it receives (back-channel logout,
  SCIM, Shared Signals, the admin API). Without a signal, a task runs to its own expiry.

See section 5 of [the spec](spec/v0.1.md).

Under `poll`, after five provider failures in a row (no connection, a timeout, a `5xx` or `429`,
or no service token), the sponsor check answers `temporarily_unavailable` at once for five
seconds, then lets one request through to test the provider. An unusable answer about one
person, such as a `403` for one account, refuses that person but does not count as a provider
failure. The identity provider client times out after ten seconds and never follows a redirect:
the discovery, key set and admin API URLs must answer directly.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:UpstreamIdp:Issuer` | — | A plain realm URL: no query string or fragment. The discovery URL is derived from it. |
| `SubactId:UpstreamIdp:MetadataUrl` | — | Alternative to `Issuer`: the full discovery URL, ending in `/.well-known/openid-configuration`. Setting both is an error. |
| `SubactId:UpstreamIdp:Audience` | — | Required. |
| `SubactId:UpstreamIdp:SubjectTokenTypes` | any | The `typ` header values a subject token may carry, comma-separated, for example `at+jwt`. `at+jwt` and `application/at+jwt` are one type. Unset, any `typ` or none is accepted, as the spec requires. Set, any other `typ`, or none, is `invalid_grant`, recorded as `subject_unaccepted_type`. See below. |
| `SubactId:UpstreamIdp:SponsorCheck:Mode` | `poll` | `poll` or `signals`, case-insensitive. |
| `SubactId:UpstreamIdp:SponsorCheck:UsersUrl` | — | The admin users collection, for example `https://idp/admin/realms/main/users`. Required under `poll`, refused under `signals`. |
| `SubactId:UpstreamIdp:SponsorCheck:TokenUrl` | — | The identity provider's token endpoint. Subact ID authenticates there with `private_key_jwt`, signed by its active signing key. Required under `poll`, refused under `signals`. |
| `SubactId:UpstreamIdp:SponsorCheck:ClientId` | — | The client id Subact ID is registered under at the identity provider. Required under `poll`, refused under `signals`. |
| `SubactId:UpstreamIdp:SponsorCheck:CacheTtl` | `PT30S` | How long a sponsor's status is reused by a renewal. At most `SubactId:Tokens:DefaultTokenTtl`. A renewal never reuses a status fetched before its task was created. Refused under `signals`. |
| `SubactId:UpstreamIdp:SponsorKeyClaim` | `sub` | The claim each task records the human under, used by the block list and by signals. At most 64 characters, no whitespace. See below. |
| `SubactId:UpstreamIdp:BackchannelLogout:Audience` | — | Turns on `POST /backchannel-logout`. See [Back-channel logout](#back-channel-logout). |

About `SponsorKeyClaim`:

- Change it only if the provider's `sub` is not the identifier its other interfaces (SCIM,
  signals) use. It does not change the token's `sub`, and under `poll` the provider is still
  asked by `sub`.
- A subject token whose value for the claim is missing, not a string, empty, over 256
  characters, or contains whitespace or a control character is refused.
- If you change it on a running deployment, existing tasks stay keyed by the old claim until
  they expire, and a block under the new key does not reach them.

About `SubjectTokenTypes`:

- It only narrows what is accepted. Set it only if the provider marks its access tokens with a
  type none of its other tokens carries, such as RFC 9068 `at+jwt`.
- Keycloak marks access and ID tokens alike `JWT` unless the client is set to RFC 9068 types. See
  [Keycloak](keycloak.md#requiring-rfc-9068-access-tokens).
- Without it, an ID token that carries the audience still gets no token: ID tokens normally carry
  no `scope`, and no scope is granted without one.

## Back-channel logout

`SubactId:UpstreamIdp:BackchannelLogout:Audience` turns on `POST /backchannel-logout`. When a session
ends at the identity provider, the tasks it started end too. Unset, the route does not exist.

Set it to the **human-facing** client: the one people sign in to and the one the logout URI is
registered on. It is not `SubactId:UpstreamIdp:Audience`. A logout token carrying the wrong audience
is refused.

A logout revokes tasks but does not block the person. They can sign in again and start a new
task. To block, use `PUT /admin/sponsors/{sponsor_key}/block` (see [the admin API](admin-api.md)).
See section 6 of [the spec](spec/v0.1.md). You register the logout URI at the provider; for
Keycloak see [Keycloak](keycloak.md).

A logout also refuses the subject tokens it signed out for `SubactId:Revocations:SignOutRetention`
(see [Lifetimes and the sweeper](#lifetimes-and-the-sweeper)), which must be at least the
provider's longest access-token lifetime.

## SCIM provisioning

`SubactId:Scim:BearerToken` turns on the SCIM 2.0 receiver at `/scim/v2`. When a provisioning client
deactivates someone, their tasks end. Unset, the routes do not exist and answer `404`. See
[SCIM provisioning](scim.md) and section 6 of [the spec](spec/v0.1.md).

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Scim:BearerToken` | — | The credential a provisioning client presents. At least 32 characters. Separate from the admin key. A secret. |
| `SubactId:Scim:PreviousBearerToken` | — | A second accepted credential, for a two-step rotation. At least 32 characters and different from `BearerToken`. Remove it when the rotation is done. A secret. |
| `SubactId:Scim:SponsorKeyAttribute` | `externalId` | `externalId` or `userName`: which user attribute names the person. It must match the value of `SubactId:UpstreamIdp:SponsorKeyClaim` for that person, or a deactivation matches nothing. A user that cannot supply it is refused at creation. |
| `SubactId:Scim:MaxUsers` | `50000` | Most user records held. A create past it is refused. |

The other `SubactId:Scim:*` settings are refused without `SubactId:Scim:BearerToken`.

## Shared Signals

`SubactId:Ssf:Issuer` turns on the Shared Signals / CAEP receiver at `POST /events`. A transmitter
pushes signed security event tokens, and an account disabled at the identity provider ends that
person's tasks. Unset, the route does not exist. See [Shared Signals](shared-signals.md) and
section 6 of [the spec](spec/v0.1.md).

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Ssf:Issuer` | — | The transmitter's own issuer URL, with no query string or fragment. Its discovery document and keys are read from it, without following a redirect. At Okta this is the organisation, not the authorization server that issues subject tokens. |
| `SubactId:Ssf:Audience` | — | Required with `Issuer`. The audience every event must carry. |
| `SubactId:Ssf:BearerToken` | — | Required with `Issuer`. The credential the transmitter presents when it pushes, checked in addition to the event signature. At least 32 characters. A secret. |
| `SubactId:Ssf:PreviousBearerToken` | — | A second accepted credential, for rotation. At least 32 characters and different from `BearerToken`. A secret. |

The other `SubactId:Ssf:*` settings are refused without `SubactId:Ssf:Issuer`.

## Lifetimes and the sweeper

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Tokens:DefaultTaskTtl` | `PT30M` | `max_task_ttl` for a registration that sets none. |
| `SubactId:Tokens:DefaultTokenTtl` | `PT5M` | `max_token_ttl` for a registration that sets none. At most `DefaultTaskTtl`. |
| `SubactId:Agents:MinTaskTtl` | `PT1M` | Shortest `max_task_ttl` a registration may set. |
| `SubactId:Agents:MaxTaskTtl` | `P1D` | Longest `max_task_ttl` a registration may set. Lowering it also shortens tasks of agents registered before, from their next exchange. |
| `SubactId:Agents:MinTokenTtl` | `PT30S` | Shortest `max_token_ttl` a registration may set. |
| `SubactId:Agents:MaxTokenTtl` | `PT1H` | Longest `max_token_ttl` a registration may set. Lowering it also shortens tokens of agents registered before, from their next exchange or refresh. |
| `SubactId:Tasks:SweepInterval` | `PT1M` | Time between passes that mark expired tasks terminal. Between `PT1S` and `P1D`. |
| `SubactId:Tasks:SweepBatchSize` | `20` | Tasks expired per transaction. A pass repeats until a batch comes back short. |
| `SubactId:Tasks:Retention` | `P7D` | How long an expired or revoked task is kept before the sweeper deletes it and its grants. The ledger keeps its records. An agent can be deleted once its tasks are gone. |
| `SubactId:Revocations:SignOutRetention` | `PT24H` | How long a back-channel logout or a Shared Signals `session-revoked` keeps refusing the subject tokens it signed out, after which its record is removed. At most `P30D`. Set it to at least the identity provider's longest access-token lifetime plus a minute; see [Revocation](revocation.md). |

A registration's own `max_task_ttl` and `max_token_ttl` apply to its tasks and tokens. The
`SubactId:Tokens:*` settings apply only to a registration that sets none. To hold every registration
to shorter lifetimes, lower the `SubactId:Agents:*` bounds.

Whatever these say, a token's lifetime is cut to what remains of its task, and a task with less
than five seconds left is refused a token.

## Agent keys

An agent registered with a `jwks_uri` has its keys fetched from that URL. The fetch never follows
a redirect: the URL must answer with the key set itself, and one that answers `3xx` counts as one
that cannot be reached.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:AllowInsecureHttp` | `false` | `true` allows plain `http` on hosts that are not loopback for the issuer, the identity provider, the Shared Signals transmitter and the audit sink. For demos and networks you trust. |
| `SubactId:AgentKeys:BlockPrivateNetworks` | `false` | `true` refuses to fetch from any address that is not public: IPv4 loopback, private, link-local, shared (`100.64.0.0/10`), documentation, benchmarking, reserved and multicast; IPv6 unique-local, link-local, site-local, documentation, discard and multicast; and an IPv6 address that carries one of those IPv4 addresses (IPv4-mapped, -compatible or -translated, NAT64, 6to4). |

Turn it on when every agent publishes its keys on a public host, so a registered `jwks_uri` cannot
reach internal infrastructure. Leave it off if an agent publishes on an internal host, as the
quickstart's does.

- The address checked is the address connected to, so a name cannot pass the check and then
  resolve somewhere else. A name that resolves to both kinds of address is reached on its public
  ones only.
- The fetch connects directly, never through a proxy: through a proxy, the proxy picks the address
  and there is nothing left to check. On a host with no direct route out, filter at the proxy
  instead and leave this off. The instance warns at startup when it has a proxy and this is on.
- A refused fetch is `invalid_client`, recorded as `actor_keys_refused`, and not
  `temporarily_unavailable`: asking again is refused again.

## Signing keys

See [Signing keys](keys.md). `N` is a number from `0`. Gaps are allowed.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Signing:Keys:N:Path` | — | Path to a PEM file, typically a mounted secret. |
| `SubactId:Signing:Keys:N:Pem` | — | The PEM inline. Set exactly one of `Path` or `Pem` per key. A secret. |
| `SubactId:Signing:Keys:N:Kid` | the RFC 7638 thumbprint | An explicit key id. |
| `SubactId:Signing:ActiveKid` | — | The key to sign with. Required when more than one key is configured. |

With no key configured, a `Development` host generates an ephemeral key and logs that it did.
Tokens signed with it stop verifying after a restart. Any other environment refuses to start.

## Admin API

See [Admin API](admin-api.md).

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Admin:ApiKey` | — | At least 32 characters. Unset, the admin API answers `503`. A secret. |

## Audit delivery

Records are always written to the ledger. If a sink is set, they are also queued in the outbox
and posted to the sink in the background, so a slow or failing sink does not delay token
issuance.

An outbox entry is deleted in the same transaction that records its delivery, so `audit_outbox`
holds only what is still to be sent. A crash between the sink's answer and that commit sends the
batch again (at-least-once delivery). A failed entry stays, with its error and next retry time,
until it is delivered.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Audit:Sink:Url` | — | Where records are posted. Unset, nothing is queued. Must not contain credentials. |
| `SubactId:Audit:Sink:BearerToken` | — | Sent to the sink. Requires `Sink:Url`, and that it is `https`. A secret. |
| `SubactId:Audit:DrainInterval` | `PT5S` | Time between delivery passes. Between `PT1S` and `PT1H`. |
| `SubactId:Audit:DrainBatchSize` | `100` | Records posted per request. A pass repeats until a batch comes back short. |

## Audit checkpoints

The ledger is sealed by signed checkpoints. A background pass on each instance takes the records
not yet sealed, builds a Merkle tree over them, signs the root with the active signing key and
links the checkpoint to the previous one. Replicas share this work; each range is sealed once.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Audit:Checkpoint:Interval` | `PT1M` | Time between sealing passes. Between `PT1S` and `PT1H`. This is also the longest a record stays outside a signed root. A shorter interval writes more checkpoint rows. |

Checkpoints are served by `GET /audit/checkpoints` and a record's inclusion proof by
`GET /audit/records/{seq}/proof`, both behind the admin API key. Keep copies of checkpoints
outside the database: `SubactId.Server audit-verify` can check that an earlier checkpoint is still
present and signs the same root.

## Audit retention

The ledger keeps everything unless you set a retention, and nothing is removed until you run the
archive command.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Audit:Retention` | — | Unset, the ledger grows without bound. At least `P31D`, because the ledger is removed a whole month at a time. Postgres only. |
| `SubactId:Audit:Partitions:MonthsAhead` | `2` | Between `1` and `12`. Months of ledger partitions created ahead of the current one, by `migrate` and by each server's background pass. Each extra partition adds planning time to every `/audit` query. Postgres only. |

`SubactId:Audit:Retention` deletes nothing by itself. It is the default cutoff for
`SubactId.Server audit-archive --to <directory>` when `--before` is not given. See
[Storage](storage.md#retention-taking-a-month-out-of-the-ledger) and §7.5 of
[the spec](spec/v0.1.md).

## Audit aggregation

A denial that identifies nobody (no agent, sponsor, task or token) is collapsed into one summary
record per reason per window. The first denial for each reason is still written at once. A
denial that can be attributed is never collapsed. A task's renewals after the first are also
counted and written as one record when the task ends. See §7.2 of [the spec](spec/v0.1.md) for
the summary record.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Audit:Aggregation:Enabled` | `true` | `true` or `false`. Covers both kinds of summary. Change it only when no tasks are running: renewals written individually while it was off are counted again in the summary. |
| `SubactId:Audit:Aggregation:Window` | `PT1M` | Between `PT1S` and `PT15M`. Counts are held in memory for a window, so a crash loses up to one window of counts. |

Turning aggregation off logs a warning at startup: an unauthenticated caller can then add one
ledger row per request, and every renewal adds a row.

## Rate limiting

A token bucket per source. A refused request gets `429`, `Retry-After` and the `slow_down`
error, and is audited as an aggregated denial with reason `rate_limited`. The limiter applies to
every endpoint except `/healthz` and `/readyz`.

A request spends one of three buckets, chosen by its path:

| Path | Bucket |
|---|---|
| `POST /oauth2/introspect` | `Introspection`, per source |
| `/backchannel-logout`, `/scim`, `/events` | `Signals`, per receiver per source |
| `/healthz`, `/readyz` | none |
| everything else, including `/oauth2/token` | the main bucket, per source |

| Setting | Default | Notes |
|---|---|---|
| `SubactId:RateLimit:Enabled` | `true` | `true` or `false`. |
| `SubactId:RateLimit:PermitsPerMinute` | `600` | Sustained requests per source. Agents behind one egress address are one source, so raise this for a large fleet. |
| `SubactId:RateLimit:Burst` | `120` | Bucket size: the burst absorbed before a caller is held to the sustained rate. |
| `SubactId:RateLimit:Signals:PermitsPerMinute` | `6000` | Sustained signals per source per receiver. An identity provider does not retry a refused signal. |
| `SubactId:RateLimit:Signals:Burst` | `5000` | Signal bucket size. This is the most sessions a provider can end in one burst without a logout being dropped. |
| `SubactId:RateLimit:Introspection:PermitsPerMinute` | `6000` | Sustained introspection calls per source. Size it at about one per high-risk tool call. |
| `SubactId:RateLimit:Introspection:Burst` | `1200` | Introspection bucket size, for a fleet whose agents all make their first tool call at once. |
| `SubactId:RateLimit:TrustedProxies` | — | Comma-separated CIDR networks whose `X-Forwarded-For` is trusted, for example `10.0.0.0/8`. A network that matches every address (`0.0.0.0/0`) is refused. |

- **The bucket refills every second.** Each second adds `PermitsPerMinute / 60`, rounded up, up
  to the burst. Each `Burst` must be at least one second's worth of its `PermitsPerMinute`;
  a smaller value is refused at startup.
- **The limit is per instance.** `n` replicas admit up to `n` times the configured rate.
- **Behind a proxy, set `TrustedProxies`.** Otherwise every request appears to come from the
  proxy and all callers share one bucket. The server logs a reminder at startup when the limiter
  is on and no proxy is set. List every hop: `X-Forwarded-For` is read from the right, skipping
  trusted proxies, and the first address that is not a trusted proxy is the source.

## Overload

This caps the work the whole instance takes on at once, across all callers. The rate limiter
caps each source.

At most `ConcurrencyLimit` requests run at once, at most `QueueLimit` wait, and none waits longer
than `QueueTimeout`. Other requests get `503`, `Retry-After: 1` and `temporarily_unavailable`
(under `/scim`, the SCIM error shape) before any work is done. They are audited as aggregated
denials with reason `overloaded`. A caller that disconnects while waiting is removed from the
queue.

Each kind of work has its own limit and queue, so a slow token endpoint cannot starve
introspection or delay a revocation:

| Kind | Paths |
|---|---|
| Token | `/oauth2/token` |
| Introspection | `/oauth2/introspect` |
| Revocation | `/oauth2/revoke`, `/backchannel-logout`, `/scim`, `/events`, `/admin` |
| Other | everything else: discovery, key sets, `/audit` |

`/healthz`, `/readyz` and paths with no endpoint are never limited. For the token, introspection,
revocation and back-channel logout endpoints, the form body is read before the request waits for
a turn, so a slow sender cannot hold a turn. That body is held to 64 KiB, whether or not this
limiter is on, and a longer one is refused as malformed (`invalid_request`, or the logout
receiver's `400`) and not read past 64 KiB. One that declares a longer `Content-Length` is
refused without being read at all. The largest real body, an exchange, is well under half that.

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Overload:Enabled` | `true` | `true` or `false`. |
| `SubactId:Overload:ConcurrencyLimit` | 16 per core | From `1` to `100000`. Requests run at once, per kind. The core count is what the process may use: in a container, what its CPU limit allows. A pod with no CPU limit (the chart's default) sees every core of its node, so set a limit or this value. |
| `SubactId:Overload:QueueLimit` | 4 × `ConcurrencyLimit` | From `0` to `1000000`. Requests that may wait, per kind. `0` means a request that finds no free turn is refused at once. |
| `SubactId:Overload:QueueTimeout` | `PT1S` | How long a request may wait for a turn. At most `PT30S`. |

A refusal here means the instance is full. If you see them in the ledger, add instances or
cores. For how the defaults behave under load, see
[sizing](sizing.md#what-overload-does-and-why-the-limiter-is-on).

When the database cannot be reached or cannot answer in time, requests also get `503`,
`temporarily_unavailable`, with `Retry-After: 5`, not `500`. No audit record can be written for
these, and no token is issued without its record. Requests waiting for a database connection
count towards `ConcurrencyLimit`, so a limit far above the pool's `Maximum Pool Size` mostly adds
waiting.

## Rules checked across settings

These are startup errors like any other.

| Rule | Why |
|---|---|
| `SubactId:Tokens:DefaultTokenTtl` ≤ `SubactId:Tokens:DefaultTaskTtl` | A token may not outlive its task. |
| `SubactId:Agents:MinTaskTtl` ≤ `MaxTaskTtl`, and `MinTokenTtl` ≤ `MaxTokenTtl` | The bounds must be a range. |
| `SubactId:Agents:MinTokenTtl` ≤ `SubactId:Agents:MinTaskTtl` | Otherwise no registration at the shortest task lifetime is valid. |
| Each `SubactId:Tokens:Default*` is within its `SubactId:Agents:*` bounds | Otherwise every registration that sets no lifetime is refused. |
| `SubactId:UpstreamIdp:SponsorCheck:CacheTtl` ≤ `SubactId:Tokens:DefaultTokenTtl` (under `poll`) | A disabled user's tasks must end within one token lifetime. |
| Each rate-limit `Burst` ≥ one second of its `PermitsPerMinute` | A smaller bucket would cap the sustained rate. |
| `SubactId:Audit:Sink:BearerToken` requires `SubactId:Audit:Sink:Url`, and `https` | The token must not be sent in the clear. |
| `SubactId:UpstreamIdp:Issuer` and `SubactId:UpstreamIdp:MetadataUrl` are not both set | One is derived from the other. |
| No `SponsorCheck` URL, client id or `CacheTtl` under `signals` | The identity provider is not asked in that mode. |
| No `SubactId:Scim:*` without `SubactId:Scim:BearerToken` | There is no SCIM receiver without a credential. |
| No `SubactId:Ssf:*` without `SubactId:Ssf:Issuer`; `Audience` and `BearerToken` required with it | The receiver needs a transmitter to trust, an audience and a credential. |
| Each `PreviousBearerToken` differs from its `BearerToken` | Two identical values are not a rotation. |
| Each database provider refuses the other provider's settings | A leftover setting usually means the wrong database is assumed. |
| Exactly one of `Pem` or `Path` per signing key | One key needs one source. |

## Secrets

These settings hold secrets:

- `SubactId:Database:ConnectionString` and `SubactId:Database:MigrationConnectionString`
- `SubactId:Admin:ApiKey`
- `SubactId:Audit:Sink:BearerToken`
- `SubactId:Scim:BearerToken` and `SubactId:Scim:PreviousBearerToken`
- `SubactId:Ssf:BearerToken` and `SubactId:Ssf:PreviousBearerToken`
- `SubactId:Signing:Keys:N:Pem` (a private key)

None is logged, echoed in an error or returned by any endpoint. Pass them as secrets (a mounted
file or a secret reference in the chart), never in a committed manifest. For signing keys,
prefer `Path` with a mounted file over `Pem`, so the key is not in the process environment.

## Checking it

    SubactId.Server doctor

Loads the configuration, runs the readiness checks and a few more, and prints one line per
check. It exits non-zero if a check fails, so it works as a Helm test or a CI step. It never
prints a token or a secret. It fetches from the identity provider as the server does, without
following a redirect.

`SubactId.Server migrate` reads the same configuration and applies the provider's schema. Migrations
never run at startup.

## Other environment variables

| Variable | What it does |
|---|---|
| `ASPNETCORE_HTTP_PORTS` | The port the server listens on. The container image sets `5100`. |
| `ASPNETCORE_ENVIRONMENT` | `Development` makes the server generate a signing key when none is configured. Do not use it in a deployment. |
| `SUBACTID_ADMIN_KEY` | Read by the `agent apply` command, not the server. See [Agents as files](gitops.md). |
