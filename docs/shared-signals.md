# Shared Signals

Subact ID can receive Shared Signals (RFC 8935 push delivery) with CAEP and RISC events. When your
identity provider disables an account or revokes its sessions, it pushes an event and Subact ID ends
that person's tasks within seconds.

Subact ID accepts three inbound signals:

| Signal | Says | Arrives |
|---|---|---|
| Shared Signals (this page) | What happened, to whom, and when | As it happens |
| [SCIM](scim.md) | A person was deprovisioned | At the next directory sync |
| [Back-channel logout](keycloak.md#ending-tasks-when-a-session-ends) | One session ended | When the session ends |

The receiver is off until you configure a transmitter. Without one there is no `/events` route,
and requests to it get `404`.

## Events Subact ID acts on

| Event | What Subact ID does |
|---|---|
| CAEP `session-revoked` | Revokes the person's live tasks, and refuses their subject tokens issued before the event. They can sign in again and start new ones. |
| RISC `account-disabled` | Blocks the person and revokes their live tasks |
| RISC `account-purged` | Same, recorded as deleted rather than disabled |
| RISC `account-enabled` | Lifts a block that Shared Signals placed, and only that |

Any other valid event (credential change, device compliance, assurance level) is accepted with
`202` and ignored. Refusing it would make the transmitter retry.

A block placed by an operator through the admin API, or by SCIM, is never lifted by
`account-enabled` and never replaced by `account-disabled`. Lifting a block never restores a
revoked task.

Account events are ordered by their `iat`, because a transmitter may deliver them out of order,
for example from the queue it kept while Subact ID was down. Subact ID remembers, per person, the
latest `iat` of the `account-disabled`, `account-purged` and `account-enabled` events it has taken
in order, whether or not they changed anything, and keeps it after a block is lifted. An account
event issued before that is not applied:

- A late `account-enabled` does not lift a block that a newer `account-disabled` placed or
  restated.
- A late `account-disabled` or `account-purged` does not block a person that a newer
  `account-enabled` let back in, and ends none of their tasks.

Either is acknowledged with `202` like any other event, and recorded as a refused
`sponsor.unblocked` or `sponsor.blocked` with reason `signal_out_of_order`. An event with the same
`iat` as the latest one is applied after it: of two events issued in the same second, the one that
arrives last decides. `session-revoked` is not ordered against them.

## How an event is checked

An event must pass all of these:

1. **Credential.** The request carries `Authorization: Bearer <SubactId:Ssf:BearerToken>`. Subact ID checks
   this first because it is cheap.
2. **Media type.** The body is a signed security event token sent as `application/secevent+jwt`,
   at most 64 KiB.
3. **Signature and claims.** The token verifies against the keys the transmitter publishes. Its
   `iss` is the configured transmitter, its `aud` includes the stream audience, it has a `jti`,
   and its `iat` is no more than 24 hours old (plus 60 seconds of clock skew). The 24 hours let a
   transmitter deliver events it queued while Subact ID was down.
4. **Replay.** Subact ID acts on each `jti` from a transmitter once. A repeat delivery gets `202`, as
   the first did, and changes and records nothing.

A stolen credential without the transmitter's signing key cannot push an event. A forged event
without the credential never reaches the signature check.

## Set it up

The Okta details on this page come from Okta's documentation. They have not been tested against
Subact ID.

### 1. Point Subact ID at the transmitter

```
SubactId__Ssf__Issuer=https://example.okta.com
```

**Use the transmitter's issuer, not your authorization server's.** At Okta the transmitter is the
organization (`https://example.okta.com`), while subject tokens come from an authorization server
under it (`https://example.okta.com/oauth2/default`). They have different keys. If this is wrong,
every event is refused with `invalid_issuer` or `invalid_key`.

Subact ID fetches keys from `<issuer>/.well-known/openid-configuration`. `SubactId.Server doctor` prints
that URL on its `signals receiver` line.

### 2. Set the stream audience and a credential

```
SubactId__Ssf__Audience=https://subactid.example.com/events
SubactId__Ssf__BearerToken=<a random string of at least 32 characters>
```

The audience is the value you configure the stream to address events to. It stops events meant
for another receiver being accepted here. Keep the credential in the environment. Subact ID never logs
or returns it.

### 3. Create the stream at the provider

Configure the stream at the transmitter:

- Push endpoint: `https://<your subactid>/events`
- Authorization header: `Bearer <the credential>`
- Events: the four listed above. Sending more is harmless.

Subact ID is a receiver only. It does not implement stream management (`/ssf/streams`),
verification events or poll delivery.

## Rotating the credential

Set the new credential and keep the old one alongside it while the transmitter switches:

```
SubactId__Ssf__BearerToken=<the new credential>
SubactId__Ssf__PreviousBearerToken=<the old one>
```

Subact ID accepts both. Remove `PreviousBearerToken` once the transmitter uses the new one.

## Which person an event is about

An event names its subject with an RFC 9493 subject identifier, either as a top-level `sub_id` or
as `subject` inside the event. Subact ID reads two formats:

| Format | Subact ID reads |
|---|---|
| `iss_sub` | `sub`. Its `iss` must be your upstream identity provider, because a transmitter can speak for several. |
| `opaque` | `id` |

Any other format is refused with `400 invalid_request`.

The value must be the identifier Subact ID keys tasks by: the claim named by
`SubactId:UpstreamIdp:SponsorKeyClaim`, `sub` by default. If it is not, the event is accepted but
matches no task. SCIM has the same requirement for its attribute; see [SCIM](scim.md).

If both a top-level `sub_id` and an event `subject` are present:

- If they name different people, the event is refused.
- A readable top-level `sub_id` is used even when the event's own `subject` is in a format Subact ID
  does not read.
- An unreadable top-level `sub_id` is refused.

## Responses

| Status | Body | When |
|---|---|---|
| `202` | Empty | The event was accepted (including repeats and events Subact ID ignores) |
| `400` | RFC 8935 `err` and `description` | `invalid_key`, `invalid_issuer`, `invalid_audience` or `invalid_request`, naming the check that failed |
| `401` | `err: authentication_failed` | The credential is missing or wrong. Subact ID records an `ssf.denied` audit event. |
| `503` | `err: invalid_key` | Subact ID could not fetch the transmitter's keys. Retry later. |

A `400` names the failed check because only a caller holding the push credential can reach it.
Subact ID records each refused event as `signal.denied`.

## Settings

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Ssf:Issuer` | none | The transmitter's issuer URL, with no query or fragment. Setting it turns the receiver on, and then the audience and credential are required. |
| `SubactId:Ssf:Audience` | none | The audience the stream addresses events to |
| `SubactId:Ssf:BearerToken` | none | The push credential. At least 32 characters. |
| `SubactId:Ssf:PreviousBearerToken` | none | A second accepted credential, for rotation. At least 32 characters and different from the first. |

Subact ID refuses to start if any of the last three is set without `Issuer`.

## Limits

- **Subact ID cannot request events.** If the stream is not configured, or the provider stops
  sending, tasks run until they expire, which `max_task_ttl` bounds.
- **A stolen push credential** alone cannot make Subact ID act. Every event must be signed by the
  transmitter, and each `jti` is acted on once. Rotate the credential like any other secret.
- **Other event types are ignored.** A credential change or a device falling out of compliance
  does not end a task.

## See also

- [SCIM provisioning](scim.md)
- [Revocation](revocation.md) for the other ways to end a task
- [Configuration](configuration.md) for every setting
