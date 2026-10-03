# SCIM provisioning

Subact ID can receive SCIM 2.0 user provisioning from your identity provider. When the provider
deactivates or deletes a person, Subact ID ends the tasks their agents are running and refuses new
ones. It accepts any SCIM 2.0 client, and is the way to feed the sponsor check when your provider
has no admin API Subact ID can poll.

The receiver is off until you set a credential. Without one there is no `/scim` route, and
requests to it get `404`.

## What a write does

Subact ID applies the `active` state that each write leaves the user in:

| The provisioning client sends | Subact ID |
|---|---|
| A user with `active: false`, by `POST`, `PUT` or `PATCH` | Blocks the person and revokes all their live tasks |
| `DELETE` of the user | Same, recorded as deleted rather than disabled. Only a new user record naming the person lifts this block |
| A user left active (`active: true`, or a create or replace with no `active`) | Lifts a block that SCIM placed, so the person can start tasks again, except as below |

Details:

- Revocation is permanent. Reactivating a person lets them start new tasks. It does not restore
  ended ones.
- A block placed by an operator (`PUT /admin/sponsors/{key}/block`) or by Shared Signals is not
  lifted or replaced by SCIM. Only the source that placed a block can lift it.
- If a deactivating write also changes the attribute that names the person, Subact ID blocks both
  the old and the new value.
- Two user records may name the same person (two `userName`s with one `externalId`, for
  example). While any of them is inactive, the person stays blocked: a write leaving another
  record active does not lift the block. It lifts once no record naming the person is inactive.
- A deletion removes the record, so nothing said later about another record stands for it. A
  block that a `DELETE` placed or restated stays until a new user record naming the person is
  created (`POST /Users`). Replacing, patching or re-sending a record that already exists, active,
  does not lift it, even when no record naming the person is inactive. The new record then decides
  as any other write does: active, it lifts the block unless another record naming the person is
  inactive; inactive, it keeps the person blocked as deactivated. A write that leaves the block in
  place this way records nothing, since nothing changed.
- Subact ID writes audit records only when a block is placed or lifted or a task ends, not for a
  write that repeats the current state.

## Set it up

The Okta and Entra ID details on this page come from those providers' documentation. They have
not been tested against Subact ID.

### 1. Set a credential

Generate a random string of at least 32 characters and set it:

```
SubactId__Scim__BearerToken=<the credential>
```

Keep it in the environment, not in the repository. Subact ID never logs or returns it. It is separate
from the admin API key and only works on the SCIM routes.

### 2. Choose the attribute that names a person

Subact ID keys each task by a claim of the subject token: `sub`, unless you changed
`SubactId:UpstreamIdp:SponsorKeyClaim`. A SCIM user must carry the same value in the attribute set
by `SubactId:Scim:SponsorKeyAttribute`, or a deactivation matches no task and blocks nobody.

```
SubactId__Scim__SponsorKeyAttribute=externalId   # the default
SubactId__Scim__SponsorKeyAttribute=userName
```

Provider notes:

- **Okta** sends its user id as `externalId`, and uses the same id as `sub`. The defaults work.
- **Entra ID** issues a `sub` that differs per application. Set
  `SubactId:UpstreamIdp:SponsorKeyClaim` to `oid` and map `externalId` to the user's object id.

Check the match before you rely on it:

```
SubactId.Server doctor
```

The `SCIM receiver` line names the attribute in use and the claim it must match.

A create or replace without a usable value in that attribute is refused with `400`
`invalidValue`, so a wrong mapping fails during setup rather than at offboarding.

### 3. Point the provider at Subact ID

Base URL: `https://<your subactid>/scim/v2`. Put the credential in the provider's bearer token
field.

**Okta.** In the application's **Provisioning** tab, enable API integration, set the base URL,
and paste the credential as the API token. Enable *Push New Users*, *Push Profile Updates* and
*Deactivate Users*.

**Entra ID.** In the enterprise application's **Provisioning** blade, set *Tenant URL* to the base
URL and *Secret Token* to the credential, then run **Test Connection**. In the attribute
mappings, keep `userName` and `externalId` and delete the rest. Subact ID does not store other
attributes.

**Other clients.** Any SCIM 2.0 client that can `POST`, `PUT` or `PATCH`, and `DELETE` on
`/Users` with a bearer token works.

## Rotating the credential

Set the new credential and keep the old one alongside it while the provider switches:

```
SubactId__Scim__BearerToken=<the new credential>
SubactId__Scim__PreviousBearerToken=<the old one>
```

Subact ID accepts both. When the provider uses the new one, remove `PreviousBearerToken` and restart.
The old credential stops working then.

## What Subact ID stores

For each user: the id Subact ID assigned, `userName`, `externalId`, the resolved sponsor key, whether
the user is active, and created and updated timestamps. Nothing else.

Subact ID accepts and discards every other attribute (names, emails, phone numbers and so on). A `GET`
returns only what Subact ID kept.

## What the receiver supports

| Supported | Not supported |
|---|---|
| `/Users`: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | Groups |
| `GET /scim/v2/ServiceProviderConfig` | Bulk |
| Filters `userName eq "..."` and `externalId eq "..."` | Any other filter |
| Paging with `startIndex` and `count` (at most 200) | Sorting, entity tags, password change |

Request bodies must be `application/scim+json` or `application/json` in UTF-8, and at most
64 KiB. A `charset` parameter may be left out or name `utf-8`. Any other media type or charset
is refused with `415`, because JSON between systems is UTF-8 (RFC 8259 section 8.1). Responses
are always `application/scim+json`. Attribute names are read whatever their case, as RFC 7643
section 2.1 requires, so `"Active": false` deactivates. A body naming one attribute twice, in
any case, is refused with `400 invalidSyntax`.

## Responses to expect

| Status | When |
|---|---|
| `400 invalidValue` | A create, replace or `PATCH` gives a kept attribute (`active`, `userName`, `externalId`) a value of the wrong type, for example `"active": "maybe"`. Subact ID refuses rather than ignoring it, so a failed deactivation is never reported as success. The strings `"True"` and `"False"` are accepted, because Entra ID sends them. |
| `400 invalidValue` | A create or replace has no usable `userName`, or no usable value in the sponsor key attribute |
| `401` | The credential is missing or wrong. Subact ID records a `scim.denied` audit event. |
| `409 uniqueness` | Another user already has that `userName` |
| `412` | The user kept changing during the write. Subact ID re-reads it and tries again, three attempts in all, then answers `412`. The client should read the user again and retry. |
| `507` | Subact ID already holds `SubactId:Scim:MaxUsers` users. Raise the limit. |

## Settings

| Setting | Default | Notes |
|---|---|---|
| `SubactId:Scim:BearerToken` | none | The credential. Setting it turns the receiver on. At least 32 characters. |
| `SubactId:Scim:PreviousBearerToken` | none | A second accepted credential, for rotation. At least 32 characters and different from the first. |
| `SubactId:Scim:SponsorKeyAttribute` | `externalId` | `externalId` or `userName`: the attribute that names the person tasks are keyed by. |
| `SubactId:Scim:MaxUsers` | `50000` | The most user records Subact ID holds. A create past it gets `507`. |

Subact ID refuses to start if any of the last three is set without `BearerToken`.

## Limits

- **Subact ID only knows what the provider sends.** If the provider does not deprovision, or syncs
  hourly, a deactivated person's tasks keep running until Subact ID hears, or until they expire
  (bounded by `max_task_ttl`). See the sponsor check in [Concepts](concepts.md#the-sponsor-check).
- **A stolen SCIM credential** can deactivate people and stop their agents. It cannot issue a
  token, widen a scope, or lift an operator's block. Rotate it like any other secret.
- **Blocks from a `DELETE` are permanent.** They are bounded by how many people the provider
  deletes. `SubactId:Scim:MaxUsers` bounds user records, but nothing bounds the number of blocks.

## See also

- [Configuration](configuration.md) for every setting.
- [Revocation](revocation.md) for the other ways to end a task.
- [Shared Signals](shared-signals.md), which receives the same kind of decision as it happens.
- [Back-channel logout](keycloak.md#ending-tasks-when-a-session-ends), which ends a session's
  tasks without blocking the person.
