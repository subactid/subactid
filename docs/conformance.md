# Conformance suite

`tests/SubactId.Conformance` is a suite of 20 adversarial tests. It runs against a live Subact ID
instance through its public endpoints only and references no server project. Each test guards
one server check: remove the check and the test fails. Where a test provokes a refusal, it also
checks that the refusal was written to the audit ledger, under the reason
[section 7.6 of the spec](spec/v0.1.md#76-reasons) gives it.

The maintainers own the suite. It is a required CI job.

## The tests

| # | Test | What it asserts |
|---|---|---|
| 1 | The subject is always the human | `sub` is the human, and `act.sub` and `client_id` are the agent, in the token and in introspection. A subject token whose subject is an agent is `invalid_grant`, recorded as `subject_is_agent`. |
| 2 | Scope at exchange is the intersection | The token holds only user ∩ agent ∩ requested scopes. An empty intersection is `invalid_scope`, recorded as `scope_intersection_empty`. |
| 3 | Scope only narrows on refresh | A scope the task does not hold is `invalid_scope` (`scope_widened`), even when user and agent allow it. A refresh for the same scope keeps the `task_id` and issues a new `jti`. |
| 4 | The audience must be allowed and a task is bound to it | An audience outside `allowed_audiences` is `invalid_target` (`audience_not_allowed`). A refresh for another allowed audience is `invalid_target` (`audience_mismatch`). |
| 5 | A token never outlives its task | With a one-minute task, `exp` is never past the task's expiry, at issue or at a refresh 20 seconds in. |
| 6 | A client assertion is accepted once, from the registered key | A replayed assertion, a forged signature and an unknown agent are each `invalid_client`, each recorded. |
| 7 | Revocation and disabling take effect at once | After `DELETE /admin/tasks/{id}`, refresh is `access_denied` and the token introspects inactive with reason `operator_kill_switch`. After the agent revokes its own grant, refresh is refused. After the agent is disabled, exchange and refresh are `access_denied` and its token introspects inactive with reason `agent_disabled`. |
| 8 | A subject token is trusted only from the identity provider | Expired, foreign-signed, wrong-audience and wrong-issuer subject tokens are each `invalid_grant`, and each is recorded as a denial. |
| 9 | A task dies with the human it acts for | A person disabled at the identity provider fails the next refresh with `access_denied` (`sponsor_disabled`). A person deleted there fails with `access_denied` (`sponsor_not_found`). Needs `poll` mode. |
| 10 | The audit ledger is sealed | Every new record is sealed into a signed checkpoint within a minute. The suite rebuilds each record's leaf, folds its audit path to the checkpoint's root, checks each checkpoint's signature against the JWKS and its link to the previous checkpoint, and gets `404` for a proof of a sequence number that does not exist. |
| 11 | A high-risk audience says so in the token | `introspect_required` is `true` for an audience in `high_risk_audiences` and absent for any other. |
| 12 | No refusal hands back the credential it refused | No subject token, client assertion or task grant appears in an error body, whole or in part, including for an oversized request. |
| 13 | A human the control plane will not act for is refused | After `PUT /admin/sponsors/{key}/block`, the running token introspects inactive, refresh and a new exchange are `access_denied`, and a denial is recorded, while the identity provider still reports the person as active. Another person is unaffected. |
| 14 | Discovery advertises only what the control plane does | `private_key_jwt` at the token and revocation endpoints, `none` at introspection, the three assertion algorithms, an empty `response_types_supported`, and no ID token or authorization endpoint claims. An assertion addressed to the issuer, not the token endpoint, is accepted. |
| 15 | A request the token endpoint does not do is refused as such | An unknown `grant_type` is `unsupported_grant_type`, and an exchange without `scope` is `invalid_request`, never a token for a default scope. Both are recorded. |
| 16 | Only the agent a token was issued to can revoke it | Another agent revoking an agent's token, its grant, or something that is no token at all gets the same empty `200` each time. Nothing is revoked: the token stays active and its task renews. Each attempt is recorded as a `token.denied` with reason `revocation_not_owner` against the agent that made it. |
| 17 | A revoked token introspects as revoked at once | After the agent revokes its own token, introspection says `active: false` with `revoked_at` and a `revocation_reason`, and no claims. The task carries on: its grant renews and the new token is active. |
| 18 | A logout ends that session's tasks and does not block | A back-channel logout naming a session ends the task that session started and leaves the other session's. A logout naming only the person ends all of theirs. Neither blocks them: they start a new task straight after. A logout token the identity provider did not sign is `400` and ends nothing. Needs the logout receiver. |
| 19 | A provisioning deactivation blocks until reactivation | A SCIM `PATCH` setting `active` to `false` ends the running task, refuses refresh and a new exchange with `access_denied`, and leaves a block with source `scim`. Setting it back to `true` lifts the block, and the person starts a new task, but the old one stays over. A request without the credential is `401`. Needs the SCIM receiver. |
| 20 | A transmitter's events act as they say, only with its credential and key | A push without the credential is `401`, and one signed with a key the transmitter does not publish is `400`; neither changes anything. `account-disabled` ends the running task and blocks the person with source `ssf`, and delivered twice is still `202`. `account-enabled` lifts that block. `session-revoked` ends the running task and blocks nobody. Needs the Shared Signals receiver. |

## Running it

The suite runs a stub that stands in for everything the instance calls out to: the upstream
identity provider (discovery, JWKS, the admin users API and the token endpoint used by the
sponsor check) and every agent's JWKS. Configure the instance to find all of these at one https
base URL. The suite listens there with a certificate the instance must trust. The URL must be
https, because agent JWKS are only fetched over https.

| Variable | Meaning |
|---|---|
| `SUBACTID_CONFORMANCE_URL` | Base URL of the instance under test |
| `SUBACTID_CONFORMANCE_ADMIN_KEY` | The instance's `SubactId:Admin:ApiKey` |
| `SUBACTID_CONFORMANCE_STUB_URL` | The https base URL the instance uses for the identity provider and agent JWKS, for example `https://localhost:5199` |
| `SUBACTID_CONFORMANCE_STUB_PFX` | A PKCS#12 file with no password, for that URL's host. The stub keeps the identity provider's and the transmitter's signing keys next to it, so repeated runs against one instance use the same keys. |
| `SUBACTID_CONFORMANCE_LOGOUT_AUDIENCE` | The instance's `SubactId:UpstreamIdp:BackchannelLogout:Audience`. Test 18 only. |
| `SUBACTID_CONFORMANCE_SCIM_TOKEN` | The instance's `SubactId:Scim:BearerToken`. Test 19 only. |
| `SUBACTID_CONFORMANCE_SSF_AUDIENCE` | The instance's `SubactId:Ssf:Audience`. Test 20 only. |
| `SUBACTID_CONFORMANCE_SSF_TOKEN` | The instance's `SubactId:Ssf:BearerToken`. Test 20 only. |

Configure the instance like this, for a stub at `https://localhost:5199`:

```
SubactId__UpstreamIdp__MetadataUrl=https://localhost:5199/.well-known/openid-configuration
SubactId__UpstreamIdp__Audience=subactid
SubactId__UpstreamIdp__SponsorCheck__UsersUrl=https://localhost:5199/admin/realms/main/users
SubactId__UpstreamIdp__SponsorCheck__TokenUrl=https://localhost:5199/realms/main/protocol/openid-connect/token
SubactId__UpstreamIdp__SponsorCheck__ClientId=subactid
```

Tests 18 to 20 also need the three receivers turned on. The stub serves the Shared Signals
transmitter's discovery document and keys under `/transmitter`, so the transmitter's issuer is
the stub's URL plus that path. Any audience and credentials will do, as long as the suite is given
the same values:

```
SubactId__UpstreamIdp__BackchannelLogout__Audience=conformance-portal
SubactId__Scim__BearerToken=<at least 32 characters>
SubactId__Ssf__Issuer=https://localhost:5199/transmitter
SubactId__Ssf__Audience=<the stream audience>
SubactId__Ssf__BearerToken=<at least 32 characters>
```

Then run:

```
dotnet test tests/SubactId.Conformance
```

If configuration is missing or the instance does not answer, every test fails with the reason.
The suite sends a few hundred requests from one address, more than the default burst allows at
once. It waits out a `429` for as long as `Retry-After` asks and sends the request again, so it
needs no change to the instance's rate limits and does not test them.
If a receiver's variables are missing, its test fails with the reason.

To run against an instance without the receivers, leave out the three tests that need them.
Each carries the trait `Receiver`:

```
dotnet test tests/SubactId.Conformance --filter "Receiver!=logout&Receiver!=scim&Receiver!=ssf"
```

The remaining 17 tests must pass on any conformant instance.

### Instance settings the suite relies on

The shipped defaults satisfy all of these except the checkpoint interval. The CI job sets them
explicitly.

| Setting | Required value | Why |
|---|---|---|
| `SubactId:Audit:Aggregation:Window` | At most one minute (default `PT1M`) | Denials that name nobody are written once per window. The suite looks back one minute for them. |
| `SubactId:Audit:Checkpoint:Interval` | Well under one minute. CI uses `PT5S`. | Test 10 waits at most one minute for its records to be sealed. |
| `SubactId:Agents:MinTaskTtl` | At most `PT1M` (default `PT1M`) | Test 5 registers a one-minute task. |
| `SubactId:Tokens:DefaultTaskTtl` | At least `PT1M` (default `PT30M`) | Test 5 refreshes 20 seconds into its task. |
| `SubactId:UpstreamIdp:SponsorKeyClaim` | `sub` (default) | Tests 13, 19 and 20 name a person by the subject they put in their token. |
| `SubactId:Scim:SponsorKeyAttribute` | `externalId` (default) | Test 19 provisions the person with their subject as `externalId`. |

`SubactId:UpstreamIdp:SponsorCheck:CacheTtl` can be anything: test 9 uses a different person for
each outcome, so no answer comes from the cache.

### In CI

The `conformance` job in `.github/workflows/ci.yml` is the reference setup. It creates a CA and a
`localhost` certificate, trusts the CA, migrates and starts an instance against a Postgres
service, and runs the suite. The job fails if the suite runs no tests.

## Signals mode

Test 9 disables a person at the stub's admin API, which a `signals`-mode instance never asks.
The other 19 tests do not depend on the sponsor check mode.

The `conformance-signals` job runs those 19 against an instance with
`SubactId:UpstreamIdp:SponsorCheck:Mode=signals` and no sponsor check URLs. It:

- excludes test 9 by name,
- checks with `SubactId.Server doctor` that the instance really is in `signals` mode,
- fails if fewer than 19 tests run.

This also shows that in `signals` mode, exchange and refresh work with no outbound call about
the person.

Test 13 covers the same property as test 9 (a task dies with the human it acts for) through
Subact ID's own block list, which every instance enforces in either mode. The identity provider keeps
reporting the person as active throughout, so an instance that answered from the provider would
fail it.

## The receivers

The back-channel logout, SCIM and Shared Signals receivers exist only when configured, and an
unconfigured instance answers `404` there. Tests 18 to 20 therefore need them turned on, and are
the three to leave out against an instance that has not enabled them (see
[Running it](#running-it)). Both CI jobs turn all three on, so every run covers them.

The receivers are also covered in more depth by integration tests that drive each one over HTTP
against a real database: `BackchannelLogoutEndpointTests`, `ScimEndpointTests` and
`SecurityEventEndpointTests` in `tests/SubactId.IntegrationTests`.
