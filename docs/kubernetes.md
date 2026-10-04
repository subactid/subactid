# Running on Kubernetes

The Helm chart in [`deploy/helm/subactid`](../deploy/helm/subactid) installs:

- a Deployment behind a Service, with a PodDisruptionBudget that keeps one replica up through
  node drains when there is more than one,
- a migrate Job that runs before every install and upgrade,
- an optional Ingress for the token endpoint and discovery documents only,
- an optional second Ingress for the admin API, for an internal-only controller,
- an optional NetworkPolicy that limits egress to the database, the identity provider, DNS and
  the rules you add,
- a `helm test` pod that runs `doctor` and checks `/readyz`.

The chart creates no Secret and generates no key. It reads Secrets you create, by name, so
`helm template` output contains no secret.

The chart supports Postgres only. The embedded SQLite provider in [Storage](storage.md) is for
one node with one writer, which a multi-replica Deployment is not.

## Before you install

You need a Postgres database (16 or later), an identity provider, and these Secrets:

```sh
kubectl create namespace subactid

# The role the server runs as: reads and writes rows, no DDL.
kubectl -n subactid create secret generic subactid-db \
  --from-literal=connection-string='Host=postgres;Database=subactid;Username=subactid;Password=...'

# Optional: a role that may change the schema. Only the migrate Job gets it.
kubectl -n subactid create secret generic subactid-db-migrate \
  --from-literal=connection-string='Host=postgres;Database=subactid;Username=subactid_admin;Password=...'

# The signing key. "keys generate" reads no configuration, so run it anywhere. See keys.md.
SubactId.Server keys generate --out active.pem
kubectl -n subactid create secret generic subactid-signing --from-file=active.pem
rm active.pem

# Optional: the admin API key. Without it /admin and /audit answer 503.
kubectl -n subactid create secret generic subactid-admin --from-literal=api-key="$(openssl rand -hex 32)"
```

The chart's default `signing.keys` entry reads the key `active.pem` from the signing Secret. If
you name the file differently, set `signing.keys[0].key` to match.

To keep keys out of manifests entirely, project the Secrets from a secret manager.
[`deploy/kubernetes/external-secret.yaml`](../deploy/kubernetes/external-secret.yaml) shows this
with the External Secrets Operator.

The identity provider needs a client for the control plane (`upstream.sponsorCheck.clientId`,
default `subactid`). It must:

- authenticate with a signed assertion (`private_key_jwt`), not a client secret,
- use this control plane's `/.well-known/jwks.json` as its JWKS URL,
- have a service account that may only read users (`view-users` in Keycloak).

A refresh uses this client to check that the human is still active.
[Keycloak](keycloak.md) covers the Keycloak setup.

## Installing

The release publishes the chart to `oci://ghcr.io/subactid/charts` and the image to
`ghcr.io/subactid/subactid`, with the same version number.

Install:

```sh
helm install subactid oci://ghcr.io/subactid/charts/subactid --version 0.1.0 -n subactid \
  --set issuer=https://subactid.example.com \
  --set upstream.issuer=https://kc.example.com/realms/corp \
  --set database.existingSecret=subactid-db \
  --set signing.existingSecret=subactid-signing \
  --wait
helm test subactid -n subactid
```

To install from a working tree, point Helm at the directory and at an image you built:

```sh
helm install subactid deploy/helm/subactid -n subactid \
  --set image.repository=subactid --set image.tag=dev \
  --set issuer=https://subactid.example.com \
  --set upstream.issuer=https://kc.example.com/realms/corp \
  --set database.existingSecret=subactid-db \
  --set signing.existingSecret=subactid-signing \
  --wait
```

[`deploy/kubernetes/values.yaml`](../deploy/kubernetes/values.yaml) is an annotated values file
for a production install.

### Verifying the release

The release workflow signs the chart and the image keylessly with cosign. Verify both before
you install:

```sh
cosign verify ghcr.io/subactid/charts/subactid:0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/subactid/subactid/\.github/workflows/release\.yml@refs/tags/v'
cosign verify ghcr.io/subactid/subactid:0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/subactid/subactid/\.github/workflows/release\.yml@refs/tags/v'
```

The identity ends in the tag the workflow ran for, so a signature made by any other run of the
same workflow, on a branch or by hand, does not verify as a release.

The chart archive attached to the GitHub release comes with a cosign bundle next to it,
`subactid-0.1.0.tgz.sigstore.json`. To verify a downloaded archive instead of the OCI chart:

```sh
cosign verify-blob subactid-0.1.0.tgz \
  --bundle subactid-0.1.0.tgz.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/subactid/subactid/\.github/workflows/release\.yml@refs/tags/v'
```

To run exactly the image that verified, set `image.digest` to its `sha256:` digest, which `cosign
verify` prints. The chart then pulls by digest and the tag is not used.

The image carries its SBOM and build provenance as attestations:

```sh
docker buildx imagetools inspect ghcr.io/subactid/subactid:0.1.0 --format '{{ json .SBOM }}'
```

GitHub records its own build provenance for the same digest. It verifies with the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/subactid/subactid:0.1.0 --owner subactid
```

## Required values

The chart fails to render, with a message naming the missing value, when one of these is unset:

| Value | What it is |
|---|---|
| `issuer` | The absolute URL clients reach this control plane at. It is the `iss` of every token and the base URL in discovery. |
| `upstream.issuer` | The identity provider's realm URL, for example `https://kc.example.com/realms/corp`. The discovery URL, token URL and admin users URL are derived from it. For a provider that is not shaped like Keycloak, set `upstream.metadataUrl`, `upstream.sponsorCheck.usersUrl` and `upstream.sponsorCheck.tokenUrl` instead. |
| `database.existingSecret` | The Secret holding the server's connection string, under the key `connection-string`. |
| `signing.existingSecret` | The Secret holding the signing key PEM files. |

If you enable `ingress`, also set `ingress.host` and `rateLimit.trustedProxies` (the ingress
controller's pod network). The chart refuses an ingress without trusted proxies, because every
request would count as coming from the ingress controller for rate limiting.

## Every other setting

Every server setting in [Configuration](configuration.md) has a value in the chart, except those
it leaves out on purpose: `SubactId:Database:Provider` and `Path`, since the chart supports
Postgres only, and `SubactId:Signing:Keys:N:Pem`, since keys are projected from a Secret as
files. An empty value leaves the server's default. The chart refuses a value it does not know,
so a mistyped name fails the render instead of being ignored.

A credential is never a value itself: its value names a Secret, and the key within it.

| Value | Setting |
|---|---|
| `issuer` | `SubactId:Issuer` |
| `upstream.issuer` | `SubactId:UpstreamIdp:Issuer` |
| `upstream.metadataUrl` | `SubactId:UpstreamIdp:MetadataUrl`, instead of `upstream.issuer` |
| `upstream.audience` | `SubactId:UpstreamIdp:Audience` |
| `upstream.subjectTokenTypes` | `SubactId:UpstreamIdp:SubjectTokenTypes` |
| `upstream.sponsorKeyClaim` | `SubactId:UpstreamIdp:SponsorKeyClaim` |
| `upstream.sponsorCheck.mode` | `SubactId:UpstreamIdp:SponsorCheck:Mode` |
| `upstream.sponsorCheck.clientId` | `SubactId:UpstreamIdp:SponsorCheck:ClientId` |
| `upstream.sponsorCheck.usersUrl` | `SubactId:UpstreamIdp:SponsorCheck:UsersUrl`, derived from `upstream.issuer` when empty |
| `upstream.sponsorCheck.tokenUrl` | `SubactId:UpstreamIdp:SponsorCheck:TokenUrl`, derived from `upstream.issuer` when empty |
| `upstream.sponsorCheck.cacheTtl` | `SubactId:UpstreamIdp:SponsorCheck:CacheTtl` |
| `upstream.backchannelLogout.audience` | `SubactId:UpstreamIdp:BackchannelLogout:Audience` |
| `database.existingSecret` | `SubactId:Database:ConnectionString` |
| `database.migration.existingSecret` | `SubactId:Database:MigrationConnectionString`, for the migrate Job only |
| `signing.keys[].key` | `SubactId:Signing:Keys:N:Path`, a file under `signing.mountPath` |
| `signing.keys[].kid` | `SubactId:Signing:Keys:N:Kid` |
| `signing.activeKid` | `SubactId:Signing:ActiveKid` |
| `admin.existingSecret` | `SubactId:Admin:ApiKey` |
| `audit.sink.url` | `SubactId:Audit:Sink:Url` |
| `audit.sink.existingSecret` | `SubactId:Audit:Sink:BearerToken` |
| `audit.drainInterval` | `SubactId:Audit:DrainInterval` |
| `audit.drainBatchSize` | `SubactId:Audit:DrainBatchSize` |
| `audit.checkpointInterval` | `SubactId:Audit:Checkpoint:Interval` |
| `audit.retention` | `SubactId:Audit:Retention` |
| `audit.partitionMonthsAhead` | `SubactId:Audit:Partitions:MonthsAhead` |
| `audit.aggregation.enabled` | `SubactId:Audit:Aggregation:Enabled` |
| `audit.aggregation.window` | `SubactId:Audit:Aggregation:Window` |
| `rateLimit.enabled` | `SubactId:RateLimit:Enabled` |
| `rateLimit.permitsPerMinute` | `SubactId:RateLimit:PermitsPerMinute` |
| `rateLimit.burst` | `SubactId:RateLimit:Burst` |
| `rateLimit.trustedProxies` | `SubactId:RateLimit:TrustedProxies` |
| `rateLimit.signals.permitsPerMinute` | `SubactId:RateLimit:Signals:PermitsPerMinute` |
| `rateLimit.signals.burst` | `SubactId:RateLimit:Signals:Burst` |
| `rateLimit.introspection.permitsPerMinute` | `SubactId:RateLimit:Introspection:PermitsPerMinute` |
| `rateLimit.introspection.burst` | `SubactId:RateLimit:Introspection:Burst` |
| `overload.enabled` | `SubactId:Overload:Enabled` |
| `overload.concurrencyLimit` | `SubactId:Overload:ConcurrencyLimit` |
| `overload.queueLimit` | `SubactId:Overload:QueueLimit` |
| `overload.queueTimeout` | `SubactId:Overload:QueueTimeout` |
| `agentKeys.blockPrivateNetworks` | `SubactId:AgentKeys:BlockPrivateNetworks` |
| `allowInsecureHttp` | `SubactId:AllowInsecureHttp` |
| `scim.existingSecret` | `SubactId:Scim:BearerToken` |
| `scim.previousSecretKey` | `SubactId:Scim:PreviousBearerToken`, another key in the same Secret |
| `scim.sponsorKeyAttribute` | `SubactId:Scim:SponsorKeyAttribute` |
| `scim.maxUsers` | `SubactId:Scim:MaxUsers` |
| `ssf.issuer` | `SubactId:Ssf:Issuer` |
| `ssf.audience` | `SubactId:Ssf:Audience` |
| `ssf.existingSecret` | `SubactId:Ssf:BearerToken` |
| `ssf.previousSecretKey` | `SubactId:Ssf:PreviousBearerToken`, another key in the same Secret |
| `tokens.defaultTaskTtl` | `SubactId:Tokens:DefaultTaskTtl` |
| `tokens.defaultTokenTtl` | `SubactId:Tokens:DefaultTokenTtl` |
| `agents.minTaskTtl` | `SubactId:Agents:MinTaskTtl` |
| `agents.maxTaskTtl` | `SubactId:Agents:MaxTaskTtl` |
| `agents.minTokenTtl` | `SubactId:Agents:MinTokenTtl` |
| `agents.maxTokenTtl` | `SubactId:Agents:MaxTokenTtl` |
| `tasks.sweepInterval` | `SubactId:Tasks:SweepInterval` |
| `tasks.sweepBatchSize` | `SubactId:Tasks:SweepBatchSize` |
| `tasks.retention` | `SubactId:Tasks:Retention` |
| `revocations.signOutRetention` | `SubactId:Revocations:SignOutRetention` |

`logging.minimumLevel` and `logging.overrides` set Serilog's levels, and `containerPort` the port
the server listens on.

## Signals mode and the receivers

- **Signals mode.** Set `upstream.sponsorCheck.mode` to `signals` for an identity provider
  without an admin API the control plane can ask. Leave `upstream.sponsorCheck.usersUrl`,
  `tokenUrl` and `cacheTtl` empty: the chart refuses them in that mode, as the server does, and
  `clientId` goes unused. The chart derives nothing from `upstream.issuer` then, so it need not
  be a Keycloak realm URL.
- **Back-channel logout.** Set `upstream.backchannelLogout.audience` to the human-facing client
  id. [Keycloak](keycloak.md#ending-tasks-when-a-session-ends) covers the rest.
- **SCIM.** Create a Secret whose key `bearer-token` holds the credential the provisioning
  client presents, at least 32 characters, and name it in `scim.existingSecret`.
- **Shared Signals.** Set `ssf.issuer` and `ssf.audience`, and name in `ssf.existingSecret` a
  Secret whose key `bearer-token` holds the credential the transmitter presents.

To rotate a SCIM or Shared Signals credential, add the new one to its Secret under another key,
point `existingSecretKey` at it and `previousSecretKey` at the old one, and upgrade. Once the
client has the new one, remove the old key and `previousSecretKey`, and upgrade again.

The receivers answer at `/backchannel-logout`, `/scim` and `/events`, which the public ingress
does not carry by default. Add a path to `ingress.paths` when the identity provider reaches it
from outside the cluster.

## Other environment variables and egress

- **`extraEnv`** adds environment variables to every container, for what is not a Subact ID
  setting, such as `HTTPS_PROXY`. The chart refuses a Subact ID setting there, since each has a
  value of its own.
- **`networkPolicy.extraEgress`** adds egress rules. With `networkPolicy.enabled`, the control
  plane reaches only the database, the identity provider and DNS without one. The audit sink, a
  Shared Signals transmitter on other hosts than the identity provider, an agent registered with
  a `jwks_uri` and an HTTPS proxy each need a rule. An agent with inline keys needs none.
- **`networkPolicy.ingressFrom`** limits what may reach the control plane's port, for example to
  the ingress controller's namespace. Empty lets every pod in the cluster connect. The `helm test`
  pod is let in either way, since it reads `/readyz`. It and the migrate Job's pod are labelled
  `app.kubernetes.io/name: subactid-test` and `subactid-migrate` rather than `subactid`, so the
  Service never routes to them and the policy's egress rules do not apply to them.

## What the chart refuses

- **Publishing the admin API on the public ingress.** `ingress.paths` defaults to `/oauth2` and
  `/.well-known`. A path starting with `/admin` or `/audit`, or `/` on its own, fails the render.
  Use `ingress.admin` on an internal-only controller instead. `ingress.admin` in turn requires
  `admin.existingSecret`.
- **An ingress without `rateLimit.trustedProxies`**, unless `rateLimit.enabled` is `false`.
- **Several signing keys without `signing.activeKid`.** With more than one key, you name the
  signer.
- **A value it does not know.** The values schema lists every value, so a mistyped name fails
  the render instead of being ignored.
- **`upstream.sponsorCheck.usersUrl`, `tokenUrl` or `cacheTtl` in signals mode**, which the
  server refuses too.
- **A receiver value without what turns the receiver on**: a `scim` value without
  `scim.existingSecret`, an `ssf` value without `ssf.issuer`, and `ssf.issuer` without
  `ssf.audience` and `ssf.existingSecret`.
- **A Subact ID setting in `extraEnv`.**

## Migrations

The schema is changed only by the migrate Job, a `pre-install` and `pre-upgrade` hook. The server
never migrates at startup.

When `database.migration.existingSecret` is set, the Job connects with that role and the server
pod never receives it. When it is empty, the Job uses the server's connection string.

## Upgrading

```sh
helm upgrade subactid oci://ghcr.io/subactid/charts/subactid --version 0.2.0 -n subactid -f values.yaml --wait
```

The chart version and the image version are the same number, so `--version` selects both.

The migrate Job runs before the new pods start. If it fails, the upgrade fails and the running
version stays in place. The failed Job is kept so you can read its logs. The next upgrade
replaces it.

## Signing keys

One key signs. Every key in `signing.keys` is published in the JWKS, so tokens signed by an
older key still verify.

With one key, `signing.keys` has one entry. `kid` is optional and defaults to the RFC 7638
thumbprint.

To rotate a key, do three upgrades:

1. Add the new PEM to the Secret and to `signing.keys`. Set `signing.activeKid` to the **old**
   kid. Both keys are published and the old one still signs, so clients that cache the JWKS can
   pick up the new key.
2. Set `signing.activeKid` to the new kid. New tokens use the new key. Old tokens still verify.
3. Once every token signed by the old key has expired, remove the old key from `signing.keys`
   and from the Secret. Wait at least the longest `max_token_ttl` of any agent. The
   deployment-wide ceiling defaults to one hour (`agents.maxTokenTtl`).

`SubactId.Server keys rotate --out <path>` writes the new key and prints these steps with the exact
settings, including how long step 3 must wait. [Signing keys](keys.md) covers key management in
full.

## Registering an agent

The default ingress does not publish the admin API. Use a port-forward:

```sh
kubectl -n subactid port-forward svc/subactid 5100:80 &
export SUBACTID_ADMIN_KEY=$(kubectl -n subactid get secret subactid-admin -o jsonpath='{.data.api-key}' | base64 -d)
SubactId.Server agent apply deploy/kubernetes/agent.yaml --server http://127.0.0.1:5100
```

[`deploy/kubernetes/agent.yaml`](../deploy/kubernetes/agent.yaml) is an annotated registration.
[Agents as files](gitops.md) covers `agent init` and `agent apply`.

## When a pod is not ready

`/readyz` returns 503 until all four readiness checks pass:

| Check | Passes when |
|---|---|
| `database` | The database answers. |
| `audit-partition` | The audit ledger has a partition for the current month. |
| `signing-key` | The signing key is loaded. |
| `upstream-jwks` | The identity provider's discovery document and keys have been fetched at least once. |

Start with the logs and pod status:

```sh
kubectl -n subactid logs deployment/subactid | tail -20
kubectl -n subactid get pods -l app.kubernetes.io/name=subactid
```

- **`CrashLoopBackOff` with a configuration error in the first log lines.** The server refuses
  to start on incomplete configuration. The error names the setting but never prints its value.
- **Running but never ready.** One of the four checks is failing. `helm test subactid -n subactid` runs
  `doctor`, which names it. The test pod gets the server's settings, its database connection
  string and its signing key, so `doctor` checks those for real. It does not get the admin API
  key, the SCIM and Shared Signals credentials or the audit sink's token, so `doctor` reports the
  admin API, SCIM and the signals receiver as off there.
- **`audit-partition` failing.** Every audit append, and so every exchange, is refused.
  Run `SubactId.Server migrate` with the migration credentials. It creates this month's partition
  and the months ahead, and the pod becomes ready without a restart. See
  [Storage](storage.md#the-ledgers-partitions).

## When the identity provider goes down after startup

Readiness does not go red when the identity provider stops answering after the pod became
ready. The pod still holds the provider's keys, so it can still validate subject tokens and issue
tokens. Taking every replica out of rotation would turn a provider outage into a control plane
outage.

Instead:

- The keys are re-fetched every five minutes.
- The first failed fetch logs a warning, `The identity provider stopped answering. ...`, and
  recovery logs `The identity provider is answering again ...`.
- Once the last successful fetch is more than fifteen minutes old, `/readyz` still returns 200,
  with the body `Degraded`.

```sh
kubectl -n subactid port-forward svc/subactid 5100:80 &
curl -s http://127.0.0.1:5100/readyz
# Degraded
kubectl -n subactid logs deployment/subactid | grep 'identity provider'
```

During the outage:

- A refresh that needs a fresh sponsor check is refused with `temporarily_unavailable` and
  audited as `sponsor_status_unavailable`.
- If the provider rotates its keys during the outage, tokens signed with the new key are
  rejected until the fetch succeeds.

Alert on the warning in the logs, not on readiness.
