# Subact ID

Subact ID is an agent identity and delegation control plane. It issues short-lived, scoped tokens
that let an AI agent act on behalf of a specific human, and it records every decision in a
ledger that names that human.

Status: pre-release, targeting v0.1.

## The problem

An agent needs authority it does not have of its own. The usual ways to give it some all fail
in the same way:

- **A service account.** Every action is attributed to the service account, not to a person.
- **The human's own access token.** The agent can do everything that person can, for as long as
  the token lives, and no log tells the agent's actions apart from the person's.
- **A long-lived API key.** It does not expire, it is not narrowed to the task, and revoking it
  stops every agent that shares it.

In each case the authority is wider than the task, it cannot be withdrawn while the task runs,
and the record cannot say which human is answerable for an action.

## What Subact ID issues

An agent presents the human's token and its own signed assertion. It gets back a token scoped
to one task:

```json
{
  "iss": "https://subactid.internal.example.com",
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "https://jira.internal",
  "scope": "jira:read jira:comment",
  "exp": 1757426520,
  "act": { "sub": "agent:jira-triage", "instance": "pod-7f9c4b", "depth": 1 },
  "task": { "id": "task_01HQZX9K4M", "exp": 1757428020, "sponsor": "f47ac10b-…" }
}
```

- `sub` is the human. The agent is in `act`, never in `sub`: this is delegation, not
  impersonation.
- The scope is the intersection of what the human has, what the agent is allowed, and what it
  asked for.
- The token expires in minutes and never outlives its task.
- Every decision, allowed or refused, is a record in an append-only ledger, sealed by signed
  checkpoints and queryable by the human's id.

[Concepts](docs/concepts.md) explains the whole model on one page. The full claim set is in
section 4 of [the spec](docs/spec/v0.1.md).

## Try it

```sh
cd quickstart
docker compose up
```

This starts an identity provider, the control plane, a tool server and an agent acting for a
human. It runs a scoped exchange, a refusal and a kill switch, and shows the ledger of all of
it. [`quickstart/README.md`](quickstart/README.md) explains what to watch.

To drive it yourself, open <http://localhost:8090> once it is up. Sign in, start a task, and
compare the agent's token with your own: the `sub` is the same, and the agent's `act` says who
holds it.

## What it guarantees

| Guarantee | What it means |
|---|---|
| The subject is always the human | `sub` is the human and the agent is only in `act`. A subject token that names an agent is refused. |
| Scope only narrows | At issue and at refresh. It never widens. v0.1 issues depth 1 only; sub-agent delegation is not supported. |
| A token never outlives its task | `exp` is bounded by the task's expiry as well as by the agent's `max_token_ttl`. |
| An agent proves who it is | `private_key_jwt` against a registered key, and each assertion is accepted once. No shared secrets. |
| A kill switch takes effect | Renewal fails at once. Tokens for high-risk audiences are introspected on every call, so they stop at once too. For other audiences, see [Revocation](docs/revocation.md). |
| Every decision is in the ledger | Every allow and every denial, with a machine-readable reason. |

[`tests/SubactId.Conformance`](tests/SubactId.Conformance) holds twenty adversarial tests. They
attack a live instance through its public API and check that each refusal reaches the ledger.
[Conformance](docs/conformance.md) lists what they assert and how to run them against your own
instance.

## Running your own

The quickstart is a demonstration, not a deployment. The steps below set up a real one.

`SubactId.Server` is the server binary. The container image runs it as its entrypoint, so each
command below is an argument to the image. From a clone of this repository, run
`dotnet run --project src/SubactId.Server -- <command>` instead.

```sh
# 1. Make a signing key. This reads no configuration.
SubactId.Server keys generate --out /run/secrets/subactid/active.pem

# 2. Configure the server. A missing or invalid setting stops startup with an error that names it.
export SubactId__Issuer=https://subactid.example.com
export SubactId__Database__ConnectionString='Host=…;Database=subactid;Username=subactid;Password=…'
export SubactId__Signing__Keys__0__Path=/run/secrets/subactid/active.pem

# The identity provider that issues the human's token.
export SubactId__UpstreamIdp__Issuer=https://kc.example.com/realms/corp
export SubactId__UpstreamIdp__Audience=subactid

# How to check that the human is still active, on every exchange and refresh.
# These three settings use Keycloak's admin API. For another provider, set
# SubactId__UpstreamIdp__SponsorCheck__Mode=signals and leave them out.
export SubactId__UpstreamIdp__SponsorCheck__UsersUrl=https://kc.example.com/admin/realms/corp/users
export SubactId__UpstreamIdp__SponsorCheck__TokenUrl=https://kc.example.com/realms/corp/protocol/openid-connect/token
export SubactId__UpstreamIdp__SponsorCheck__ClientId=subactid

# The admin API (registry, kill switches, audit query) is off until this is set.
# It must be at least 32 characters.
export SubactId__Admin__ApiKey=$(openssl rand -base64 32)

# 3. Apply the schema. Migrations never run at startup.
SubactId.Server migrate

# 4. Check the configuration, the database and the identity provider.
SubactId.Server doctor

# 5. Serve.
SubactId.Server
```

With no command, `SubactId.Server` runs the control plane. `/readyz` reports ready once the
database, the signing key, the identity provider's keys and this month's audit partition are
all available. If the identity provider stops answering after that, readiness reports
`Degraded` and still returns `200`.

`doctor` runs the readiness checks and more, and prints one line per check. It catches the two
common Keycloak mistakes: a realm whose issuer is not the URL you reach it on, and Keycloak's
default audience. [Keycloak](docs/keycloak.md) explains both, and
[`deploy/keycloak`](deploy/keycloak) sets up the realm as code.

For a trial or a single node, you can use an embedded database instead of Postgres: set
`SubactId__Database__Provider=sqlite` and `SubactId__Database__Path` instead of a connection string.
[Storage](docs/storage.md) covers both and what the embedded database gives up.

Every setting is listed in [Configuration](docs/configuration.md).

### Registering an agent

Agent registrations are files, reviewed like code:

```sh
export SUBACTID_ADMIN_KEY=…   # the admin key; there is no flag for it
SubactId.Server agent init jira-triage --out agents/
# fill in allowed_scopes and allowed_audiences in agents/jira-triage.yaml
SubactId.Server agent apply agents/*.yaml --server https://subactid.example.com
```

- `init` writes the registration, the agent's private key and its public key set. The scope and
  audience lists start empty, and `apply` refuses the file until both are filled in.
- `apply` creates missing agents and patches only the fields that differ, through the admin
  API, so every change is in the ledger.
- `apply --dry-run` needs no admin key, so you can run it on a pull request.

[Agents as files](docs/gitops.md) has the repository layout and the CI job.

### Kubernetes

There is a Helm chart in [`deploy/helm/subactid`](deploy/helm/subactid) and an annotated reference
install in [`deploy/kubernetes`](deploy/kubernetes). A tagged release publishes the image and
the chart to GHCR, signed with cosign, with an SBOM attached to the image. No release has been
tagged, so install the chart from a working tree.
[Kubernetes](docs/kubernetes.md) has the install steps.

## Documentation

[`docs/README.md`](docs/README.md) lists every page.

## SDKs

The client libraries live in a separate repository, `subactid-sdk`, which is not public, and are
licensed Apache-2.0. The packages are not published to npm, so none of them can be installed from
a registry:

- `@subactid/client`, for the agent: exchange, proactive refresh and typed errors.
- `@subactid/server` and `@subactid/mcp`, for the tool server: verify the token, enforce per-route
  scope, introspect when required, and log `sub` and `act.sub` on every request. This is
  section 9 of [the spec](docs/spec/v0.1.md).

The samples in [`samples/`](samples) do the same against the platform alone, with no library.

## The project

- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Changes come from members of the
  organization; it says how to report a bug or ask to join.
- Security reports: [`SECURITY.md`](SECURITY.md). Do not open a public issue for a
  vulnerability.
- Licence: the control plane is AGPL-3.0-or-later ([`LICENSE`](LICENSE), [`NOTICE`](NOTICE)).
  The documentation in [`docs/`](docs) is CC-BY-4.0. The samples, the Helm chart, the deployment
  files, the Keycloak module, the quickstart and the bench rig are Apache-2.0, so they can be
  copied into your own agents and infrastructure. [`REUSE.toml`](REUSE.toml) says which licence
  covers each path and [`LICENSES/`](LICENSES) holds the texts. The SDKs are Apache-2.0. The
  Subact ID name and logo are not covered by any of these licences; see
  [`TRADEMARKS.md`](TRADEMARKS.md).
