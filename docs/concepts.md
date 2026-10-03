# Concepts

This page is the Subact ID model on one page: what it issues, what limits it, and what it records.
Every endpoint, claim, error code and record field is defined in
[the v0.1 API surface](spec/v0.1.md).

The rule behind all of it:

> A task token never carries more authority than the human who started the task, and every
> action traces back to that human.

## Delegation, not impersonation

An agent never uses the human's token. It sends that token to Subact ID, together with proof of
its own identity, and gets a different token back:

```json
{
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "https://jira.internal",
  "scope": "jira:read",
  "client_id": "agent:jira-triage",
  "act": { "sub": "agent:jira-triage", "instance": "pod-7f9c4b", "depth": 1 },
  "task": { "id": "task_01HQZX9K4M", "exp": 1757428020, "sponsor": "f47ac10b-58cc-4372-a567-0e02b2c3d479" }
}
```

- `sub` is always the human. It never names an agent. A subject token whose subject is an
  agent is refused with `invalid_grant`.
- `act.sub` and `client_id` name the agent.
- `task` names the task the token belongs to, when that task ends, and the human it acts for.
- `act.instance` is the agent's own label for which copy of it is running. Subact ID copies it from
  the agent's signed assertion and never checks it. Use it to correlate logs, not as an
  identity.

A tool server that sees no `act` claim was called by a human directly. One that sees `act`
knows which agent holds the token and for whom. Because `sub` is always the human, "everything
any agent did for this person" is one filter on `sub` in the audit query.

## Tasks and tokens

A token exchange starts a **task**, and every token belongs to a task. A task and a token have
separate lifetimes:

| | Set by | Default |
|---|---|---|
| Task | `max_task_ttl` on the agent's registration | 30 minutes |
| Token | `max_token_ttl` on the registration, cut to what is left of the task | 5 minutes |

A registration that sets neither gets `SubactId:Tokens:DefaultTaskTtl` and
`SubactId:Tokens:DefaultTokenTtl`. `SubactId:Agents:MaxTaskTtl` and `SubactId:Agents:MaxTokenTtl` are the
most any registration may set. See [Configuration](configuration.md).

A long task never holds a long-lived credential. The agent renews: same `task_id`, new `jti`.
Every renewal is a new decision by Subact ID.

The task's lifetime comes from the registration, not from the subject token. A five-minute
session token can start a six-hour task. The human is checked again at every renewal. If you
want tasks no longer than the sessions that start them, set `max_task_ttl` to match.

### The task grant

The exchange returns a **task grant** in the `refresh_token` field. It is bound to one task and
one agent. It cannot widen scope, and it stops working when the task expires or is revoked.
Any other agent presenting it gets `invalid_grant`.

### What a renewal checks

In order:

1. The agent's client assertion is valid.
2. The grant exists and belongs to this agent.
3. The task is not revoked and has not expired.
4. The human may still be acted for (see [The sponsor check](#the-sponsor-check)).
5. The audience is the task's audience.
6. The requested scope is within the scope of the last renewal, or of the exchange before the
   first.
7. The policy still allows it against the agent's registration as it is now.

A registration narrowed ten minutes ago narrows the next renewal. A disabled agent is refused.

Renew at about 60% of `expires_in`, not after a `401`. `@subactid/client` in the SDKs does
this for you.

## The sponsor check

Subact ID keeps its own list of humans it will not act for. A human on that list is refused with
`access_denied` at every exchange and every renewal. Blocking a human also revokes their live
tasks at once.

`SubactId:UpstreamIdp:SponsorCheck:Mode` sets how Subact ID learns who to refuse:

| Mode | What Subact ID does |
|---|---|
| `poll` (default) | Checks its own list **and** asks the identity provider's admin API (Keycloak's) on every exchange and every renewal. An exchange always asks fresh. A renewal may reuse an answer for up to `SubactId:UpstreamIdp:SponsorCheck:CacheTtl` (default 30 seconds), and never for longer than the token being issued. It never reuses an answer fetched before its task was created. A provider that cannot answer is `temporarily_unavailable`, never treated as active. |
| `signals` | Checks only its own list. Operators add to it through the [admin API](admin-api.md), and the identity provider through [SCIM](scim.md) and [Shared Signals](shared-signals.md). If nothing tells Subact ID, a task runs to its own expiry, which `max_task_ttl` bounds. |

Use `signals` when your identity provider has no admin API that Subact ID can read.

The list works in both modes. [Back-channel logout](keycloak.md#ending-tasks-when-a-session-ends)
and the CAEP `session-revoked` event also work in both modes: they end tasks but do not add the
human to the list.

In `poll` mode, a human disabled or deleted at the identity provider fails the next renewal of
every task, so no task outlives that by more than one token lifetime.

## Scope only narrows

On every exchange, Subact ID computes the effective scope:

```
effective = user_scopes ∩ agent.allowed_scopes ∩ requested_scopes
```

Three parties must agree: the identity provider (what this human may do), the operator (what
this agent may ever do, set at registration), and the agent (what it asks for now).

An empty intersection is `invalid_scope`. Subact ID never issues a token with no scope.

On renewal, the requested scope must be within the scope of the last renewal, or of the exchange
before the first. An agent asking for `jira:comment` on a task that only holds `jira:read` gets
`invalid_scope`, even if the human and the registration would both allow it in a new exchange.
Asking for less on renewal is allowed, and the narrowing sticks: a later renewal cannot ask for
the dropped scope back.

The decision is a pure function of `(user_scopes, agent, requested_scopes, audience, depth)`. It
does no I/O, so it gives the same answer on every instance.

## Audience

Every task token has one audience, and it must be in the registration's `allowed_audiences`.
Otherwise the exchange is `invalid_target`. A task is bound to its audience: renewing for a
different one is also `invalid_target`.

A tool server checks `aud` against itself. This stops a token minted for one service being
replayed against another.

`high_risk_audiences` on the registration lists audiences whose tokens must be introspected on
every call. Tokens for those audiences carry `introspect_required: true`. It does not change
which audiences a token can be issued for. See [Revocation](revocation.md).

## Delegation depth

The `act` claim can nest, one level per agent hop, and `max_delegation_depth` on the
registration limits the depth.

**In v0.1, Subact ID only issues `depth: 1`.** An exchange validates the subject token against the
upstream identity provider, so a task token presented as a subject token is `invalid_grant`.
The SDKs' tool-server packages, `@subactid/server` and `@subactid/mcp`, enforce their own depth
limit when they read tokens, 1 unless configured otherwise. Subact ID v0.1 issues no nested chain.

## How an agent authenticates

Agents authenticate with `private_key_jwt` only. Subact ID does not support client secrets.

A registration names exactly one key source:

| Source | How keys are read | When a removed key stops working |
|---|---|---|
| `jwks` (inline public keys) | From the registration on every assertion. Subact ID also serves them at `/agents/{agent_id}/jwks.json`. | On the next request |
| `jwks_uri` (an https URL) | Fetched without following a redirect and cached for 10 minutes, refreshed early when an assertion names an unknown key. If the URL cannot be reached, the last keys fetched are used for up to an hour, then none | Up to 10 minutes later, or up to an hour while the URL is down |

A key that includes a private member is refused at registration. If a key must stop working at
once, hold it inline, or disable the agent.

Each assertion is accepted once. A replayed assertion, a bad signature and an unknown agent are
all `invalid_client`.

`sponsor_required` must be `true` in v0.1: every token has a human subject token behind it.

## The audit ledger

Every authorization decision writes an audit record, including every denial.

```json
{
  "seq": 10428,
  "checkpoint": 271,
  "ts": "2026-09-09T14:03:41.882Z",
  "event": "token.issued",
  "task_id": "task_01HQZX9K4M",
  "agent_id": "jira-triage",
  "sponsor": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "audience": "https://jira.internal",
  "scope": "jira:read jira:comment",
  "jti": "tok_01HQZX9K5P",
  "delegation_depth": 1,
  "decision": "allow",
  "reason": null
}
```

### Events

| Event | Written when |
|---|---|
| `token.issued` | An exchange creates a task and its first token. There is no separate `task.created`. |
| `token.refreshed` | A task is renewed |
| `token.denied` | A token request is refused |
| `token.revoked` | An agent revokes one of its tokens by `jti` |
| `task.revoked` | A task is revoked |
| `task.expired` | A task reaches its end. Expiry is never recorded as a revocation. |
| `agent.registered`, `agent.updated`, `agent.deleted` | A registration changes, or a registration or deletion is refused (decision `deny`) |
| `admin.denied` | An admin API call fails authentication |
| `sponsor.blocked`, `sponsor.unblocked` | An operator blocks or unblocks a human, or is refused because another source placed the block (decision `deny`) |
| `sponsor.signal` | An inbound signal (back-channel logout, SCIM, Shared Signals) blocks a human, unblocks them, or ends their tasks |
| `signal.denied`, `scim.denied`, `ssf.denied` | An inbound signal or its credential is refused |
| `audit.archived` | A month of the ledger is archived |

`tool.called` is reserved and not produced in v0.1. A tool server records its own calls.

Two kinds of summary keep the ledger from growing with traffic. Nothing is dropped:

- A task's first renewal gets its own `token.refreshed` record. Later renewals are counted, and
  one `token.refreshed` record with a `count` is written when the task ends.
- A denial that names no agent, human or task is written once per reason, then counted for the
  rest of `SubactId:Audit:Aggregation:Window` (default one minute) and written as one record with a
  `count`.

See section 7.2 of [the spec](spec/v0.1.md).

### The seal

The ledger table is append-only. A database trigger refuses any update or delete.

A background pass seals new records, every minute by default (`SubactId:Audit:Checkpoint:Interval`).
It builds a Merkle tree over them in sequence order, signs the root with the control plane's
key, and links the new checkpoint to the previous one. A record's `checkpoint` field names the
checkpoint that seals it, and is `null` until the pass reaches it.

If a record is removed, changed or inserted, its tree no longer produces the signed root. If a
checkpoint is removed or replaced, the link from the next checkpoint breaks.

| To | Use |
|---|---|
| Copy checkpoints somewhere the database cannot reach | `GET /audit/checkpoints` |
| Prove one record against a signed root, using only the public JWKS | `GET /audit/records/{seq}/proof` |
| Verify the whole ledger | `SubactId.Server audit-verify` |

`audit-verify` reports the first fault it finds, and prints its last checkpoint as
`checkpoint_id:root`. Store that outside the database and pass it to the next run. The next run
then also detects records cut from the end, which a walk alone cannot.

### Reading and exporting records

[`GET /audit`](admin-api.md) queries the ledger by `sponsor`, `agent_id`, `task_id`, time range
and `decision`, oldest first, with cursor paging.

Set `SubactId:Audit:Sink:Url` to also post every record to an external sink. The ledger stays the
record of truth. Sink delivery is queued and never slows a token request.

### Retention

On Postgres the ledger is partitioned by month. Records leave it only when you run
`SubactId.Server audit-archive`, which exports a month, checks the export, records an
`audit.archived` event, and then drops the partition. Nothing runs it automatically. `/audit`
reports how far back the online ledger goes. See
[Storage](storage.md#retention-taking-a-month-out-of-the-ledger) and section 7.5 of
[the spec](spec/v0.1.md).

## What a tool server must do

The SDKs' `@subactid/server` and `@subactid/mcp` do all six:

1. Fetch and cache the control plane's JWKS.
2. Validate the signature, `iss`, `aud` and `exp`.
3. Enforce the scope the route requires.
4. Introspect instead of validating locally when the route is high-risk or the token carries
   `introspect_required`.
5. Log `sub` (the human) and `act.sub` (the agent) on every request.
6. Reject a token whose `act` chain is deeper than the tool server's own limit.

Step 5 is what makes every action traceable to a human. Do not skip it.
