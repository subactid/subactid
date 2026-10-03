# Admin API

The admin API manages agent registrations, revokes tasks, blocks humans and reads the audit
ledger. It is for operators and GitOps tooling, not for agents or end users.

## Authentication

Every request under `/admin` and `/audit` carries one shared API key as a bearer token:

    Authorization: Bearer <SubactId:Admin:ApiKey>

- Set the key with `SubactId:Admin:ApiKey` (environment variable `SubactId__Admin__ApiKey`). It must be
  at least 32 characters. Generate one with `openssl rand -base64 32`.
- If the key is not set, the admin API is disabled and every request answers `503`.
- A missing or wrong key answers `401` and writes an `admin.denied` audit record.
- The key is checked before the request body is read.

v0.1 has no admin identities or roles. The one key grants every operation. To rotate it, change
the setting and restart.

## Endpoints

| Method | Path | Result |
|---|---|---|
| `POST` | `/admin/agents` | `201` with the agent; `400` with per-field errors; `409` if the id exists |
| `GET` | `/admin/agents` | `200` with a page of agents; `400` |
| `GET` | `/admin/agents/{agent_id}` | `200`; `404` |
| `PATCH` | `/admin/agents/{agent_id}` | `200` with the updated agent; `400`; `404` |
| `DELETE` | `/admin/agents/{agent_id}` | `204`; `404`; `409` while any of the agent's tasks is still stored |
| `DELETE` | `/admin/agents/{agent_id}/tasks` | `200` with `{"revoked_tasks": n}`; `404` |
| `DELETE` | `/admin/tasks/{task_id}` | `200` with `{"revoked_tasks": n}`; `404` |
| `GET` | `/admin/sponsors/{sponsor_key}` | `200` with the block on that human; `404` if not blocked; `400` |
| `PUT` | `/admin/sponsors/{sponsor_key}/block` | `200` with the block and `revoked_tasks`; `409` if another source already blocks them; `400` |
| `DELETE` | `/admin/sponsors/{sponsor_key}/block` | `204`; `404` if not blocked; `409` if another source placed it; `400` |
| `DELETE` | `/admin/sponsors/{sponsor_key}/tasks` | `200` with `{"revoked_tasks": n}`; `400` |
| `GET` | `/audit` | `200` with a page of audit records; `400` with per-field errors |
| `GET` | `/audit/checkpoints` | `200` with a page of checkpoints; `400` |
| `GET` | `/audit/records/{seq}/proof` | `200` with an inclusion proof; `404`; `410` if archived; `500` if the ledger no longer matches its checkpoint |

Errors use the problem details format. `400` on a sponsor route means the sponsor key is not
valid (see [Sponsor keys](#sponsor-keys)).

## Agents

The `POST` body is the registration payload in section 2 of the spec. The `PATCH`
body is any subset of those fields plus `enabled`, and the merged registration is validated as a
whole. `agent_id` cannot be changed: a `PATCH` may carry it only as the id already in the path. Either body is refused with `400` if it carries a member it does not have, so a misspelt
optional field such as `high_risk_audience` cannot be silently ignored. Every invalid field is
reported, not only the first. Two updates of one agent at once are applied one after the other,
each to what the other left: a rename made while the agent is being disabled does not re-enable
it. Each change writes `agent.registered`, `agent.updated` or `agent.deleted` to the audit
ledger in the same transaction. A refused change is recorded too, with decision `deny`: a
registration under an id already taken as `agent.registered` with reason `agent_already_exists`,
and a deletion refused because tasks are still stored as `agent.deleted` with reason
`agent_has_tasks`.

Disabling an agent (`"enabled": false`) takes effect on its next request. Tokens it already
holds stay valid until they expire.

`GET /admin/agents?after=&limit=` lists agents in id order, one page at a time:
`{"agents": [...], "next_after": "..."}`. `limit` is 1 to 1000, default 100. Pass `next_after`
from one page as `after` for the next; it is `null` on the last page.

An agent cannot be deleted while any of its tasks, finished or not, is still stored. The sweeper
removes finished tasks after `SubactId:Tasks:Retention` (a week by default). To retire an agent:

1. Revoke its tasks: `DELETE /admin/agents/{agent_id}/tasks`.
2. Disable it.
3. Delete it once the retention period has passed.

## Revoking tasks

- `DELETE /admin/tasks/{task_id}` revokes the task, every task delegated from it, and every grant
  under them. The named task gets reason `operator_kill_switch`, its descendants
  `parent_revoked`.
- `DELETE /admin/agents/{agent_id}/tasks` does the same for every live task of the agent.
- `DELETE /admin/sponsors/{sponsor_key}/tasks` does the same for every live task acting for one
  human. It never answers `404`: a human with nothing running gets `revoked_tasks: 0`. The person
  can start new tasks afterwards; to stop that, block them.

Each writes one `task.revoked` record per task in the same transaction. A repeat answers `200`
with `revoked_tasks: 0` and writes nothing.

Tokens already issued stay valid until they expire, at most the agent's `max_token_ttl`. The
exception is tokens for `high_risk_audiences`, which tool servers must introspect on every call.
A refresh of a revoked task fails at once with `access_denied`.

## Blocking a human

`PUT /admin/sponsors/{sponsor_key}/block` refuses one person and revokes their live tasks in the
same transaction. After that, no exchange or refresh succeeds for them, in either sponsor check
mode. The ledger records `sponsor.blocked` for the block and `sponsor_blocked` on each revoked
task. Blocking is idempotent: a repeat keeps the block as first placed and records nothing new
unless it ends a task. You can block someone who has nothing running to stop them before their
first task. A person already blocked by SCIM or Shared Signals answers `409`: that block stands
unchanged, and it is lifted only at its source. Their live tasks are still ended, with
`sponsor_blocked` on each, and the ledger records the refused block as a `sponsor.blocked` with
decision `deny` and reason `sponsor_blocked_elsewhere`.

`DELETE /admin/sponsors/{sponsor_key}/block` lifts a block that an operator placed. Each block
records its source, and only that source can lift it. A block from the identity provider or a
provisioning feed answers `409` here, recorded as a `sponsor.unblocked` with decision `deny` and
reason `sponsor_block_not_owned`; clear it at its source. Lifting a block does not restore
revoked tasks. It only lets the person start new ones.

See section 6 of the spec.

### Sponsor keys

The `{sponsor_key}` path segment is the value of the claim named by
`SubactId:UpstreamIdp:SponsorKeyClaim` (`sub` by default). It is what each task is stored under and
what signals name a person by.

If that claim is not `sub`, the sponsor key is not the value the `sponsor` filter of `GET /audit`
matches. A `sponsor` read from the ledger is then not the key to block by.

A sponsor key is 1 to 256 characters with no whitespace or control characters. Anything else is
`400`. Token exchange applies the same rule, so every stored key is accepted here.

## Audit query

`GET /audit` is the query in §7.4 of the spec.

| Parameter | Meaning |
|---|---|
| `sponsor`, `agent_id`, `task_id` | Exact-match filters. |
| `from`, `to` | Time range: `from` inclusive, `to` exclusive. An ISO 8601 timestamp or a bare date (UTC midnight). A bare date in `to` covers that whole day. |
| `decision` | `allow` or `deny`. |
| `limit` | Page size, 1 to 1000. Default 100. |
| `cursor` | The `next_cursor` from the previous page. |

Filters combine with AND. Records come back oldest first. `next_cursor` is `null` on the last
page. A record not yet sealed has a `null` `checkpoint`. The query writes nothing to the ledger,
except `admin.denied` for a failed authentication.

Every page has `archived_before`: the earliest instant still in the online ledger, or `null` if
nothing has been archived. A range older than that returns an empty page, not an error. The
archived records are in the export named by the `audit.archived` record; see
[Storage](storage.md#retention-taking-a-month-out-of-the-ledger).

## Checkpoints and proofs

`GET /audit/checkpoints?after=&limit=` lists signed checkpoints, oldest first. `limit` is 1 to
1000, default 100. Pass `next_after` from one page as `after` for the next.

`GET /audit/records/{seq}/proof` returns the checkpoint that seals a record, the record's leaf
index and the audit path. It answers:

- `404` if the record does not exist or is not sealed yet,
- `410` if its checkpoint has been archived (verify the export with
  `SubactId.Server audit-verify --archive <export>`),
- `500` if the records no longer rebuild the checkpoint's root (run `SubactId.Server audit-verify`).

See §7.1 of the spec.
