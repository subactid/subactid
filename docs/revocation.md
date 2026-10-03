# Revocation

This page covers how to stop a token, a task, an agent or a human, and what each method does
and does not stop.

## Local validation or introspection

A tool server checks a token in one of two ways:

| | Local validation | Introspection |
|---|---|---|
| How | Checks signature, `iss`, `aud` and `exp` against a cached JWKS | Calls `POST /oauth2/introspect` on every request |
| Cost | No call to Subact ID per request | One round trip per request; Subact ID is on the request path |
| Revocation takes effect | When the token expires, at most `max_token_ttl` later | At once |

In short: accept up to `max_token_ttl` of exposure, or pay a round trip per call. A short
`max_token_ttl` (default five minutes) keeps the window small for everything you validate
locally.

## Choosing which calls to introspect

Mark an audience high-risk on the agent's registration:

```json
{
  "allowed_audiences": ["https://jira.internal", "https://db.internal"],
  "high_risk_audiences": ["https://db.internal"]
}
```

Every token for that audience then carries:

```json
{ "aud": "https://db.internal", "introspect_required": true }
```

The claim is written only when it is true. Because it travels in the token, every tool server
sees it without extra configuration. The SDKs' `@subactid/server` and `@subactid/mcp`
introspect whenever they see it. A tool server without them must read `introspect_required` itself.

A tool server can also mark individual routes high-risk. The two settings combine:

| Setting | Effect |
|---|---|
| `high_risk_audiences` on the registration | Every token for that audience is introspected by any tool server that honours `introspect_required` |
| A high-risk route on the tool server | That route is introspected, even when the audience is not high-risk |

Rule of thumb: if the action must not happen five minutes after you revoke, make it high-risk.
Reads usually are not. Writes, deletions, payments and anything that leaves your systems usually
are.

## How to revoke

| What | How | Effect |
|---|---|---|
| One token | `POST /oauth2/revoke` with the token and the agent's client assertion | That `jti` is revoked. A disabled agent may still revoke its own tokens and grants. |
| One task | `DELETE /admin/tasks/{task_id}` | The task, every task delegated from it, and their grants |
| Every task of an agent | `DELETE /admin/agents/{agent_id}/tasks` | All of that agent's live tasks, as above |
| An agent | `PATCH /admin/agents/{agent_id}` with `{"enabled": false}` | Refused on its next request. Its live tokens introspect as inactive. |
| Every task of a human | `DELETE /admin/sponsors/{sponsor_key}/tasks` | Their live tasks. They can start a new one at once. |
| A human, until unblocked | `PUT /admin/sponsors/{sponsor_key}/block` | Their live tasks, and no new task until `DELETE /admin/sponsors/{sponsor_key}/block` |
| A session ended at the identity provider | The provider posts a logout token to `POST /backchannel-logout` ([setup](keycloak.md#ending-tasks-when-a-session-ends)) | The tasks that session started, or all the person's tasks if the token names no session. The session's access tokens, or the person's issued before the logout, can no longer start a task. They can sign in again. |
| A person deactivated at the identity provider | The provider's provisioning client updates them over [SCIM](scim.md) | Their live tasks, and no new task until they are reactivated |
| A person disabled at the identity provider | The provider pushes a [security event](shared-signals.md) to `POST /events` | Same as SCIM, sent as it happens rather than at the next sync |

The admin endpoints need the admin API key. Protect it: it can end any task. See
[Admin API](admin-api.md).

### Revoking versus blocking

Revoking ends what is running. Blocking ends what is running **and** refuses new tasks until the
block is lifted. Lifting a block never restores a revoked task.

An exchange that is under way when a human is blocked, killed or logged out cannot slip past it.
The two wait for each other: a revocation that starts while a task is being stored waits for it
and ends it, and an exchange that reaches the end while a block or a logout is being recorded
waits for it and is then refused. Exchanges for the same human do not wait for each other.

A logout also refuses the sign-in it ended, not only the tasks it started. An exchange whose
subject token carries the `sid` of a session that was logged out is refused, and so, after a
logout naming only the person or a Shared Signals `session-revoked`, is one whose subject token
was issued before that logout or event. The refusal is `invalid_grant`, recorded as a
`token.denied` with reason `subject_logged_out`. `iat` has whole-second resolution, so a subject
token issued in the same second as the logout is let through; a subject token without an `iat`
cannot be shown to be newer and is refused once the person has been logged out. An operator's
kill switch is not a logout: it ends what is running and the person may start again with the same
token.

These sign-outs are kept in the `revocations` table for `SubactId:Revocations:SignOutRetention`
(a day by default) after they were recorded, and then removed by an hourly pass on every
instance. A sign-out only has to outlive the subject tokens it refuses, and those stop working
when they expire anyway. Set the retention to at least the identity provider's longest
access-token lifetime, plus a minute for the clock skew allowed on subject tokens: a token signed
out at the start of a longer life could otherwise start a task once its sign-out is gone. Subact
ID cannot read that lifetime from the provider, so it checks the tokens it is shown instead, and
logs a warning the first time a subject token is valid for longer than the retention (for a token
without an `iat`, the first time one has longer than the retention left). No other revocation
is removed.

A block can only be lifted by the source that placed it. `DELETE /admin/sponsors/{key}/block`
answers `409` for a block placed by SCIM or Shared Signals. Clear those at the identity provider.

The sponsor key is the value of the claim named by `SubactId:UpstreamIdp:SponsorKeyClaim` (`sub` by
default). How Subact ID learns about a human disabled at the identity provider without a signal
depends on `SubactId:UpstreamIdp:SponsorCheck:Mode`. See [Concepts](concepts.md#the-sponsor-check).

### `POST /oauth2/revoke`

This is RFC 7009. Only the agent a token or grant was issued to can revoke it.

- Revoking a task grant revokes its task and every task delegated from it.
- Revoking a task token revokes that `jti` only.
- A token of another agent, or one that does not exist, gets the same empty `200` and changes
  nothing, so the endpoint cannot be used to test which tokens are real. Subact ID records it as a
  denial.
- A disabled agent may still revoke its own tokens and grants, since revoking only takes access
  away. It gets the same empty `200`.
- Revoking twice has the same effect as revoking once.

A request that fails client authentication or is malformed gets an OAuth error, not `200`.

### Repeating a kill switch

`DELETE /admin/tasks/{task_id}`, `DELETE /admin/agents/{agent_id}/tasks` and
`DELETE /admin/sponsors/{sponsor_key}/tasks` are idempotent. A repeat answers `200` with
`revoked_tasks: 0` and writes no audit record.

## Introspection

```
POST /oauth2/introspect
```

A token is active only if all of these hold:

- It verifies against Subact ID's signing keys.
- It has not expired.
- Its `jti` has not been revoked.
- Its task is active and has not expired.
- Its agent is enabled.

Otherwise the answer is `active: false`. When the token or its task was revoked, the answer also
carries `revoked_at` and `revocation_reason`:

```json
{ "active": false, "revoked_at": "2026-09-09T14:05:11Z", "revocation_reason": "operator_kill_switch" }
```

A token whose agent is disabled carries `revocation_reason: "agent_disabled"` without
`revoked_at`. An expired token or task gets a plain `active: false`, because expiry is not
revocation.

In v0.1 the token itself is the only credential introspection asks for. The answer tells the
holder nothing beyond what the token already says, except its revocation state.

## What revocation does not stop

A token already in an agent's hand and validated locally keeps working until it expires. Only
introspection closes that gap.

Renewal stops at once. A revoked task cannot produce another token (`access_denied`), so the
longest anything survives a revocation is the life of the token already issued.

## Revocation reasons

Every revocation writes audit records. `task.revoked` carries one of these reasons. A task
revoked because its parent was revoked carries `parent_revoked`.

| Reason | Cause |
|---|---|
| `operator_kill_switch` | `DELETE /admin/tasks/…`, `/admin/agents/…/tasks` or `/admin/sponsors/…/tasks` |
| `client_revoked` | The agent revoked its own grant or token through `POST /oauth2/revoke` |
| `sponsor_blocked` | `PUT /admin/sponsors/{sponsor_key}/block` |
| `sponsor_logged_out` | A back-channel logout |
| `scim_deactivated`, `scim_deleted` | A SCIM deactivation or delete |
| `ssf_sessions_revoked`, `ssf_account_disabled`, `ssf_account_purged` | A Shared Signals event |

A single token revoked by `jti` writes `token.revoked`. A task that reaches its own end writes
`task.expired`, never a revocation.
