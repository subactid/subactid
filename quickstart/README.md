# Quickstart

Run an agent acting for a human, end to end, on your machine:

```
cd quickstart
docker compose up
```

This starts Postgres, Keycloak, the Subact ID control plane, a sample tool server, a demo agent and a
portal. A one-shot `subactid-migrate` service applies the schema before the control plane starts.
The demo agent then runs through the whole flow and prints it in the logs.

To drive it yourself instead, open <http://localhost:8090> once everything is up. See
[The portal](#the-portal).

The first run pulls four base images (Postgres, Keycloak, and the .NET SDK and runtime) and builds
the rest, which takes most of the time.

## What the demo agent shows

The agent prints eight steps. Step 3 looks like this:

```
[3/8] the agent exchanges the human's token for a scoped task token
    ok  task task_01M2A5WB4S9FCX3QV4DPM088AR started
        sub                  11111111-1111-4111-8111-111111111111   <- the human, not the agent
        act.sub              agent:demo-agent   <- the agent, as the actor
        scope                jira:read jira:comment
        expires_in           300s, while the task runs until 2026-09-12 07:14:58Z
```

| Step | What happens |
|---|---|
| 1 | The demo user signs in at Keycloak and gets an ordinary access token. |
| 2 | The agent is registered with the scopes, audiences and lifetimes it may ever have. |
| 3 | The agent exchanges the human's token for a task token: `sub` is the human, the agent is in `act`. |
| 4 | The tool server accepts the token. It checks `search` locally and introspects `comment` with the control plane. |
| 5 | The agent refreshes the token with a narrower scope. The narrowing sticks: the tool server refuses `comment`, and no later refresh can ask for it back. |
| 6 | The agent asks for a scope nobody granted. The control plane refuses with `invalid_scope`. |
| 7 | An operator kills the task. The unexpired token stops working on the next introspected call. |
| 8 | The agent prints the audit ledger for the human: every allow and deny. |

The tool server logs one line per call, for example:

```json
{"tool":"comment","decision":"refused","reason":"operator_kill_switch","sub":"1111...","act":"agent:demo-agent"}
```

## The portal

Open <http://localhost:8090> and sign in as **`demo` / demo** or **`viewer` / viewer**. The page
shows two tokens side by side: yours from Keycloak, and the one the agent got in exchange. Both
have the same `sub`. The agent's token also has `act`, naming the agent.

Things to try:

- **Sign in as each user.** `demo` has the realm role `jira-commenter` and `viewer` does not.
  Keycloak puts `jira:comment` in the token only for users with that role. The same agent,
  asking for the same scopes, gets `jira:read jira:comment` for `demo` and `jira:read` for
  `viewer`, and the tool server refuses `comment` for `viewer`.
- **Press `try your own token instead`.** It sends your Keycloak token to the tool server instead
  of the agent's token. The tool server answers `401`: it accepts only task tokens from this
  control plane.
- **Start a `long` task.** Its tokens last 30 seconds and the task runs for 10 minutes. The
  renewal counter climbs while the task keeps working.
- **Start a `short` task.** It ends when it reaches its two-minute `max_task_ttl`.
- **Revoke a running task, then call `comment`.** The token is still unexpired and validly
  signed, but `comment` is a high-risk tool that the tool server introspects, so it is refused.
- **Watch the ledger** at the bottom of the page.

### Signing in through Keycloak's login page

By default the portal collects the password itself and requests the token from Keycloak. A real
application redirects to Keycloak's login page instead. The portal supports that, but it needs
one change on your machine.

Keycloak sets a token's `iss` from the hostname the sign-in arrived on. Your browser reaches
Keycloak as `localhost:8080`, while the control plane reaches it as `keycloak:8080`. The control
plane refuses a token whose `iss` differs from the issuer it discovered, so a browser sign-in
works only if both use the same name. To enable it:

1. Add `127.0.0.1 keycloak` to your hosts file (`/etc/hosts`, or
   `C:\Windows\System32\drivers\etc\hosts`).
2. On the `portal` service in `compose.yaml`, set `PORTAL_LOGIN_MODE: redirect` and
   `KEYCLOAK_PUBLIC_URL: http://keycloak:8080`.
3. Run `docker compose up -d --force-recreate portal` and sign in at <http://localhost:8090>.

The portal then uses the authorization code flow with PKCE and never sees your password.

## Exploring afterwards

Everything keeps running after the demo. All ports are bound to `127.0.0.1`:

| Service | URL |
|---|---|
| Control plane | <http://localhost:5100> |
| Portal | <http://localhost:8090> |
| Tool server | <http://localhost:8082> |
| Keycloak (`admin` / `admin`) | <http://localhost:8080> |

```sh
# Discovery document.
curl -s http://localhost:5100/.well-known/openid-configuration | jq .

# The audit ledger for the demo user, allows and denials.
ADMIN_KEY=$(docker compose exec -T subactid cat /etc/subactid/admin-key)
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  'http://localhost:5100/audit?sponsor=11111111-1111-4111-8111-111111111111&limit=50' | jq .

# Verify the ledger's signed checkpoints and the records they cover.
docker compose exec subactid dotnet /app/SubactId.Server.dll audit-verify

# The signed checkpoints, and the inclusion proof for record 1.
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://localhost:5100/audit/checkpoints | jq .
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://localhost:5100/audit/records/1/proof | jq .

# The registered agents, and revoking every task of the demo agent.
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://localhost:5100/admin/agents | jq .
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_KEY" \
  http://localhost:5100/admin/agents/demo-agent/tasks | jq .

# Run the demo again. The ledger keeps both runs.
docker compose up --force-recreate demo-agent
```

To see the sponsor check, disable the `demo` user in the Keycloak console and run the demo again.
The exchange fails with `access_denied`, even though the user's token is still valid. A task that
is already running fails its next refresh the same way.

To stop everything and delete the database and the agents' keys:

```
docker compose down -v
```

The quickstart runs Postgres 18. If you ran it before, when it used Postgres 16, run the command
above once first: the Postgres 18 image refuses to start on the old volume.

## Files

| File | What it is |
|---|---|
| `compose.yaml` | The eight services and how they connect |
| `keycloak/subactid-demo-realm.json` | The demo realm: the users `demo` and `viewer`, the sign-in clients, and the control plane's client |
| `Dockerfile` | All quickstart images from one build: the control plane with demo credentials, the tool server, the agents and the portal |
| `../samples/SubactId.Sample.ToolServer` | The tool server: spec section 9 in minimal form |
| `../samples/SubactId.Sample.Agent` | The demo agent, and the `serve` mode the portal drives |
| `../samples/SubactId.Sample.Portal` | The portal: sign-in, the two tokens, and the ledger |

The sample tool server uses only the .NET platform, so every check it makes is visible in its
code. For TypeScript, `@subactid/mcp` from npm (`npm install @subactid/mcp`) puts an MCP server
behind the same checks.

## Limits of the demo

This runs on one machine. It is not a deployment.

- **Credentials are generated when the images are built:** the control plane's signing key, its
  admin API key, and a certificate authority with a TLS certificate for the agents' JWKS
  endpoints. None is in this repository, and they change on every rebuild. Do not push these
  images anywhere.
- **The agents' signing keys are created on first run** and kept in Docker volumes.
- **The credentials in `compose.yaml` protect nothing.** The database is reachable only inside the
  compose network, and Keycloak's console is `admin` / `admin`.
- **The control plane image differs from the release image.** It adds the demo credentials and
  trusts the demo certificate authority, because the control plane fetches agent JWKS over https
  only.
- **Keycloak runs in development mode**, with its database inside the container. Recreating the
  container re-imports the realm. `docker compose restart keycloak` does not.
- **The portal holds the admin API key** to show the ledger, and by default it collects a
  password. A real application does neither.
- **Traffic inside the compose network is plain http.** A real deployment terminates TLS in front
  of the control plane and keeps its keys in a secret store.

## Troubleshooting

- `docker compose logs subactid`: the control plane refuses to start on incomplete configuration and
  names the missing setting.
- `curl -s http://localhost:5100/readyz`: returns 503 until the database, the signing key and
  Keycloak's keys have all been reached, for example while Keycloak is still starting. If Keycloak
  stops answering later, it still returns 200, with `Degraded` in the body.
- `docker compose logs demo-agent`: the agent waits up to five minutes for each dependency and
  says what it is waiting for.
- Rebuild with `docker compose build`, not one service at a time. The control plane and agent
  images share the demo certificate authority.
