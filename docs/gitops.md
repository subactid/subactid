# Agents as files

An agent registration sets the most an agent may ever do. Keep it in a repository and change it
through review. Two commands support this:

```sh
SubactId.Server agent init jira-triage --out agents/
# fill in allowed_scopes and allowed_audiences in agents/jira-triage.yaml
SubactId.Server agent apply agents/*.yaml --server https://subactid.example.com
```

- `agent init` writes a new agent's key pair and a registration with tight defaults.
- `agent apply` reconciles registration files with a running control plane through the admin
  API. Every create and update is audited like any other admin request.

## Repository layout

```
agents/
  jira-triage.yaml          the registration (commit it)
  jira-triage.jwks.json     its public keys (commit it)
  payroll-export.yaml
  payroll-export.jwks.json
```

`agent init` also writes `<agent-id>.key.pem`, the agent's private key, readable by its owner
only. Move it to your secret store. Do not commit it. Only the agent needs it, to sign its
assertions.

## `agent init`

```sh
$ SubactId.Server agent init jira-triage --out agents/
Wrote a registration for 'jira-triage':
    agents/jira-triage.yaml  the registration; fill in allowed_scopes and allowed_audiences
    agents/jira-triage.jwks.json  its public keys, the same set the registration embeds
    agents/jira-triage.key.pem  its private key, readable by its owner only

Key id: Ci5e1ZwRAyMabLE7JOcKIyBPfdDxuZK90C9BN1OIDqQ (RFC 7638 thumbprint)
```

- It reads no configuration, so it runs before any deployment exists.
- It refuses to overwrite any of the three files.
- It never prints the private key.

The registration it writes has these defaults:

| Field | Value |
|---|---|
| `sponsor_required` | `true` (the only value v0.1 accepts) |
| `max_task_ttl` | `PT30M` |
| `max_token_ttl` | `PT5M` |
| `max_delegation_depth` | `1` (no onward delegation) |
| `high_risk_audiences` | empty |
| `allowed_scopes` | **empty** |
| `allowed_audiences` | **empty** |

`agent apply` refuses the file, including with `--dry-run`, until `allowed_scopes` and
`allowed_audiences` are filled in.

## Agent keys held by the control plane

The registration from `agent init` embeds the agent's public keys:

```yaml
jwks:
  keys:
    - kid: Ci5e1ZwRAyMabLE7JOcKIyBPfdDxuZK90C9BN1OIDqQ
      kty: EC
      crv: P-256
      x: _Pdfr-n34d1RB3MQmz2E8FNEovLh_D06la9ePRcOBlM
      y: aRlvzUh4VA8i-w_NvWYiAk_0rlXtDQwxtab_D0vbHg8
      alg: ES256
      use: sig
```

The control plane serves them at `GET /agents/<agent-id>/jwks.json`. The agent needs no public
endpoint of its own, and the control plane needs no egress to reach one.

Alternatively, set `jwks_uri` to an https URL where the agent publishes its keys. Use this when
something else already publishes and rotates the agent's key set. The URL must answer with the key
set itself: a redirect is not followed. A deployment with `SubactId:AgentKeys:BlockPrivateNetworks`
on also refuses a URL that resolves only to addresses that are not public. A registration must set
exactly one of `jwks` and `jwks_uri`.

An inline key set must be public:

- A key with a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, `oth`) is refused. The
  error names the member but never repeats its value.
- Members the server does not model are dropped, not stored.

## `agent apply`

```sh
$ export SUBACTID_ADMIN_KEY=...
$ SubactId.Server agent apply agents/*.yaml --server https://subactid.example.com
created  payroll-export
updated  jira-triage
    max_token_ttl: PT5M -> PT2M
unchanged  build-bot

3 file(s), 2 changed.
```

For each file, `apply`:

1. Validates it locally with the admin API's rules and the server's default limits, since
   `apply` reads no server configuration. A file those would refuse is reported before
   anything is sent. A deployment that changed `SubactId:Agents:*` can still refuse, or accept,
   a lifetime the default limits judge differently; the server's answer is the one that counts.
2. Reads the agent with `GET /admin/agents/<agent-id>`.
3. Sends `POST` if the agent does not exist, or `PATCH` with only the fields that differ.
   The audit record for an update lists exactly those fields.
4. Sends nothing if the agent already matches. A second run makes only the `GET`.

A lifetime the file leaves out is not compared, since the server may have applied a different
default.

Exit status:

| Code | Meaning |
|---|---|
| `0` | Every file applied. |
| `1` | At least one file was refused, by local validation or by the server. |
| `2` | Bad arguments, or no admin key. |

### Dry run

`--dry-run` validates each file locally and sends nothing. It needs no admin key and no
`--server`. It does not contact the server, so it cannot tell a new agent from a changed one:
every valid file is reported as `would create`. Use it on pull requests.

### The admin key

`apply` reads the admin key from `SUBACTID_ADMIN_KEY`, or from standard input when input is piped:

```sh
kubectl -n subactid get secret subactid-admin -o jsonpath='{.data.api-key}' | base64 -d \
  | SubactId.Server agent apply agents/*.yaml --server https://subactid.example.com
```

There is no `--admin-key` flag. Command-line arguments are visible in the process list and in
most CI logs.

The key goes with every request, so `--server` must be `https`. Plain `http` is accepted only on
a loopback host, such as `http://127.0.0.1:5100` through a port-forward.

### In CI

Run `apply` from a CI job that holds the key, so no person needs a copy:

```yaml
- name: Reconcile agents
  env:
    SUBACTID_ADMIN_KEY: ${{ secrets.SUBACTID_ADMIN_KEY }}
  run: SubactId.Server agent apply agents/*.yaml --server https://subactid.example.com
```

On pull requests, run it with `--dry-run` and without the secret, so the key never reaches a job
that runs untrusted code.

## What `apply` does not do

- **It never deletes an agent.** A registration removed from the repository stays registered.
  Delete it through the admin API, which removes only an agent that has no tasks.
- **It never enables or disables an agent.** `enabled` is an operational switch, not a
  registration field. Use the admin API for it.
