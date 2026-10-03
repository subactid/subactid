# Connecting Subact ID to Keycloak

Keycloak issues the human's token. Subact ID validates it and issues a narrower, short-lived token
that an agent acts with. This page covers the Keycloak realm settings that make that work.

It assumes `SubactId:UpstreamIdp:SponsorCheck:Mode` is `poll`, the default. In `poll` mode, Subact ID asks
Keycloak's admin API whether the human is still active. An identity provider without such an API
uses `signals` mode and needs none of the sponsor check settings below. See
[Configuration](configuration.md).

When something here does not work, run `SubactId.Server doctor` from where Subact ID runs first. It names
the failing part.

## Common problems

### The realm's issuer does not match the URL Subact ID uses

Subact ID fetches `<realm URL>/.well-known/openid-configuration` and requires the document's `issuer`
to equal that realm URL exactly, as OpenID Connect Discovery requires.

Keycloak builds `issuer` from its frontend URL, not from the address the request arrived on. A
Keycloak behind a proxy, or started with `KC_HOSTNAME` set to a public name, may serve
`https://sso.example.com/realms/corp` as its issuer while Subact ID reaches it at
`http://keycloak.internal:8080`. Discovery then fails and readiness stays red. `doctor` reports:

```
FAIL  upstream  The upstream discovery document declares an issuer that does not match the URL it was fetched from.
                Likely cause: the identity provider's frontend URL differs from the URL it is reached on. It must
                declare 'http://keycloak.internal:8080/realms/corp' as its issuer; in Keycloak that is the realm's
                frontend URL or KC_HOSTNAME.
```

To fix it, make the two URLs the same: either set Keycloak's frontend URL to the address Subact ID
uses, or have Subact ID reach Keycloak at its frontend URL. Then set `SubactId__UpstreamIdp__Issuer` to
that realm URL.

A related case: if the frontend URL is `http://` while Subact ID fetches discovery over `https://`,
the advertised `jwks_uri` is http and Subact ID refuses it. `doctor` reports that too.

### The URL Subact ID uses answers with a redirect

Subact ID never follows a redirect from the identity provider. A proxy in front of Keycloak that
redirects `http://` to `https://` leaves readiness red. `doctor` reports:

```
FAIL  upstream  The identity provider answered with a redirect (301). The control plane never follows one, so it
                cannot fetch the keys.
                Likely cause: a URL it is reached at is not the one it answers on, such as http where it redirects
                to https. Set SubactId__UpstreamIdp__Issuer to the realm URL it redirects to; if the jwks_uri it
                advertises is what redirects, fix its frontend URL instead.
```

To fix it, set `SubactId__UpstreamIdp__Issuer` to the realm URL the proxy redirects to, usually its
`https://` form.

### Tokens do not carry Subact ID's audience

By default a Keycloak access token's `aud` holds the client itself and `account`. Subact ID requires
its own audience (`SubactId__UpstreamIdp__Audience`, typically `subactid`). Without an audience mapper on
the human-facing client, every exchange fails. `doctor --subject-token` reports:

```
FAIL  subject token  Rejected: AudienceMismatch.
                     The token's aud does not include 'subactid'. Keycloak issues the client itself and 'account' by
                     default, so the client needs an audience mapper emitting 'subactid'.
```

Both the Terraform module and `setup.sh` below create this mapper.

### Tokens have no `sub`

Keycloak's built-in `basic` client scope puts `sub` in the token. Subact ID refuses a token without
`sub`. Replacing a client's default scopes instead of adding to them drops `basic`. Both the
Terraform module and `setup.sh` keep Keycloak's built-in scopes and add to them.

## Setting up the realm

Both tools below configure an existing realm. They do not create the realm. They set up:

- the human-facing client (default `workbench`),
- an audience mapper on it that emits Subact ID's audience,
- one client scope per permission a human may delegate,
- the client Subact ID authenticates as (default `subactid`), using a signed assertion checked against
  Subact ID's JWKS, with a service account that has only `view-users`,
- the back-channel logout URL, when you give the Subact ID URL.

Both report the Subact ID settings the realm implies. Neither outputs a secret.

### Terraform

```hcl
module "subactid_keycloak" {
  source = "./deploy/keycloak/terraform"

  keycloak_url = "https://sso.example.com"
  realm_id     = "corp"
  subactid_url     = "https://subactid.example.com"

  workbench_client_id           = "workbench"
  workbench_valid_redirect_uris = ["https://workbench.example.com/*"]

  subactid_audience          = "subactid"
  control_plane_jwks_url = "https://subactid.example.com/.well-known/jwks.json"

  delegable_scopes = [
    { name = "jira:read", description = "Read Jira issues" },
    { name = "jira:comment", description = "Comment on Jira issues" },
    { name = "payroll:read", description = "Read payroll records", assignment = "optional" },
  ]
}

output "subactid_settings" {
  value = module.subactid_keycloak.subactid_settings
}
```

Provider credentials are your own. The module's outputs are:

| Output | What it holds |
|---|---|
| `subactid_settings` | The `SubactId__UpstreamIdp__*` settings for issuer, audience and sponsor check. |
| `subactid_logout_settings` | `SubactId__UpstreamIdp__BackchannelLogout__Audience`, when `subactid_url` is set. |
| `workbench_client_id` | The human-facing client id. |
| `delegable_scope_names` | The delegable scopes. |

A scope's `assignment` is `"default"` (always in the token, the default) or `"optional"` (only
when the client requests it). Subact ID only narrows from the scopes in the token, so a permission
that is not listed can never be delegated.

### Script, with kcadm

```sh
deploy/keycloak/setup.sh \
  --url https://sso.example.com --realm corp \
  --admin-user admin --admin-password-file ./admin.pw \
  --redirect-uris 'https://workbench.example.com/*' \
  --scopes jira:read,jira:comment,payroll:read \
  --control-plane-jwks-url https://subactid.example.com/.well-known/jwks.json \
  --subactid-url https://subactid.example.com
```

- The script is idempotent. Run it again after changing `--scopes` and it adds the new ones.
- Scopes are attached as default scopes.
- `--subactid-url` sets the back-channel logout URL. Without it, logout is not configured.
- `--control-plane-jwks-url` is required unless you pass `--no-control-plane-client`.
- The admin password is read from a file, so it stays out of your shell history.
- Run `deploy/keycloak/setup.sh --help` for the other options.

The script needs `kcadm.sh`. Set `KCADM=/opt/keycloak/bin/kcadm.sh` to run it inside the
Keycloak container.

## Ending tasks when a session ends

Keycloak can notify Subact ID when a session ends, and Subact ID then revokes the tasks that session
started. Configure both sides:

1. On the human-facing client, set **Backchannel logout URL** to `<subactid>/backchannel-logout`
   and turn on **Backchannel logout session required**. That puts a `sid` in the token. Without
   a `sid`, a logout names only the person, and Subact ID ends all of their tasks, not only that
   session's.
2. Set `SubactId__UpstreamIdp__BackchannelLogout__Audience` to the **human-facing client id**. A
   logout token's `aud` is that client, not the audience your mapper emits for Subact ID. Setting the
   mapper's audience here is the most common mistake, and logouts are then refused as an
   audience mismatch.

The Terraform module and `setup.sh` do step 1 when given the Subact ID URL.

A logout revokes tasks. It does not block the person, who can sign in again and start a new task.
To block a person, use the admin API.

A logout also ends the sign-in it names. An access token from the logged-out session, or, for a
logout that names no session, any of the person's access tokens issued before the logout token,
can no longer start a task, even while it has not expired. The exchange is refused with
`invalid_grant` and recorded with reason `subject_logged_out`. A token from a new sign-in works.
This is one more reason to turn on **Backchannel logout session required**: with a `sid`, only
that session's tokens are refused.

Signing out every session in the realm sends one logout token per session in a single burst from
one address. `SubactId:RateLimit:Signals:*` limits that burst. The defaults (a burst of 5000, then
6000 per minute) cover a few thousand sessions. Raise it for a larger realm. Keycloak does not retry a refused logout, so the tasks of
each refused session run until they expire. See [Configuration](configuration.md).

## Settings

| Subact ID setting | Value from Keycloak |
|---|---|
| `SubactId__UpstreamIdp__Issuer` | The realm URL, `<keycloak>/realms/<realm>`. Must equal the realm's advertised issuer. Subact ID appends `/.well-known/openid-configuration`. |
| `SubactId__UpstreamIdp__Audience` | The value the audience mapper emits. |
| `SubactId__UpstreamIdp__SponsorCheck__ClientId` | The client Subact ID authenticates as. Its service account has `view-users`. |
| `SubactId__UpstreamIdp__SponsorCheck__UsersUrl` | `<keycloak>/admin/realms/<realm>/users`. The admin API, not the realm URL. |
| `SubactId__UpstreamIdp__SponsorCheck__TokenUrl` | `<realm URL>/protocol/openid-connect/token`. Where Subact ID presents its signed assertion. |
| `SubactId__UpstreamIdp__BackchannelLogout__Audience` | The human-facing client id. Not the audience the mapper emits. |

`SubactId__UpstreamIdp__MetadataUrl` takes the full discovery URL instead of `Issuer`. Setting both
is a configuration error. Prefer `Issuer`, so the discovery URL and the expected issuer cannot
disagree.

Subact ID authenticates to Keycloak with a signed assertion (`private_key_jwt`), so there is no client
secret. Keycloak checks the assertion against the JWKS Subact ID publishes at
`/.well-known/jwks.json`. [Signing keys](keys.md) covers that key.

## Requiring RFC 9068 access tokens

`SubactId__UpstreamIdp__SubjectTokenTypes` is optional. Keycloak gives its access and ID tokens
alike a `typ` header of `JWT`, so setting it to `at+jwt` on its own refuses every subject token. To
use it, set the client that people sign in with to issue RFC 9068 access tokens: set the client
attribute `access.token.header.type.rfc9068` to `true`. Its access tokens then carry
`typ: at+jwt`, and its ID tokens keep `JWT`.

`doctor --subject-token` holds a token to the same list the server does, and names the setting when
it refuses one.

## Checking the setup

```sh
SubactId.Server doctor
```

To also check a real token from the human-facing client, pass it on standard input:

```sh
printf '%s' "$ACCESS_TOKEN" | SubactId.Server doctor --subject-token -
```

Standard input keeps the token out of the process list. `doctor` never prints a token or a
secret.
