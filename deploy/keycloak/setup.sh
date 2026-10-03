#!/usr/bin/env bash
# Sets up a Keycloak realm for Subact ID without Terraform. Like the Terraform module, it creates the
# human-facing client, the audience mapper, and one client scope per delegable permission.
# Optionally it also creates the client Subact ID authenticates as.
#
# Idempotent. Uses no client secrets.
#
# Usage:
#   deploy/keycloak/setup.sh --url https://sso.example.com --realm corp \
#     --admin-user admin --admin-password-file ./admin.pw \
#     --scopes jira:read,jira:comment,payroll:read
#
# See docs/keycloak.md.
set -euo pipefail

KCADM=${KCADM:-kcadm.sh}
URL=""
REALM=""
ADMIN_REALM="master"
ADMIN_USER=""
ADMIN_PASSWORD_FILE=""
WORKBENCH_CLIENT="workbench"
WORKBENCH_NAME="Subact ID workbench"
WORKBENCH_PUBLIC="true"
REDIRECT_URIS=""
AUDIENCE="subactid"
SCOPES=""
CONTROL_PLANE_CLIENT="subactid"
CONTROL_PLANE_JWKS_URL=""
SUBACTID_URL=""

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'USAGE'
deploy/keycloak/setup.sh --url <keycloak> --realm <realm> --admin-user <user>
                         --admin-password-file <file> [--scopes a,b,c]
                         [--client <id>] [--client-name <name>] [--confidential]
                         [--redirect-uris <a,b>] [--audience <value>]
                         [--control-plane-client <id>] [--control-plane-jwks-url <url>]
                         [--no-control-plane-client] [--subactid-url <url>]

Sets up a Keycloak realm for Subact ID. Idempotent. See docs/keycloak.md.
USAGE
}

# Prints the id from kcadm "id,name" rows whose name matches. No awk or sed, since the Keycloak
# image has neither.
id_named() {
  local wanted=$1 id name
  while IFS=, read -r id name; do
    if [ "$name" = "$wanted" ]; then
      printf '%s' "$id"
      return 0
    fi
  done
  return 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL=$2; shift 2 ;;
    --realm) REALM=$2; shift 2 ;;
    --admin-realm) ADMIN_REALM=$2; shift 2 ;;
    --admin-user) ADMIN_USER=$2; shift 2 ;;
    --admin-password-file) ADMIN_PASSWORD_FILE=$2; shift 2 ;;
    --client) WORKBENCH_CLIENT=$2; shift 2 ;;
    --client-name) WORKBENCH_NAME=$2; shift 2 ;;
    --confidential) WORKBENCH_PUBLIC="false"; shift ;;
    --redirect-uris) REDIRECT_URIS=$2; shift 2 ;;
    --audience) AUDIENCE=$2; shift 2 ;;
    --scopes) SCOPES=$2; shift 2 ;;
    --control-plane-client) CONTROL_PLANE_CLIENT=$2; shift 2 ;;
    --control-plane-jwks-url) CONTROL_PLANE_JWKS_URL=$2; shift 2 ;;
    --subactid-url) SUBACTID_URL=$2; shift 2 ;;
    --no-control-plane-client) CONTROL_PLANE_CLIENT=""; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument '$1'" ;;
  esac
done

[ -n "$URL" ] || die "--url is required"
[ -n "$REALM" ] || die "--realm is required"
[ -n "$ADMIN_USER" ] || die "--admin-user is required"
[ -n "$ADMIN_PASSWORD_FILE" ] || die "--admin-password-file is required"
[ -r "$ADMIN_PASSWORD_FILE" ] || die "cannot read $ADMIN_PASSWORD_FILE"
if [ -n "$CONTROL_PLANE_CLIENT" ] && [ -z "$CONTROL_PLANE_JWKS_URL" ]; then
  die "--control-plane-jwks-url is required unless --no-control-plane-client is given"
fi

# The admin password comes from a file, not a script argument, so it stays out of the shell history.
"$KCADM" config credentials --server "$URL" --realm "$ADMIN_REALM" \
  --user "$ADMIN_USER" --password "$(cat "$ADMIN_PASSWORD_FILE")" > /dev/null

client_uuid() {
  "$KCADM" get clients -r "$REALM" -q "clientId=$1" --fields id --format csv --noquotes 2>/dev/null | head -1
}

say() { printf '%s\n' "$1"; }

# --- the human-facing client -------------------------------------------------------------------
WORKBENCH_UUID=$(client_uuid "$WORKBENCH_CLIENT")
REDIRECTS_JSON="[]"
if [ -n "$REDIRECT_URIS" ]; then
  IFS=',' read -r -a REDIRECT_LIST <<< "$REDIRECT_URIS"
  REDIRECTS_JSON=""
  for uri in "${REDIRECT_LIST[@]}"; do
    [ -n "$uri" ] || continue
    REDIRECTS_JSON="$REDIRECTS_JSON${REDIRECTS_JSON:+,}\"$uri\""
  done
  REDIRECTS_JSON="[$REDIRECTS_JSON]"
fi

# Back-channel logout to Subact ID, only when --subactid-url is given. Session-required puts a sid in the
# token, so a logout ends only that session's tasks.
LOGOUT_ARGS=()
if [ -n "$SUBACTID_URL" ]; then
  LOGOUT_ARGS=(
    -s "attributes.\"backchannel.logout.url\"=${SUBACTID_URL%/}/backchannel-logout"
    -s 'attributes."backchannel.logout.session.required"=true'
  )
fi

if [ -z "$WORKBENCH_UUID" ]; then
  "$KCADM" create clients -r "$REALM" \
    -s "clientId=$WORKBENCH_CLIENT" -s "name=$WORKBENCH_NAME" -s enabled=true \
    -s "publicClient=$WORKBENCH_PUBLIC" -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false -s serviceAccountsEnabled=false \
    -s "redirectUris=$REDIRECTS_JSON" "${LOGOUT_ARGS[@]}" > /dev/null
  WORKBENCH_UUID=$(client_uuid "$WORKBENCH_CLIENT")
  say "created client $WORKBENCH_CLIENT"
else
  "$KCADM" update "clients/$WORKBENCH_UUID" -r "$REALM" \
    -s "name=$WORKBENCH_NAME" -s enabled=true \
    -s "publicClient=$WORKBENCH_PUBLIC" -s standardFlowEnabled=true \
    -s "redirectUris=$REDIRECTS_JSON" "${LOGOUT_ARGS[@]}" > /dev/null
  say "client $WORKBENCH_CLIENT is up to date"
fi

# --- the audience mapper -----------------------------------------------------------------------
# Without this mapper, Subact ID rejects every exchange with an audience mismatch.
# Uses the literal-value form "included.custom.audience", as the Terraform module does.
MAPPER_ID=$("$KCADM" get "clients/$WORKBENCH_UUID/protocol-mappers/models" -r "$REALM" \
  --fields id,name --format csv --noquotes 2>/dev/null | id_named "subactid-audience")

if [ -z "$MAPPER_ID" ]; then
  "$KCADM" create "clients/$WORKBENCH_UUID/protocol-mappers/models" -r "$REALM" \
    -s name=subactid-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.custom.audience\"=$AUDIENCE" \
    -s 'config."access.token.claim"=true' \
    -s 'config."id.token.claim"=false' > /dev/null
  say "created audience mapper emitting '$AUDIENCE'"
else
  "$KCADM" update "clients/$WORKBENCH_UUID/protocol-mappers/models/$MAPPER_ID" -r "$REALM" \
    -s name=subactid-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.custom.audience\"=$AUDIENCE" \
    -s 'config."access.token.claim"=true' \
    -s 'config."id.token.claim"=false' > /dev/null
  say "audience mapper emitting '$AUDIENCE' is up to date"
fi

# --- one client scope per delegable permission -------------------------------------------------
# Subact ID only narrows the scopes in the token, so a permission not listed here cannot be delegated.
# Attached as default scopes, so they are always in the token.
if [ -n "$SCOPES" ]; then
  IFS=',' read -r -a SCOPE_LIST <<< "$SCOPES"
  for scope in "${SCOPE_LIST[@]}"; do
    [ -n "$scope" ] || continue
    scope_id=$("$KCADM" get client-scopes -r "$REALM" --fields id,name --format csv --noquotes 2>/dev/null | id_named "$scope")
    if [ -z "$scope_id" ]; then
      "$KCADM" create client-scopes -r "$REALM" \
        -s "name=$scope" -s protocol=openid-connect \
        -s 'attributes."include.in.token.scope"=true' \
        -s 'attributes."display.on.consent.screen"=true' > /dev/null
      scope_id=$("$KCADM" get client-scopes -r "$REALM" --fields id,name --format csv --noquotes 2>/dev/null | id_named "$scope")
      say "created client scope $scope"
    fi

    # Idempotent. Keycloak's own default scopes are left alone: "basic" carries the sub claim,
    # which Subact ID requires.
    "$KCADM" update "clients/$WORKBENCH_UUID/default-client-scopes/$scope_id" -r "$REALM" > /dev/null
    say "client scope $scope is attached to $WORKBENCH_CLIENT"
  done
fi

# --- the control plane's own client ------------------------------------------------------------
if [ -n "$CONTROL_PLANE_CLIENT" ]; then
  CP_UUID=$(client_uuid "$CONTROL_PLANE_CLIENT")
  # No secret. Subact ID authenticates with a signed assertion that Keycloak checks against Subact ID's JWKS.
  CP_ARGS=(-s "clientId=$CONTROL_PLANE_CLIENT" -s "name=Subact ID control plane" -s enabled=true
           -s publicClient=false -s standardFlowEnabled=false -s directAccessGrantsEnabled=false
           -s serviceAccountsEnabled=true
           -s 'attributes."token.endpoint.auth.signing.alg"=ES256'
           -s 'attributes."use.jwks.url"=true'
           -s "attributes.\"jwks.url\"=$CONTROL_PLANE_JWKS_URL"
           -s clientAuthenticatorType=client-jwt)

  if [ -z "$CP_UUID" ]; then
    "$KCADM" create clients -r "$REALM" "${CP_ARGS[@]}" > /dev/null
    CP_UUID=$(client_uuid "$CONTROL_PLANE_CLIENT")
    say "created client $CONTROL_PLANE_CLIENT"
  else
    "$KCADM" update "clients/$CP_UUID" -r "$REALM" "${CP_ARGS[@]}" > /dev/null
    say "client $CONTROL_PLANE_CLIENT is up to date"
  fi

  # view-users only, for the sponsor check.
  SERVICE_ACCOUNT=$("$KCADM" get "clients/$CP_UUID/service-account-user" -r "$REALM" \
    --fields id --format csv --noquotes | head -1)
  "$KCADM" add-roles -r "$REALM" --uid "$SERVICE_ACCOUNT" --cclientid realm-management --rolename view-users > /dev/null
  say "service account of $CONTROL_PLANE_CLIENT may view-users"
fi

cat <<SETTINGS

Configure Subact ID with:
    SubactId__UpstreamIdp__Issuer=${URL%/}/realms/$REALM
    SubactId__UpstreamIdp__Audience=$AUDIENCE
    SubactId__UpstreamIdp__SponsorCheck__UsersUrl=${URL%/}/admin/realms/$REALM/users
    SubactId__UpstreamIdp__SponsorCheck__TokenUrl=${URL%/}/realms/$REALM/protocol/openid-connect/token
    SubactId__UpstreamIdp__SponsorCheck__ClientId=${CONTROL_PLANE_CLIENT:-<the client Subact ID authenticates as>}

Then check it from where Subact ID runs:
    SubactId.Server doctor
SETTINGS
