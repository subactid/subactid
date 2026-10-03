locals {
  realm_url = "${trimsuffix(var.keycloak_url, "/")}/realms/${var.realm_id}"
  base_url  = trimsuffix(var.keycloak_url, "/")

  default_scope_names  = [for scope in var.delegable_scopes : scope.name if scope.assignment == "default"]
  optional_scope_names = [for scope in var.delegable_scopes : scope.name if scope.assignment == "optional"]
}

# The application humans sign in to. Agents present its access tokens to Subact ID as subject_token,
# so it sets the audience and the permissions in the token.
resource "keycloak_openid_client" "workbench" {
  realm_id  = var.realm_id
  client_id = var.workbench_client_id
  name      = var.workbench_client_name
  enabled   = true

  access_type                  = var.workbench_public_client ? "PUBLIC" : "CONFIDENTIAL"
  standard_flow_enabled        = true
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  valid_redirect_uris          = var.workbench_valid_redirect_uris

  # Back-channel logout to Subact ID. Session-required puts a sid in the token, so a logout ends only
  # that session's tasks.
  backchannel_logout_url              = var.subactid_url == "" ? null : "${trimsuffix(var.subactid_url, "/")}/backchannel-logout"
  backchannel_logout_session_required = var.subactid_url == "" ? null : true
}

# Without this mapper, Subact ID rejects every exchange with an audience mismatch.
resource "keycloak_openid_audience_protocol_mapper" "subactid" {
  realm_id  = var.realm_id
  client_id = keycloak_openid_client.workbench.id
  name      = "subactid-audience"

  included_custom_audience = var.subactid_audience
  add_to_access_token      = true
  add_to_id_token          = false
}

# One client scope per delegable permission, included in the token's scope claim. Subact ID only
# narrows the token's scopes, so a permission not listed here cannot be delegated.
resource "keycloak_openid_client_scope" "delegable" {
  for_each = { for scope in var.delegable_scopes : scope.name => scope }

  realm_id               = var.realm_id
  name                   = each.value.name
  description            = each.value.description
  include_in_token_scope = true
}

# This resource replaces the whole default-scope set, so Keycloak's built-in scopes are listed
# again. "basic" carries the sub claim, which Subact ID requires.
resource "keycloak_openid_client_default_scopes" "workbench" {
  realm_id  = var.realm_id
  client_id = keycloak_openid_client.workbench.id

  default_scopes = concat(var.builtin_default_scopes, local.default_scope_names)

  depends_on = [keycloak_openid_client_scope.delegable]
}

resource "keycloak_openid_client_optional_scopes" "workbench" {
  realm_id  = var.realm_id
  client_id = keycloak_openid_client.workbench.id

  optional_scopes = concat(var.builtin_optional_scopes, local.optional_scope_names)

  depends_on = [keycloak_openid_client_scope.delegable]
}

# The control plane's own client. It uses a signed assertion, so no secret is in Terraform state.
resource "keycloak_openid_client" "control_plane" {
  count = var.create_control_plane_client ? 1 : 0

  realm_id  = var.realm_id
  client_id = var.control_plane_client_id
  name      = "Subact ID control plane"
  enabled   = true

  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = true

  # Keycloak verifies the assertion against the JWKS Subact ID publishes.
  client_authenticator_type = "client-jwt"

  extra_config = {
    "token.endpoint.auth.signing.alg" = "ES256"
    "use.jwks.url"                    = "true"
    "jwks.url"                        = var.control_plane_jwks_url
  }
}

data "keycloak_openid_client" "realm_management" {
  count = var.create_control_plane_client ? 1 : 0

  realm_id  = var.realm_id
  client_id = "realm-management"
}

data "keycloak_role" "view_users" {
  count = var.create_control_plane_client ? 1 : 0

  realm_id  = var.realm_id
  client_id = data.keycloak_openid_client.realm_management[0].id
  name      = "view-users"
}

# view-users only, for the sponsor check.
resource "keycloak_openid_client_service_account_role" "view_users" {
  count = var.create_control_plane_client ? 1 : 0

  realm_id                = var.realm_id
  service_account_user_id = keycloak_openid_client.control_plane[0].service_account_user_id
  client_id               = data.keycloak_openid_client.realm_management[0].id
  role                    = data.keycloak_role.view_users[0].name
}
