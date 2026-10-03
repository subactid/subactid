variable "keycloak_url" {
  description = "Base URL of the Keycloak server, as clients reach it. This is also the URL its realms must declare as their issuer."
  type        = string
}

variable "realm_id" {
  description = "The realm these clients live in. The realm itself is not managed here: a production realm usually predates Subact ID."
  type        = string
}

variable "subactid_audience" {
  description = "The audience value Subact ID requires in a subject token. Must equal SubactId__UpstreamIdp__Audience."
  type        = string
  default     = "subactid"
}

variable "workbench_client_id" {
  description = "Client id of the human-facing application whose users delegate to agents."
  type        = string
  default     = "workbench"
}

variable "workbench_client_name" {
  description = "Display name of the human-facing client."
  type        = string
  default     = "Subact ID workbench"
}

variable "workbench_public_client" {
  description = "Whether the human-facing client is public (a browser application) rather than confidential."
  type        = bool
  default     = true
}

variable "workbench_valid_redirect_uris" {
  description = "Redirect URIs of the human-facing client."
  type        = list(string)
  default     = []
}

variable "subactid_url" {
  description = <<-EOT
    Public URL of the Subact ID control plane, used to set the workbench client's back-channel logout
    URL so a session ending here ends the tasks it started. Empty leaves logout unconfigured,
    which is the only sensible default: a URL guessed wrong is a logout Keycloak keeps failing to
    deliver, with nothing on the Subact ID side to show it.
  EOT
  type        = string
  default     = ""
}

variable "delegable_scopes" {
  description = <<-EOT
    The permissions a human may delegate to an agent. Each becomes a client scope carrying a
    matching scope value, attached to the human-facing client, so the value reaches the access
    token and Subact ID can narrow from it. Subact ID never widens a scope, so anything not here can never
    be delegated.
  EOT
  type = list(object({
    name        = string
    description = optional(string, "")
    # "default" is always in the token. "optional" only when the client requests it.
    assignment = optional(string, "default")
  }))
  default = []

  validation {
    condition     = alltrue([for s in var.delegable_scopes : contains(["default", "optional"], s.assignment)])
    error_message = "Each delegable scope's assignment must be \"default\" or \"optional\"."
  }
}

variable "create_control_plane_client" {
  description = <<-EOT
    Also create the client Subact ID itself authenticates as when it re-checks that a human is still
    active, with a service account that may read users and nothing else. Without it a refresh
    cannot re-check the sponsor. Set false if that client is managed elsewhere.
  EOT
  type        = bool
  default     = true
}

variable "control_plane_client_id" {
  description = "Client id Subact ID authenticates as. Must equal SubactId__UpstreamIdp__SponsorCheck__ClientId."
  type        = string
  default     = "subactid"
}

variable "control_plane_jwks_url" {
  description = <<-EOT
    Where Subact ID publishes the public half of its signing key, normally
    https://<subactid>/.well-known/jwks.json. Subact ID authenticates with a signed assertion, so no shared
    secret is created, stored or passed through Terraform state.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = !var.create_control_plane_client || length(var.control_plane_jwks_url) > 0
    error_message = "control_plane_jwks_url is required when create_control_plane_client is true."
  }
}

variable "builtin_default_scopes" {
  description = <<-EOT
    Keycloak's own default client scopes, restated because the default-scope resource replaces the
    whole set rather than adding to it. "basic" carries the sub claim; a token without it is
    rejected by Subact ID as having no subject, so dropping these is never cosmetic.
  EOT
  type        = list(string)
  default     = ["basic", "acr", "profile", "email", "roles", "web-origins"]
}

variable "builtin_optional_scopes" {
  description = "Keycloak's own optional client scopes, restated for the same reason as the default ones."
  type        = list(string)
  default     = ["address", "phone", "offline_access", "microprofile-jwt", "organization"]
}
