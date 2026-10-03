output "subactid_settings" {
  description = <<-EOT
    The Subact ID settings this realm implies. Every value is public: a URL, a client id or an
    audience. This module produces no secret.
  EOT
  value = {
    "SubactId__UpstreamIdp__Issuer"                 = local.realm_url
    "SubactId__UpstreamIdp__Audience"               = var.subactid_audience
    "SubactId__UpstreamIdp__SponsorCheck__UsersUrl" = "${local.base_url}/admin/realms/${var.realm_id}/users"
    "SubactId__UpstreamIdp__SponsorCheck__TokenUrl" = "${local.realm_url}/protocol/openid-connect/token"
    "SubactId__UpstreamIdp__SponsorCheck__ClientId" = var.control_plane_client_id
  }
}

output "subactid_logout_settings" {
  description = <<-EOT
    The logout setting this realm implies, when subactid_url was given. The audience is the
    human-facing client, which is what a logout token carries; it is not subactid_audience, and
    setting that here is the usual way to get this wrong.
  EOT
  value = var.subactid_url == "" ? {} : {
    "SubactId__UpstreamIdp__BackchannelLogout__Audience" = keycloak_openid_client.workbench.client_id
  }
}

output "workbench_client_id" {
  description = "Client id of the human-facing application."
  value       = keycloak_openid_client.workbench.client_id
}

output "delegable_scope_names" {
  description = "The permissions this realm lets a human delegate."
  value       = sort([for scope in keycloak_openid_client_scope.delegable : scope.name])
}
