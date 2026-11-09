output "connect_in_cloud_copilot" {
  description = "Accounts → Connect an account → Azure → Service principal"
  value = {
    auth_method      = "service_principal"
    tenant_id        = data.azurerm_client_config.me.tenant_id
    client_id        = azuread_application.scanner.client_id
    subscription_ids = var.subscription_id
    client_secret    = "run: terraform output -raw scanner_client_secret"
  }
}

output "scanner_client_secret" {
  value     = azuread_application_password.scanner.value
  sensitive = true
}

output "portal" {
  value = "https://portal.azure.com/#@${data.azurerm_client_config.me.tenant_id}/resource${azurerm_resource_group.lab.id}/overview"
}
