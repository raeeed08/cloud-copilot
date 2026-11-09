output "url" {
  value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "acr_login_server" {
  value = azurerm_container_registry.this.login_server
}

output "key_vault" {
  value = azurerm_key_vault.this.name
}

output "scanner_client_id" {
  value = module.scanner_identity.client_id
}
