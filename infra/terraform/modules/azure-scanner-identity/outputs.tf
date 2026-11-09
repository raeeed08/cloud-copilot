output "id" {
  value = azurerm_user_assigned_identity.scanner.id
}

output "client_id" {
  description = "Set as AZURE_CLIENT_ID / workload identity annotation"
  value       = azurerm_user_assigned_identity.scanner.client_id
}

output "principal_id" {
  value = azurerm_user_assigned_identity.scanner.principal_id
}
