# User-assigned managed identity with read-only roles on each subscription to scan.
resource "azurerm_user_assigned_identity" "scanner" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

locals {
  roles = ["Reader", "Security Reader", "Cost Management Reader"]
  assignments = {
    for pair in setproduct(var.subscription_ids, local.roles) : "${pair[0]}|${pair[1]}" => {
      scope = "/subscriptions/${pair[0]}"
      role  = pair[1]
    }
  }
}

resource "azurerm_role_assignment" "read" {
  for_each             = local.assignments
  scope                = each.value.scope
  role_definition_name = each.value.role
  principal_id         = azurerm_user_assigned_identity.scanner.principal_id
  principal_type       = "ServicePrincipal"
}

# Optional: AKS workload identity federation (pod service account -> managed identity, no secrets)
resource "azurerm_federated_identity_credential" "aks" {
  count               = var.aks_oidc_issuer_url == null ? 0 : 1
  name                = "aks-${var.k8s_namespace}-${var.k8s_service_account}"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.scanner.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"
}
