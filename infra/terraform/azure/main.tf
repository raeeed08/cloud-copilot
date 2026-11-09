data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

locals {
  name = "cloud-copilot-${var.environment}"
  tags = { project = "cloud-copilot", environment = var.environment, managed-by = "terraform" }
  subs = length(var.scan_subscription_ids) > 0 ? var.scan_subscription_ids : [var.subscription_id]
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

# ---------------------------------------------------------------------------- identity
module "scanner_identity" {
  source              = "../modules/azure-scanner-identity"
  name                = "id-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  subscription_ids    = local.subs
  tags                = local.tags
}

# ---------------------------------------------------------------------------- registry
resource "azurerm_container_registry" "this" {
  name                = "acrcopilot${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = "Standard"
  admin_enabled       = false # rule AZ-ACR-001
  tags                = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = module.scanner_identity.principal_id
}

# ---------------------------------------------------------------------------- secrets
resource "azurerm_key_vault" "this" {
  name                          = "kv-copilot-${random_string.suffix.result}"
  location                      = azurerm_resource_group.this.location
  resource_group_name           = azurerm_resource_group.this.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true # rule AZ-KV-002
  purge_protection_enabled      = true # rule AZ-KV-001
  soft_delete_retention_days    = 30
  public_network_access_enabled = true # Container Apps (consumption) has no private endpoint; restrict via network_acls in prod
  tags                          = local.tags
}

resource "azurerm_role_assignment" "kv_secrets_user" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.scanner_identity.principal_id
}

resource "azurerm_role_assignment" "kv_admin_deployer" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "random_password" "api_key" {
  length  = 40
  special = false
}

resource "azurerm_key_vault_secret" "api_keys" {
  name         = "api-keys"
  value        = random_password.api_key.result
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin_deployer]
}

# LLM key is set out-of-band: az keyvault secret set --vault-name <kv> -n llm-api-key --value <key>
resource "azurerm_key_vault_secret" "llm_api_key" {
  name         = "llm-api-key"
  value        = "set-me"
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin_deployer]
  lifecycle {
    ignore_changes = [value]
  }
}

# ---------------------------------------------------------------------------- runtime
resource "azurerm_container_app_environment" "this" {
  name                       = "cae-${local.name}"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  tags                       = local.tags
}

resource "azurerm_container_app" "api" {
  name                         = "ca-${local.name}"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [module.scanner_identity.id]
  }

  secret {
    name                = "api-keys"
    key_vault_secret_id = azurerm_key_vault_secret.api_keys.versionless_id
    identity            = module.scanner_identity.id
  }
  secret {
    name                = "llm-api-key"
    key_vault_secret_id = azurerm_key_vault_secret.llm_api_key.versionless_id
    identity            = module.scanner_identity.id
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    min_replicas = 1
    max_replicas = 3

    container {
      name   = "api"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"
      args   = ["serve", "--host", "0.0.0.0", "--port", "8000"]

      env {
        name  = "ENVIRONMENT"
        value = var.environment == "prod" ? "prod" : "staging"
      }
      env {
        name  = "DEMO_MODE"
        value = tostring(var.demo_mode)
      }
      env {
        name  = "SCAN_ON_STARTUP"
        value = "true"
      }
      env {
        name  = "PROVIDERS"
        value = "azure"
      }
      env {
        name  = "AZURE_CLIENT_ID"
        value = module.scanner_identity.client_id
      }
      env {
        name  = "AZURE_SUBSCRIPTION_IDS"
        value = join(",", local.subs)
      }
      env {
        name        = "API_KEYS"
        secret_name = "api-keys"
      }
      env {
        name        = "LLM_API_KEY"
        secret_name = "llm-api-key"
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/healthz"
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/readyz"
      }
    }
  }
}
