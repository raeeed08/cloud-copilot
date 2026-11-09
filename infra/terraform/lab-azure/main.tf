# Cloud Copilot practice lab (Azure). Cost: a few cents per day (empty storage account, Key Vault, NSG).
data "azurerm_client_config" "me" {}

resource "random_string" "s" {
  length  = 6
  upper   = false
  special = false
}

locals {
  name = "ccl${random_string.s.result}"
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}-lab"
  location = var.location
  tags     = { purpose = "cloud-copilot-lab" }
}

# ---------------------------------------------------------------------------- storage
resource "azurerm_storage_account" "data" {
  name                            = "st${local.name}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  https_traffic_only_enabled      = true
  min_tls_version                 = var.secure ? "TLS1_2" : "TLS1_0" # AZ-STOR-003
  allow_nested_items_to_be_public = !var.secure                      # AZ-STOR-001 (no container is made public)
  shared_access_key_enabled       = true                             # AZ-STOR-004 stays: Terraform's data plane needs it
  network_rules {
    default_action = var.secure ? "Deny" : "Allow" # AZ-STOR-005
    bypass         = ["AzureServices"]
    ip_rules       = []
  }
}

# ---------------------------------------------------------------------------- network
resource "azurerm_network_security_group" "jump" {
  name                = "nsg-${local.name}-jump"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  security_rule {
    name                       = "rdp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.secure ? "10.0.0.0/8" : "Internet" # AZ-NSG-001
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "idle" {
  count               = var.secure ? 0 : 1 # AZ-COST-001
  name                = "pip-${local.name}-idle"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ---------------------------------------------------------------------------- key vault
resource "azurerm_key_vault" "lab" {
  name                       = "kv-${local.name}"
  location                   = azurerm_resource_group.lab.location
  resource_group_name        = azurerm_resource_group.lab.name
  tenant_id                  = data.azurerm_client_config.me.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = var.secure # AZ-KV-002
  soft_delete_retention_days = 7
  # AZ-KV-001: purge protection is left off even when secure, because it makes `terraform destroy` unable to purge.
  purge_protection_enabled      = false
  public_network_access_enabled = true
  network_acls {
    default_action = var.secure ? "Deny" : "Allow" # AZ-KV-003
    bypass         = "AzureServices"
  }
}

# ---------------------------------------------------------------------------- scanner identity (read-only)
resource "azuread_application" "scanner" {
  display_name = "cloud-copilot-${local.name}-scanner"
}

resource "azuread_service_principal" "scanner" {
  client_id = azuread_application.scanner.client_id
}

resource "azuread_application_password" "scanner" {
  application_id = azuread_application.scanner.id
  display_name   = "cloud-copilot"
  end_date       = timeadd(timestamp(), "720h") # 30 days
  lifecycle {
    ignore_changes = [end_date]
  }
}

resource "azurerm_role_assignment" "scanner" {
  for_each             = toset(["Reader", "Security Reader", "Cost Management Reader"])
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = each.value
  principal_id         = azuread_service_principal.scanner.object_id
}
