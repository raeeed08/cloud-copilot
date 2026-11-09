terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.14" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # terraform init -backend-config=backend.hcl  (storage account + container, Entra ID auth)
  backend "azurerm" {}
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
  subscription_id = var.subscription_id
}
