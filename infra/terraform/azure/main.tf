# Azure lab stub — secure-by-default (Checkov). Ne pas appliquer sans revue.
# Usage : cd infra/terraform/azure && terraform init && terraform plan

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "prefix" {
  type    = string
  default = "spaylab"
}

resource "azurerm_resource_group" "lab" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags = {
    Project     = "SecurePay"
    Environment = "lab"
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_storage_account" "logs" {
  name                            = "${var.prefix}logs001"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  public_network_access_enabled   = false
  tags = {
    Project = "SecurePay"
  }
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}
