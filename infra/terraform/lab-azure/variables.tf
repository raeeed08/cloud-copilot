variable "subscription_id" {
  description = "Subscription to deploy the lab into (az account show --query id -o tsv)"
  type        = string
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "secure" {
  description = "false = misconfigured lab; true = apply the fixes"
  type        = bool
  default     = false
}
