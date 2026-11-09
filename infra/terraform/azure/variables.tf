variable "subscription_id" {
  type = string
}

variable "scan_subscription_ids" {
  description = "Subscriptions Cloud Copilot may read (defaults to the deployment subscription)"
  type        = list(string)
  default     = []
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "image" {
  description = "Container image (e.g. ghcr.io/raeeed08/cloud-copilot:2.0.0 or <acr>.azurecr.io/cloud-copilot@sha256:...)"
  type        = string
  default     = "ghcr.io/raeeed08/cloud-copilot:2.0.0"
}

variable "demo_mode" {
  type    = bool
  default = false
}
