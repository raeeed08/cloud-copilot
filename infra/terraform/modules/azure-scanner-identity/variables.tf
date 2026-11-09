variable "name" {
  type    = string
  default = "id-cloud-copilot-scanner"
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "subscription_ids" {
  description = "Subscriptions the scanner may read"
  type        = list(string)
}

variable "aks_oidc_issuer_url" {
  type    = string
  default = null
}

variable "k8s_namespace" {
  type    = string
  default = "cloud-copilot"
}

variable "k8s_service_account" {
  type    = string
  default = "cloud-copilot"
}

variable "tags" {
  type    = map(string)
  default = {}
}
