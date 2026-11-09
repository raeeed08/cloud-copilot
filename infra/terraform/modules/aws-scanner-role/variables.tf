variable "name" {
  description = "IAM role name"
  type        = string
  default     = "cloud-copilot-scanner"
}

variable "eks_oidc_provider_arn" {
  description = "EKS OIDC provider ARN to allow IRSA (null to disable)"
  type        = string
  default     = null
}

variable "k8s_namespace" {
  type    = string
  default = "cloud-copilot"
}

variable "k8s_service_account" {
  type    = string
  default = "cloud-copilot"
}

variable "trusted_principal_arns" {
  description = "Principals (e.g. a central security account role) allowed to assume this role"
  type        = list(string)
  default     = []
}

variable "external_id" {
  description = "Optional sts:ExternalId required for cross-account assumption"
  type        = string
  default     = null
  sensitive   = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
