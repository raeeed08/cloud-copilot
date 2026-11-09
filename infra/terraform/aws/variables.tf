variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "cluster_version" {
  type    = string
  default = "1.31"
}

variable "github_repository" {
  description = "owner/repo allowed to push images and deploy via GitHub OIDC"
  type        = string
  default     = "raeeed08/cloud-copilot"
}

variable "admin_cidrs" {
  description = "CIDRs allowed to reach the public EKS API endpoint"
  type        = list(string)
  default     = []
}

variable "enable_gitops" {
  description = "Install Argo CD + External Secrets and register the app"
  type        = bool
  default     = true
}
