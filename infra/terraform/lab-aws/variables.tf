variable "region" {
  description = "Region for the lab resources"
  type        = string
  default     = "eu-west-1"
}

variable "secure" {
  description = "false = deploy the misconfigured lab; true = apply the fixes Cloud Copilot recommends"
  type        = bool
  default     = false
}

variable "create_instance" {
  description = "Also create a t3.micro with a public IP to demonstrate an attack path (~$0.01/h, free tier eligible). No SSH key is attached."
  type        = bool
  default     = false
}

variable "account_level_settings" {
  description = "When secure=true, also manage account-wide settings (password policy, EBS default encryption, S3 account Block Public Access). Destroying the lab removes them."
  type        = bool
  default     = true
}
