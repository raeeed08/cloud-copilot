terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # Local state on purpose: this is a disposable lab. Never commit terraform.tfstate (it is gitignored).
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "cloud-copilot-lab", ManagedBy = "terraform", Purpose = "security-training" }
  }
}
