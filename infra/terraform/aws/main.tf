data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  name = "cloud-copilot-${var.environment}"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)
  tags = {
    Project     = "cloud-copilot"
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = var.github_repository
  }
}

# ---------------------------------------------------------------------------- network
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.16"

  name            = local.name
  cidr            = "10.40.0.0/16"
  azs             = local.azs
  private_subnets = ["10.40.0.0/19", "10.40.32.0/19", "10.40.64.0/19"]
  public_subnets  = ["10.40.96.0/22", "10.40.100.0/22", "10.40.104.0/22"]

  enable_nat_gateway                              = true
  single_nat_gateway                              = var.environment != "prod" # cost vs. availability trade-off
  enable_dns_hostnames                            = true
  enable_flow_log                                 = true # our own rule VPC-001
  flow_log_traffic_type                           = "REJECT"
  create_flow_log_cloudwatch_log_group            = true
  create_flow_log_cloudwatch_iam_role             = true
  flow_log_cloudwatch_log_group_retention_in_days = 30

  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1, "karpenter.sh/discovery" = local.name }
}

# ---------------------------------------------------------------------------- kubernetes
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = local.name
  cluster_version = var.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access           = length(var.admin_cidrs) > 0
  cluster_endpoint_public_access_cidrs     = var.admin_cidrs # rule EKS-001
  cluster_endpoint_private_access          = true
  cluster_enabled_log_types                = ["api", "audit", "authenticator"] # rule EKS-002
  create_kms_key                           = true                              # rule EKS-003 (secrets envelope encryption)
  enable_irsa                              = true
  enable_cluster_creator_admin_permissions = true

  cluster_addons = {
    coredns                = {}
    kube-proxy             = {}
    vpc-cni                = { before_compute = true }
    eks-pod-identity-agent = {}
  }

  eks_managed_node_groups = {
    default = {
      ami_type       = "AL2023_ARM_64_STANDARD" # Graviton: better price-performance
      instance_types = ["m7g.large", "m6g.large"]
      capacity_type  = var.environment == "prod" ? "ON_DEMAND" : "SPOT"
      min_size       = 2
      max_size       = 5
      desired_size   = 2
      metadata_options = {
        http_tokens                 = "required" # IMDSv2, rule EC2-005
        http_put_response_hop_limit = 1
      }
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs         = { volume_size = 40, volume_type = "gp3", encrypted = true }
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------- registry
resource "aws_ecr_repository" "app" {
  name                 = "cloud-copilot"
  image_tag_mutability = "IMMUTABLE" # rule ECR-002
  image_scanning_configuration {
    scan_on_push = true # rule ECR-001
  }
  encryption_configuration {
    encryption_type = "KMS"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep last 30 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }
      action       = { type = "expire" }
    }]
  })
}

# ---------------------------------------------------------------------------- identities
module "scanner_role" {
  source                = "../modules/aws-scanner-role"
  name                  = "${local.name}-scanner"
  eks_oidc_provider_arn = module.eks.oidc_provider_arn
  tags                  = local.tags
}

# GitHub Actions -> AWS without long-lived keys
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/main", "repo:${var.github_repository}:environment:${var.environment}"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name               = "${local.name}-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_trust.json
}

data "aws_iam_policy_document" "github_deploy" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages",
    ]
    resources = [aws_ecr_repository.app.arn]
  }
  statement {
    actions   = ["eks:DescribeCluster"]
    resources = [module.eks.cluster_arn]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy.json
}

# ---------------------------------------------------------------------------- secrets
resource "aws_secretsmanager_secret" "app" {
  name                    = "cloud-copilot/${var.environment}"
  description             = "API_KEYS, LLM_API_KEY, DATABASE_URL, synced into the cluster by External Secrets"
  recovery_window_in_days = 7
}

module "external_secrets_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.48"

  role_name                                          = "${local.name}-external-secrets"
  attach_external_secrets_policy                     = true
  external_secrets_secrets_manager_arns              = [aws_secretsmanager_secret.app.arn]
  external_secrets_secrets_manager_create_permission = false
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["external-secrets:external-secrets"]
    }
  }
}

# ---------------------------------------------------------------------------- GitOps bootstrap
resource "helm_release" "argocd" {
  count            = var.enable_gitops ? 1 : 0
  name             = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = "7.7.11"
  namespace        = "argocd"
  create_namespace = true
  values = [yamlencode({
    configs = { params = { "server.insecure" = true } }
    server  = { service = { type = "ClusterIP" } }
  })]
}

resource "helm_release" "external_secrets" {
  count            = var.enable_gitops ? 1 : 0
  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  version          = "0.12.1"
  namespace        = "external-secrets"
  create_namespace = true
  values = [yamlencode({
    serviceAccount = { annotations = { "eks.amazonaws.com/role-arn" = module.external_secrets_irsa.iam_role_arn } }
  })]
}
