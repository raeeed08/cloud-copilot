# Read-only role assumed by Cloud Copilot. It can read configuration and billing, never change anything.
data "aws_partition" "current" {}

locals {
  irsa_subject = "system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"
}

data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = var.eks_oidc_provider_arn == null ? [] : [1]
    content {
      sid     = "EksIrsa"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [var.eks_oidc_provider_arn]
      }
      condition {
        test     = "StringEquals"
        variable = "${replace(var.eks_oidc_provider_arn, "/^.*oidc-provider\\//", "")}:sub"
        values   = [local.irsa_subject]
      }
      condition {
        test     = "StringEquals"
        variable = "${replace(var.eks_oidc_provider_arn, "/^.*oidc-provider\\//", "")}:aud"
        values   = ["sts.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.trusted_principal_arns) == 0 ? [] : [1]
    content {
      sid     = "TrustedPrincipals"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.trusted_principal_arns
      }
      dynamic "condition" {
        for_each = var.external_id == null ? [] : [1]
        content {
          test     = "StringEquals"
          variable = "sts:ExternalId"
          values   = [var.external_id]
        }
      }
    }
  }
}

resource "aws_iam_role" "scanner" {
  name                 = var.name
  description          = "Cloud Copilot read-only posture & cost scanner"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/job-function/ViewOnlyAccess"
}

data "aws_iam_policy_document" "extra" {
  statement {
    sid = "CostExplorerRead"
    actions = [
      "ce:GetCostAndUsage",
      "ce:GetCostForecast",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "DenyDataPlaneReads"
    effect    = "Deny"
    actions   = ["s3:GetObject", "secretsmanager:GetSecretValue", "ssm:GetParameter*", "kms:Decrypt", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "extra" {
  name   = "cost-read-and-data-deny"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.extra.json
}
