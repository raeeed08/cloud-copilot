output "cluster_name" {
  value = module.eks.cluster_name
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "scanner_role_arn" {
  description = "Annotate the chart service account with this (serviceAccount.annotations)"
  value       = module.scanner_role.role_arn
}

output "github_deploy_role_arn" {
  description = "Set as AWS_DEPLOY_ROLE_ARN secret in GitHub"
  value       = aws_iam_role.github_deploy.arn
}

output "secrets_manager_secret" {
  value = aws_secretsmanager_secret.app.name
}
