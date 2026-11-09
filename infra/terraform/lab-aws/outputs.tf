output "connect_in_cloud_copilot" {
  description = "Accounts → Connect an account → AWS → IAM role (assume role)"
  value = {
    auth_method = "assume_role"
    role_arn    = aws_iam_role.scanner.arn
    external_id = random_password.external_id.result
    access_key  = aws_iam_access_key.scanner.id
    regions     = var.region
    secret_key  = "run: terraform output -raw scanner_secret_access_key"
  }
  sensitive = true
}

output "scanner_secret_access_key" {
  value     = aws_iam_access_key.scanner.secret
  sensitive = true
}

output "console_sign_in" {
  value = "https://${data.aws_caller_identity.me.account_id}.signin.aws.amazon.com/console"
}

output "mode" {
  value = var.secure ? "SECURE: fixes applied, re-scan to verify" : "INSECURE: scan it with Cloud Copilot"
}
