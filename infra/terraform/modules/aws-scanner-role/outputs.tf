output "role_arn" {
  description = "ARN of the read-only scanner role"
  value       = aws_iam_role.scanner.arn
}

output "role_name" {
  value = aws_iam_role.scanner.name
}
