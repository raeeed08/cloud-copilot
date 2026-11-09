# AWS account security baseline

## Identity
- Root: MFA (hardware key preferred), no access keys, contact details current, used only for the few root-only
  tasks (IAM-001, IAM-002).
- Humans log in through **IAM Identity Center** (SSO) with MFA, not IAM users. Permission sets map to job
  functions; no long-lived keys on laptops (use `aws sso login`).
- Workloads use roles: instance profiles, IRSA / EKS Pod Identity, Lambda execution roles, GitHub OIDC for CI.
- Password policy ≥14 characters, reuse prevention 24 (IAM-003) for any remaining IAM users.
- IAM Access Analyzer in every region (IAM-011) to catch resources shared outside the organization.

## Multi-account with AWS Organizations
- Separate accounts for security tooling, log archive, shared services, and each environment (dev/stage/prod).
- **Service Control Policies**: deny leaving the organization, deny disabling CloudTrail/GuardDuty/Config, deny
  unused regions, deny root user actions, require IMDSv2 (`ec2:MetadataHttpTokens`).
- AWS Control Tower or Landing Zone Accelerator to bootstrap this pattern.

## Detection
- Organization CloudTrail, multi-region, log file validation, KMS-encrypted, delivered to an immutable
  (Object Lock) bucket in the log-archive account (CT-001…CT-005).
- GuardDuty (all regions, with S3/EKS/Malware/Runtime protection), Security Hub with FSBP + CIS standards,
  AWS Config recording all resources (GD-001, SH-001, CFG-001).
- CloudWatch metric filters and alarms for: root login, console login without MFA, IAM policy changes,
  CloudTrail changes, security group changes, NACL changes (CIS section 4).

## Data protection
- S3 Block Public Access at account level (S3-001), TLS-only bucket policies (S3-004), KMS for sensitive data.
- EBS encryption by default per region (EBS-001), RDS encryption and private subnets (RDS-001, RDS-002).
- AWS Backup with a vault lock for ransomware-resistant backups.
