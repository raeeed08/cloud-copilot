# Playbook: compromised AWS access key

## Signals
- GuardDuty findings such as `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`, `Recon:IAMUser/*`,
  `CryptoCurrency:EC2/BitcoinTool`.
- An AWS Health / Trusted Advisor "exposed access key" notification (AWS scans public GitHub).
- Unexpected `RunInstances` in unused regions, new IAM users, or `StopLogging` events in CloudTrail.

## Contain (first 15 minutes)
1. **Deactivate, don't delete** the key so evidence stays linked:
   `aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive`
2. Attach an explicit deny-all inline policy to the user (`AWSDenyAll`) to cut active sessions using the key.
3. If the key belonged to a role session (ASIA…), revoke sessions: IAM console → Role → *Revoke active sessions*
   (adds an `aws:TokenIssueTime` deny condition).
4. Check for persistence: new IAM users, access keys, login profiles, roles with external trust, Lambda functions,
   EC2 key pairs, SSO users.

## Investigate
- CloudTrail Lake / Athena: filter `userIdentity.accessKeyId = '<AKIA...>'` across **all regions**, from first
  sighting minus 7 days.
- Look for `GetCallerIdentity` (attacker recon), `ListBuckets`, `GetObject` bursts (exfiltration),
  `CreateUser`, `AttachUserPolicy`, `PutBucketPolicy`, `ModifySnapshotAttribute` (data sharing).
- Review billing (Cost Explorer, hourly granularity) for crypto-mining GPU instances.

## Eradicate and recover
- Delete attacker-created resources, rotate every secret the principal could read (Secrets Manager, SSM, Lambda
  env vars), and redeploy workloads with new credentials.
- Replace long-lived keys with roles: IAM Roles Anywhere, OIDC federation for CI (GitHub Actions → `AssumeRoleWithWebIdentity`),
  instance profiles / IRSA / EKS Pod Identity.

## Prevent
- Rules IAM-005/IAM-006/IAM-007 (rotation, unused credentials, single key) and IAM-009 (no full admin).
- Pre-commit secret scanning (gitleaks), GitHub push protection, and an SCP denying `iam:CreateAccessKey` outside
  break-glass.
