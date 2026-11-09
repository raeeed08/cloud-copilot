# Playbook: publicly exposed storage (S3 bucket, Azure blob, snapshots)

## Triage
- Confirm exposure: is the bucket/container readable anonymously? `curl -I https://<bucket>.s3.amazonaws.com/<key>`.
- Identify data classification. Macie (AWS) or Purview (Azure) can classify objects for PII/secrets quickly.
- Determine exposure window: S3 `PutBucketPolicy` / `PutBucketAcl` / `DeletePublicAccessBlock` events in CloudTrail;
  Azure Activity Log `Microsoft.Storage/storageAccounts/write` with `allowBlobPublicAccess`.

## Contain
- AWS: enable Block Public Access on the bucket **and at account level** (rule S3-001). It overrides any policy or
  ACL immediately and is reversible.
- Azure: set `allowBlobPublicAccess=false` on the storage account (rule AZ-STOR-001) and container access level to
  Private.
- Public EBS/RDS snapshots: remove the `all` group permission (rules EBS-003, RDS-003); turn on *Block public access
  for EBS snapshots* at region level.

## Assess access
- S3 server access logs or CloudTrail data events (`GetObject` with anonymous principal).
- Azure Storage analytics / diagnostic logs (`StorageRead` with `AuthenticationType=Anonymous`).
- If personal data was accessed, involve legal/DPO: GDPR requires notification within 72 hours.

## Legitimate public content
Never make the origin bucket public. Use CloudFront with Origin Access Control (AWS) or Azure Front Door with a
private endpoint, so the bucket keeps Block Public Access while content is still served.
