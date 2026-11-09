"""AWS data-protection rules (S3, RDS, DynamoDB, KMS, Secrets Manager, SQS/SNS)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloud_copilot.core.registry import Hit, rule
from cloud_copilot.models import Category, Provider, Severity
from cloud_copilot.providers.aws.scanners.s3 import fully_blocked

AWS = Provider.AWS
S3_ARN = "arn:aws:s3:::{}"


# ----------------------------------------------------------------------------- S3
@rule(
    id="S3-001",
    title="Account-level S3 Block Public Access disabled",
    provider=AWS,
    service="s3",
    severity=Severity.HIGH,
    description="The account-wide switch is the safety net that stops any bucket from becoming public by mistake.",
    remediation="Enable all four Block Public Access settings at account level.",
    cis=["2.1.4"],
    nist=["AC-3", "AC-21"],
    terraform='resource "aws_s3_account_public_access_block" "this" {\n  block_public_acls       = true\n'
    "  block_public_policy     = true\n  ignore_public_acls      = true\n"
    "  restrict_public_buckets = true\n}",
)
def account_pab(d: dict[str, Any]) -> Iterator[Hit]:
    if not fully_blocked(d.get("account_public_access_block")):
        yield Hit(
            "s3-account-public-access-block",
            "Account-level S3 Block Public Access is not fully enabled.",
            resource_name="S3 account settings",
        )


@rule(
    id="S3-002",
    title="S3 bucket is publicly accessible",
    provider=AWS,
    service="s3",
    severity=Severity.CRITICAL,
    description="A bucket policy or ACL grants access to everyone and nothing blocks it. Data is exposed to "
    "the internet.",
    remediation="Remove the public grant and enable Block Public Access on the bucket. Serve public content "
    "through CloudFront with Origin Access Control instead.",
    cis=["2.1.4"],
    nist=["AC-3", "AC-21", "SC-7"],
    terraform='resource "aws_s3_bucket_public_access_block" "this" {\n  bucket                  = "{resource}"\n'
    "  block_public_acls       = true\n  block_public_policy     = true\n"
    "  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
)
def public_bucket(d: dict[str, Any]) -> Iterator[Hit]:
    account_blocked = fully_blocked(d.get("account_public_access_block"))
    for b in d["buckets"]:
        if account_blocked or fully_blocked(b["public_access_block"]):
            continue
        reasons = [r for r, on in (("bucket policy", b["policy"]["public"]), ("ACL", b["acl_public"])) if on]
        if reasons:
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' is public via {' and '.join(reasons)}.",
                resource_name=b["name"],
                region=b["region"],
            )


@rule(
    id="S3-003",
    title="S3 bucket Block Public Access not enabled",
    provider=AWS,
    service="s3",
    severity=Severity.MEDIUM,
    description="Without Block Public Access, one wrong policy or ACL change makes the bucket public.",
    remediation="Enable the four Block Public Access settings on the bucket.",
    cis=["2.1.4"],
    nist=["AC-3"],
    terraform='resource "aws_s3_bucket_public_access_block" "this" {\n  bucket                  = "{resource}"\n'
    "  block_public_acls       = true\n  block_public_policy     = true\n"
    "  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
)
def bucket_pab(d: dict[str, Any]) -> Iterator[Hit]:
    if fully_blocked(d.get("account_public_access_block")):
        return
    for b in d["buckets"]:
        if not fully_blocked(b["public_access_block"]) and not (b["policy"]["public"] or b["acl_public"]):
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' has no complete Block Public Access.",
                resource_name=b["name"],
                region=b["region"],
            )


@rule(
    id="S3-004",
    title="S3 bucket allows plain HTTP",
    provider=AWS,
    service="s3",
    severity=Severity.MEDIUM,
    description="Without a policy denying aws:SecureTransport=false, clients can read and write over HTTP.",
    remediation="Add a bucket policy statement that denies requests where aws:SecureTransport is false.",
    cis=["2.1.1"],
    nist=["SC-8"],
    terraform='data "aws_iam_policy_document" "tls_only" {\n  statement {\n    effect    = "Deny"\n'
    '    actions   = ["s3:*"]\n    resources = ["arn:aws:s3:::{resource}", "arn:aws:s3:::{resource}/*"]\n'
    '    principals {\n      type        = "*"\n      identifiers = ["*"]\n    }\n'
    '    condition {\n      test     = "Bool"\n      variable = "aws:SecureTransport"\n'
    '      values   = ["false"]\n    }\n  }\n}',
)
def tls_only(d: dict[str, Any]) -> Iterator[Hit]:
    for b in d["buckets"]:
        if not b["policy"]["enforces_tls"]:
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' does not enforce TLS.",
                resource_name=b["name"],
                region=b["region"],
            )


@rule(
    id="S3-005",
    title="S3 bucket versioning disabled",
    provider=AWS,
    service="s3",
    severity=Severity.LOW,
    description="Versioning protects against accidental deletion and ransomware-style overwrites.",
    remediation="Enable versioning (and a lifecycle rule to expire old versions).",
    nist=["CP-9", "SI-12"],
    category=Category.RELIABILITY,
    terraform='resource "aws_s3_bucket_versioning" "this" {\n  bucket = "{resource}"\n'
    '  versioning_configuration {\n    status = "Enabled"\n  }\n}',
)
def versioning(d: dict[str, Any]) -> Iterator[Hit]:
    for b in d["buckets"]:
        if not b["versioning"]:
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' has versioning disabled.",
                resource_name=b["name"],
                region=b["region"],
            )


@rule(
    id="S3-006",
    title="S3 server access logging disabled",
    provider=AWS,
    service="s3",
    severity=Severity.LOW,
    description="Access logs are needed to investigate who read or changed data during an incident.",
    remediation="Enable server access logging to a dedicated log bucket (or CloudTrail S3 data events).",
    nist=["AU-2", "AU-12"],
    terraform='resource "aws_s3_bucket_logging" "this" {\n  bucket        = "{resource}"\n'
    '  target_bucket = "<log-bucket>"\n  target_prefix = "s3/{resource}/"\n}',
)
def logging(d: dict[str, Any]) -> Iterator[Hit]:
    for b in d["buckets"]:
        if not b["logging"]:
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' has no access logging.",
                resource_name=b["name"],
                region=b["region"],
            )


@rule(
    id="S3-007",
    title="S3 bucket not encrypted with KMS",
    provider=AWS,
    service="s3",
    severity=Severity.INFO,
    description="Since 2023 S3 encrypts everything with SSE-S3. SSE-KMS adds key-level access control and "
    "audit. Recommended for sensitive data.",
    remediation="Use SSE-KMS with a customer-managed key and S3 Bucket Keys to limit KMS cost.",
    nist=["SC-28", "SC-12"],
    terraform='resource "aws_s3_bucket_server_side_encryption_configuration" "this" {\n'
    '  bucket = "{resource}"\n  rule {\n    apply_server_side_encryption_by_default {\n'
    '      sse_algorithm     = "aws:kms"\n      kms_master_key_id = "<kms-key-arn>"\n    }\n'
    "    bucket_key_enabled = true\n  }\n}",
)
def kms_encryption(d: dict[str, Any]) -> Iterator[Hit]:
    for b in d["buckets"]:
        if b["encryption"] not in ("aws:kms", "aws:kms:dsse"):
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' uses {b['encryption'] or 'default'} encryption, not KMS.",
                resource_name=b["name"],
                region=b["region"],
            )


@rule(
    id="S3-008",
    title="S3 bucket without lifecycle policy",
    provider=AWS,
    service="s3",
    severity=Severity.LOW,
    category=Category.COST,
    description="Without lifecycle rules, old objects and non-current versions stay in Standard storage forever.",
    remediation="Add lifecycle rules: transition to Intelligent-Tiering/Glacier, expire non-current "
    "versions, abort incomplete multipart uploads.",
    terraform='resource "aws_s3_bucket_lifecycle_configuration" "this" {\n  bucket = "{resource}"\n'
    '  rule {\n    id     = "tiering"\n    status = "Enabled"\n    filter {}\n'
    '    transition {\n      days          = 30\n      storage_class = "INTELLIGENT_TIERING"\n'
    "    }\n    noncurrent_version_expiration {\n      noncurrent_days = 90\n    }\n"
    "    abort_incomplete_multipart_upload {\n      days_after_initiation = 7\n    }\n  }\n}",
)
def lifecycle(d: dict[str, Any]) -> Iterator[Hit]:
    for b in d["buckets"]:
        if b.get("lifecycle_rules", 0) == 0:
            yield Hit(
                S3_ARN.format(b["name"]),
                f"Bucket '{b['name']}' has no lifecycle rules.",
                resource_name=b["name"],
                region=b["region"],
            )


# ----------------------------------------------------------------------------- RDS
RDS_TF = (
    'resource "aws_db_instance" "{resource}" {\n  # ...\n  publicly_accessible     = false\n'
    "  storage_encrypted       = true\n  backup_retention_period = 7\n  deletion_protection     = true\n"
    "  auto_minor_version_upgrade = true\n  multi_az                = true\n}"
)


@rule(
    id="RDS-001",
    title="RDS instance publicly accessible",
    provider=AWS,
    service="rds",
    severity=Severity.CRITICAL,
    description="A database with a public endpoint is directly exposed to brute force and exploit attempts.",
    remediation="Set publicly_accessible=false and place the instance in private subnets; use a bastion, "
    "SSM port forwarding or VPN for admin access.",
    cis=["2.3.3"],
    nist=["SC-7", "AC-3"],
    terraform=RDS_TF,
)
def rds_public(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if i["public"]:
            yield Hit(
                i["id"], f"RDS instance '{i['id']}' is publicly accessible.", resource_name=i["id"], region=i["region"]
            )


@rule(
    id="RDS-002",
    title="RDS storage not encrypted",
    provider=AWS,
    service="rds",
    severity=Severity.HIGH,
    description="Unencrypted storage, snapshots and replicas expose data if copied or shared.",
    remediation="Encryption can't be enabled in place: snapshot, copy the snapshot with KMS encryption, "
    "restore, then switch over.",
    cis=["2.3.1"],
    nist=["SC-28"],
    terraform=RDS_TF,
)
def rds_encryption(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if not i["encrypted"]:
            yield Hit(
                i["id"],
                f"RDS instance '{i['id']}' is not encrypted at rest.",
                resource_name=i["id"],
                region=i["region"],
            )


@rule(
    id="RDS-003",
    title="RDS snapshot shared publicly",
    provider=AWS,
    service="rds",
    severity=Severity.CRITICAL,
    description="Anyone with an AWS account can restore a public snapshot: a full copy of your database.",
    remediation="Remove the 'all' restore attribute: aws rds modify-db-snapshot-attribute "
    "--db-snapshot-identifier <id> --attribute-name restore --values-to-remove all",
    nist=["AC-3", "AC-21"],
)
def rds_public_snapshot(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["snapshots"]:
        if s["public"]:
            yield Hit(s["id"], f"RDS snapshot '{s['id']}' is public.", resource_name=s["id"], region=s["region"])


@rule(
    id="RDS-004",
    title="RDS backups retained less than 7 days",
    provider=AWS,
    service="rds",
    severity=Severity.MEDIUM,
    category=Category.RELIABILITY,
    description="Short retention limits point-in-time recovery after corruption or a malicious change.",
    remediation="Set backup_retention_period to at least 7 days (35 for production).",
    nist=["CP-9"],
    terraform=RDS_TF,
)
def rds_backup(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if i["backup_retention_days"] < 7:
            yield Hit(
                i["id"],
                f"RDS instance '{i['id']}' keeps backups {i['backup_retention_days']} day(s).",
                resource_name=i["id"],
                region=i["region"],
            )


@rule(
    id="RDS-005",
    title="RDS deletion protection disabled",
    provider=AWS,
    service="rds",
    severity=Severity.LOW,
    category=Category.RELIABILITY,
    description="Deletion protection prevents an accidental or malicious delete of the database.",
    remediation="Set deletion_protection=true.",
    nist=["CP-9", "SI-7"],
    terraform=RDS_TF,
)
def rds_deletion(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if not i["deletion_protection"]:
            yield Hit(
                i["id"],
                f"RDS instance '{i['id']}' has no deletion protection.",
                resource_name=i["id"],
                region=i["region"],
            )


@rule(
    id="RDS-006",
    title="RDS auto minor version upgrade disabled",
    provider=AWS,
    service="rds",
    severity=Severity.LOW,
    description="Minor versions carry security patches. Disabling auto-upgrade leaves known CVEs open.",
    remediation="Enable auto_minor_version_upgrade with a maintenance window.",
    cis=["2.3.2"],
    nist=["SI-2"],
    terraform=RDS_TF,
)
def rds_minor_upgrade(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if not i["auto_minor_upgrade"]:
            yield Hit(
                i["id"],
                f"RDS instance '{i['id']}' won't receive minor security patches automatically.",
                resource_name=i["id"],
                region=i["region"],
            )


@rule(
    id="RDS-007",
    title="RDS instance not Multi-AZ",
    provider=AWS,
    service="rds",
    severity=Severity.LOW,
    category=Category.RELIABILITY,
    description="Single-AZ databases go down with their Availability Zone.",
    remediation="Enable Multi-AZ for production databases.",
    nist=["CP-7"],
    terraform=RDS_TF,
)
def rds_multi_az(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if not i["multi_az"]:
            yield Hit(
                i["id"], f"RDS instance '{i['id']}' runs in a single AZ.", resource_name=i["id"], region=i["region"]
            )


# ----------------------------------------------------------------------------- DynamoDB
@rule(
    id="DDB-001",
    title="DynamoDB point-in-time recovery disabled",
    provider=AWS,
    service="dynamodb",
    severity=Severity.MEDIUM,
    category=Category.RELIABILITY,
    description="PITR allows restoring a table to any second of the last 35 days.",
    remediation="Enable point-in-time recovery.",
    nist=["CP-9"],
    terraform='resource "aws_dynamodb_table" "{resource}" {\n  # ...\n  point_in_time_recovery {\n'
    "    enabled = true\n  }\n  deletion_protection_enabled = true\n}",
)
def ddb_pitr(d: dict[str, Any]) -> Iterator[Hit]:
    for t in d["tables"]:
        if not t["pitr"]:
            yield Hit(
                t["arn"], f"DynamoDB table '{t['name']}' has no PITR.", resource_name=t["name"], region=t["region"]
            )


@rule(
    id="DDB-002",
    title="DynamoDB deletion protection disabled",
    provider=AWS,
    service="dynamodb",
    severity=Severity.LOW,
    category=Category.RELIABILITY,
    description="Deletion protection blocks accidental DeleteTable calls.",
    remediation="Enable deletion_protection_enabled.",
    nist=["CP-9"],
)
def ddb_deletion(d: dict[str, Any]) -> Iterator[Hit]:
    for t in d["tables"]:
        if not t["deletion_protection"]:
            yield Hit(
                t["arn"],
                f"DynamoDB table '{t['name']}' has no deletion protection.",
                resource_name=t["name"],
                region=t["region"],
            )


# ----------------------------------------------------------------------------- KMS & secrets
@rule(
    id="KMS-001",
    title="KMS key rotation disabled",
    provider=AWS,
    service="kms",
    severity=Severity.MEDIUM,
    description="Automatic yearly rotation limits the amount of data protected by a single key version.",
    remediation="Enable automatic rotation on symmetric customer-managed keys.",
    cis=["3.6"],
    nist=["SC-12"],
    terraform='resource "aws_kms_key" "this" {\n  description         = "{resource}"\n  enable_key_rotation = true\n}',
)
def kms_rotation(d: dict[str, Any]) -> Iterator[Hit]:
    for k in d["keys"]:
        if k["symmetric"] and not k["rotation_enabled"]:
            yield Hit(
                k["arn"],
                f"KMS key {k['id']} has automatic rotation disabled.",
                resource_name=k["id"],
                region=k["region"],
            )


@rule(
    id="SM-001",
    title="Secret rotation disabled",
    provider=AWS,
    service="secretsmanager",
    severity=Severity.MEDIUM,
    description="Secrets that never rotate stay valid forever once leaked.",
    remediation="Configure a rotation Lambda (managed rotation for RDS/Redshift/DocumentDB).",
    nist=["IA-5(1)"],
)
def secret_rotation(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["secrets"]:
        if not s["rotation_enabled"]:
            yield Hit(s["arn"], f"Secret '{s['name']}' is never rotated.", resource_name=s["name"], region=s["region"])


@rule(
    id="SM-002",
    title="Unused secret (90+ days)",
    provider=AWS,
    service="secretsmanager",
    severity=Severity.LOW,
    category=Category.COST,
    description="Each secret costs $0.40/month and widens the attack surface if nobody uses it.",
    remediation="Delete secrets unused for 90 days after confirming with the owner.",
    nist=["CM-7"],
)
def secret_unused(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["secrets"]:
        if (s.get("last_accessed_days") or 0) > 90:
            yield Hit(
                s["arn"],
                f"Secret '{s['name']}' not accessed for {s['last_accessed_days']} days.",
                resource_name=s["name"],
                region=s["region"],
                monthly_savings=0.40,
            )


# ----------------------------------------------------------------------------- SQS / SNS
@rule(
    id="MSG-001",
    title="Queue or topic not encrypted",
    provider=AWS,
    service="messaging",
    severity=Severity.LOW,
    description="Messages often carry PII or tokens. Server-side encryption protects them at rest.",
    remediation="Enable SQS-managed SSE or KMS encryption on queues, KMS on SNS topics.",
    nist=["SC-28"],
)
def msg_encryption(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["resources"]:
        if not r["encrypted"]:
            yield Hit(
                r["arn"],
                f"{r['kind'].upper()} '{r['name']}' is not encrypted at rest.",
                resource_name=r["name"],
                region=r["region"],
            )


@rule(
    id="MSG-002",
    title="Queue or topic policy is public",
    provider=AWS,
    service="messaging",
    severity=Severity.HIGH,
    description="A resource policy allowing '*' lets anyone publish or consume messages.",
    remediation="Restrict the Principal or add aws:SourceArn / aws:SourceAccount conditions.",
    nist=["AC-3"],
)
def msg_public(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["resources"]:
        if r["public_policy"]:
            yield Hit(
                r["arn"],
                f"{r['kind'].upper()} '{r['name']}' has a public resource policy.",
                resource_name=r["name"],
                region=r["region"],
            )
