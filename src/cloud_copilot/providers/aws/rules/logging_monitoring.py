"""AWS logging & detection rules (CloudTrail, GuardDuty, Config, Security Hub, CloudWatch Logs)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloud_copilot.core.registry import Hit, rule
from cloud_copilot.models import Category, Provider, Severity

AWS = Provider.AWS
TRAIL_TF = (
    'resource "aws_cloudtrail" "org" {\n  name                          = "account-trail"\n'
    '  s3_bucket_name                = "<log-bucket>"\n  is_multi_region_trail         = true\n'
    "  include_global_service_events = true\n  enable_log_file_validation    = true\n"
    '  kms_key_id                    = "<kms-key-arn>"\n'
    '  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"\n'
    "  cloud_watch_logs_role_arn     = aws_iam_role.trail.arn\n}"
)


@rule(
    id="CT-001",
    title="No multi-region CloudTrail",
    provider=AWS,
    service="cloudtrail",
    severity=Severity.CRITICAL,
    description="Without a multi-region trail that is logging, API activity is not recorded everywhere and "
    "incidents can't be investigated.",
    remediation="Create one multi-region trail (or an organization trail) with management events.",
    cis=["3.1"],
    nist=["AU-2", "AU-12"],
    terraform=TRAIL_TF,
)
def no_trail(d: dict[str, Any]) -> Iterator[Hit]:
    if not any(t["multi_region"] and t["is_logging"] and t.get("management_events", True) for t in d["trails"]):
        yield Hit("cloudtrail", "No active multi-region trail records management events.", resource_name="CloudTrail")


@rule(
    id="CT-002",
    title="CloudTrail log file validation disabled",
    provider=AWS,
    service="cloudtrail",
    severity=Severity.MEDIUM,
    description="Digest files make it possible to prove logs were not tampered with after an intrusion.",
    remediation="Enable log file validation.",
    cis=["3.2"],
    nist=["AU-9"],
    terraform=TRAIL_TF,
)
def log_validation(d: dict[str, Any]) -> Iterator[Hit]:
    for t in d["trails"]:
        if not t["log_validation"]:
            yield Hit(
                t["arn"],
                f"Trail '{t['name']}' has log file validation disabled.",
                resource_name=t["name"],
                region=t["region"],
            )


@rule(
    id="CT-003",
    title="CloudTrail is not logging",
    provider=AWS,
    service="cloudtrail",
    severity=Severity.HIGH,
    description="A stopped trail is a classic attacker move to cover their tracks.",
    remediation="aws cloudtrail start-logging --name <trail>, then alert on StopLogging events.",
    nist=["AU-2", "AU-5"],
)
def not_logging(d: dict[str, Any]) -> Iterator[Hit]:
    for t in d["trails"]:
        if not t["is_logging"]:
            yield Hit(
                t["arn"], f"Trail '{t['name']}' exists but is not logging.", resource_name=t["name"], region=t["region"]
            )


@rule(
    id="CT-004",
    title="CloudTrail logs not encrypted with KMS",
    provider=AWS,
    service="cloudtrail",
    severity=Severity.LOW,
    description="SSE-KMS adds a second permission layer: reading logs also requires kms:Decrypt.",
    remediation="Configure a customer-managed KMS key on the trail.",
    cis=["3.5"],
    nist=["AU-9", "SC-28"],
    terraform=TRAIL_TF,
)
def trail_kms(d: dict[str, Any]) -> Iterator[Hit]:
    for t in d["trails"]:
        if not t["kms_key"]:
            yield Hit(
                t["arn"], f"Trail '{t['name']}' is not KMS-encrypted.", resource_name=t["name"], region=t["region"]
            )


@rule(
    id="CT-005",
    title="CloudTrail not integrated with CloudWatch Logs",
    provider=AWS,
    service="cloudtrail",
    severity=Severity.LOW,
    description="Sending events to CloudWatch Logs enables real-time metric filters and alarms "
    "(root login, IAM changes, console login failures…).",
    remediation="Configure a CloudWatch Logs group and role on the trail.",
    nist=["SI-4", "AU-6"],
    terraform=TRAIL_TF,
)
def trail_cwl(d: dict[str, Any]) -> Iterator[Hit]:
    for t in d["trails"]:
        if not t["cloudwatch_logs"]:
            yield Hit(
                t["arn"],
                f"Trail '{t['name']}' is not sent to CloudWatch Logs.",
                resource_name=t["name"],
                region=t["region"],
            )


@rule(
    id="GD-001",
    title="GuardDuty disabled",
    provider=AWS,
    service="detective",
    severity=Severity.HIGH,
    description="GuardDuty is AWS's managed threat detection (crypto-mining, credential exfiltration, "
    "recon). Attackers like quiet regions.",
    remediation="Enable GuardDuty in every region, ideally via a delegated admin in AWS Organizations.",
    nist=["SI-4", "RA-5"],
    terraform='resource "aws_guardduty_detector" "this" {\n  enable = true\n}',
)
def guardduty(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["regions"]:
        if not r["guardduty"]:
            yield Hit(
                f"guardduty/{r['region']}",
                f"GuardDuty is not enabled in {r['region']}.",
                resource_name="GuardDuty",
                region=r["region"],
            )


@rule(
    id="CFG-001",
    title="AWS Config not recording",
    provider=AWS,
    service="detective",
    severity=Severity.MEDIUM,
    description="AWS Config keeps the configuration history needed for audits and drift detection.",
    remediation="Enable a configuration recorder for all resources in every region.",
    cis=["3.3"],
    nist=["CM-8", "CM-3"],
)
def config_recorder(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["regions"]:
        if not r["config_recording"]:
            yield Hit(
                f"config/{r['region']}",
                f"AWS Config is not recording in {r['region']}.",
                resource_name="AWS Config",
                region=r["region"],
            )


@rule(
    id="SH-001",
    title="Security Hub disabled",
    provider=AWS,
    service="detective",
    severity=Severity.LOW,
    description="Security Hub aggregates findings from GuardDuty, Inspector, Macie and the FSBP standard.",
    remediation="Enable Security Hub with the AWS Foundational Security Best Practices standard.",
    nist=["CA-7", "SI-4"],
    terraform='resource "aws_securityhub_account" "this" {}',
)
def securityhub(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["regions"]:
        if not r["securityhub"]:
            yield Hit(
                f"securityhub/{r['region']}",
                f"Security Hub is not enabled in {r['region']}.",
                resource_name="Security Hub",
                region=r["region"],
            )


@rule(
    id="LOGS-001",
    title="Log group without retention",
    provider=AWS,
    service="logs",
    severity=Severity.LOW,
    category=Category.COST,
    description="'Never expire' log groups grow (and bill) forever.",
    remediation="Set a retention period that matches your compliance needs (e.g. 30–365 days).",
    nist=["AU-11"],
    terraform='resource "aws_cloudwatch_log_group" "this" {\n  name              = "{resource}"\n'
    "  retention_in_days = 90\n}",
)
def log_retention(d: dict[str, Any]) -> Iterator[Hit]:
    for g in d["log_groups"]:
        if not g["retention_days"]:
            yield Hit(
                g["arn"],
                f"Log group '{g['name']}' never expires ({g['stored_gb']} GB stored).",
                resource_name=g["name"],
                region=g["region"],
                monthly_savings=round(g["stored_gb"] * 0.03 * 0.5, 2) or None,
            )
