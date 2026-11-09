"""AWS identity rules (IAM, root account, Access Analyzer)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloud_copilot.core.registry import Hit, rule
from cloud_copilot.models import Provider, Severity

AWS = Provider.AWS
IAM_REF = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"


@rule(
    id="IAM-001",
    title="Root account has no MFA",
    provider=AWS,
    service="iam",
    severity=Severity.CRITICAL,
    description="The root user has unrestricted access to the account. Without MFA, a leaked password is a "
    "full account takeover.",
    remediation="Enable a hardware or virtual MFA device on the root user, then lock the credentials away.",
    cis=["1.5"],
    nist=["IA-2(1)"],
    references=[IAM_REF],
)
def root_mfa(d: dict[str, Any]) -> Iterator[Hit]:
    if not d["root"]["mfa_enabled"]:
        yield Hit("root", "The root user does not have MFA enabled.", resource_name="root")


@rule(
    id="IAM-002",
    title="Root account has access keys",
    provider=AWS,
    service="iam",
    severity=Severity.CRITICAL,
    description="Programmatic root credentials cannot be scoped down and are a prime target for attackers.",
    remediation="Delete the root access keys and use IAM roles for automation.",
    cis=["1.4"],
    nist=["AC-6(2)", "IA-4"],
)
def root_keys(d: dict[str, Any]) -> Iterator[Hit]:
    if d["root"]["access_keys_present"]:
        yield Hit("root", "The root user has active access keys.", resource_name="root")


@rule(
    id="IAM-003",
    title="Weak or missing password policy",
    provider=AWS,
    service="iam",
    severity=Severity.MEDIUM,
    description="Without a strong password policy, IAM users can choose short or reused passwords.",
    remediation="Require at least 14 characters and prevent reuse of the last 24 passwords.",
    cis=["1.8", "1.9"],
    nist=["IA-5(1)"],
    terraform='resource "aws_iam_account_password_policy" "strict" {\n'
    "  minimum_password_length        = 14\n  password_reuse_prevention      = 24\n"
    "  require_symbols                = true\n  require_numbers                = true\n"
    "  require_uppercase_characters   = true\n  require_lowercase_characters   = true\n"
    "  allow_users_to_change_password = true\n}",
)
def password_policy(d: dict[str, Any]) -> Iterator[Hit]:
    p = d.get("password_policy")
    if not p:
        yield Hit("account-password-policy", "No IAM password policy is configured.", resource_name="password policy")
        return
    problems = []
    if p.get("MinimumPasswordLength", 0) < 14:
        problems.append(f"minimum length {p.get('MinimumPasswordLength', 0)} < 14")
    if p.get("PasswordReusePrevention", 0) < 24:
        problems.append("password reuse prevention < 24")
    if problems:
        yield Hit(
            "account-password-policy",
            "Password policy is weak: " + ", ".join(problems) + ".",
            resource_name="password policy",
            details={"problems": problems},
        )


@rule(
    id="IAM-004",
    title="Console user without MFA",
    provider=AWS,
    service="iam",
    severity=Severity.HIGH,
    description="Users who can sign in to the console without MFA are vulnerable to phishing and credential stuffing.",
    remediation="Enforce MFA for every console user, ideally via an IAM policy that denies actions without "
    "aws:MultiFactorAuthPresent, or move humans to IAM Identity Center.",
    cis=["1.10"],
    nist=["IA-2(1)"],
)
def console_mfa(d: dict[str, Any]) -> Iterator[Hit]:
    for u in d["users"]:
        if u["console_access"] and not u["mfa_enabled"]:
            yield Hit(u["arn"], f"User '{u['name']}' can sign in to the console without MFA.", resource_name=u["name"])


@rule(
    id="IAM-005",
    title="Access key not rotated in 90 days",
    provider=AWS,
    service="iam",
    severity=Severity.MEDIUM,
    description="Long-lived static keys increase the blast radius of an undetected leak.",
    remediation="Rotate keys (create new, deploy, deactivate old, delete) or replace them with role-based "
    "short-lived credentials.",
    cis=["1.14"],
    nist=["IA-5(1)", "AC-2(3)"],
)
def stale_keys(d: dict[str, Any]) -> Iterator[Hit]:
    for u in d["users"]:
        for k in u["access_keys"]:
            if k["status"] == "Active" and (k["age_days"] or 0) > 90:
                yield Hit(
                    f"{u['arn']}/{k['id']}",
                    f"Access key {k['id'][:8]}… of '{u['name']}' is {k['age_days']} days old.",
                    resource_name=u["name"],
                    details={"age_days": k["age_days"]},
                )


@rule(
    id="IAM-006",
    title="Unused credentials (45+ days)",
    provider=AWS,
    service="iam",
    severity=Severity.MEDIUM,
    description="Credentials nobody uses are pure risk: they can be stolen and nobody notices their use.",
    remediation="Disable passwords and deactivate keys unused for 45 days.",
    cis=["1.12"],
    nist=["AC-2(3)"],
)
def unused_credentials(d: dict[str, Any]) -> Iterator[Hit]:
    for u in d["users"]:
        last_pw = u.get("password_last_used_days")
        if u["console_access"] and ((last_pw is None and (u.get("age_days") or 0) > 45) or (last_pw or 0) > 45):
            yield Hit(
                f"{u['arn']}/password",
                f"Console password of '{u['name']}' unused for 45+ days.",
                resource_name=u["name"],
            )
        for k in u["access_keys"]:
            used = k.get("last_used_days")
            if k["status"] == "Active" and ((used is None and (k["age_days"] or 0) > 45) or (used or 0) > 45):
                yield Hit(
                    f"{u['arn']}/{k['id']}",
                    f"Access key {k['id'][:8]}… of '{u['name']}' unused for 45+ days.",
                    resource_name=u["name"],
                )


@rule(
    id="IAM-007",
    title="User has more than one active access key",
    provider=AWS,
    service="iam",
    severity=Severity.LOW,
    description="Two active keys usually means a rotation that never finished.",
    remediation="Keep a single active key per user.",
    cis=["1.13"],
    nist=["IA-5"],
)
def multiple_keys(d: dict[str, Any]) -> Iterator[Hit]:
    for u in d["users"]:
        if sum(k["status"] == "Active" for k in u["access_keys"]) > 1:
            yield Hit(u["arn"], f"User '{u['name']}' has several active access keys.", resource_name=u["name"])


@rule(
    id="IAM-008",
    title="Policies attached directly to users",
    provider=AWS,
    service="iam",
    severity=Severity.LOW,
    description="Permissions granted per user are hard to audit and revoke. Use groups or roles.",
    remediation="Move managed and inline policies to IAM groups (or Identity Center permission sets).",
    cis=["1.15"],
    nist=["AC-2", "AC-6"],
    terraform='resource "aws_iam_group" "team" {\n  name = "team"\n}\n\n'
    'resource "aws_iam_user_group_membership" "this" {\n  user   = "{resource}"\n'
    "  groups = [aws_iam_group.team.name]\n}",
)
def direct_policies(d: dict[str, Any]) -> Iterator[Hit]:
    for u in d["users"]:
        attached = u["attached_policies"] + u.get("inline_policies", [])
        if attached:
            yield Hit(
                u["arn"],
                f"User '{u['name']}' has {len(attached)} policy(ies) attached directly: {', '.join(attached[:5])}.",
                resource_name=u["name"],
                details={"policies": attached},
            )


@rule(
    id="IAM-009",
    title="Full administrator privileges granted",
    provider=AWS,
    service="iam",
    severity=Severity.HIGH,
    description="Policies allowing '*' on '*' break least privilege. A compromised principal owns the account.",
    remediation="Replace with job-function or scoped policies; keep break-glass admin in a role with MFA.",
    cis=["1.16"],
    nist=["AC-6"],
)
def full_admin(d: dict[str, Any]) -> Iterator[Hit]:
    for p in d.get("admin_policies", []):
        yield Hit(
            p["arn"], f"Customer-managed policy '{p['name']}' grants Action:* on Resource:*.", resource_name=p["name"]
        )
    for u in d["users"]:
        if "AdministratorAccess" in u["attached_policies"]:
            yield Hit(
                f"{u['arn']}/AdministratorAccess",
                f"User '{u['name']}' has AdministratorAccess attached directly.",
                resource_name=u["name"],
            )


@rule(
    id="IAM-010",
    title="No AWS Support role",
    provider=AWS,
    service="iam",
    severity=Severity.LOW,
    description="A dedicated role for AWS Support avoids handing out broader access during incidents.",
    remediation="Create a role with the AWSSupportAccess managed policy.",
    cis=["1.17"],
    nist=["IR-7"],
)
def support_role(d: dict[str, Any]) -> Iterator[Hit]:
    if not d.get("support_role_exists", True):
        yield Hit("support-role", "No IAM role has the AWSSupportAccess policy.", resource_name="support role")


@rule(
    id="IAM-011",
    title="IAM Access Analyzer disabled",
    provider=AWS,
    service="accessanalyzer",
    severity=Severity.LOW,
    description="Access Analyzer continuously finds resources shared outside the account.",
    remediation="Create an account analyzer in every active region.",
    cis=["1.20"],
    nist=["AC-3", "CA-7"],
    terraform='resource "aws_accessanalyzer_analyzer" "account" {\n  analyzer_name = "account"\n'
    '  type          = "ACCOUNT"\n}',
)
def access_analyzer(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["regions"]:
        if not r["enabled"]:
            yield Hit(
                f"accessanalyzer/{r['region']}",
                f"No active Access Analyzer in {r['region']}.",
                resource_name="Access Analyzer",
                region=r["region"],
            )
