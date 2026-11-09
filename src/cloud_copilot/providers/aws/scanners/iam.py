"""IAM: account summary, password policy, users, credentials, customer-managed admin policies."""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from cloud_copilot.core.registry import scanner
from cloud_copilot.models import Provider
from cloud_copilot.providers.aws.context import AwsContext, paginate, soft_call


def _days_since(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    return (datetime.now(UTC) - ts).days


def _statements(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, str):
        doc = json.loads(urllib.parse.unquote(doc))
    stmts = doc.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def grants_full_admin(doc: Any) -> bool:
    """True if a policy document allows Action '*' on Resource '*'."""
    for st in _statements(doc):
        if st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        resources = st.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


@scanner(Provider.AWS, "iam", "IAM users, credentials, password policy, root account")
def scan_iam(ctx: AwsContext) -> dict[str, Any]:
    iam = ctx.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    password_policy = soft_call(lambda: iam.get_account_password_policy()["PasswordPolicy"], None, "NoSuchEntity")

    users: list[dict[str, Any]] = []
    for u in paginate(iam, "list_users", "Users"):
        name = u["UserName"]
        login = soft_call(lambda n=name: iam.get_login_profile(UserName=n), None, "NoSuchEntity")
        keys = []
        for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {})
            keys.append(
                {
                    "id": k["AccessKeyId"],
                    "status": k["Status"],
                    "age_days": _days_since(k["CreateDate"]),
                    "last_used_days": _days_since(last.get("LastUsedDate")),
                }
            )
        users.append(
            {
                "name": name,
                "arn": u["Arn"],
                "age_days": _days_since(u["CreateDate"]),
                "console_access": login is not None,
                "password_last_used_days": _days_since(u.get("PasswordLastUsed")),
                "mfa_enabled": bool(iam.list_mfa_devices(UserName=name)["MFADevices"]),
                "access_keys": keys,
                "attached_policies": [
                    p["PolicyName"]
                    for p in paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)
                ],
                "inline_policies": paginate(iam, "list_user_policies", "PolicyNames", UserName=name),
                "groups": [g["GroupName"] for g in paginate(iam, "list_groups_for_user", "Groups", UserName=name)],
            }
        )

    admin_policies = []
    for p in paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True):
        version = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
        if grants_full_admin(version["PolicyVersion"]["Document"]):
            admin_policies.append({"name": p["PolicyName"], "arn": p["Arn"]})

    support_roles = soft_call(
        lambda: paginate(
            iam, "list_entities_for_policy", "PolicyRoles", PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess"
        ),
        [],
        "NoSuchEntity",
    )

    return {
        "root": {
            "mfa_enabled": bool(summary.get("AccountMFAEnabled", 0)),
            "access_keys_present": bool(summary.get("AccountAccessKeysPresent", 0)),
        },
        "password_policy": password_policy,
        "users": users,
        "admin_policies": admin_policies,
        "support_role_exists": bool(support_roles),
    }


@scanner(Provider.AWS, "accessanalyzer", "IAM Access Analyzer per region")
def scan_access_analyzer(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        analyzers = ctx.client("accessanalyzer", r).list_analyzers(type="ACCOUNT").get("analyzers", [])
        return [{"region": r, "enabled": any(a.get("status") == "ACTIVE" for a in analyzers)}]

    return {"regions": ctx.for_each_region(region, "accessanalyzer")}
