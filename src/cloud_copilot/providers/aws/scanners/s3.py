"""S3: account & bucket public-access block, policies, ACLs, encryption, versioning, logging, lifecycle."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from cloud_copilot.core.registry import scanner
from cloud_copilot.models import Provider
from cloud_copilot.providers.aws.context import AwsContext, error_code, soft_call

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def analyse_policy(policy_json: str | None) -> dict[str, bool]:
    """Return whether a bucket policy is public (Allow to '*' without conditions) and enforces TLS."""
    if not policy_json:
        return {"public": False, "enforces_tls": False}
    doc = json.loads(policy_json)
    public = enforces_tls = False
    for st in _as_list(doc.get("Statement", [])):
        principal = st.get("Principal")
        is_star = principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS", [])))
        if st.get("Effect") == "Allow" and is_star and not st.get("Condition"):
            public = True
        cond = st.get("Condition", {})
        secure = cond.get("Bool", {}).get("aws:SecureTransport")
        if st.get("Effect") == "Deny" and str(secure).lower() == "false":
            enforces_tls = True
    return {"public": public, "enforces_tls": enforces_tls}


def _pab(get: Any) -> dict[str, bool] | None:
    cfg = soft_call(get, None, "NoSuchPublicAccessBlockConfiguration")
    return dict(cfg["PublicAccessBlockConfiguration"]) if cfg else None


@scanner(Provider.AWS, "s3", "S3 buckets and account public access block")
def scan_s3(ctx: AwsContext) -> dict[str, Any]:
    s3 = ctx.client("s3")
    s3control = ctx.client("s3control")
    account_pab = _pab(lambda: s3control.get_public_access_block(AccountId=ctx.account_id))

    buckets: list[dict[str, Any]] = []
    errors: list[str] = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            c = ctx.client("s3", region)
            policy = soft_call(lambda c=c, n=name: c.get_bucket_policy(Bucket=n)["Policy"], None, "NoSuchBucketPolicy")
            acl = c.get_bucket_acl(Bucket=name)
            acl_public = any(g.get("Grantee", {}).get("URI") in (ALL_USERS, AUTH_USERS) for g in acl.get("Grants", []))
            enc = soft_call(
                lambda c=c, n=name: c.get_bucket_encryption(Bucket=n)["ServerSideEncryptionConfiguration"],
                None,
                "ServerSideEncryptionConfigurationNotFoundError",
            )
            algo = None
            if enc:
                algo = enc["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            versioning = c.get_bucket_versioning(Bucket=name)
            lifecycle = soft_call(
                lambda c=c, n=name: c.get_bucket_lifecycle_configuration(Bucket=n)["Rules"],
                [],
                "NoSuchLifecycleConfiguration",
            )
            buckets.append(
                {
                    "name": name,
                    "region": region,
                    "public_access_block": _pab(lambda c=c, n=name: c.get_public_access_block(Bucket=n)),
                    "policy": analyse_policy(policy),
                    "acl_public": acl_public,
                    "encryption": algo,
                    "versioning": versioning.get("Status") == "Enabled",
                    "mfa_delete": versioning.get("MFADelete") == "Enabled",
                    "logging": "LoggingEnabled" in c.get_bucket_logging(Bucket=name),
                    "lifecycle_rules": len(lifecycle),
                }
            )
        except ClientError as exc:  # one unreadable bucket must not hide the others
            errors.append(f"s3://{name}: {error_code(exc)}")
    ctx.warnings.extend(errors)
    return {"account_public_access_block": account_pab, "buckets": buckets}


def fully_blocked(pab: dict[str, bool] | None) -> bool:
    return bool(pab) and all(
        pab.get(k, False)  # type: ignore[union-attr]
        for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    )
