"""Remaining AWS services. Each scanner is small: read + normalise, no decisions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from cloud_copilot.core.registry import scanner
from cloud_copilot.models import Provider
from cloud_copilot.providers.aws.context import AwsContext, paginate, soft_call


def _days(ts: datetime | None) -> int | None:
    return (datetime.now(UTC) - ts).days if ts else None


def _policy_is_public(policy: str | dict[str, Any] | None) -> bool:
    if not policy:
        return False
    doc = json.loads(policy) if isinstance(policy, str) else policy
    stmts = doc.get("Statement", [])
    for st in stmts if isinstance(stmts, list) else [stmts]:
        p = st.get("Principal")
        star = p == "*" or (isinstance(p, dict) and p.get("AWS") in ("*", ["*"]))
        if st.get("Effect") == "Allow" and star and not st.get("Condition"):
            return True
    return False


# ----------------------------------------------------------------------------- CloudTrail
@scanner(Provider.AWS, "cloudtrail", "CloudTrail trails (all regions)")
def scan_cloudtrail(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        ct = ctx.client("cloudtrail", r)
        out = []
        for t in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
            status = ct.get_trail_status(Name=t["TrailARN"])
            selectors = soft_call(
                lambda t=t: ct.get_event_selectors(TrailName=t["TrailARN"]), {}, "TrailNotFoundException"
            )
            mgmt = any(s.get("IncludeManagementEvents") for s in selectors.get("EventSelectors", [])) or bool(
                selectors.get("AdvancedEventSelectors")
            )
            out.append(
                {
                    "name": t["Name"],
                    "arn": t["TrailARN"],
                    "region": r,
                    "multi_region": t.get("IsMultiRegionTrail", False),
                    "log_validation": t.get("LogFileValidationEnabled", False),
                    "is_logging": status.get("IsLogging", False),
                    "kms_key": t.get("KmsKeyId"),
                    "cloudwatch_logs": bool(t.get("CloudWatchLogsLogGroupArn")),
                    "management_events": mgmt,
                    "s3_bucket": t.get("S3BucketName"),
                }
            )
        return out

    return {"trails": ctx.for_each_region(region, "cloudtrail")}


# ----------------------------------------------------------------------------- RDS
@scanner(Provider.AWS, "rds", "RDS instances and manual snapshots (all regions)")
def scan_rds(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        rds = ctx.client("rds", r)
        instances = [
            {
                "id": i["DBInstanceIdentifier"],
                "region": r,
                "engine": i.get("Engine"),
                "engine_version": i.get("EngineVersion"),
                "public": i.get("PubliclyAccessible", False),
                "encrypted": i.get("StorageEncrypted", False),
                "backup_retention_days": i.get("BackupRetentionPeriod", 0),
                "multi_az": i.get("MultiAZ", False),
                "deletion_protection": i.get("DeletionProtection", False),
                "auto_minor_upgrade": i.get("AutoMinorVersionUpgrade", False),
                "iam_auth": i.get("IAMDatabaseAuthenticationEnabled", False),
                "security_groups": [g["VpcSecurityGroupId"] for g in i.get("VpcSecurityGroups", [])],
            }
            for i in paginate(rds, "describe_db_instances", "DBInstances")
        ]
        snapshots = []
        for s in paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
            attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=s["DBSnapshotIdentifier"])
            public = any(
                a["AttributeName"] == "restore" and "all" in a.get("AttributeValues", [])
                for a in attrs["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
            )
            snapshots.append(
                {"id": s["DBSnapshotIdentifier"], "region": r, "public": public, "encrypted": s.get("Encrypted", False)}
            )
        return [{"instances": instances, "snapshots": snapshots}]

    parts = ctx.for_each_region(region, "rds")
    return {
        "instances": [i for p in parts for i in p["instances"]],
        "snapshots": [s for p in parts for s in p["snapshots"]],
    }


# ----------------------------------------------------------------------------- KMS
@scanner(Provider.AWS, "kms", "Customer-managed KMS keys (all regions)")
def scan_kms(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        kms = ctx.client("kms", r)
        out = []
        for k in paginate(kms, "list_keys", "Keys"):
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                continue
            symmetric = meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"
            rotation = kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"] if symmetric else None
            out.append(
                {
                    "id": k["KeyId"],
                    "arn": meta["Arn"],
                    "region": r,
                    "symmetric": symmetric,
                    "rotation_enabled": rotation,
                }
            )
        return out

    return {"keys": ctx.for_each_region(region, "kms")}


# ----------------------------------------------------------------------------- Lambda
@scanner(Provider.AWS, "lambda", "Lambda functions: runtimes, URLs, resource policies")
def scan_lambda(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        lam = ctx.client("lambda", r)
        out = []
        for f in paginate(lam, "list_functions", "Functions"):
            name = f["FunctionName"]
            urls = soft_call(
                lambda n=name: lam.list_function_url_configs(FunctionName=n)["FunctionUrlConfigs"],
                [],
                "ResourceNotFoundException",
            )
            policy = soft_call(
                lambda n=name: lam.get_policy(FunctionName=n)["Policy"], None, "ResourceNotFoundException"
            )
            out.append(
                {
                    "name": name,
                    "arn": f["FunctionArn"],
                    "region": r,
                    "runtime": f.get("Runtime"),
                    "url_auth_none": any(u.get("AuthType") == "NONE" for u in urls),
                    "public_policy": _policy_is_public(policy),
                    "env_var_names": sorted((f.get("Environment") or {}).get("Variables", {}).keys()),
                }
            )
        return out

    return {"functions": ctx.for_each_region(region, "lambda")}


# ----------------------------------------------------------------------------- Detective controls
@scanner(Provider.AWS, "detective", "GuardDuty, AWS Config and Security Hub enablement per region")
def scan_detective(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        gd = ctx.client("guardduty", r).list_detectors().get("DetectorIds", [])
        cfg = ctx.client("config", r)
        recorders = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        hub = soft_call(
            lambda: ctx.client("securityhub", r).describe_hub(),
            None,
            "InvalidAccessException",
            "ResourceNotFoundException",
        )
        return [
            {
                "region": r,
                "guardduty": bool(gd),
                "config_recording": any(x.get("recording") for x in recorders),
                "securityhub": hub is not None,
            }
        ]

    return {"regions": ctx.for_each_region(region, "detective")}


# ----------------------------------------------------------------------------- ELBv2
@scanner(Provider.AWS, "elb", "Application/Network load balancers")
def scan_elb(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        elb = ctx.client("elbv2", r)
        out = []
        for lb in paginate(elb, "describe_load_balancers", "LoadBalancers"):
            arn = lb["LoadBalancerArn"]
            attrs = {
                a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]
            }
            listeners = paginate(elb, "describe_listeners", "Listeners", LoadBalancerArn=arn)
            plain_http = [
                listener
                for listener in listeners
                if listener.get("Protocol") == "HTTP"
                and not any(a.get("Type") == "redirect" for a in listener.get("DefaultActions", []))
            ]
            out.append(
                {
                    "name": lb["LoadBalancerName"],
                    "arn": arn,
                    "region": r,
                    "type": lb.get("Type"),
                    "internet_facing": lb.get("Scheme") == "internet-facing",
                    "http_without_redirect": len(plain_http),
                    "ssl_policies": sorted({x["SslPolicy"] for x in listeners if x.get("SslPolicy")}),
                    "access_logs": attrs.get("access_logs.s3.enabled") == "true",
                    "deletion_protection": attrs.get("deletion_protection.enabled") == "true",
                    "drop_invalid_headers": attrs.get("routing.http.drop_invalid_header_fields.enabled") == "true",
                }
            )
        return out

    return {"load_balancers": ctx.for_each_region(region, "elb")}


# ----------------------------------------------------------------------------- Containers
@scanner(Provider.AWS, "eks", "EKS clusters")
def scan_eks(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        eks = ctx.client("eks", r)
        out = []
        for name in paginate(eks, "list_clusters", "clusters"):
            c = eks.describe_cluster(name=name)["cluster"]
            vpc = c.get("resourcesVpcConfig", {})
            enabled_logs = [
                t
                for lg in c.get("logging", {}).get("clusterLogging", [])
                if lg.get("enabled")
                for t in lg.get("types", [])
            ]
            out.append(
                {
                    "name": name,
                    "arn": c["arn"],
                    "region": r,
                    "version": c.get("version"),
                    "public_endpoint": vpc.get("endpointPublicAccess", True),
                    "public_cidrs": vpc.get("publicAccessCidrs", []),
                    "log_types": enabled_logs,
                    "secrets_encryption": bool(c.get("encryptionConfig")),
                }
            )
        return out

    return {"clusters": ctx.for_each_region(region, "eks")}


@scanner(Provider.AWS, "ecr", "ECR repositories")
def scan_ecr(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        ecr = ctx.client("ecr", r)
        out = []
        for repo in paginate(ecr, "describe_repositories", "repositories"):
            name = repo["repositoryName"]
            policy = soft_call(
                lambda n=name: ecr.get_repository_policy(repositoryName=n)["policyText"],
                None,
                "RepositoryPolicyNotFoundException",
            )
            out.append(
                {
                    "name": name,
                    "arn": repo["repositoryArn"],
                    "region": r,
                    "scan_on_push": repo.get("imageScanningConfiguration", {}).get("scanOnPush", False),
                    "immutable_tags": repo.get("imageTagMutability") == "IMMUTABLE",
                    "public_policy": _policy_is_public(policy),
                }
            )
        return out

    return {"repositories": ctx.for_each_region(region, "ecr")}


# ----------------------------------------------------------------------------- Data stores
@scanner(Provider.AWS, "dynamodb", "DynamoDB tables")
def scan_dynamodb(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        ddb = ctx.client("dynamodb", r)
        out = []
        for name in paginate(ddb, "list_tables", "TableNames"):
            backups = ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
            pitr = backups.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
            table = ddb.describe_table(TableName=name)["Table"]
            out.append(
                {
                    "name": name,
                    "arn": table["TableArn"],
                    "region": r,
                    "pitr": pitr == "ENABLED",
                    "deletion_protection": table.get("DeletionProtectionEnabled", False),
                    "kms": (table.get("SSEDescription") or {}).get("SSEType") == "KMS",
                }
            )
        return out

    return {"tables": ctx.for_each_region(region, "dynamodb")}


@scanner(Provider.AWS, "secretsmanager", "Secrets Manager secrets")
def scan_secrets(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        sm = ctx.client("secretsmanager", r)
        return [
            {
                "name": s["Name"],
                "arn": s["ARN"],
                "region": r,
                "rotation_enabled": s.get("RotationEnabled", False),
                "last_accessed_days": _days(s.get("LastAccessedDate")),
            }
            for s in paginate(sm, "list_secrets", "SecretList")
        ]

    return {"secrets": ctx.for_each_region(region, "secretsmanager")}


@scanner(Provider.AWS, "messaging", "SQS queues and SNS topics")
def scan_messaging(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        sqs, sns = ctx.client("sqs", r), ctx.client("sns", r)
        out: list[dict[str, Any]] = []
        for url in sqs.list_queues().get("QueueUrls", []):
            a = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
            out.append(
                {
                    "kind": "sqs",
                    "name": url.rsplit("/", 1)[-1],
                    "arn": a.get("QueueArn", url),
                    "region": r,
                    "encrypted": a.get("SqsManagedSseEnabled") == "true" or bool(a.get("KmsMasterKeyId")),
                    "public_policy": _policy_is_public(a.get("Policy")),
                }
            )
        for t in paginate(sns, "list_topics", "Topics"):
            a = sns.get_topic_attributes(TopicArn=t["TopicArn"])["Attributes"]
            out.append(
                {
                    "kind": "sns",
                    "name": t["TopicArn"].rsplit(":", 1)[-1],
                    "arn": t["TopicArn"],
                    "region": r,
                    "encrypted": bool(a.get("KmsMasterKeyId")),
                    "public_policy": _policy_is_public(a.get("Policy")),
                }
            )
        return out

    return {"resources": ctx.for_each_region(region, "messaging")}


# ----------------------------------------------------------------------------- Logs & certs
@scanner(Provider.AWS, "logs", "CloudWatch log groups")
def scan_logs(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        logs = ctx.client("logs", r)
        return [
            {
                "name": g["logGroupName"],
                "arn": g.get("arn", g["logGroupName"]),
                "region": r,
                "retention_days": g.get("retentionInDays"),
                "stored_gb": round(g.get("storedBytes", 0) / 1e9, 2),
                "kms": bool(g.get("kmsKeyId")),
            }
            for g in paginate(logs, "describe_log_groups", "logGroups")
        ]

    return {"log_groups": ctx.for_each_region(region, "logs")}


@scanner(Provider.AWS, "acm", "ACM certificates")
def scan_acm(ctx: AwsContext) -> dict[str, Any]:
    def region(r: str) -> list[dict[str, Any]]:
        acm = ctx.client("acm", r)
        out = []
        for c in paginate(acm, "list_certificates", "CertificateSummaryList"):
            not_after = c.get("NotAfter")
            out.append(
                {
                    "arn": c["CertificateArn"],
                    "domain": c.get("DomainName"),
                    "region": r,
                    "status": c.get("Status"),
                    "in_use": c.get("InUse", False),
                    "days_to_expiry": (not_after - datetime.now(UTC)).days if not_after else None,
                }
            )
        return out

    return {"certificates": ctx.for_each_region(region, "acm")}
