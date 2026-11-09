"""Deep links from a finding to the resource in the AWS console or the Azure portal."""

from __future__ import annotations

from urllib.parse import quote

from cloud_copilot.models import Finding, Provider

GLOBAL = "us-east-1"


def _aws(service_path: str, region: str | None, fragment: str = "") -> str:
    r = region or GLOBAL
    return f"https://{r}.console.aws.amazon.com/{service_path}?region={r}{fragment}"


def aws_url(f: Finding) -> str | None:
    rid, name, region = f.resource_id, f.resource_name, f.region
    rule = f.rule_id
    if f.service == "iam":
        if rule in ("IAM-001", "IAM-002"):
            return "https://us-east-1.console.aws.amazon.com/iam/home#/security_credentials"
        if rule in ("IAM-003", "IAM-010"):
            return "https://us-east-1.console.aws.amazon.com/iam/home#/account_settings"
        if ":policy/" in rid:
            return f"https://us-east-1.console.aws.amazon.com/iam/home#/policies/details/{quote(rid, safe='')}"
        return f"https://us-east-1.console.aws.amazon.com/iam/home#/users/details/{quote(name)}?section=security_credentials"
    if f.service == "accessanalyzer":
        return _aws("access-analyzer/home", region)
    if f.service == "s3":
        if rule == "S3-001":
            return "https://s3.console.aws.amazon.com/s3/settings"
        return f"https://s3.console.aws.amazon.com/s3/buckets/{quote(name)}?region={region or GLOBAL}&tab=permissions"
    if f.service == "ec2":
        if rid.startswith("sg-"):
            return _aws("ec2/home", region, f"#SecurityGroup:groupId={rid}")
        if rid.startswith("i-"):
            return _aws("ec2/home", region, f"#InstanceDetails:instanceId={rid}")
        if rid.startswith("vol-"):
            return _aws("ec2/home", region, f"#VolumeDetails:volumeId={rid}")
        if rid.startswith("snap-"):
            return _aws("ec2/home", region, f"#SnapshotDetails:snapshotId={rid}")
        if rid.startswith("eipalloc-"):
            return _aws("ec2/home", region, f"#ElasticIpDetails:AllocationId={rid}")
        if rid.startswith("vpc-"):
            return _aws("vpcconsole/home", region, f"#VpcDetails:VpcId={rid}")
        if rid.startswith("ebs-default-encryption"):
            return _aws("ec2/home", region, "#Settings:tab=ebsEncryption")
        return _aws("ec2/home", region)
    if f.service == "cloudtrail":
        return _aws("cloudtrailv2/home", region, "#/trails")
    if f.service == "rds":
        frag = "#db-snapshot:id=" if rule == "RDS-003" else "#database:id="
        return _aws("rds/home", region, f"{frag}{quote(name)}")
    if f.service == "kms":
        return _aws("kms/home", region, f"#/kms/keys/{quote(name)}")
    if f.service == "lambda":
        return _aws("lambda/home", region, f"#/functions/{quote(name)}")
    if f.service == "detective":
        page = {"GD-001": "guardduty/home", "CFG-001": "config/home", "SH-001": "securityhub/home"}.get(rule)
        return _aws(page or "securityhub/home", region)
    if f.service == "elb":
        return _aws("ec2/home", region, f"#LoadBalancer:loadBalancerArn={quote(rid, safe='')}")
    if f.service == "eks":
        return _aws("eks/home", region, f"#/clusters/{quote(name)}")
    if f.service == "ecr":
        return _aws("ecr/repositories", region)
    if f.service == "dynamodb":
        return _aws("dynamodbv2/home", region, f"#table?name={quote(name)}")
    if f.service == "secretsmanager":
        return _aws("secretsmanager/secret", region, f"&name={quote(name)}")
    if f.service == "messaging":
        if ":sqs:" in rid:
            return _aws("sqs/v3/home", region, "#/queues")
        return _aws("sns/v3/home", region, f"#/topic/{quote(rid, safe='')}")
    if f.service == "logs":
        return _aws("cloudwatch/home", region, f"#logsV2:log-groups/log-group/{quote(quote(name, safe=''), safe='')}")
    if f.service == "acm":
        return _aws("acm/home", region, "#/certificates/list")
    return None


def azure_url(f: Finding) -> str | None:
    rid = f.resource_id
    if f.rule_id.startswith("AZ-DEF"):
        return "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings"
    if f.rule_id == "AZ-MON-002":
        return "https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/alertsV2"
    if rid.startswith("/subscriptions/"):
        base = rid.split("/activity-alerts")[0]
        return f"https://portal.azure.com/#@/resource{base}/overview"
    return None


def console_url(f: Finding) -> str | None:
    try:
        return aws_url(f) if f.provider is Provider.AWS else azure_url(f)
    except Exception:  # a broken link must never break a scan
        return None
