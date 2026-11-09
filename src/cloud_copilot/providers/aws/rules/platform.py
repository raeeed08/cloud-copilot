"""AWS platform rules (load balancers, EKS, ECR, ACM)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloud_copilot.core.registry import Hit, rule
from cloud_copilot.models import Category, Provider, Severity

AWS = Provider.AWS
WEAK_TLS_POLICIES = {
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-TLS-1-1-2017-01",
    "ELBSecurityPolicy-2015-05",
}
EKS_LOG_TYPES = {"api", "audit", "authenticator"}


@rule(
    id="ELB-001",
    title="Load balancer serves plain HTTP",
    provider=AWS,
    service="elb",
    severity=Severity.MEDIUM,
    description="An HTTP listener without a redirect to HTTPS sends traffic and cookies in clear text.",
    remediation="Change the HTTP listener default action to redirect to HTTPS (301).",
    nist=["SC-8"],
    terraform='resource "aws_lb_listener" "http" {\n  load_balancer_arn = "{resource}"\n  port = 80\n'
    '  protocol = "HTTP"\n  default_action {\n    type = "redirect"\n    redirect {\n'
    '      port        = "443"\n      protocol    = "HTTPS"\n      status_code = "HTTP_301"\n'
    "    }\n  }\n}",
)
def elb_http(d: dict[str, Any]) -> Iterator[Hit]:
    for lb in d["load_balancers"]:
        if lb["http_without_redirect"]:
            yield Hit(
                lb["arn"],
                f"Load balancer '{lb['name']}' has an HTTP listener without HTTPS redirect.",
                resource_name=lb["name"],
                region=lb["region"],
            )


@rule(
    id="ELB-002",
    title="Load balancer allows outdated TLS",
    provider=AWS,
    service="elb",
    severity=Severity.MEDIUM,
    description="TLS 1.0/1.1 policies are deprecated and fail PCI-DSS.",
    remediation="Use ELBSecurityPolicy-TLS13-1-2-2021-06 or newer.",
    nist=["SC-8", "SC-13"],
)
def elb_tls(d: dict[str, Any]) -> Iterator[Hit]:
    for lb in d["load_balancers"]:
        weak = [p for p in lb["ssl_policies"] if p in WEAK_TLS_POLICIES]
        if weak:
            yield Hit(
                lb["arn"],
                f"Load balancer '{lb['name']}' uses weak TLS policy {', '.join(weak)}.",
                resource_name=lb["name"],
                region=lb["region"],
            )


@rule(
    id="ELB-003",
    title="Load balancer access logs disabled",
    provider=AWS,
    service="elb",
    severity=Severity.LOW,
    description="Access logs record every request, which you need for forensics and debugging.",
    remediation="Enable access logs to an S3 bucket.",
    nist=["AU-2", "AU-12"],
)
def elb_logs(d: dict[str, Any]) -> Iterator[Hit]:
    for lb in d["load_balancers"]:
        if lb["type"] == "application" and not lb["access_logs"]:
            yield Hit(
                lb["arn"],
                f"Load balancer '{lb['name']}' has access logs disabled.",
                resource_name=lb["name"],
                region=lb["region"],
            )


@rule(
    id="ELB-004",
    title="ALB does not drop invalid headers",
    provider=AWS,
    service="elb",
    severity=Severity.LOW,
    description="Dropping invalid header fields mitigates HTTP request smuggling/desync attacks.",
    remediation="Set routing.http.drop_invalid_header_fields.enabled=true.",
    nist=["SI-10"],
)
def elb_headers(d: dict[str, Any]) -> Iterator[Hit]:
    for lb in d["load_balancers"]:
        if lb["type"] == "application" and not lb["drop_invalid_headers"]:
            yield Hit(
                lb["arn"],
                f"ALB '{lb['name']}' forwards invalid HTTP headers.",
                resource_name=lb["name"],
                region=lb["region"],
            )


@rule(
    id="EKS-001",
    title="EKS API endpoint open to the internet",
    provider=AWS,
    service="eks",
    severity=Severity.HIGH,
    description="A public Kubernetes API reachable from 0.0.0.0/0 is exposed to credential and 0-day attacks.",
    remediation="Disable the public endpoint or restrict publicAccessCidrs to trusted ranges.",
    nist=["SC-7", "AC-17"],
    terraform='resource "aws_eks_cluster" "{resource}" {\n  # ...\n  vpc_config {\n'
    "    endpoint_private_access = true\n    endpoint_public_access  = false\n  }\n}",
)
def eks_public(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["clusters"]:
        if c["public_endpoint"] and (not c["public_cidrs"] or "0.0.0.0/0" in c["public_cidrs"]):
            yield Hit(
                c["arn"],
                f"EKS cluster '{c['name']}' API is reachable from anywhere.",
                resource_name=c["name"],
                region=c["region"],
            )


@rule(
    id="EKS-002",
    title="EKS control plane logging incomplete",
    provider=AWS,
    service="eks",
    severity=Severity.MEDIUM,
    description="API, audit and authenticator logs are required to investigate cluster activity.",
    remediation="Enable api, audit and authenticator log types.",
    nist=["AU-2", "AU-12"],
)
def eks_logs(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["clusters"]:
        missing = sorted(EKS_LOG_TYPES - set(c["log_types"]))
        if missing:
            yield Hit(
                c["arn"],
                f"EKS cluster '{c['name']}' is missing logs: {', '.join(missing)}.",
                resource_name=c["name"],
                region=c["region"],
            )


@rule(
    id="EKS-003",
    title="EKS secrets not envelope-encrypted",
    provider=AWS,
    service="eks",
    severity=Severity.MEDIUM,
    description="KMS envelope encryption protects Kubernetes Secrets in etcd.",
    remediation="Configure encryption_config with a KMS key for 'secrets'.",
    nist=["SC-28"],
)
def eks_secrets(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["clusters"]:
        if not c["secrets_encryption"]:
            yield Hit(
                c["arn"],
                f"EKS cluster '{c['name']}' does not encrypt secrets with KMS.",
                resource_name=c["name"],
                region=c["region"],
            )


@rule(
    id="ECR-001",
    title="ECR scan on push disabled",
    provider=AWS,
    service="ecr",
    severity=Severity.MEDIUM,
    description="Images are pushed without vulnerability scanning.",
    remediation="Enable scan on push (or Inspector enhanced scanning at registry level).",
    nist=["RA-5"],
    terraform='resource "aws_ecr_repository" "{resource}" {\n  name                 = "{resource}"\n'
    '  image_tag_mutability = "IMMUTABLE"\n  image_scanning_configuration {\n'
    "    scan_on_push = true\n  }\n}",
)
def ecr_scan(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["repositories"]:
        if not r["scan_on_push"]:
            yield Hit(
                r["arn"],
                f"Repository '{r['name']}' does not scan images on push.",
                resource_name=r["name"],
                region=r["region"],
            )


@rule(
    id="ECR-002",
    title="ECR tags are mutable",
    provider=AWS,
    service="ecr",
    severity=Severity.LOW,
    description="Mutable tags let someone silently replace a deployed image (supply-chain risk).",
    remediation="Set image_tag_mutability = IMMUTABLE and deploy by digest.",
    nist=["CM-14", "SI-7"],
)
def ecr_mutable(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["repositories"]:
        if not r["immutable_tags"]:
            yield Hit(
                r["arn"],
                f"Repository '{r['name']}' allows tag overwrites.",
                resource_name=r["name"],
                region=r["region"],
            )


@rule(
    id="ECR-003",
    title="ECR repository is public",
    provider=AWS,
    service="ecr",
    severity=Severity.HIGH,
    description="A '*' repository policy lets anyone pull (or push) images.",
    remediation="Restrict the repository policy to your accounts / organization.",
    nist=["AC-3"],
)
def ecr_public(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["repositories"]:
        if r["public_policy"]:
            yield Hit(
                r["arn"], f"Repository '{r['name']}' has a public policy.", resource_name=r["name"], region=r["region"]
            )


@rule(
    id="ACM-001",
    title="Certificate expiring soon",
    provider=AWS,
    service="acm",
    severity=Severity.HIGH,
    category=Category.RELIABILITY,
    description="An expired certificate causes an outage, and users learn to click through warnings.",
    remediation="Fix DNS validation so ACM auto-renews, or re-import the renewed certificate.",
    nist=["SC-17"],
)
def acm_expiry(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["certificates"]:
        days = c["days_to_expiry"]
        if c["in_use"] and days is not None and days < 30:
            yield Hit(
                c["arn"],
                f"Certificate for {c['domain']} expires in {days} day(s).",
                resource_name=c["domain"] or c["arn"],
                region=c["region"],
                severity=Severity.CRITICAL if days < 7 else None,
            )
