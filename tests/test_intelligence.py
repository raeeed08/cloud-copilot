"""Attack-path correlation, remediation strategy and console deep links."""

from __future__ import annotations

from typing import Any

import pytest

from cloud_copilot.config import Settings
from cloud_copilot.core.correlation import correlate
from cloud_copilot.core.engine import ScanEngine
from cloud_copilot.core.strategy import build_plan
from cloud_copilot.models import Category, Finding, Provider, Severity
from cloud_copilot.providers import demo
from cloud_copilot.providers.console import console_url


@pytest.fixture(scope="module")
def demo_scan() -> Any:
    return ScanEngine(Settings(_env_file=None, demo_mode=True)).run()


def test_demo_attack_paths(demo_scan: Any) -> None:
    paths = correlate(demo_scan.raw, demo_scan.findings)
    titles = " | ".join(p["title"] for p in paths)
    assert "bastion → cloud credential theft" in titles
    assert "Database reporting-pg exposed" in titles
    assert "admin user 'bob.dev'" in titles
    assert "Detection blind spot" in titles
    assert "vm-jumpbox" in titles and titles.count("vm-jumpbox") == 1  # aggregated per VM
    assert [p["severity"] for p in paths] == sorted((p["severity"] for p in paths), key=lambda s: Severity(s).rank)
    ids = {f.id for f in demo_scan.findings}
    for p in paths:
        assert p["finding_ids"] and set(p["finding_ids"]) <= ids
        assert p["break_first"] and p["steps"]
        assert all(st["technique"] is None or st["technique"].startswith("T1") for st in p["steps"])


def test_instance_path_requires_reachability(demo_scan: Any) -> None:
    raw = {k: dict(v) for k, v in demo_scan.raw.items()}
    aws_key = next(k for k in raw if k.startswith("aws:"))
    ec2 = demo.data(Provider.AWS, "ec2")
    for i in ec2["instances"]:
        i["public_ip"] = None
    raw[aws_key]["ec2"] = ec2
    titles = [p["title"] for p in correlate(raw, demo_scan.findings)]
    assert not any("Internet-exposed server" in t for t in titles)


def test_suppressed_findings_do_not_build_paths(demo_scan: Any) -> None:
    findings = [f.model_copy(update={"suppressed": f.rule_id == "CT-001"}) for f in demo_scan.findings]
    titles = [p["title"] for p in correlate(demo_scan.raw, findings)]
    assert not any("blind spot" in t for t in titles)


def test_plan_structure(demo_scan: Any) -> None:
    paths = correlate(demo_scan.raw, demo_scan.findings)
    plan = build_plan(demo_scan.findings, paths, demo_scan.evaluated_rules)
    phases = {p["id"]: p for p in plan["phases"]}
    assert next(iter(phases)) == "now"
    now_rules = {a["rule_id"] for a in phases["now"]["actions"]}
    assert {p["break_rule"] for p in paths} <= now_rules  # every attack path is broken in phase 1
    assert phases["now"]["actions"][0]["breaks"]  # chain-breaking actions come first
    assert all(a["category"] == "cost" for a in phases["cost"]["actions"])
    assert all(f.category is not Category.COST for f in demo_scan.findings if f.rule_id in now_rules)
    # fixing every action restores the full score
    total_gain = sum(p["score_gain"] for p in plan["phases"])
    assert abs(plan["current_score"] + total_gain - 100) <= 1.5
    assert plan["target_score"] == 100
    assert plan["guardrails"][-1]["title"].startswith("Scan continuously")
    assert any("S3" in g["title"] for g in plan["guardrails"])
    action = phases["now"]["actions"][0]
    assert action["resources"][0]["console_url"].startswith("https://")


def test_effort_and_resource_grouping(demo_scan: Any) -> None:
    plan = build_plan(demo_scan.findings, [], demo_scan.evaluated_rules)
    actions = {a["rule_id"]: a for p in plan["phases"] for a in p["actions"]}
    assert actions["EC2-001"]["effort"] == "M" and len(actions["EC2-001"]["resources"]) == 3
    assert actions["RDS-002"]["effort"] == "L"
    assert actions["COST-001"]["monthly_savings"] > 0


def _finding(provider: Provider, service: str, rule: str, rid: str, name: str, region: str | None) -> Finding:
    return Finding(
        id="x",
        rule_id=rule,
        title="t",
        provider=provider,
        service=service,
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource_id=rid,
        resource_name=name,
        region=region,
        message="m",
        remediation="r",
    )


@pytest.mark.parametrize(
    ("service", "rule", "rid", "name", "expected"),
    [
        ("ec2", "EC2-001", "sg-123", "web", "#SecurityGroup:groupId=sg-123"),
        ("ec2", "EC2-005", "i-abc", "bastion", "#InstanceDetails:instanceId=i-abc"),
        ("s3", "S3-002", "arn:aws:s3:::my-bucket", "my-bucket", "s3/buckets/my-bucket"),
        ("iam", "IAM-004", "arn:aws:iam::1:user/bob", "bob", "/users/details/bob"),
        ("iam", "IAM-001", "root", "root", "#/security_credentials"),
        ("rds", "RDS-001", "db1", "db1", "#database:id=db1"),
        ("lambda", "LAMBDA-002", "arn:fn", "fn", "#/functions/fn"),
    ],
)
def test_aws_console_links(service: str, rule: str, rid: str, name: str, expected: str) -> None:
    url = console_url(_finding(Provider.AWS, service, rule, rid, name, "eu-west-1"))
    assert url and url.startswith("https://") and expected in url


def test_azure_portal_link() -> None:
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st"
    url = console_url(_finding(Provider.AZURE, "storage", "AZ-STOR-001", rid, "st", "westeurope"))
    assert url == f"https://portal.azure.com/#@/resource{rid}/overview"
