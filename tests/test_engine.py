"""Engine behaviour: fault isolation, provider skipping, scoring, suppression."""

from typing import Any

import pytest

from cloud_copilot.config import Settings
from cloud_copilot.core.engine import ScanEngine, score
from cloud_copilot.core.registry import RULES, SCANNERS, Scanner
from cloud_copilot.models import Provider, ScanStatus, ServiceStatus
from cloud_copilot.providers.aws.context import NotConfiguredError


def test_demo_scan(settings: Settings) -> None:
    r = ScanEngine(settings).run()
    assert r.status is ScanStatus.SUCCEEDED
    assert 0 < (r.score or 0) < 100
    assert len(r.findings) > 50 and r.costs and r.accounts
    sev_ranks = [f.severity.rank for f in r.findings]
    assert sev_ranks == sorted(sev_ranks)


def test_failing_scanner_is_isolated(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from cloud_copilot.providers import demo

    original = demo.data

    def flaky(provider: Provider, service: str) -> dict[str, Any]:
        if service == "s3":
            raise RuntimeError("boom")
        return original(provider, service)

    monkeypatch.setattr(demo, "data", flaky)
    r = ScanEngine(settings).run()
    s3 = next(s for s in r.services if s.service == "s3")
    assert s3.status is ServiceStatus.ERROR and "boom" in (s3.error or "")
    assert r.status is ScanStatus.PARTIAL
    assert not any(f.service == "s3" for f in r.findings)
    assert any(f.service == "iam" for f in r.findings)


def test_unconfigured_provider_is_skipped(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    settings.demo_mode = False
    engine = ScanEngine(settings)

    def no_creds(provider: Provider) -> Any:
        raise NotConfiguredError("no credentials")

    monkeypatch.setattr(engine, "_context", no_creds)
    r = engine.run()
    assert all(s.status is ServiceStatus.SKIPPED for s in r.services)
    assert r.status is ScanStatus.FAILED and "DEMO_MODE" in (r.error or "")


def test_buggy_rule_does_not_kill_service(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    rule = RULES["S3-005"]

    def broken(_: dict) -> Any:
        raise KeyError("missing")

    monkeypatch.setattr(rule, "fn", broken)
    r = ScanEngine(settings).run([Provider.AWS])
    s3 = next(s for s in r.services if s.service == "s3")
    assert s3.status is ServiceStatus.PARTIAL and any("S3-005" in w for w in s3.warnings)
    assert any(f.rule_id == "S3-002" for f in r.findings)


def test_suppression_excluded_from_score(settings: Settings) -> None:
    engine = ScanEngine(settings)
    first = engine.run([Provider.AWS])
    critical = [f for f in first.findings if f.rule_id == "CT-001"]
    second = engine.run([Provider.AWS], suppressed_ids={f.id for f in critical})
    assert all(f.suppressed for f in second.findings if f.rule_id == "CT-001")
    assert (second.score or 0) > (first.score or 0)


def test_score_ignores_cost_rules() -> None:
    assert score([], {"COST-001"}) == (None, 0, 0)
    s, passed, failed = score([], {"IAM-001", "S3-005"})
    assert (s, passed, failed) == (100, 2, 0)


def test_scanner_registry_contains_all_services() -> None:
    services = {s for (_, s) in SCANNERS}
    assert {"iam", "s3", "ec2", "rds", "eks", "storage", "network", "keyvault", "aks"} <= services
    assert all(isinstance(v, Scanner) for v in SCANNERS.values())
