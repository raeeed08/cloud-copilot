"""Catalog-wide invariants: every rule is complete, wired to a scanner, and runs on demo data."""

import re

import pytest

from cloud_copilot.core.engine import evaluate
from cloud_copilot.core.registry import RULES, SCANNERS, load_all
from cloud_copilot.models import Category, Provider
from cloud_copilot.providers import demo

load_all()


def test_catalog_size() -> None:
    assert len(RULES) >= 100
    assert len({r.info.provider for r in RULES.values()}) == 2


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_metadata_complete(rule_id: str) -> None:
    info = RULES[rule_id].info
    assert re.fullmatch(r"[A-Z0-9]+(-[A-Z0-9]+)*-\d{3}", info.id)
    assert len(info.title) > 8 and len(info.description) > 20 and len(info.remediation) > 15
    assert (info.provider, info.service) in SCANNERS, "rule has no scanner for its service"
    if info.category is Category.SECURITY:
        assert info.compliance, "security rules must map to at least one framework"


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_runs_on_demo_data(rule_id: str) -> None:
    r = RULES[rule_id]
    findings = evaluate(r, demo.data(r.info.provider, r.info.service), "acct")
    for f in findings:
        assert f.rule_id == rule_id and f.resource_id and f.message
        if f.terraform:
            assert "{resource}" not in f.terraform


def test_finding_ids_are_stable_and_unique() -> None:
    ids = []
    for r in RULES.values():
        ids += [f.id for f in evaluate(r, demo.data(r.info.provider, r.info.service), "acct")]
    assert len(ids) == len(set(ids))


def test_every_scanner_has_demo_data() -> None:
    for provider, service in SCANNERS:
        assert demo.data(provider, service) is not None
    assert demo.data(Provider.AZURE, "storage")["accounts"][0]["subscription"] == demo.SUB
