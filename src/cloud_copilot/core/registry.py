"""
Rule and scanner registries.

A *scanner* reads one cloud service and returns normalised, provider-agnostic data (plain dicts).
A *rule* is a pure function over that data that yields ``Hit`` objects. Rules never call the cloud,
which makes every rule unit-testable with a dict fixture.

Adding a check = writing one decorated function. The engine, API, dashboard, compliance view,
knowledge base and MCP server pick it up automatically.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from cloud_copilot.models import Category, Provider, RuleInfo, Severity


@dataclass(slots=True)
class Hit:
    """One failed check on one resource."""

    resource_id: str
    message: str
    resource_name: str | None = None
    region: str | None = None
    account: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    monthly_savings: float | None = None
    severity: Severity | None = None  # optional per-hit override (e.g. escalate admin ports)


RuleFn = Callable[[dict[str, Any]], Iterable[Hit]]
ScannerFn = Callable[[Any], dict[str, Any]]


@dataclass(slots=True)
class Rule:
    info: RuleInfo
    fn: RuleFn


@dataclass(slots=True)
class Scanner:
    provider: Provider
    service: str
    fn: ScannerFn
    description: str = ""


RULES: dict[str, Rule] = {}
SCANNERS: dict[tuple[Provider, str], Scanner] = {}


def rule(
    *,
    id: str,
    title: str,
    provider: Provider,
    service: str,
    severity: Severity,
    description: str,
    remediation: str,
    category: Category = Category.SECURITY,
    terraform: str | None = None,
    cis: list[str] | None = None,
    nist: list[str] | None = None,
    references: list[str] | None = None,
) -> Callable[[RuleFn], RuleFn]:
    """Register a rule. ``cis`` ids refer to the CIS Foundations benchmark of the provider."""

    def decorator(fn: RuleFn) -> RuleFn:
        if id in RULES:
            raise ValueError(f"duplicate rule id {id}")
        compliance: dict[str, list[str]] = {}
        if cis:
            key = "CIS AWS Foundations v3.0" if provider is Provider.AWS else "CIS Azure Foundations v2.0"
            compliance[key] = cis
        if nist:
            compliance["NIST 800-53 r5"] = nist
        RULES[id] = Rule(
            info=RuleInfo(
                id=id,
                title=title,
                provider=provider,
                service=service,
                severity=severity,
                category=category,
                description=description,
                remediation=remediation,
                terraform=terraform,
                compliance=compliance,
                references=references or [],
            ),
            fn=fn,
        )
        return fn

    return decorator


def scanner(provider: Provider, service: str, description: str = "") -> Callable[[ScannerFn], ScannerFn]:
    def decorator(fn: ScannerFn) -> ScannerFn:
        SCANNERS[(provider, service)] = Scanner(provider, service, fn, description)
        return fn

    return decorator


def rules_for(provider: Provider, service: str) -> list[Rule]:
    return [r for r in RULES.values() if r.info.provider is provider and r.info.service == service]


def load_all() -> None:
    """Import every rule/scanner module so the decorators run."""
    from cloud_copilot.providers.aws import rules as aws_rules  # noqa: F401
    from cloud_copilot.providers.aws import scanners as aws_scanners  # noqa: F401
    from cloud_copilot.providers.azure import rules as azure_rules  # noqa: F401
    from cloud_copilot.providers.azure import scanners as azure_scanners  # noqa: F401
