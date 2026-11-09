"""
Scan engine: scanners -> rules -> findings, with per-service fault isolation.

One broken service (missing permission, throttling, SDK bug) yields a ServiceResult with status=error and
never aborts the whole scan. Results are scored as a weighted share of passing controls.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from cloud_copilot.config import Settings
from cloud_copilot.core.registry import RULES, SCANNERS, Rule, load_all, rules_for
from cloud_copilot.log import get_logger
from cloud_copilot.models import (
    CostSummary,
    Finding,
    Provider,
    ScanResult,
    ScanStatus,
    ServiceResult,
    ServiceStatus,
    Severity,
)
from cloud_copilot.providers.aws.context import NotConfiguredError

log = get_logger(__name__)
ProgressFn = Callable[[str], None]


def _count_resources(data: dict[str, Any]) -> int:
    return sum(len(v) for v in data.values() if isinstance(v, list))


def evaluate(rule: Rule, data: dict[str, Any], account: str | None) -> list[Finding]:
    info = rule.info
    out = []
    for hit in rule.fn(data):
        name = hit.resource_name or hit.resource_id
        out.append(
            Finding(
                id=Finding.make_id(info.id, hit.resource_id, hit.region, hit.account or account),
                rule_id=info.id,
                title=info.title,
                provider=info.provider,
                service=info.service,
                severity=hit.severity or info.severity,
                category=info.category,
                resource_id=hit.resource_id,
                resource_name=name,
                region=hit.region,
                account=hit.account or account,
                message=hit.message,
                remediation=info.remediation,
                terraform=info.terraform.replace("{resource}", name) if info.terraform else None,
                compliance=info.compliance,
                estimated_monthly_savings=hit.monthly_savings,
                details=hit.details,
            )
        )
    return out


def score(findings: list[Finding], evaluated_rule_ids: set[str]) -> tuple[int | None, int, int]:
    """Weighted share of passing security/reliability controls (0-100). Cost rules don't affect the score."""
    failed = {f.rule_id for f in findings if not f.suppressed}
    total_w = passed_w = 0
    passed = failed_n = 0
    for rid in evaluated_rule_ids:
        info = RULES[rid].info
        if info.category.value == "cost" or info.severity is Severity.INFO:
            continue
        w = info.severity.weight
        total_w += w
        if rid in failed:
            failed_n += 1
        else:
            passed_w += w
            passed += 1
    if total_w == 0:
        return None, 0, 0
    return round(100 * passed_w / total_w), passed, failed_n


class ScanEngine:
    def __init__(self, settings: Settings, contexts: dict[Provider, Any] | None = None) -> None:
        load_all()
        self.settings = settings
        self._contexts = contexts or {}

    # -- provider contexts (lazy so a missing provider only skips its services) --------
    def _context(self, provider: Provider) -> Any:
        if provider not in self._contexts:
            if provider is Provider.AWS:
                from cloud_copilot.providers.aws.context import AwsContext

                ctx: Any = AwsContext(
                    regions=self.settings.aws_regions,
                    home_region=self.settings.aws_home_region,
                    max_workers=self.settings.aws_max_workers,
                    profile=self.settings.aws_profile,
                )
                _ = ctx.account_id  # fail fast -> NotConfigured
            else:
                from cloud_copilot.providers.azure.context import AzureContext

                ctx = AzureContext(self.settings.azure_subscription_ids)
                _ = ctx.subscription_ids
            self._contexts[provider] = ctx
        return self._contexts[provider]

    def _data_source(self, provider: Provider, service: str) -> Callable[[], dict[str, Any]]:
        if self.settings.demo_mode:
            from cloud_copilot.providers import demo

            return lambda: demo.data(provider, service)
        scanner_fn = SCANNERS[(provider, service)].fn
        return lambda: scanner_fn(self._context(provider))

    def run(
        self,
        providers: list[Provider] | None = None,
        suppressed_ids: set[str] | None = None,
        progress: ProgressFn | None = None,
    ) -> ScanResult:
        providers = providers or [Provider(p) for p in self.settings.providers]
        suppressed_ids = suppressed_ids or set()
        result = ScanResult(status=ScanStatus.RUNNING, demo=self.settings.demo_mode)
        evaluated: set[str] = set()
        unavailable: set[Provider] = set()

        for (provider, service), _scanner in sorted(SCANNERS.items()):
            if provider not in providers:
                continue
            if provider in unavailable:
                result.services.append(
                    ServiceResult(
                        provider=provider,
                        service=service,
                        status=ServiceStatus.SKIPPED,
                        error="provider not configured",
                    )
                )
                continue
            if progress:
                progress(f"{provider.value}:{service}")
            started = time.perf_counter()
            sr = ServiceResult(provider=provider, service=service, status=ServiceStatus.OK)
            ctx_warnings_before = 0
            try:
                ctx = None if self.settings.demo_mode else self._context(provider)
                ctx_warnings_before = len(ctx.warnings) if ctx is not None else 0
                data = self._data_source(provider, service)()
                account = self._account_label(provider, ctx)
                if account:
                    result.accounts[provider.value] = account
            except NotConfiguredError as exc:
                unavailable.add(provider)
                sr.status, sr.error = ServiceStatus.SKIPPED, str(exc)
                log.info("provider_skipped", provider=provider.value, reason=str(exc))
                result.services.append(sr)
                continue
            except Exception as exc:
                sr.status, sr.error = ServiceStatus.ERROR, f"{type(exc).__name__}: {str(exc)[:300]}"
                log.warning("service_scan_failed", provider=provider.value, service=service, error=sr.error)
                sr.duration_ms = int((time.perf_counter() - started) * 1000)
                result.services.append(sr)
                continue

            if ctx is not None and len(ctx.warnings) > ctx_warnings_before:
                sr.warnings = ctx.warnings[ctx_warnings_before:]
                sr.status = ServiceStatus.PARTIAL
            sr.resources = _count_resources(data)
            result.inventory[f"{provider.value}:{service}"] = sr.resources

            for r in rules_for(provider, service):
                try:
                    found = evaluate(r, data, account)
                except Exception as exc:  # a buggy rule must not hide the others
                    sr.warnings.append(f"rule {r.info.id} failed: {type(exc).__name__}: {exc}")
                    sr.status = ServiceStatus.PARTIAL
                    continue
                evaluated.add(r.info.id)
                sr.rules_evaluated += 1
                for f in found:
                    f.suppressed = f.id in suppressed_ids
                result.findings.extend(found)
            sr.duration_ms = int((time.perf_counter() - started) * 1000)
            result.services.append(sr)

        if self.settings.cost_enabled:
            result.costs = self._costs(providers, unavailable)

        result.findings.sort(key=lambda f: (f.suppressed, f.severity.rank, f.provider, f.rule_id))
        result.score, result.controls_passed, result.controls_failed = score(result.findings, evaluated)
        result.finished_at = datetime.now(UTC)
        statuses = {s.status for s in result.services}
        if statuses and statuses <= {ServiceStatus.SKIPPED}:
            result.status = ScanStatus.FAILED
            result.error = "No provider is configured. Set credentials or DEMO_MODE=true."
        elif statuses & {ServiceStatus.ERROR, ServiceStatus.PARTIAL}:
            result.status = ScanStatus.PARTIAL
        else:
            result.status = ScanStatus.SUCCEEDED
        log.info("scan_finished", status=result.status.value, findings=len(result.findings), score=result.score)
        return result

    def _account_label(self, provider: Provider, ctx: Any) -> str | None:
        if self.settings.demo_mode:
            from cloud_copilot.providers import demo

            return demo.ACCOUNTS[provider]
        if ctx is None:
            return None
        if provider is Provider.AWS:
            return str(ctx.account_id)
        subs = ctx.subscription_ids
        return subs[0] if len(subs) == 1 else f"{len(subs)} subscriptions"

    def _costs(self, providers: list[Provider], unavailable: set[Provider]) -> list[CostSummary]:
        out: list[CostSummary] = []
        for p in providers:
            if p in unavailable:
                continue
            try:
                if self.settings.demo_mode:
                    from cloud_copilot.providers import demo

                    cost: CostSummary | None = demo.costs(p)
                elif p is Provider.AWS:
                    from cloud_copilot.providers.aws.cost import aws_costs

                    cost = aws_costs(self._context(p))
                else:
                    from cloud_copilot.providers.azure.cost import azure_costs

                    cost = azure_costs(self._context(p))
            except Exception as exc:
                log.info("cost_collection_failed", provider=p.value, error=type(exc).__name__)
                cost = None
            if cost:
                out.append(cost)
        return out
