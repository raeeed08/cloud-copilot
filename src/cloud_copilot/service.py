"""
Application service layer shared by the REST API, the CLI, the scheduler and the MCP server.
Keeps orchestration (targets, scan lifecycle, correlation, strategy, AI) out of the transport layers.

Scan targets
    demo      the built-in synthetic estate
    account   a connected account (credentials stored encrypted, see store/accounts.py)
    ambient   whatever credentials the process has (env, ~/.aws, IRSA, managed identity)
"""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cached_property
from typing import Any

from cloud_copilot.config import Settings, get_settings
from cloud_copilot.core.correlation import correlate
from cloud_copilot.core.engine import ScanEngine, score
from cloud_copilot.core.registry import load_all
from cloud_copilot.core.strategy import build_plan
from cloud_copilot.crypto import SecretBox
from cloud_copilot.llm.advisor import Copilot
from cloud_copilot.llm.gateway import LLMGateway, LLMUnavailableError
from cloud_copilot.llm.providers import PRESETS, LLMConfig
from cloud_copilot.log import get_logger
from cloud_copilot.metrics import FINDINGS, POSTURE_SCORE, SAVINGS, SCAN_DURATION, SCANS, SERVICE_ERRORS
from cloud_copilot.models import (
    Finding,
    Provider,
    ScanResult,
    ScanStatus,
    ServiceResult,
    ServiceStatus,
    Severity,
)
from cloud_copilot.providers import accounts as acct
from cloud_copilot.providers.aws.context import NotConfiguredError
from cloud_copilot.rag.retriever import Retriever, build_retriever
from cloud_copilot.store.accounts import AccountStore, SettingsStore
from cloud_copilot.store.db import Database
from cloud_copilot.store.repository import Repository, summarise

log = get_logger(__name__)
LLM_SETTING = "llm"


class ScanInProgressError(RuntimeError):
    pass


class NotFoundError(LookupError):
    pass


def _natural_key(control: str) -> list[tuple[int, int, str]]:
    """Sort 'AC-6(2)' / '1.10' / '2.1.4' naturally (1.2 < 1.10)."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.()\-\s]+", control) if p]


@dataclass
class Target:
    kind: str  # demo | account | ambient
    id: str
    name: str
    providers: list[Provider] = field(default_factory=list)


def merge(results: list[ScanResult], targets: list[Target]) -> ScanResult:
    """Combine per-target results into one scan (findings, services, inventory, costs, score)."""
    out = ScanResult(status=ScanStatus.RUNNING, demo=any(r.demo for r in results), targets=[t.id for t in targets])
    evaluated: set[str] = set()
    for r, t in zip(results, targets, strict=True):
        out.findings.extend(r.findings)
        out.services.extend(r.services)
        out.costs.extend(r.costs)
        out.raw.update(r.raw)
        evaluated |= set(r.evaluated_rules)
        for k, v in r.inventory.items():
            out.inventory[k] = out.inventory.get(k, 0) + v
        for s in r.services:
            if s.account:
                out.accounts[f"{s.provider.value}:{s.account}"] = t.name
        if r.error:
            out.error = f"{t.name}: {r.error}" if not out.error else f"{out.error}; {t.name}: {r.error}"
    out.findings.sort(key=lambda f: (f.suppressed, f.severity.rank, f.provider, f.rule_id))
    out.evaluated_rules = sorted(evaluated)
    out.score, out.controls_passed, out.controls_failed = score(out.findings, evaluated)
    out.finished_at = datetime.now(UTC)
    statuses = {r.status for r in results}
    if statuses <= {ScanStatus.FAILED}:
        out.status = ScanStatus.FAILED
    elif statuses & {ScanStatus.FAILED, ScanStatus.PARTIAL}:
        out.status = ScanStatus.PARTIAL
    else:
        out.status = ScanStatus.SUCCEEDED
    return out


class CopilotService:
    def __init__(self, settings: Settings | None = None, engine: ScanEngine | None = None) -> None:
        self.settings = settings or get_settings()
        load_all()
        self.db = Database(self.settings.database_url)
        self.db.migrate()
        self.repo = Repository(self.db)
        self.box = SecretBox.from_settings(self.settings)
        self.accounts = AccountStore(self.db, self.box)
        self.app_settings = SettingsStore(self.db, self.box)
        self._engine = engine
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scan")
        self._lock = threading.Lock()
        self._running: str | None = None
        self.llm_health: dict[str, Any] | None = None  # last real call: {"ok", "detail", "at"}
        self.restore_metrics()

    # ------------------------------------------------------------------ AI provider
    def llm_config(self) -> LLMConfig:
        stored = self.app_settings.get(LLM_SETTING)
        if not stored:
            return LLMConfig.from_settings(self.settings)
        value, secret = stored
        return LLMConfig(
            provider=value.get("provider", "custom"),
            base_url=value.get("base_url", ""),
            models=list(value.get("models") or []),
            api_key=secret.get("api_key"),
            language=value.get("language") or self.settings.llm_language,
            source="ui",
            timeout=self.settings.llm_timeout_seconds,
            max_tokens=self.settings.llm_max_tokens,
        )

    def llm_public(self) -> dict[str, Any]:
        c = self.llm_config()
        return {
            "provider": c.provider,
            "base_url": c.base_url,
            "models": c.models,
            "language": c.language,
            "source": c.source,
            "has_key": bool(c.api_key),
            "key_hint": f"…{c.api_key[-4:]}" if c.api_key else None,
            "configured": c.usable,
            "health": self.llm_health,
            "presets": PRESETS,
        }

    def set_llm(
        self, provider: str, base_url: str | None, models: list[str] | None, api_key: str | None, language: str | None
    ) -> dict[str, Any]:
        preset = PRESETS.get(provider, PRESETS["custom"])
        current = self.app_settings.get(LLM_SETTING)
        old_secret = current[1] if current else {}
        same_provider = bool(current and current[0].get("provider") == provider)
        key = api_key if api_key else (old_secret.get("api_key") if same_provider else None)
        value = {
            "provider": provider,
            "base_url": (base_url or preset["base_url"]).rstrip("/"),
            "models": [m.strip() for m in (models or preset["models"]) if m.strip()],
            "language": language or self.settings.llm_language,
        }
        self.app_settings.put(LLM_SETTING, value, {"api_key": key} if key else {})
        self.llm_health = None
        self._reload_llm()
        return self.llm_public()

    def reset_llm(self) -> dict[str, Any]:
        self.app_settings.delete(LLM_SETTING)
        self._reload_llm()
        return self.llm_public()

    def test_llm(self) -> dict[str, Any]:
        gw = LLMGateway(self.settings, config=self.llm_config())
        if not gw.available:
            return {"ok": False, "error": "Not configured: choose a provider and paste an API key."}
        started = time.perf_counter()
        try:
            # generous budget: reasoning models spend tokens thinking before answering
            reply = gw.complete([{"role": "user", "content": "Reply with exactly: OK"}], max_tokens=300)
        except LLMUnavailableError as exc:
            self._record_llm(False, str(exc))
            return {"ok": False, "error": str(exc)}
        self._record_llm(True, reply.model)
        return {
            "ok": True,
            "model": reply.model,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "reply": reply.text[:50],
        }

    def _record_llm(self, ok: bool, detail: str) -> None:
        self.llm_health = {"ok": ok, "detail": detail[:300], "at": datetime.now(UTC).isoformat()}

    def _reload_llm(self) -> None:
        if "copilot" in self.__dict__:
            cfg = self.llm_config()
            self.copilot.gateway = LLMGateway(self.settings, config=cfg)
            self.copilot.language = cfg.language

    @cached_property
    def retriever(self) -> Retriever:
        return build_retriever(self.settings)

    @cached_property
    def copilot(self) -> Copilot:
        cfg = self.llm_config()
        c = Copilot(self.settings, self.retriever, LLMGateway(self.settings, config=cfg))
        c.language = cfg.language
        return c

    # ------------------------------------------------------------------ accounts
    def add_account(
        self, name: str, provider: str, method: str, config: dict[str, Any], secret: dict[str, Any], verify: bool = True
    ) -> dict[str, Any]:
        acct.validate(provider, method, config, secret)
        created = self.accounts.create(name, provider, method, config, secret)
        return self.verify_account(created["id"]) if verify else created

    def verify_account(self, account_id: str) -> dict[str, Any]:
        creds = self.accounts.credentials(account_id)
        if not creds:
            raise NotFoundError(account_id)
        pub, secret = creds
        try:
            identity = acct.verify(pub["provider"], pub["auth_method"], pub["config"], secret)
            self.accounts.set_status(account_id, "connected", None, identity)
        except acct.AccountError as exc:
            self.accounts.set_status(account_id, "error", str(exc), None)
        return self.accounts.get(account_id) or {}

    # ------------------------------------------------------------------ targets & scans
    def resolve_targets(
        self, account_ids: list[str] | None, demo: bool | None, providers: list[Provider] | None
    ) -> list[Target]:
        all_providers = providers or [Provider(p) for p in self.settings.providers]
        if demo:
            return [Target("demo", "demo", "Demo estate", all_providers)]
        connected = [a for a in self.accounts.list() if a["enabled"]]
        if account_ids:
            chosen = [a for a in connected if a["id"] in set(account_ids)]
            if len(chosen) != len(set(account_ids)):
                raise NotFoundError("unknown or disabled account id")
        elif demo is None and connected:
            chosen = connected
        elif demo is None and self.settings.demo_mode:
            return [Target("demo", "demo", "Demo estate", all_providers)]
        else:
            return [Target("ambient", "ambient", "Local credentials", all_providers)]
        return [
            Target("account", a["id"], a["name"], [Provider(a["provider"])])
            for a in chosen
            if Provider(a["provider"]) in all_providers
        ]

    def start_scan(
        self,
        providers: list[Provider] | None = None,
        trigger: str = "api",
        explain: bool = True,
        account_ids: list[str] | None = None,
        demo: bool | None = None,
    ) -> tuple[str, Future[ScanResult]]:
        targets = self.resolve_targets(account_ids, demo, providers)
        if not targets:
            raise NotFoundError("no scan target matches")
        with self._lock:
            if self._running:
                raise ScanInProgressError(self._running)
            scan_id = self.repo.create_scan(trigger=trigger, demo=any(t.kind == "demo" for t in targets))
            self._running = scan_id
        return scan_id, self._executor.submit(self._run, scan_id, targets, trigger, explain)

    def run_scan_sync(
        self,
        providers: list[Provider] | None = None,
        trigger: str = "cli",
        explain: bool = True,
        account_ids: list[str] | None = None,
        demo: bool | None = None,
    ) -> tuple[str, ScanResult]:
        scan_id, fut = self.start_scan(providers, trigger, explain, account_ids, demo)
        return scan_id, fut.result()

    def _scan_target(self, t: Target, suppressed: set[str]) -> ScanResult:
        if t.kind == "demo":
            engine = self._engine or ScanEngine(self.settings.model_copy(update={"demo_mode": True}))
            return engine.run(t.providers, suppressed_ids=suppressed)
        live = self.settings.model_copy(update={"demo_mode": False})
        if t.kind == "ambient":
            return ScanEngine(live).run(t.providers, suppressed_ids=suppressed)
        creds = self.accounts.credentials(t.id)
        if not creds:
            raise NotFoundError(t.id)
        pub, secret = creds
        provider = Provider(pub["provider"])
        try:
            ctx = acct.build_context(provider, pub["auth_method"], pub["config"], secret)
        except (NotConfiguredError, acct.AccountError) as exc:
            self.accounts.set_status(t.id, "error", str(exc), None)
            return ScanResult(
                status=ScanStatus.FAILED,
                error=str(exc),
                services=[
                    ServiceResult(
                        provider=provider, service="*", account=t.name, status=ServiceStatus.ERROR, error=str(exc)
                    )
                ],
            )
        return ScanEngine(live, contexts={provider: ctx}).run([provider], suppressed_ids=suppressed)

    def _run(self, scan_id: str, targets: list[Target], trigger: str, explain: bool) -> ScanResult:
        started = time.perf_counter()
        try:
            self.repo.mark_running(scan_id)
            suppressed = self.repo.suppressed_ids()
            results = [self._scan_target(t, suppressed) for t in targets]
            result = merge(results, targets)
            result.id = scan_id
            result.scenarios = correlate(result.raw, result.findings)
            if explain and result.findings:
                plan = build_plan(result.findings, result.scenarios, result.evaluated_rules)
                result.explanation = self.copilot.explain_scan(
                    result.findings,
                    summarise(result.findings),
                    [c.model_dump() for c in result.costs],
                    scenarios=result.scenarios,
                    plan=plan,
                )
            self.repo.save_result(scan_id, result)
            self._update_metrics(result)
            SCANS.labels(status=result.status.value, trigger=trigger).inc()
            return result
        except Exception as exc:
            log.exception("scan_crashed", scan_id=scan_id)
            self.repo.fail_scan(scan_id, f"{type(exc).__name__}: {exc}")
            SCANS.labels(status="failed", trigger=trigger).inc()
            raise
        finally:
            SCAN_DURATION.observe(time.perf_counter() - started)
            with self._lock:
                self._running = None

    @staticmethod
    def _update_metrics(result: ScanResult) -> None:
        CopilotService._publish_posture(result.findings, result.score)
        for svc_result in result.services:
            if svc_result.status.value == "error":
                SERVICE_ERRORS.labels(provider=svc_result.provider.value, service=svc_result.service).inc()

    @staticmethod
    def _publish_posture(findings: list[Finding], score: int | None) -> None:
        FINDINGS.clear()
        for p in Provider:
            for s in Severity:
                FINDINGS.labels(provider=p.value, severity=s.value).set(
                    sum(1 for f in findings if f.provider is p and f.severity is s and not f.suppressed)
                )
        if score is not None:
            POSTURE_SCORE.set(score)
        SAVINGS.set(sum(f.estimated_monthly_savings or 0 for f in findings if not f.suppressed))

    def restore_metrics(self) -> None:
        """After a restart, gauges would read 0 until the next scan: republish the latest stored scan."""
        try:
            scan = self.latest()
            if scan:
                self._publish_posture(self.repo.findings(scan["id"], limit=100000), scan.get("score"))
        except Exception as exc:  # metrics must never prevent startup
            log.warning("metrics_restore_failed", error=str(exc))

    # ------------------------------------------------------------------ queries
    def latest(self) -> dict[str, Any] | None:
        return self.repo.latest_scan()

    def latest_findings(self, **filters: Any) -> list[Finding]:
        scan = self.latest()
        return self.repo.findings(scan["id"], **filters) if scan else []

    def plan(self, scan_id: str | None = None) -> dict[str, Any]:
        scan = self.repo.get_scan(scan_id) if scan_id else self.latest()
        if not scan:
            raise NotFoundError("no completed scan yet")
        findings = self.repo.findings(scan["id"], limit=100000)
        diff = self.repo.diff(scan["id"])
        plan = build_plan(
            findings, scan.get("scenarios", []), scan.get("evaluated_rules", []), [r["id"] for r in diff["resolved"]]
        )
        plan.update(scan_id=scan["id"], scenarios=scan.get("scenarios", []), diff=diff)
        return plan

    def ask(self, question: str, history: list[dict[str, str]] | None = None) -> dict[str, Any]:
        scan = self.latest()
        findings = self.repo.findings(scan["id"], limit=5000) if scan else []
        ans = self.copilot.chat(question, findings, history, scan)
        if ans.mode == "llm":
            self._record_llm(True, ans.model or "")
        elif self.copilot.gateway.available and ans.citations:  # a real attempt that failed
            self._record_llm(False, "last chat fell back to offline mode (provider error)")
        return ans.__dict__

    def compliance(self) -> dict[str, Any]:
        """Per-framework control status for the latest scan."""
        from cloud_copilot.core.registry import RULES

        scan = self.latest()
        if not scan:
            return {"frameworks": []}
        failing = {f.rule_id for f in self.repo.findings(scan["id"], include_suppressed=False, limit=10000)}
        evaluated = set(scan.get("evaluated_rules") or [])
        evaluated_services = {
            (s["provider"], s["service"]) for s in scan.get("services", []) if s["status"] in ("ok", "partial")
        }
        frameworks: dict[str, dict[str, dict[str, Any]]] = {}
        for r in RULES.values():
            i = r.info
            if evaluated and i.id not in evaluated:
                continue
            if not evaluated and (i.provider.value, i.service) not in evaluated_services:
                continue
            for fw, controls in i.compliance.items():
                for c in controls:
                    ctrl = frameworks.setdefault(fw, {}).setdefault(c, {"control": c, "rules": [], "status": "pass"})
                    ctrl["rules"].append(i.id)
                    if i.id in failing:
                        ctrl["status"] = "fail"
        out = []
        for fw, fw_controls in sorted(frameworks.items()):
            items = sorted(fw_controls.values(), key=lambda c: _natural_key(c["control"]))
            passed = sum(c["status"] == "pass" for c in items)
            out.append(
                {
                    "framework": fw,
                    "passed": passed,
                    "total": len(items),
                    "percent": round(100 * passed / len(items)) if items else 0,
                    "controls": items,
                }
            )
        return {"scan_id": scan["id"], "frameworks": out}
