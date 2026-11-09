"""
Application service layer shared by the REST API, the CLI, the scheduler and the MCP server.
Keeps orchestration (scan lifecycle, metrics, AI summary) out of the transport layers.
"""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from functools import cached_property
from typing import Any

from cloud_copilot.config import Settings, get_settings
from cloud_copilot.core.engine import ScanEngine
from cloud_copilot.llm.advisor import Copilot
from cloud_copilot.log import get_logger
from cloud_copilot.metrics import FINDINGS, POSTURE_SCORE, SAVINGS, SCAN_DURATION, SCANS, SERVICE_ERRORS
from cloud_copilot.models import Finding, Provider, ScanResult, Severity
from cloud_copilot.rag.retriever import Retriever, build_retriever
from cloud_copilot.store.db import Database
from cloud_copilot.store.repository import Repository, summarise

log = get_logger(__name__)


class ScanInProgressError(RuntimeError):
    pass


def _natural_key(control: str) -> list[tuple[int, int, str]]:
    """Sort 'AC-6(2)' / '1.10' / '2.1.4' naturally (1.2 < 1.10)."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.()\-\s]+", control) if p]


class CopilotService:
    def __init__(self, settings: Settings | None = None, engine: ScanEngine | None = None) -> None:
        self.settings = settings or get_settings()
        self.db = Database(self.settings.database_url)
        self.db.migrate()
        self.repo = Repository(self.db)
        self._engine = engine
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scan")
        self._lock = threading.Lock()
        self._running: str | None = None

    @property
    def engine(self) -> ScanEngine:
        if self._engine is None:
            self._engine = ScanEngine(self.settings)
        return self._engine

    @cached_property
    def retriever(self) -> Retriever:
        return build_retriever(self.settings)

    @cached_property
    def copilot(self) -> Copilot:
        return Copilot(self.settings, self.retriever)

    # ------------------------------------------------------------------ scans
    def start_scan(
        self, providers: list[Provider] | None = None, trigger: str = "api", explain: bool = True
    ) -> tuple[str, Future[ScanResult]]:
        with self._lock:
            if self._running:
                raise ScanInProgressError(self._running)
            scan_id = self.repo.create_scan(trigger=trigger, demo=self.settings.demo_mode)
            self._running = scan_id
        return scan_id, self._executor.submit(self._run, scan_id, providers, trigger, explain)

    def run_scan_sync(
        self, providers: list[Provider] | None = None, trigger: str = "cli", explain: bool = True
    ) -> tuple[str, ScanResult]:
        scan_id, fut = self.start_scan(providers, trigger, explain)
        return scan_id, fut.result()

    def _run(self, scan_id: str, providers: list[Provider] | None, trigger: str, explain: bool) -> ScanResult:
        started = time.perf_counter()
        try:
            self.repo.mark_running(scan_id)
            result = self.engine.run(providers, suppressed_ids=self.repo.suppressed_ids())
            result.id = scan_id
            if explain and result.findings:
                result.explanation = self.copilot.explain_scan(
                    result.findings, summarise(result.findings), [c.model_dump() for c in result.costs]
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
        FINDINGS.clear()
        for p in Provider:
            for s in Severity:
                FINDINGS.labels(provider=p.value, severity=s.value).set(
                    sum(1 for f in result.findings if f.provider is p and f.severity is s and not f.suppressed)
                )
        if result.score is not None:
            POSTURE_SCORE.set(result.score)
        SAVINGS.set(sum(f.estimated_monthly_savings or 0 for f in result.findings if not f.suppressed))
        for svc_result in result.services:
            if svc_result.status.value == "error":
                SERVICE_ERRORS.labels(provider=svc_result.provider.value, service=svc_result.service).inc()

    # ------------------------------------------------------------------ queries
    def latest(self) -> dict[str, Any] | None:
        return self.repo.latest_scan()

    def latest_findings(self, **filters: Any) -> list[Finding]:
        scan = self.latest()
        return self.repo.findings(scan["id"], **filters) if scan else []

    def ask(self, question: str, history: list[dict[str, str]] | None = None) -> dict[str, Any]:
        scan = self.latest()
        findings = self.repo.findings(scan["id"], limit=5000) if scan else []
        ans = self.copilot.chat(question, findings, history, scan)
        return ans.__dict__

    def compliance(self) -> dict[str, Any]:
        """Per-framework control status for the latest scan."""
        from cloud_copilot.core.registry import RULES

        scan = self.latest()
        if not scan:
            return {"frameworks": []}
        failing = {f.rule_id for f in self.repo.findings(scan["id"], include_suppressed=False, limit=10000)}
        evaluated_services = {
            (s["provider"], s["service"]) for s in scan.get("services", []) if s["status"] in ("ok", "partial")
        }
        frameworks: dict[str, dict[str, dict[str, Any]]] = {}
        for r in RULES.values():
            i = r.info
            if (i.provider.value, i.service) not in evaluated_services:
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
