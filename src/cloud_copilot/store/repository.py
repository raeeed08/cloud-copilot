"""Repository: the only place that knows how scans and findings are stored."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select

from cloud_copilot.models import Finding, ScanResult, ScanStatus, Severity
from cloud_copilot.store.db import Database, FindingRow, ScanRow, SuppressionRow


def _iso(dt: datetime | None) -> str | None:
    """SQLite drops tzinfo; every timestamp we store is UTC."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()


def summarise(findings: list[Finding]) -> dict[str, Any]:
    active = [f for f in findings if not f.suppressed]
    sev = Counter(f.severity.value for f in active)
    return {
        "total": len(active),
        "suppressed": len(findings) - len(active),
        "by_severity": {s.value: sev.get(s.value, 0) for s in Severity},
        "by_provider": dict(Counter(f.provider.value for f in active)),
        "by_service": dict(Counter(f"{f.provider.value}:{f.service}" for f in active).most_common()),
        "by_category": dict(Counter(f.category.value for f in active)),
        "estimated_monthly_savings": round(sum(f.estimated_monthly_savings or 0 for f in active), 2),
    }


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---------------------------------------------------------------- scans
    def create_scan(self, trigger: str = "api", demo: bool = False) -> str:
        scan_id = str(uuid.uuid4())
        with self.db.session() as s:
            s.add(ScanRow(id=scan_id, status=ScanStatus.QUEUED.value, trigger=trigger, demo=demo))
        return scan_id

    def mark_running(self, scan_id: str) -> None:
        with self.db.session() as s:
            row = s.get(ScanRow, scan_id)
            if row:
                row.status = ScanStatus.RUNNING.value

    def save_result(self, scan_id: str, result: ScanResult) -> None:
        with self.db.session() as s:
            row = s.get(ScanRow, scan_id)
            if row is None:
                row = ScanRow(id=scan_id)
                s.add(row)
            row.status = result.status.value
            row.started_at = result.started_at
            row.finished_at = result.finished_at or datetime.now(UTC)
            row.demo = result.demo
            row.score = result.score
            row.controls_passed = result.controls_passed
            row.controls_failed = result.controls_failed
            row.accounts = result.accounts
            row.services = [x.model_dump(mode="json") for x in result.services]
            row.inventory = result.inventory
            row.costs = [c.model_dump(mode="json") for c in result.costs]
            row.summary = summarise(result.findings)
            row.explanation = result.explanation
            row.error = result.error
            row.targets = result.targets
            row.evaluated_rules = result.evaluated_rules
            row.scenarios = result.scenarios
            s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
            s.add_all(
                FindingRow(
                    scan_id=scan_id,
                    finding_id=f.id,
                    rule_id=f.rule_id,
                    provider=f.provider.value,
                    service=f.service,
                    severity=f.severity.value,
                    category=f.category.value,
                    savings=f.estimated_monthly_savings,
                    payload=f.model_dump(mode="json"),
                )
                for f in result.findings
            )

    def fail_scan(self, scan_id: str, error: str) -> None:
        with self.db.session() as s:
            row = s.get(ScanRow, scan_id)
            if row:
                row.status = ScanStatus.FAILED.value
                row.error = error[:2000]
                row.finished_at = datetime.now(UTC)

    def set_explanation(self, scan_id: str, text: str) -> None:
        with self.db.session() as s:
            row = s.get(ScanRow, scan_id)
            if row:
                row.explanation = text

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.db.session() as s:
            row = s.get(ScanRow, scan_id)
            return self._scan_dict(row) if row else None

    def latest_scan(self, completed_only: bool = True) -> dict[str, Any] | None:
        stmt = select(ScanRow).order_by(ScanRow.started_at.desc()).limit(1)
        if completed_only:
            stmt = stmt.where(ScanRow.status.in_([ScanStatus.SUCCEEDED.value, ScanStatus.PARTIAL.value]))
        with self.db.session() as s:
            row = s.scalars(stmt).first()
            return self._scan_dict(row) if row else None

    def list_scans(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.db.session() as s:
            rows = s.scalars(select(ScanRow).order_by(ScanRow.started_at.desc()).limit(limit)).all()
            return [self._scan_dict(r, light=True) for r in rows]

    def has_running_scan(self) -> bool:
        with self.db.session() as s:
            n = s.scalar(
                select(func.count())
                .select_from(ScanRow)
                .where(ScanRow.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]))
            )
            return bool(n)

    @staticmethod
    def _scan_dict(row: ScanRow, light: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": row.id,
            "status": row.status,
            "trigger": row.trigger,
            "demo": row.demo,
            "started_at": _iso(row.started_at),
            "finished_at": _iso(row.finished_at),
            "score": row.score,
            "controls_passed": row.controls_passed,
            "controls_failed": row.controls_failed,
            "summary": row.summary or {},
            "accounts": row.accounts or {},
            "targets": row.targets or [],
            "scenario_count": len(row.scenarios or []),
            "error": row.error,
        }
        if not light:
            d.update(
                services=row.services or [],
                inventory=row.inventory or {},
                costs=row.costs or [],
                explanation=row.explanation,
                scenarios=row.scenarios or [],
                evaluated_rules=row.evaluated_rules or [],
            )
        return d

    def previous_scan_id(self, scan_id: str) -> str | None:
        """Most recent completed scan before ``scan_id`` that covered the same targets."""
        with self.db.session() as s:
            cur = s.get(ScanRow, scan_id)
            if not cur:
                return None
            rows = s.scalars(
                select(ScanRow)
                .where(ScanRow.started_at < cur.started_at)
                .where(ScanRow.status.in_([ScanStatus.SUCCEEDED.value, ScanStatus.PARTIAL.value]))
                .order_by(ScanRow.started_at.desc())
                .limit(50)
            ).all()
            for r in rows:
                if sorted(r.targets or []) == sorted(cur.targets or []):
                    return r.id
            return None

    def finding_ids(self, scan_id: str) -> set[str]:
        with self.db.session() as s:
            return set(s.scalars(select(FindingRow.finding_id).where(FindingRow.scan_id == scan_id)).all())

    def diff(self, scan_id: str) -> dict[str, Any]:
        """New / resolved / persisting findings compared with the previous scan of the same targets."""
        prev = self.previous_scan_id(scan_id)
        current = self.finding_ids(scan_id)
        if not prev:
            return {"previous_scan_id": None, "new": sorted(current), "resolved": [], "persisting": []}
        before = self.finding_ids(prev)
        resolved_rows: list[dict[str, Any]] = []
        with self.db.session() as s:
            for r in s.scalars(
                select(FindingRow).where(FindingRow.scan_id == prev).where(FindingRow.finding_id.in_(before - current))
            ).all():
                p = r.payload
                resolved_rows.append(
                    {
                        "id": p["id"],
                        "rule_id": p["rule_id"],
                        "severity": p["severity"],
                        "resource_name": p["resource_name"],
                        "title": p["title"],
                    }
                )
        return {
            "previous_scan_id": prev,
            "new": sorted(current - before),
            "resolved": resolved_rows,
            "persisting": sorted(current & before),
        }

    # ---------------------------------------------------------------- findings
    def findings(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        provider: str | None = None,
        service: str | None = None,
        category: str | None = None,
        rule_id: str | None = None,
        q: str | None = None,
        include_suppressed: bool = True,
        limit: int = 500,
        offset: int = 0,
    ) -> list[Finding]:
        stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
        for col, val in (
            (FindingRow.severity, severity),
            (FindingRow.provider, provider),
            (FindingRow.service, service),
            (FindingRow.category, category),
            (FindingRow.rule_id, rule_id),
        ):
            if val:
                stmt = stmt.where(col == val)
        stmt = stmt.order_by(FindingRow.pk).offset(offset).limit(limit)
        with self.db.session() as s:
            items = [Finding.model_validate(r.payload) for r in s.scalars(stmt).all()]
        suppressed = self.suppressed_ids()
        for f in items:
            f.suppressed = f.id in suppressed
        if not include_suppressed:
            items = [f for f in items if not f.suppressed]
        if q:
            needle = q.lower()
            items = [f for f in items if needle in f"{f.title} {f.message} {f.resource_name} {f.rule_id}".lower()]
        return items

    def finding(self, finding_id: str, scan_id: str | None = None) -> Finding | None:
        stmt = select(FindingRow).where(FindingRow.finding_id == finding_id).order_by(FindingRow.pk.desc())
        if scan_id:
            stmt = stmt.where(FindingRow.scan_id == scan_id)
        with self.db.session() as s:
            row = s.scalars(stmt).first()
            if not row:
                return None
            f = Finding.model_validate(row.payload)
        f.suppressed = f.id in self.suppressed_ids()
        return f

    def trend(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.db.session() as s:
            rows = s.scalars(
                select(ScanRow)
                .where(ScanRow.status.in_([ScanStatus.SUCCEEDED.value, ScanStatus.PARTIAL.value]))
                .order_by(ScanRow.started_at.desc())
                .limit(limit)
            ).all()
            return [
                {
                    "scan_id": r.id,
                    "at": _iso(r.started_at),
                    "score": r.score,
                    "findings": (r.summary or {}).get("total", 0),
                    "critical": (r.summary or {}).get("by_severity", {}).get("CRITICAL", 0),
                    "high": (r.summary or {}).get("by_severity", {}).get("HIGH", 0),
                }
                for r in reversed(rows)
            ]

    # ---------------------------------------------------------------- suppressions
    def suppress(self, finding_id: str, reason: str, by: str = "api", expires_at: datetime | None = None) -> None:
        with self.db.session() as s:
            s.merge(SuppressionRow(finding_id=finding_id, reason=reason, created_by=by, expires_at=expires_at))

    def unsuppress(self, finding_id: str) -> bool:
        with self.db.session() as s:
            res = s.execute(delete(SuppressionRow).where(SuppressionRow.finding_id == finding_id))
            return bool(res.rowcount)  # type: ignore[attr-defined]

    def suppressed_ids(self) -> set[str]:
        now = datetime.now(UTC)
        with self.db.session() as s:
            rows = s.scalars(select(SuppressionRow)).all()
            return {
                r.finding_id
                for r in rows
                if r.expires_at is None or (r.expires_at.replace(tzinfo=r.expires_at.tzinfo or UTC) > now)
            }

    def suppressions(self) -> list[dict[str, Any]]:
        with self.db.session() as s:
            return [
                {
                    "finding_id": r.finding_id,
                    "reason": r.reason,
                    "created_by": r.created_by,
                    "created_at": _iso(r.created_at),
                    "expires_at": _iso(r.expires_at),
                }
                for r in s.scalars(select(SuppressionRow)).all()
            ]
