"""REST API v1."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from cloud_copilot.api.security import require_api_key
from cloud_copilot.core.registry import RULES, SCANNERS, load_all
from cloud_copilot.models import Finding, Provider, RuleInfo
from cloud_copilot.service import CopilotService, ScanInProgressError

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])
Principal = Annotated[str, Depends(require_api_key)]


def svc(request: Request) -> CopilotService:
    return request.app.state.service


Svc = Annotated[CopilotService, Depends(svc)]


# ------------------------------------------------------------------ schemas
class ScanRequest(BaseModel):
    providers: list[Provider] | None = None
    explain: bool = True


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=4000)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    history: list[ChatTurn] = Field(default_factory=list, max_length=20)


class SuppressRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
    expires_at: datetime | None = None


# ------------------------------------------------------------------ scans
@router.post("/scans", status_code=status.HTTP_202_ACCEPTED, tags=["scans"])
def create_scan(body: ScanRequest, request: Request, s: Svc, who: Principal) -> dict[str, Any]:
    request.app.state.limiter.check(who, "scan", s.settings.scan_rate_limit_per_minute)
    try:
        scan_id, _ = s.start_scan(body.providers, trigger="api", explain=body.explain)
    except ScanInProgressError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan {exc} already running") from exc
    return {"id": scan_id, "status": "queued", "href": f"/api/v1/scans/{scan_id}"}


@router.get("/scans", tags=["scans"])
def list_scans(s: Svc, limit: int = Query(30, le=200)) -> list[dict[str, Any]]:
    return s.repo.list_scans(limit)


@router.get("/scans/latest", tags=["scans"])
def latest_scan(s: Svc) -> dict[str, Any]:
    scan = s.latest()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no completed scan yet")
    return scan


@router.get("/scans/{scan_id}", tags=["scans"])
def get_scan(scan_id: str, s: Svc) -> dict[str, Any]:
    scan = s.repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


@router.get("/trend", tags=["scans"])
def trend(s: Svc, limit: int = Query(30, le=200)) -> list[dict[str, Any]]:
    return s.repo.trend(limit)


# ------------------------------------------------------------------ findings
def _resolve_scan(s: CopilotService, scan_id: str | None) -> str:
    if scan_id:
        return scan_id
    latest = s.latest()
    if not latest:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no completed scan yet")
    return str(latest["id"])


@router.get("/findings", tags=["findings"])
def list_findings(
    s: Svc,
    scan_id: str | None = None,
    severity: str | None = None,
    provider: str | None = None,
    service: str | None = None,
    category: str | None = None,
    rule_id: str | None = None,
    q: str | None = Query(None, max_length=200),
    include_suppressed: bool = True,
    limit: int = Query(500, le=5000),
    offset: int = 0,
) -> list[Finding]:
    return s.repo.findings(
        _resolve_scan(s, scan_id),
        severity=severity,
        provider=provider,
        service=service,
        category=category,
        rule_id=rule_id,
        q=q,
        include_suppressed=include_suppressed,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/export", tags=["findings"])
def export_findings(s: Svc, fmt: Literal["csv", "md"] = "csv", scan_id: str | None = None) -> Any:
    sid = _resolve_scan(s, scan_id)
    items = s.repo.findings(sid, limit=100000)
    if fmt == "md":
        lines = [
            f"# Cloud Copilot report — scan {sid}",
            "",
            "| Severity | Rule | Resource | Region | Issue |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {f.severity.value} | {f.rule_id} | {f.resource_name} | {f.region or ''} | "
            f"{f.message.replace('|', '/')} |"
            for f in items
            if not f.suppressed
        ]
        return PlainTextResponse(
            "\n".join(lines),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="report-{sid[:8]}.md"'},
        )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "severity",
            "rule_id",
            "title",
            "provider",
            "service",
            "resource",
            "region",
            "account",
            "message",
            "monthly_savings",
            "suppressed",
        ]
    )
    for f in items:
        w.writerow(
            [
                f.id,
                f.severity.value,
                f.rule_id,
                f.title,
                f.provider.value,
                f.service,
                f.resource_name,
                f.region,
                f.account,
                f.message,
                f.estimated_monthly_savings or "",
                f.suppressed,
            ]
        )
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="findings-{sid[:8]}.csv"'},
    )


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(finding_id: str, s: Svc) -> Finding:
    f = s.repo.finding(finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return f


@router.put("/findings/{finding_id}/suppression", tags=["findings"])
def suppress(finding_id: str, body: SuppressRequest, s: Svc, who: Principal) -> dict[str, str]:
    if not s.repo.finding(finding_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    s.repo.suppress(finding_id, body.reason, by=who, expires_at=body.expires_at)
    return {"status": "suppressed"}


@router.delete("/findings/{finding_id}/suppression", tags=["findings"])
def unsuppress(finding_id: str, s: Svc) -> dict[str, str]:
    if not s.repo.unsuppress(finding_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no suppression for this finding")
    return {"status": "active"}


@router.get("/suppressions", tags=["findings"])
def suppressions(s: Svc) -> list[dict[str, Any]]:
    return s.repo.suppressions()


# ------------------------------------------------------------------ catalog / posture
@router.get("/rules", tags=["catalog"])
def rules(provider: Provider | None = None, service: str | None = None) -> list[RuleInfo]:
    load_all()
    return [
        r.info
        for r in RULES.values()
        if (provider is None or r.info.provider is provider) and (service is None or r.info.service == service)
    ]


@router.get("/rules/{rule_id}", tags=["catalog"])
def rule(rule_id: str) -> RuleInfo:
    load_all()
    if rule_id not in RULES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    return RULES[rule_id].info


@router.get("/services", tags=["catalog"])
def services() -> list[dict[str, Any]]:
    load_all()
    return [
        {
            "provider": p.value,
            "service": svc_name,
            "description": sc.description,
            "rules": sum(1 for r in RULES.values() if r.info.provider is p and r.info.service == svc_name),
        }
        for (p, svc_name), sc in sorted(SCANNERS.items())
    ]


@router.get("/compliance", tags=["posture"])
def compliance(s: Svc) -> dict[str, Any]:
    return s.compliance()


# ------------------------------------------------------------------ copilot
@router.post("/chat", tags=["copilot"])
def chat(body: ChatRequest, request: Request, s: Svc, who: Principal) -> dict[str, Any]:
    request.app.state.limiter.check(who, "chat", s.settings.chat_rate_limit_per_minute)
    return s.ask(body.message, [t.model_dump() for t in body.history])


@router.get("/knowledge/search", tags=["copilot"])
def knowledge_search(
    s: Svc, q: str = Query(..., min_length=2, max_length=300), k: int = Query(5, le=20)
) -> list[dict[str, Any]]:
    return [
        {"id": h.chunk.id, "title": h.chunk.title, "score": round(h.score, 4), "text": h.chunk.text}
        for h in s.retriever.search(q, k=k)
    ]
