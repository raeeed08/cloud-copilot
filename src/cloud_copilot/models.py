"""Domain model shared by the engine, the API, the store, the LLM layer and the MCP server."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}[self.value]

    @property
    def rank(self) -> int:
        return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(self.value)


class Provider(StrEnum):
    AWS = "aws"
    AZURE = "azure"


class Category(StrEnum):
    SECURITY = "security"
    COST = "cost"
    RELIABILITY = "reliability"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class ServiceStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    ERROR = "error"


class RuleInfo(BaseModel):
    id: str
    title: str
    provider: Provider
    service: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    terraform: str | None = None
    compliance: dict[str, list[str]] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    provider: Provider
    service: str
    severity: Severity
    category: Category
    resource_id: str
    resource_name: str
    region: str | None = None
    account: str | None = None
    message: str
    remediation: str
    terraform: str | None = None
    compliance: dict[str, list[str]] = Field(default_factory=dict)
    estimated_monthly_savings: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    suppressed: bool = False

    @staticmethod
    def make_id(rule_id: str, resource_id: str, region: str | None, account: str | None) -> str:
        raw = "|".join([rule_id, resource_id, region or "", account or ""])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ServiceResult(BaseModel):
    provider: Provider
    service: str
    status: ServiceStatus
    resources: int = 0
    duration_ms: int = 0
    rules_evaluated: int = 0
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)


class CostSummary(BaseModel):
    provider: Provider
    currency: str = "USD"
    period_start: str
    period_end: str
    total: float
    forecast_month_end: float | None = None
    by_service: list[dict[str, Any]] = Field(default_factory=list)


class ScanResult(BaseModel):
    id: str | None = None
    status: ScanStatus = ScanStatus.QUEUED
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    demo: bool = False
    accounts: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    services: list[ServiceResult] = Field(default_factory=list)
    inventory: dict[str, int] = Field(default_factory=dict)
    costs: list[CostSummary] = Field(default_factory=list)
    score: int | None = None
    controls_passed: int = 0
    controls_failed: int = 0
    explanation: str | None = None
    error: str | None = None
