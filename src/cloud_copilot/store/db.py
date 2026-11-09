"""Persistence (SQLAlchemy 2.0). SQLite for local dev, PostgreSQL in Compose/Kubernetes."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    demo: Mapped[bool] = mapped_column(default=False)
    trigger: Mapped[str] = mapped_column(String(32), default="api")
    score: Mapped[int | None] = mapped_column(Integer)
    controls_passed: Mapped[int] = mapped_column(Integer, default=0)
    controls_failed: Mapped[int] = mapped_column(Integer, default=0)
    accounts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    services: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    inventory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    costs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    explanation: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    evaluated_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    scenarios: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    findings: Mapped[list[FindingRow]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    provider: Mapped[str] = mapped_column(String(16), index=True)
    service: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(16))
    savings: Mapped[float | None] = mapped_column(Float)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

    scan: Mapped[ScanRow] = relationship(back_populates="findings")


class SuppressionRow(Base):
    """Accepted risk / false positive. Suppressed findings stay visible but don't count in the score."""

    __tablename__ = "suppressions"

    finding_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(128), default="api")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CloudAccountRow(Base):
    """A connected cloud account. Secrets are Fernet-encrypted, never returned by the API."""

    __tablename__ = "cloud_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(16), index=True)
    auth_method: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(16), default="unverified")
    status_detail: Mapped[str | None] = mapped_column(Text)
    identity: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AppSettingRow(Base):
    """Runtime settings changed from the UI (e.g. LLM provider). Secret part is encrypted."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Database:
    def __init__(self, url: str) -> None:
        kwargs: dict[str, Any] = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            path = url.split("///", 1)[-1]
            if path and path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
            kwargs["connect_args"] = {"check_same_thread": False}
            if path in ("", ":memory:"):
                from sqlalchemy.pool import StaticPool

                kwargs["poolclass"] = StaticPool
        self.engine: Engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", lambda c, _: c.execute("PRAGMA foreign_keys=ON"))
        self._session = sessionmaker(self.engine, expire_on_commit=False)

    def migrate(self) -> None:
        from cloud_copilot.store.migrate import upgrade

        upgrade(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def ping(self) -> bool:
        from sqlalchemy import text

        with self.engine.connect() as c:
            c.execute(text("SELECT 1"))
        return True
