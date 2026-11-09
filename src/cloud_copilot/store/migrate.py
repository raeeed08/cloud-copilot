"""Run Alembic migrations programmatically (startup, CLI, Helm hook)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Engine

MIGRATIONS = Path(__file__).parent / "migrations"
LOCK_ID = 7_202_611  # arbitrary, app-specific advisory lock key


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(engine: Engine) -> None:
    """Upgrade to head. On PostgreSQL an advisory lock serialises concurrent replicas."""
    cfg = alembic_config(engine.url.render_as_string(hide_password=False))
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LOCK_ID})
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
