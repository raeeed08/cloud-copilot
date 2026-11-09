"""Connected accounts and UI-managed settings. Secrets are encrypted with SecretBox before storage."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from cloud_copilot.crypto import SecretBox, mask
from cloud_copilot.store.db import AppSettingRow, CloudAccountRow, Database


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()


class AccountStore:
    def __init__(self, db: Database, box: SecretBox) -> None:
        self.db, self.box = db, box

    @staticmethod
    def public(row: CloudAccountRow, secret: dict[str, Any] | None = None) -> dict[str, Any]:
        """API view: never includes secret values, only masked hints."""
        hints = {k: mask(str(v)) for k, v in (secret or {}).items() if v}
        return {
            "id": row.id,
            "name": row.name,
            "provider": row.provider,
            "auth_method": row.auth_method,
            "config": row.config or {},
            "secret_hints": hints,
            "enabled": row.enabled,
            "status": row.status,
            "status_detail": row.status_detail,
            "identity": row.identity or {},
            "created_at": _iso(row.created_at),
            "verified_at": _iso(row.verified_at),
        }

    def create(
        self, name: str, provider: str, method: str, config: dict[str, Any], secret: dict[str, Any]
    ) -> dict[str, Any]:
        row = CloudAccountRow(
            id=str(uuid.uuid4()),
            name=name,
            provider=provider,
            auth_method=method,
            config=config,
            secret=self.box.encrypt(secret) if secret else None,
        )
        with self.db.session() as s:
            s.add(row)
        return self.public(row, secret)

    def update(self, account_id: str, **fields: Any) -> dict[str, Any] | None:
        with self.db.session() as s:
            row = s.get(CloudAccountRow, account_id)
            if not row:
                return None
            secret = fields.pop("secret", None)
            if secret:  # merge: blank fields keep their stored value
                merged = {**self.box.decrypt(row.secret), **{k: v for k, v in secret.items() if v}}
                row.secret = self.box.encrypt(merged)
            for k, v in fields.items():
                if v is not None:
                    setattr(row, k, v)
            return self.public(row, self.box.decrypt(row.secret))

    def set_status(self, account_id: str, status: str, detail: str | None, identity: dict[str, Any] | None) -> None:
        with self.db.session() as s:
            row = s.get(CloudAccountRow, account_id)
            if row:
                row.status, row.status_detail = status, detail
                if identity is not None:
                    row.identity = identity
                row.verified_at = datetime.now(UTC)

    def delete(self, account_id: str) -> bool:
        with self.db.session() as s:
            row = s.get(CloudAccountRow, account_id)
            if not row:
                return False
            s.delete(row)
            return True

    def list(self) -> list[dict[str, Any]]:
        with self.db.session() as s:
            rows = s.scalars(select(CloudAccountRow).order_by(CloudAccountRow.created_at)).all()
            return [self.public(r, self.box.decrypt(r.secret)) for r in rows]

    def get(self, account_id: str) -> dict[str, Any] | None:
        with self.db.session() as s:
            row = s.get(CloudAccountRow, account_id)
            return self.public(row, self.box.decrypt(row.secret)) if row else None

    def credentials(self, account_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """(public view, decrypted secret): for internal use only, never returned by the API."""
        with self.db.session() as s:
            row = s.get(CloudAccountRow, account_id)
            if not row:
                return None
            secret = self.box.decrypt(row.secret)
            return self.public(row, secret), secret


class SettingsStore:
    def __init__(self, db: Database, box: SecretBox) -> None:
        self.db, self.box = db, box

    def get(self, key: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        with self.db.session() as s:
            row = s.get(AppSettingRow, key)
            return (dict(row.value or {}), self.box.decrypt(row.secret)) if row else None

    def put(self, key: str, value: dict[str, Any], secret: dict[str, Any] | None) -> None:
        with self.db.session() as s:
            row = s.get(AppSettingRow, key)
            if row is None:
                row = AppSettingRow(key=key)
                s.add(row)
            row.value = value
            if secret is not None:
                row.secret = self.box.encrypt(secret) if secret else None
            row.updated_at = datetime.now(UTC)

    def delete(self, key: str) -> None:
        with self.db.session() as s:
            row = s.get(AppSettingRow, key)
            if row:
                s.delete(row)
