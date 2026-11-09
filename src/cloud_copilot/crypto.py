"""
Encryption at rest for stored secrets (cloud credentials, LLM API keys).

Fernet = AES-128-CBC + HMAC-SHA256 with a random IV. The key comes from SECRET_KEY (Kubernetes Secret /
Key Vault / Secrets Manager in production). In dev a key is generated once into data/secret.key (mode 0600).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from cloud_copilot.config import Settings


class SecretBoxError(RuntimeError):
    pass


class SecretBox:
    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretBox:
        if settings.secret_key:
            return cls(settings.secret_key.get_secret_value().encode())
        path = Path(settings.secret_key_file)
        if path.exists():
            return cls(path.read_bytes().strip())
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return cls(key)

    def encrypt(self, payload: dict[str, Any]) -> str:
        return self._fernet.encrypt(json.dumps(payload).encode()).decode()

    def decrypt(self, token: str | None) -> dict[str, Any]:
        if not token:
            return {}
        try:
            return json.loads(self._fernet.decrypt(token.encode()))
        except InvalidToken as exc:
            raise SecretBoxError("cannot decrypt stored secret: SECRET_KEY changed or data corrupted") from exc


def mask(value: str | None) -> str | None:
    if not value:
        return None
    return f"…{value[-4:]}" if len(value) > 8 else "…"


def generate_key() -> str:
    return Fernet.generate_key().decode()
