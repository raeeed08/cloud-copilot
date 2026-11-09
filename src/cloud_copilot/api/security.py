"""API-key authentication and in-memory token-bucket rate limiting."""

from __future__ import annotations

import hmac
import threading
import time

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from cloud_copilot.config import Settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def require_api_key(
    request: Request,
    key: str | None = Depends(api_key_header),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> str:
    settings: Settings = request.app.state.settings
    if not settings.auth_enabled:
        return "anonymous"
    supplied = key or (creds.credentials if creds else None)
    if supplied:
        for i, valid in enumerate(settings.api_keys):
            if hmac.compare_digest(supplied.encode(), valid.get_secret_value().encode()):
                return f"key-{i}"
    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED, "invalid or missing API key", headers={"WWW-Authenticate": "Bearer"}
    )


class RateLimiter:
    """Token bucket per (principal, bucket). Good enough for a single replica; use Redis for many."""

    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str], tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, principal: str, bucket: str, per_minute: int) -> None:
        if per_minute <= 0:
            return
        now = time.monotonic()
        rate = per_minute / 60.0
        with self._lock:
            tokens, last = self._buckets.get((principal, bucket), (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * rate)
            if tokens < 1:
                retry = int((1 - tokens) / rate) + 1
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded", headers={"Retry-After": str(retry)}
                )
            self._buckets[(principal, bucket)] = (tokens - 1, now)
