"""AWS session handling: credentials, region discovery, retries and parallel per-region fan-out."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import cached_property
from typing import Any, TypeVar

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from cloud_copilot.log import get_logger

log = get_logger(__name__)
T = TypeVar("T")

BOTO_CONFIG = Config(
    retries={"max_attempts": 8, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra="cloud-copilot/2.0",
)

# Errors meaning "this region/service isn't usable here" rather than "the scan is broken".
SOFT_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "OptInRequired",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "SubscriptionRequiredException",
}


class NotConfiguredError(RuntimeError):
    """The provider is not configured (no credentials / SDK). The service is skipped, not failed."""


def error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", "ClientError"))
    return type(exc).__name__


class AwsContext:
    def __init__(
        self,
        session: boto3.session.Session | None = None,
        regions: list[str] | None = None,
        home_region: str = "us-east-1",
        max_workers: int = 8,
        profile: str | None = None,
    ) -> None:
        self.session = session or boto3.session.Session(profile_name=profile)
        self._regions = regions or []
        self.home_region = home_region
        self.max_workers = max_workers
        self.warnings: list[str] = []

    def client(self, service: str, region: str | None = None) -> Any:
        return self.session.client(  # type: ignore[call-overload]
            service, region_name=region or self.home_region, config=BOTO_CONFIG
        )

    @cached_property
    def account_id(self) -> str:
        try:
            return str(self.client("sts").get_caller_identity()["Account"])
        except NoCredentialsError as exc:
            raise NotConfiguredError("no AWS credentials found") from exc
        except (ClientError, BotoCoreError) as exc:
            raise NotConfiguredError(f"AWS credentials unusable: {error_code(exc)}") from exc

    @cached_property
    def regions(self) -> list[str]:
        if self._regions:
            return list(self._regions)
        try:
            resp = self.client("ec2").describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            return sorted(r["RegionName"] for r in resp["Regions"])
        except (ClientError, BotoCoreError) as exc:
            log.warning("region_discovery_failed", error=error_code(exc))
            return [self.home_region]

    def for_each_region(self, fn: Callable[[str], list[T]], label: str) -> list[T]:
        """Run ``fn(region)`` in parallel. Soft per-region errors become warnings, not failures."""
        results: list[T] = []

        def safe(region: str) -> list[T]:
            try:
                return fn(region)
            except (ClientError, BotoCoreError) as exc:
                code = error_code(exc)
                msg = f"{label}@{region}: {code}"
                if code not in SOFT_ERROR_CODES:
                    log.warning("region_scan_error", label=label, region=region, error=str(exc))
                self.warnings.append(msg)
                return []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for chunk in pool.map(safe, self.regions):
                results.extend(chunk)
        return results


def paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def soft_call(fn: Callable[[], Any], default: Any, *ok_codes: str) -> Any:
    """Call ``fn``; return ``default`` if AWS answers with one of ``ok_codes`` (e.g. 'not configured')."""
    try:
        return fn()
    except ClientError as exc:
        if error_code(exc) in ok_codes:
            return default
        raise
