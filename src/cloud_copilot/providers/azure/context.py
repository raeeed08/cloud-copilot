"""Azure credentials & subscriptions. The Azure SDK is an optional extra (pip install cloud-copilot[azure])."""

from __future__ import annotations

from functools import cached_property
from typing import Any

from cloud_copilot.providers.aws.context import NotConfiguredError


def sdk_available() -> bool:
    try:
        import azure.identity  # noqa: F401
    except ImportError:
        return False
    return True


class AzureContext:
    def __init__(self, subscription_ids: list[str] | None = None, credential: Any = None) -> None:
        if credential is None:
            if not sdk_available():
                raise NotConfiguredError("Azure SDK not installed (pip install 'cloud-copilot[azure]')")
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        self.credential = credential
        self._subscription_ids = subscription_ids or []
        self.warnings: list[str] = []

    @cached_property
    def subscription_ids(self) -> list[str]:
        if self._subscription_ids:
            return self._subscription_ids
        try:
            from azure.mgmt.resource import SubscriptionClient

            subs = [s.subscription_id for s in SubscriptionClient(self.credential).subscriptions.list()]
        except Exception as exc:  # azure-identity raises many credential error types
            raise NotConfiguredError(f"Azure credentials unusable: {type(exc).__name__}") from exc
        if not subs:
            raise NotConfiguredError("no Azure subscription visible to these credentials")
        return subs


def resource_group(resource_id: str | None) -> str:
    parts = (resource_id or "").split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        try:
            return parts[[p.lower() for p in parts].index("resourcegroups") + 1]
        except (ValueError, IndexError):
            return ""
