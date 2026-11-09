from __future__ import annotations

import os
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

# Never let tests touch real clouds or LLMs.
os.environ.update(
    AWS_ACCESS_KEY_ID="testing",
    AWS_SECRET_ACCESS_KEY="testing",
    AWS_SECURITY_TOKEN="testing",
    AWS_SESSION_TOKEN="testing",
    AWS_DEFAULT_REGION="us-east-1",
    LLM_API_KEY="",
    OPENROUTER_API_KEY="",
    LOG_LEVEL="WARNING",
    MOTO_IAM_LOAD_MANAGED_POLICIES="true",
)

from cloud_copilot.config import Settings
from cloud_copilot.service import CopilotService


@pytest.fixture
def settings(tmp_path: Any) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        demo_mode=True,
        database_url=f"sqlite:///{tmp_path}/test.db",
        llm_api_key=None,
        openrouter_api_key=None,
        environment="test",
    )


@pytest.fixture
def service(settings: Settings) -> Iterator[CopilotService]:
    svc = CopilotService(settings)
    yield svc
    svc._executor.shutdown(wait=True)


@pytest.fixture
def scanned(service: CopilotService) -> CopilotService:
    service.run_scan_sync(trigger="test", explain=True)
    return service


class FakeCompletions:
    def __init__(self, replies: list[Any]) -> None:
        self.replies = replies
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        reply = self.replies.pop(0) if self.replies else "ok"
        if isinstance(reply, Exception):
            raise reply
        return SimpleNamespace(
            model=kwargs["model"],
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
        )


class FakeOpenAI:
    def __init__(self, replies: list[Any]) -> None:
        self.chat = SimpleNamespace(completions=FakeCompletions(replies))


@pytest.fixture
def fake_llm() -> type[FakeOpenAI]:
    return FakeOpenAI
