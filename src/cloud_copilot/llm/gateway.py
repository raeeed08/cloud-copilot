"""
LLM gateway: one OpenAI-compatible client for OpenRouter, Groq, OpenAI, Azure OpenAI, Ollama, vLLM…

* ordered model fallback chain
* retries with exponential backoff on transient errors (429/5xx/timeouts) only
* hard timeouts, token accounting, Prometheus metrics
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from cloud_copilot.config import Settings
from cloud_copilot.log import get_logger
from cloud_copilot.metrics import LLM_LATENCY, LLM_REQUESTS, LLM_TOKENS

log = get_logger(__name__)


class LLMUnavailableError(RuntimeError):
    pass


@dataclass
class LLMReply:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0


def _transient(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None)
    name = type(exc).__name__
    return status in (408, 409, 429, 500, 502, 503, 504) or name in ("APITimeoutError", "APIConnectionError")


class LLMGateway:
    def __init__(self, settings: Settings, client: Any = None) -> None:
        self.settings = settings
        self.models = settings.llm_models
        self._client = client
        if self._client is None and settings.effective_llm_key:
            from openai import OpenAI

            self._client = OpenAI(
                base_url=settings.llm_base_url,
                api_key=settings.effective_llm_key,
                timeout=settings.llm_timeout_seconds,
                max_retries=0,  # retries handled below, per model
                default_headers={"X-Title": "Cloud Copilot"},
            )

    @property
    def available(self) -> bool:
        return self._client is not None

    def complete(
        self, messages: list[dict[str, str]], max_tokens: int | None = None, temperature: float = 0.2
    ) -> LLMReply:
        if not self.available:
            raise LLMUnavailableError("no LLM API key configured")
        last: Exception | None = None
        for model in self.models:
            try:
                return self._call(model, messages, max_tokens or self.settings.llm_max_tokens, temperature)
            except Exception as exc:
                last = exc
                LLM_REQUESTS.labels(model=model, outcome="error").inc()
                log.warning("llm_model_failed", model=model, error=type(exc).__name__)
                if getattr(exc, "status_code", None) in (401, 403):  # same key for every model: stop early
                    raise LLMUnavailableError("LLM credentials rejected (check LLM_API_KEY)") from exc
        raise LLMUnavailableError(f"all models failed: {type(last).__name__ if last else 'unknown'}")

    @retry(
        retry=retry_if_exception(_transient),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=6),
        reraise=True,
    )
    def _call(self, model: str, messages: list[dict[str, str]], max_tokens: int, temperature: float) -> LLMReply:
        started = time.perf_counter()
        resp = self._client.chat.completions.create(
            model=model, messages=messages, max_tokens=max_tokens, temperature=temperature
        )
        elapsed = time.perf_counter() - started
        text = (resp.choices[0].message.content or "").strip()
        if not text:
            raise ValueError("empty completion")
        usage = getattr(resp, "usage", None)
        reply = LLMReply(
            text=text,
            model=getattr(resp, "model", None) or model,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            latency_ms=int(elapsed * 1000),
        )
        LLM_REQUESTS.labels(model=model, outcome="ok").inc()
        LLM_LATENCY.labels(model=model).observe(elapsed)
        LLM_TOKENS.labels(model=model, kind="prompt").inc(reply.prompt_tokens)
        LLM_TOKENS.labels(model=model, kind="completion").inc(reply.completion_tokens)
        return reply
