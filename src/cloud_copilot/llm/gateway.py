"""
LLM gateway: one OpenAI-compatible client for OpenRouter, Groq, OpenAI, Azure OpenAI, Ollama, vLLM…

* ordered model fallback chain
* retries with exponential backoff on transient errors (429/5xx/timeouts) only
* hard timeouts, token accounting, Prometheus metrics
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from cloud_copilot.config import Settings
from cloud_copilot.llm.providers import LLMConfig
from cloud_copilot.log import get_logger
from cloud_copilot.metrics import LLM_LATENCY, LLM_REQUESTS, LLM_TOKENS

log = get_logger(__name__)
# reasoning models (Qwen, DeepSeek-R1…) may inline their chain of thought; never show it to users
THINK = re.compile(r"<think>.*?</think>", re.S)
# Models put <br> in table cells; the UI never renders raw HTML, so turn it into a separator.
BR = re.compile(r"<br\s*/?>", re.I)


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
    def __init__(self, settings: Settings, client: Any = None, config: LLMConfig | None = None) -> None:
        self.settings = settings
        self.config = config or LLMConfig.from_settings(settings)
        self.models = self.config.models
        self.max_tokens = self.config.max_tokens
        self._client = client
        if self._client is None and self.config.usable:
            from openai import OpenAI

            self._client = OpenAI(
                base_url=self.config.base_url,
                api_key=self.config.api_key or "not-needed",
                timeout=self.config.timeout,
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
            raise LLMUnavailableError("no AI provider configured (Settings → AI provider)")
        errors: list[str] = []
        for model in self.models:
            try:
                return self._call(model, messages, max_tokens or self.max_tokens, temperature)
            except Exception as exc:
                errors.append(f"{model}: {type(exc).__name__}: {str(exc)[:160]}")
                LLM_REQUESTS.labels(model=model, outcome="error").inc()
                log.warning("llm_model_failed", model=model, error=type(exc).__name__)
                if getattr(exc, "status_code", None) in (401, 403):  # same key for every model: stop early
                    raise LLMUnavailableError("AI provider rejected the API key") from exc
        detail = " | ".join(errors) if errors else "no model configured"
        raise LLMUnavailableError(f"all models failed ({detail})")

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
        text = BR.sub(" ", THINK.sub("", resp.choices[0].message.content or "")).strip()
        if not text:
            raise ValueError("empty completion (reasoning model ran out of max_tokens?)")
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
