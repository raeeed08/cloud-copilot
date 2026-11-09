"""LLM provider presets and the runtime configuration (env defaults, overridable from the UI)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_copilot.config import Settings

PRESETS: dict[str, dict[str, Any]] = {
    "groq": {
        "label": "Groq (fast, free tier)",
        "base_url": "https://api.groq.com/openai/v1",
        "models": ["llama-3.3-70b-versatile", "openai/gpt-oss-20b", "llama-3.1-8b-instant"],
        "key_url": "https://console.groq.com/keys",
        "needs_key": True,
    },
    "openrouter": {
        "label": "OpenRouter (many models, free tier)",
        "base_url": "https://openrouter.ai/api/v1",
        "models": ["openrouter/free", "openai/gpt-oss-20b:free", "google/gemma-3-27b-it:free"],
        "key_url": "https://openrouter.ai/settings/keys",
        "needs_key": True,
    },
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o-mini"],
        "key_url": "https://platform.openai.com/api-keys",
        "needs_key": True,
    },
    "ollama": {
        "label": "Ollama (local, no key)",
        "base_url": "http://ollama:11434/v1",
        "models": ["llama3.2"],
        "key_url": "https://ollama.com",
        "needs_key": False,
    },
    "custom": {
        "label": "Custom OpenAI-compatible endpoint",
        "base_url": "",
        "models": [],
        "key_url": "",
        "needs_key": True,
    },
}


def detect_provider(base_url: str) -> str:
    for name, p in PRESETS.items():
        if p["base_url"] and p["base_url"].split("/v1")[0] in base_url:
            return name
    return "custom"


@dataclass
class LLMConfig:
    provider: str
    base_url: str
    models: list[str]
    api_key: str | None
    language: str = "English"
    source: str = "env"  # env | ui | none
    timeout: float = 45.0
    max_tokens: int = 1200
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        needs_key = PRESETS.get(self.provider, PRESETS["custom"])["needs_key"]
        return bool(self.base_url and self.models and (self.api_key or not needs_key))

    @classmethod
    def from_settings(cls, s: Settings) -> LLMConfig:
        key = s.effective_llm_key
        return cls(
            provider=detect_provider(s.llm_base_url),
            base_url=s.llm_base_url,
            models=list(s.llm_models),
            api_key=key,
            language=s.llm_language,
            source="env" if key else "none",
            timeout=s.llm_timeout_seconds,
            max_tokens=s.llm_max_tokens,
        )
