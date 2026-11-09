"""Application settings, loaded from environment variables (12-factor) or a .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- runtime -----------------------------------------------------------
    environment: Literal["dev", "test", "staging", "prod"] = "dev"
    log_level: str = "INFO"
    log_json: bool = False
    demo_mode: bool = Field(
        default=False,
        description="Scan a built-in synthetic multi-cloud estate instead of real accounts.",
    )

    # --- providers ---------------------------------------------------------
    providers: Annotated[list[str], NoDecode] = ["aws", "azure"]
    aws_profile: str | None = None
    aws_regions: Annotated[list[str], NoDecode] = Field(
        default_factory=list, description="Regions to scan. Empty = every enabled region."
    )
    aws_home_region: str = "us-east-1"
    aws_max_workers: int = 8
    azure_subscription_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)
    cost_enabled: bool = True
    scan_on_startup: bool = Field(default=False, description="Run a scan at API startup if none exists yet.")

    # --- persistence -------------------------------------------------------
    database_url: str = "sqlite:///./data/cloud_copilot.db"
    secret_key: SecretStr | None = Field(
        default=None,
        description="Fernet key encrypting stored credentials. Generated into data/secret.key if unset (dev).",
    )
    secret_key_file: str = "./data/secret.key"  # noqa: S105 - a path, not a secret

    # --- API ---------------------------------------------------------------
    api_keys: Annotated[list[SecretStr], NoDecode] = Field(
        default_factory=list, description="Accepted API keys. Empty = auth disabled (dev only)."
    )
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    chat_rate_limit_per_minute: int = 20
    scan_rate_limit_per_minute: int = 2

    # --- LLM ---------------------------------------------------------------
    llm_base_url: str = "https://openrouter.ai/api/v1"
    llm_api_key: SecretStr | None = Field(default=None, alias="LLM_API_KEY")
    openrouter_api_key: SecretStr | None = None  # backward compatibility with v1 .env
    llm_models: Annotated[list[str], NoDecode] = [
        "openrouter/free",
        "openai/gpt-oss-20b:free",
        "google/gemma-3-27b-it:free",
    ]
    llm_timeout_seconds: float = 45.0
    llm_max_tokens: int = 1200
    llm_language: str = "English"
    llm_redact: bool = Field(default=True, description="Pseudonymise account IDs, ARNs, IPs before sending.")

    # --- RAG ---------------------------------------------------------------
    knowledge_dir: Path | None = None
    embeddings_base_url: str | None = None  # e.g. http://ollama:11434/v1
    embeddings_model: str = "nomic-embed-text"
    embeddings_api_key: SecretStr | None = None
    rag_top_k: int = 5

    # --- observability -----------------------------------------------------
    otel_exporter_otlp_endpoint: str | None = None

    _split = field_validator(
        "providers",
        "aws_regions",
        "azure_subscription_ids",
        "cors_origins",
        "llm_models",
        "api_keys",
        mode="before",
    )(_split_csv)

    @property
    def effective_llm_key(self) -> str | None:
        key = self.llm_api_key or self.openrouter_api_key
        return key.get_secret_value() if key else None

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_keys)


@lru_cache
def get_settings() -> Settings:
    return Settings()
