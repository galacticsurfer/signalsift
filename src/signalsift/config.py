"""Application configuration via Pydantic Settings.

All limits are configurable but ship with safe defaults. The log-group
allowlist is the primary security boundary: an empty allowlist rejects
every query.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIGNALSIFT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # AWS
    aws_profile: str | None = None
    aws_region: str | None = None

    # Security boundary: only these log groups may ever be queried.
    # NoDecode: the env var is comma-separated, not JSON.
    allowed_log_groups: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Query guardrails
    max_time_range_minutes: int = 120
    max_query_results: int = 5000
    query_timeout_seconds: int = 90
    query_poll_initial_seconds: float = 1.0
    query_poll_max_seconds: float = 5.0

    # Local LLM. Default is a NON-thinking model: thinking models generate
    # a hidden reasoning chain that multiplies latency and makes it
    # unpredictable, which structured incident extraction doesn't need.
    ollama_url: str = "http://localhost:11434"
    llm_model: str = "qwen2.5:7b"
    llm_timeout_seconds: int = 120
    max_llm_input_chars: int = 40000
    max_llm_output_chars: int = 20000
    # Thinking models (qwen3 etc.) generate a hidden reasoning chain before
    # the JSON — often thousands of tokens. Off by default: latency beats
    # marginal quality here (spec §4). Ignored by non-thinking models.
    llm_thinking: bool = False

    # Reduction budgets
    max_clusters: int = 50
    max_clusters_to_llm: int = 10
    # Clusters shown in a focused incident report (search results always
    # include every cluster that survived the max_clusters budget).
    max_report_clusters: int = 10
    max_examples_per_cluster: int = 3
    max_chars_per_example: int = 800

    # MCP response guardrail
    max_mcp_response_chars: int = 12000

    # Cache
    cache_path: Path = Path("~/.signalsift/cache.sqlite3")
    cache_ttl_seconds: int = 900

    # Optional PII redaction (secrets are always redacted)
    redact_emails: bool = True
    redact_phone_numbers: bool = False
    redact_ip_addresses: bool = False

    # Logging
    log_level: str = "INFO"
    debug: bool = False

    @field_validator("allowed_log_groups", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("cache_path", mode="after")
    @classmethod
    def _expand_path(cls, v: Path) -> Path:
        return v.expanduser()


def load_settings(**overrides: object) -> Settings:
    """Load settings from environment / .env, with optional overrides."""
    return Settings(**overrides)  # type: ignore[arg-type]
