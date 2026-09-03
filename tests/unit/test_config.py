"""Configuration loading tests."""

from __future__ import annotations

from signalsift.config import Settings


def test_allowlist_parsed_from_csv_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "SIGNALSIFT_ALLOWED_LOG_GROUPS", "/aws/app/a, /aws/app/b ,/aws/app/c"
    )
    settings = Settings(_env_file=None)
    assert settings.allowed_log_groups == ["/aws/app/a", "/aws/app/b", "/aws/app/c"]


def test_allowlist_single_value_env(monkeypatch) -> None:
    monkeypatch.setenv("SIGNALSIFT_ALLOWED_LOG_GROUPS", "/aws/app/test")
    settings = Settings(_env_file=None)
    assert settings.allowed_log_groups == ["/aws/app/test"]


def test_allowlist_defaults_empty() -> None:
    assert Settings(_env_file=None).allowed_log_groups == []


def test_cache_path_expands_user() -> None:
    settings = Settings(_env_file=None, cache_path="~/x/cache.sqlite3")
    assert "~" not in str(settings.cache_path)


def test_safe_default_limits() -> None:
    settings = Settings(_env_file=None)
    assert settings.max_time_range_minutes == 120
    assert settings.max_query_results == 5000
    assert settings.max_llm_input_chars == 40000
