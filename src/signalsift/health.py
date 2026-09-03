"""Health checks: configuration, AWS, CloudWatch, Ollama, model, SQLite."""

from __future__ import annotations

import asyncio
from typing import Literal

from pydantic import BaseModel

from signalsift.cache.sqlite import SqliteCache
from signalsift.config import Settings
from signalsift.llm.base import LocalLLMProvider

CheckStatus = Literal["ok", "warn", "fail"]


class HealthCheck(BaseModel):
    name: str
    status: CheckStatus
    detail: str = ""


class HealthReport(BaseModel):
    checks: list[HealthCheck]

    @property
    def ready(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def render(self) -> str:
        lines = ["SignalSift health", ""]
        symbol = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}
        for check in self.checks:
            detail = f"  {check.detail}" if check.detail else ""
            lines.append(f"{check.name:<22}{symbol[check.status]}{detail}")
        lines.append("")
        lines.append("Ready." if self.ready else "Not ready — fix the failures above.")
        return "\n".join(lines)


async def run_health_checks(settings: Settings, llm: LocalLLMProvider) -> HealthReport:
    checks: list[HealthCheck] = []

    # Configuration
    if settings.allowed_log_groups:
        checks.append(
            HealthCheck(
                name="Config",
                status="ok",
                detail=f"{len(settings.allowed_log_groups)} log group(s) allowlisted",
            )
        )
    else:
        checks.append(
            HealthCheck(
                name="Config",
                status="warn",
                detail="SIGNALSIFT_ALLOWED_LOG_GROUPS is empty; all queries will be rejected",
            )
        )

    # AWS credentials + region
    def _check_aws() -> tuple[HealthCheck, HealthCheck]:
        try:
            import boto3

            session = boto3.Session(
                profile_name=settings.aws_profile, region_name=settings.aws_region
            )
            credentials = session.get_credentials()
            if credentials is None:
                return (
                    HealthCheck(
                        name="AWS credentials",
                        status="fail",
                        detail="none found — run `aws sso login` or configure a profile",
                    ),
                    HealthCheck(name="CloudWatch", status="fail", detail="skipped"),
                )
            region = session.region_name or "not set"
            creds_check = HealthCheck(
                name="AWS credentials", status="ok", detail=f"region {region}"
            )
            try:
                client = session.client("logs")
                client.describe_log_groups(limit=1)
                cw_check = HealthCheck(name="CloudWatch", status="ok")
            except Exception as exc:  # noqa: BLE001
                cw_check = HealthCheck(name="CloudWatch", status="warn", detail=str(exc)[:120])
            return creds_check, cw_check
        except Exception as exc:  # noqa: BLE001
            return (
                HealthCheck(name="AWS credentials", status="fail", detail=str(exc)[:120]),
                HealthCheck(name="CloudWatch", status="fail", detail="skipped"),
            )

    aws_checks = await asyncio.to_thread(_check_aws)
    checks.extend(aws_checks)

    # Ollama
    if await llm.is_available():
        checks.append(HealthCheck(name="Ollama", status="ok", detail=settings.ollama_url))
        if await llm.model_available():
            checks.append(HealthCheck(name="Model", status="ok", detail=llm.model_name))
        else:
            checks.append(
                HealthCheck(
                    name="Model",
                    status="warn",
                    detail=f"{llm.model_name} not pulled — run: ollama pull {llm.model_name}",
                )
            )
    else:
        checks.append(
            HealthCheck(
                name="Ollama",
                status="warn",
                detail=f"unreachable at {settings.ollama_url} — deterministic analysis still works",
            )
        )
        checks.append(HealthCheck(name="Model", status="warn", detail="skipped"))

    # SQLite cache
    try:
        cache = SqliteCache(settings.cache_path, settings.cache_ttl_seconds)
        cache.close()
        checks.append(
            HealthCheck(name="SQLite cache", status="ok", detail=str(settings.cache_path))
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(HealthCheck(name="SQLite cache", status="fail", detail=str(exc)[:120]))

    return HealthReport(checks=checks)
