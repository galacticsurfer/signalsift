"""Shared fixtures: settings, fake CloudWatch client, fake LLM provider."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from signalsift.analysis.schemas import (
    Evidence,
    IncidentAnalysis,
    RootCauseHypothesis,
)
from signalsift.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        allowed_log_groups=["/aws/app/payments-prod", "/aws/app/orders-prod"],
        cache_path=":memory:",
        aws_profile=None,
        aws_region="us-east-1",
    )


class FakeLogsClient:
    """Implements the LogsInsightsClient protocol against canned rows."""

    def __init__(self, rows: list[list[dict]], statistics: dict | None = None) -> None:
        self.rows = rows
        self.statistics = statistics or {
            "recordsMatched": float(len(rows)),
            "recordsScanned": float(len(rows) * 3),
            "bytesScanned": 1024.0 * len(rows),
        }
        self.started_queries: list[dict[str, Any]] = []
        self.stopped: list[str] = []

    def start_query(self, **kwargs: Any) -> dict[str, Any]:
        self.started_queries.append(kwargs)
        return {"queryId": f"q-{len(self.started_queries)}"}

    def get_query_results(self, *, queryId: str) -> dict[str, Any]:  # noqa: N803
        return {"status": "Complete", "results": self.rows, "statistics": self.statistics}

    def stop_query(self, *, queryId: str) -> dict[str, Any]:  # noqa: N803
        self.stopped.append(queryId)
        return {"success": True}


class FakeLLMProvider:
    """Deterministic LocalLLMProvider double; records every prompt."""

    def __init__(
        self,
        analysis: IncidentAnalysis | None = None,
        error: Exception | None = None,
    ) -> None:
        self.prompts: list[str] = []
        self.error = error
        self.analysis = analysis or IncidentAnalysis(
            summary="Database connectivity failure dominates the window.",
            severity="high",
            likely_root_causes=[
                RootCauseHypothesis(
                    cause="MongoDB connectivity or pool exhaustion",
                    confidence=0.8,
                    evidence=[Evidence(statement="Timeout cluster dominates", cluster_ids=[])],
                )
            ],
            affected_components=["/checkout"],
            timeline=["14:07 first spike"],
            recommended_checks=["Check Mongo connection pool saturation"],
            uncertainties=["Cannot distinguish node failure from network issues"],
        )

    @property
    def model_name(self) -> str:
        return "fake-model"

    async def is_available(self) -> bool:
        return self.error is None

    async def model_available(self) -> bool:
        return self.error is None

    async def analyze(self, prompt: str, schema: type[BaseModel]) -> BaseModel:
        self.prompts.append(prompt)
        if self.error is not None:
            raise self.error
        return self.analysis


@pytest.fixture
def fake_llm() -> FakeLLMProvider:
    return FakeLLMProvider()
