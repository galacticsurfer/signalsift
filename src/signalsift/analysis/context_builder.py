"""Builds the compact structured evidence payload for the local model.

Not a concatenation of log lines: a JSON document with window metadata,
per-cluster counts, endpoints and a few representative (redacted,
truncated) examples. Enforces the LLM input character budget by dropping
lowest-ranked clusters first, then trimming examples.
"""

from __future__ import annotations

import json
from typing import Any

from signalsift.config import Settings
from signalsift.processing.clusterer import LogCluster
from signalsift.processing.reducer import ReducedLogs


class ContextBuilder:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _cluster_payload(self, cluster: LogCluster) -> dict[str, Any]:
        return {
            "cluster_id": cluster.fingerprint,
            "exception_type": cluster.exception_type,
            "normalized_message": cluster.normalized_message[:300],
            "count": cluster.count,
            "first_seen": cluster.first_seen.isoformat(),
            "last_seen": cluster.last_seen.isoformat(),
            "affected_endpoints": cluster.affected_endpoints,
            "status_codes": cluster.status_codes,
            "examples": [
                event.message[: self._settings.max_chars_per_example]
                for event in cluster.representative_events
            ],
        }

    def build_incident_evidence(
        self,
        reduced: ReducedLogs,
        service: str | None,
        log_group: str,
    ) -> tuple[str, list[LogCluster]]:
        """Return (evidence JSON, clusters actually included)."""
        selected = reduced.clusters[: self._settings.max_clusters_to_llm]
        payload: dict[str, Any] = {
            "service": service,
            "log_group": log_group,
            "window": {
                "start": reduced.window_start.isoformat(),
                "end": reduced.window_end.isoformat(),
            },
            "total_error_events": reduced.stats.cloudwatch_events,
            "distinct_failure_clusters": reduced.stats.clusters,
            "clusters": [self._cluster_payload(c) for c in selected],
        }
        text = json.dumps(payload, indent=1)

        # Shrink until inside the input budget: drop clusters, then examples.
        while len(text) > self._settings.max_llm_input_chars and len(selected) > 1:
            selected = selected[:-1]
            payload["clusters"] = [self._cluster_payload(c) for c in selected]
            payload["truncated_for_budget"] = True
            text = json.dumps(payload, indent=1)
        while len(text) > self._settings.max_llm_input_chars and any(
            c["examples"] for c in payload["clusters"]
        ):
            for cluster_payload in payload["clusters"]:
                if cluster_payload["examples"]:
                    cluster_payload["examples"] = cluster_payload["examples"][:-1]
            payload["truncated_for_budget"] = True
            text = json.dumps(payload, indent=1)
        if len(text) > self._settings.max_llm_input_chars:
            text = text[: self._settings.max_llm_input_chars]
        return text, selected

    def build_comparison_evidence(
        self,
        baseline_payload: dict[str, Any],
        comparison_payload: dict[str, Any],
        deltas: dict[str, Any],
    ) -> str:
        payload = {
            "baseline": baseline_payload,
            "comparison": comparison_payload,
            "deltas": deltas,
        }
        text = json.dumps(payload, indent=1)
        if len(text) > self._settings.max_llm_input_chars:
            text = text[: self._settings.max_llm_input_chars]
        return text
