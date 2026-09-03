"""Phase-1 clustering: exact fingerprint grouping.

Events already carry fingerprints computed from (exception chain, top
frames, normalized message, endpoint, status). Grouping by fingerprint
plus deterministic ranking gives dominant clusters without embeddings.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from signalsift.cloudwatch.models import LogEvent


class LogCluster(BaseModel):
    fingerprint: str
    count: int
    first_seen: datetime
    last_seen: datetime
    exception_type: str | None
    normalized_message: str
    level: str | None = None
    affected_endpoints: dict[str, int] = Field(default_factory=dict)
    status_codes: dict[str, int] = Field(default_factory=dict)
    representative_events: list[LogEvent] = Field(default_factory=list)
    score: float = 0.0


def count_logical_events(events: list[LogEvent]) -> int:
    """Unique fingerprints = deduplicated logical events."""
    return len({event.fingerprint or "unfingerprinted" for event in events})


def cluster_events(events: list[LogEvent]) -> list[LogCluster]:
    """Two-level grouping.

    Level 1 (dedup): exact fingerprint — identical failures collapse.
    Level 2 (cluster): (exception_type, normalized_message) — the same
    failure hitting different endpoints/statuses merges into one cluster
    with aggregated endpoint/status counts. The cluster keeps the
    fingerprint of its largest member group as its stable ID.
    """
    groups: dict[tuple[str | None, str], list[LogEvent]] = {}
    for event in events:
        key = (event.exception_type, event.normalized_message or event.message[:200])
        groups.setdefault(key, []).append(event)

    clusters: list[LogCluster] = []
    for _, members in groups.items():
        members.sort(key=lambda e: e.timestamp)
        endpoints: dict[str, int] = {}
        statuses: dict[str, int] = {}
        for member in members:
            if member.endpoint:
                endpoints[member.endpoint] = endpoints.get(member.endpoint, 0) + 1
            if member.status_code is not None:
                key = str(member.status_code)
                statuses[key] = statuses.get(key, 0) + 1
        fingerprint_counts: dict[str, int] = {}
        for member in members:
            fp = member.fingerprint or "unfingerprinted"
            fingerprint_counts[fp] = fingerprint_counts.get(fp, 0) + 1
        dominant_fp = max(fingerprint_counts, key=lambda k: (fingerprint_counts[k], k))
        first = members[0]
        clusters.append(
            LogCluster(
                fingerprint=dominant_fp,
                count=len(members),
                first_seen=first.timestamp,
                last_seen=members[-1].timestamp,
                exception_type=first.exception_type,
                normalized_message=first.normalized_message or first.message[:200],
                level=first.level,
                affected_endpoints=endpoints,
                status_codes=statuses,
                representative_events=members,  # sampled down later
            )
        )
    return clusters


def score_clusters(clusters: list[LogCluster], window_end: datetime) -> list[LogCluster]:
    """Deterministic incident scoring: frequency + recency + severity + 5xx."""
    if not clusters:
        return clusters
    max_count = max(cluster.count for cluster in clusters)
    for cluster in clusters:
        frequency = cluster.count / max_count
        age = window_end - cluster.last_seen
        recency = (
            1.0 if age <= timedelta(minutes=5) else max(0.0, 1.0 - age.total_seconds() / 3600.0)
        )
        severity = {
            "CRITICAL": 1.0,
            "FATAL": 1.0,
            "ERROR": 0.8,
            "WARNING": 0.4,
            "WARN": 0.4,
        }.get((cluster.level or "ERROR").upper(), 0.5)
        has_5xx = any(code.startswith("5") for code in cluster.status_codes)
        has_exception = cluster.exception_type is not None
        # 5xx association is weighted heavily so a genuine server failure
        # outranks a noisier stream of client-side 4xx validation errors.
        cluster.score = round(
            0.3 * frequency
            + 0.2 * recency
            + 0.2 * severity
            + (0.2 if has_5xx else 0.0)
            + (0.1 if has_exception else 0.0),
            4,
        )
    clusters.sort(key=lambda c: (-c.score, -c.count, c.fingerprint))
    return clusters
