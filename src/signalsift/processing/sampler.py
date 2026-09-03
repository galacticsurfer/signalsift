"""Representative sampling: first / middle / latest event per cluster."""

from __future__ import annotations

from signalsift.cloudwatch.models import LogEvent
from signalsift.processing.clusterer import LogCluster


def sample_cluster_events(events: list[LogEvent], max_examples: int) -> list[LogEvent]:
    """Pick up to `max_examples` events spread across the cluster's lifetime.

    Events must be time-sorted. Always includes the first and latest
    occurrence, filling the remainder from evenly spaced positions.
    """
    if len(events) <= max_examples:
        return list(events)
    if max_examples == 1:
        return [events[-1]]
    indices = {0, len(events) - 1}
    remaining = max_examples - 2
    for i in range(1, remaining + 1):
        indices.add(round(i * (len(events) - 1) / (remaining + 1)))
    return [events[i] for i in sorted(indices)][:max_examples]


def sample_clusters(clusters: list[LogCluster], max_examples: int) -> list[LogCluster]:
    for cluster in clusters:
        cluster.representative_events = sample_cluster_events(
            cluster.representative_events, max_examples
        )
    return clusters
