"""Evidence-validation tests: hallucinated references must not survive."""

from __future__ import annotations

from datetime import UTC, datetime

from signalsift.analysis.schemas import Evidence, IncidentAnalysis, RootCauseHypothesis
from signalsift.analysis.validator import validate_analysis
from signalsift.cloudwatch.models import LogEvent
from signalsift.processing.clusterer import LogCluster

NOW = datetime(2026, 9, 3, 14, 0, tzinfo=UTC)


def _cluster(fingerprint: str = "abc123") -> LogCluster:
    return LogCluster(
        fingerprint=fingerprint,
        count=10,
        first_seen=NOW,
        last_seen=NOW,
        exception_type="MongoServerSelectionTimeout",
        normalized_message="MongoServerSelectionTimeout: no members available",
        affected_endpoints={"/checkout": 8},
        representative_events=[LogEvent(timestamp=NOW, message="mongo-primary connection refused")],
    )


def _analysis(**overrides) -> IncidentAnalysis:
    defaults = dict(
        summary="Mongo timeouts dominate.",
        severity="high",
        likely_root_causes=[
            RootCauseHypothesis(
                cause="MongoDB down",
                confidence=0.8,
                evidence=[Evidence(statement="timeouts", cluster_ids=["abc123"])],
            )
        ],
        affected_components=["/checkout"],
    )
    defaults.update(overrides)
    return IncidentAnalysis(**defaults)


def test_valid_references_pass_cleanly() -> None:
    result = validate_analysis(_analysis(), [_cluster()])
    assert result.warnings == []
    assert result.analysis.affected_components == ["/checkout"]


def test_unknown_cluster_id_removed_and_flagged() -> None:
    analysis = _analysis(
        likely_root_causes=[
            RootCauseHypothesis(
                cause="MongoDB down",
                confidence=0.8,
                evidence=[Evidence(statement="timeouts", cluster_ids=["ghost999"])],
            )
        ]
    )
    result = validate_analysis(analysis, [_cluster()])
    assert result.analysis.likely_root_causes[0].evidence[0].cluster_ids == []
    assert any("ghost999" in w for w in result.warnings)


def test_unsupported_component_removed() -> None:
    analysis = _analysis(affected_components=["/checkout", "kafka-broker-7"])
    result = validate_analysis(analysis, [_cluster()])
    assert "/checkout" in result.analysis.affected_components
    assert "kafka-broker-7" not in result.analysis.affected_components
    assert any("kafka-broker-7" in w for w in result.warnings)


def test_component_supported_by_event_text() -> None:
    analysis = _analysis(affected_components=["mongo-primary"])
    result = validate_analysis(analysis, [_cluster()])
    assert "mongo-primary" in result.analysis.affected_components


def test_cause_without_evidence_flagged_but_kept() -> None:
    analysis = _analysis(
        likely_root_causes=[RootCauseHypothesis(cause="cosmic rays", confidence=0.9, evidence=[])]
    )
    result = validate_analysis(analysis, [_cluster()])
    assert len(result.analysis.likely_root_causes) == 1
    assert any("no verifiable cluster evidence" in w for w in result.warnings)
