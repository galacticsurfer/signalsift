"""Post-inference evidence validation.

The local model's claims are checked against the evidence it was given:
- every referenced cluster_id must exist (unknown ids are removed),
- affected components must appear in the input evidence (endpoints,
  services, exception types) or they are flagged,
- confidences are clamped to [0, 1].

Unsupported claims are removed or flagged so hallucinations do not reach
Claude as facts.
"""

from __future__ import annotations

from signalsift.analysis.schemas import IncidentAnalysis, RootCauseHypothesis
from signalsift.processing.clusterer import LogCluster


class ValidationResult:
    def __init__(self, analysis: IncidentAnalysis, warnings: list[str]) -> None:
        self.analysis = analysis
        self.warnings = warnings


def _known_terms(clusters: list[LogCluster], extra: list[str]) -> set[str]:
    terms: set[str] = set()
    for cluster in clusters:
        if cluster.exception_type:
            terms.add(cluster.exception_type.lower())
        for endpoint in cluster.affected_endpoints:
            terms.add(endpoint.lower())
        terms.update(
            token.lower() for token in cluster.normalized_message.split() if len(token) > 3
        )
        for event in cluster.representative_events:
            terms.update(token.lower() for token in event.message.split() if len(token) > 3)
    terms.update(item.lower() for item in extra if item)
    return terms


def _component_supported(component: str, terms: set[str]) -> bool:
    lowered = component.lower()
    if lowered in terms:
        return True
    # Multi-word components count as supported if any distinctive word is.
    words = [w for w in lowered.replace("/", " /").split() if len(w) > 3]
    return any(word in terms or any(word in term for term in terms) for word in words)


def validate_analysis(
    analysis: IncidentAnalysis,
    clusters: list[LogCluster],
    known_context: list[str] | None = None,
) -> ValidationResult:
    warnings: list[str] = []
    known_ids = {cluster.fingerprint for cluster in clusters}
    terms = _known_terms(clusters, known_context or [])

    validated_causes: list[RootCauseHypothesis] = []
    for cause in analysis.likely_root_causes:
        kept_evidence = []
        for evidence in cause.evidence:
            valid_ids = [cid for cid in evidence.cluster_ids if cid in known_ids]
            dropped = set(evidence.cluster_ids) - set(valid_ids)
            if dropped:
                warnings.append(
                    f"Removed unknown cluster reference(s) {sorted(dropped)} "
                    f"from evidence: {evidence.statement[:80]!r}"
                )
            evidence.cluster_ids = valid_ids
            kept_evidence.append(evidence)
        cause.evidence = kept_evidence
        cause.confidence = min(max(cause.confidence, 0.0), 1.0)
        if not any(e.cluster_ids for e in cause.evidence):
            warnings.append(
                f"Root-cause hypothesis has no verifiable cluster evidence: "
                f"{cause.cause[:100]!r} (kept, flagged as unverified)"
            )
        validated_causes.append(cause)
    analysis.likely_root_causes = validated_causes

    supported_components: list[str] = []
    for component in analysis.affected_components:
        if _component_supported(component, terms):
            supported_components.append(component)
        else:
            warnings.append(
                f"Affected component {component!r} does not appear in the "
                "supplied evidence; removed."
            )
    analysis.affected_components = supported_components

    return ValidationResult(analysis, warnings)
