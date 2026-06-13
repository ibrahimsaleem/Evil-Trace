from typing import Dict, Any


def compute_confidence(
    rule_hit: bool,
    llm_hit: bool,
    artifact_count: int,
    artifact_exact_match: bool,
) -> float:
    score = 0.0
    if rule_hit:
        score += 0.40
    if llm_hit:
        score += 0.20
    score += min(artifact_count * 0.10, 0.30)
    if artifact_exact_match:
        score += 0.10
    return round(min(score, 1.0), 2)


def severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.80:
        return "critical"
    if confidence >= 0.60:
        return "high"
    if confidence >= 0.40:
        return "medium"
    return "low"


def status_from_confidence(confidence: float, artifact_exact_match: bool) -> str:
    if artifact_exact_match and confidence >= 0.50:
        return "confirmed"
    if confidence >= 0.35:
        return "weak_evidence"
    return "rejected"
