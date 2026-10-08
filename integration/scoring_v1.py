"""
NTK Evidence-Aware Finding Scoring V1 — experimental candidate.

Deterministic report-level prioritization.

Not CVSS, calibrated likelihood, or ground-truth detection.
"""

from collections.abc import Mapping
from math import isfinite
import re
from typing import Any

SCORING_VERSION = "NTK-EVIDENCE-V1-CANDIDATE"

SEVERITY_BASE = {
    "Critical": 82,
    "High": 65,
    "Medium": 45,
    "Low": 25,
}

CWE_ADJUSTMENTS = {
    "CWE-78": 5,
    "CWE-89": 5,
    "CWE-22": 3,
    "CWE-23": 3,
    "CWE-79": 3,
}


def _get(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _normalize_cwe(value: Any) -> str | None:
    if value is None:
        return None

    match = re.search(
        r"cwe[-_\s]?0*(\d+)",
        str(value),
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    return f"CWE-{int(match.group(1))}"


def _reported_path_count(value: Any) -> int:
    if isinstance(value, bool):
        return 0

    if not isinstance(value, (int, float)):
        return 0

    if not isfinite(value) or value <= 0:
        return 0

    return max(0, int(value))


def _risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def score_finding(finding: Any) -> dict[str, Any]:
    """Return a versioned score with evidence provenance."""

    raw_severity = _get(finding, "severity")

    severity = str(raw_severity or "").strip().title()

    severity_known = severity in SEVERITY_BASE
    severity_base = SEVERITY_BASE.get(severity, 45)

    normalized_cwe = _normalize_cwe(
        _get(finding, "cwe")
    )

    cwe_adjustment = CWE_ADJUSTMENTS.get(
        normalized_cwe, 0
    )

    verdict = _get(finding, "iris_confirmed")
    path_count = _reported_path_count(
        _get(finding, "path_count")
    )

    if verdict is True:
        verdict_label = "positive"
        verdict_adjustment = 10 if path_count > 0 else 4

    elif verdict is False:
        verdict_label = "negative"
        verdict_adjustment = -22

    else:
        verdict_label = "unknown"
        verdict_adjustment = 0

    raw_score = (
        severity_base
        + cwe_adjustment
        + verdict_adjustment
    )

    score = max(0, min(100, raw_score))
    level = _risk_level(score)

    components = {
        "severity_base": severity_base,
        "cwe_family_adjustment": cwe_adjustment,
        "posthoc_evidence_adjustment": verdict_adjustment,
    }

    evidence = {
        "severity_input": raw_severity,
        "severity_recognized": severity_known,
        "normalized_cwe": normalized_cwe,
        "posthoc_verdict": verdict_label,
        "reported_path_count": path_count,
        "path_presence_used": (
            verdict is True and path_count > 0
        ),
        "rule_precision_scored": False,
        "analyzer_copresence_scored": False,
        "llm_numeric_confidence_scored": False,
    }

    explanation = (
        f"Static severity {severity if severity_known else 'Unknown'} "
        f"({severity_base}); "
        f"CWE-family heuristic ({cwe_adjustment:+d}); "
        f"IRIS posthoc {verdict_label} "
        f"({verdict_adjustment:+d}); "
        f"priority {score}/100 ({level}). "
        "Posthoc labels are not ground truth."
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "score_version": SCORING_VERSION,
        "score_components": components,
        "score_evidence": evidence,
        "score_explanation": explanation,
    }
