"""
integration/scoring_v2.py

NTK Evidence-Aware Finding Scoring V2.2 with Scientific Safety Invariants.
Integrated for OpenGrep + IRIS + Local LLM unified pipeline.
"""

from typing import Dict, Any, Optional, List, Tuple
import re
import math
from dataclasses import dataclass, asdict

SCORING_VERSION = "NTK-SAST-SCORING-V2.2-SAFETY-INVARIANTS"

# Core Weights (Sum = 1.0)
WEIGHT_SEVERITY = 0.35
WEIGHT_AI = 0.30
WEIGHT_EXPLOITABILITY = 0.25
WEIGHT_PRECISION = 0.10

SEVERITY_SCALE = {
    "CRITICAL": 1.0,
    "ERROR": 0.85,
    "HIGH": 0.80,
    "WARNING": 0.55,
    "MEDIUM": 0.55,
    "LOW": 0.25,
    "INFO": 0.10,
    "EXPERIMENT": 0.10,
    "UNKNOWN": 0.50,
}

CWE_IMPACT_MODIFIERS = {
    "CWE-78": 0.10,   # OS Command Injection
    "CWE-502": 0.10,  # Insecure Deserialization
    "CWE-89": 0.08,   # SQL Injection
    "CWE-611": 0.08,  # XXE
    "CWE-22": 0.05,   # Path Traversal
    "CWE-23": 0.05,   # Relative Path Traversal
    "CWE-79": 0.03,   # XSS
    "CWE-918": 0.05,  # SSRF
}

PRECISION_SCALE = {
    "VERY-HIGH": 1.0,
    "VERY_HIGH": 1.0,
    "HIGH": 0.85,
    "MEDIUM": 0.60,
    "LOW": 0.40,
    "UNKNOWN": 0.50,
}

RISK_BANDS = [
    (85.0, 100.0, "Critical", "Critical risk; immediate remediation required."),
    (70.0, 84.9, "High", "High priority; serious observable vulnerability."),
    (40.0, 69.9, "Medium", "Medium risk; observable finding requiring review."),
    (20.0, 39.9, "Low", "Low risk; low severity or lacks clear attack path."),
    (0.0, 19.9, "Informational", "Benign or suspect false positive; demoted.")
]

@dataclass
class ScoreBreakdownV2:
    static_severity_score: float
    cwe_impact_modifier: float
    effective_severity: float
    rule_precision_score: float
    ai_confidence_score: float
    exploitability_score: float
    raw_score: float
    penalty_factor: float
    final_score: float
    risk_level: str
    risk_description: str
    ai_verdict: str
    safety_floor_applied: bool

class SASTScoringEngineV2:
    def __init__(
        self,
        weight_severity: float = WEIGHT_SEVERITY,
        weight_ai: float = WEIGHT_AI,
        weight_exploitability: float = WEIGHT_EXPLOITABILITY,
        weight_precision: float = WEIGHT_PRECISION
    ):
        total = weight_severity + weight_ai + weight_exploitability + weight_precision
        assert abs(total - 1.0) < 1e-4
        self.w_s = weight_severity
        self.w_a = weight_ai
        self.w_e = weight_exploitability
        self.w_p = weight_precision

    @staticmethod
    def extract_cwe(finding: Any) -> Optional[str]:
        if isinstance(finding, dict):
            cwe = finding.get("cwe") or finding.get("metadata", {}).get("cwe")
            if cwe:
                m = re.search(r"CWE[-_\s]?0*(\d+)", str(cwe), re.IGNORECASE)
                if m:
                    return f"CWE-{m.group(1)}"
            text = f"{finding.get('rule_id', '')} {finding.get('message', '')}"
            m = re.search(r"CWE[-_\s]?0*(\d+)", text, re.IGNORECASE)
            return f"CWE-{m.group(1)}" if m else None
        else:
            cwe = getattr(finding, "cwe", None)
            if cwe:
                m = re.search(r"CWE[-_\s]?0*(\d+)", str(cwe), re.IGNORECASE)
                if m:
                    return f"CWE-{m.group(1)}"
            text = f"{getattr(finding, 'rule_id', '')} {getattr(finding, 'message', '')}"
            m = re.search(r"CWE[-_\s]?0*(\d+)", text, re.IGNORECASE)
            return f"CWE-{m.group(1)}" if m else None

    def calculate_static_severity(self, finding: Any) -> Tuple[float, float, float]:
        sev = getattr(finding, "severity", None) if not isinstance(finding, dict) else finding.get("severity")
        raw_sev = str(sev or "UNKNOWN").upper()
        base_score = SEVERITY_SCALE.get(raw_sev, SEVERITY_SCALE["UNKNOWN"])
        cwe_id = self.extract_cwe(finding)
        cwe_mod = CWE_IMPACT_MODIFIERS.get(cwe_id, 0.0) if cwe_id else 0.0
        effective_sev = min(1.0, base_score + cwe_mod)
        return base_score, cwe_mod, effective_sev

    def calculate_precision(self, finding: Any) -> float:
        meta = getattr(finding, "metadata", {}) if not isinstance(finding, dict) else finding.get("metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        prec = meta.get("precision", "UNKNOWN").upper()
        return PRECISION_SCALE.get(prec, PRECISION_SCALE["UNKNOWN"])

    def calculate_exploitability(self, finding: Any) -> float:
        # Invariant 2: Absence of dataflow is not safety (base E = 0.30)
        path_count = getattr(finding, "path_count", 0) if not isinstance(finding, dict) else finding.get("path_count", 0)
        has_dataflow = False
        if isinstance(finding, dict):
            has_dataflow = bool(finding.get("dataflow") or finding.get("dataflow_trace"))
        if path_count > 0:
            has_dataflow = True

        if not has_dataflow:
            return 0.30
        
        # Saturated log scale for path count
        flow_score = 0.85
        if path_count > 1:
            flow_score += min(0.15, math.log2(path_count) * 0.05)
        return min(1.0, flow_score)

    def evaluate_ai_evidence(self, finding: Any, exploitability: float, effective_sev: float) -> Tuple[float, float, str]:
        # Extract verdict / status from IRIS or Local LoRA
        status = getattr(finding, "status", "") if not isinstance(finding, dict) else finding.get("status", "")
        iris_confirmed = getattr(finding, "iris_confirmed", None) if not isinstance(finding, dict) else finding.get("iris_confirmed")
        ai_val = getattr(finding, "ai_validation", {}) if not isinstance(finding, dict) else finding.get("ai_validation", {})
        if not isinstance(ai_val, dict):
            ai_val = {}

        # Invariant 4: Flow Precedence - when taint flow is confirmed, AI cannot demote
        if exploitability >= 0.85:
            return 0.95, 1.00, "CONFIRMED_DATAFLOW_PRECEDENCE"

        if iris_confirmed is True or status == "IRIS Posthoc Positive":
            return 0.95, 1.00, "CONFIRMED_VULNERABLE"
        elif iris_confirmed is False or status == "IRIS Posthoc Negative":
            # Demote conservatively with multi-tier severity protection
            raw_sev = str(getattr(finding, "severity", "UNKNOWN") if not isinstance(finding, dict) else finding.get("severity", "UNKNOWN")).upper()
            if raw_sev in ["CRITICAL", "ERROR"] or effective_sev >= 0.85:
                return 0.20, 0.70, "SUSPECTED_FP_CRITICAL_PROTECTED"
            elif raw_sev in ["HIGH", "WARNING", "MEDIUM"] or effective_sev >= 0.70:
                return 0.30, 0.60, "SUSPECTED_FP_HIGH_PROTECTED"
            return 0.15, 0.35, "SUSPECTED_FALSE_POSITIVE"

        # Check AI validation dict
        parse_status = ai_val.get("parse_status")
        verdict_val = str(ai_val.get("verdict", "")).upper()
        if parse_status == "PARSE_ERROR" or verdict_val in ["NEEDS_REVIEW", "UNKNOWN"]:
            return 0.50, 1.00, "NEEDS_REVIEW"

        pred_type = ai_val.get("pred_type") or ai_val.get("predicted_type") or ai_val.get("api_role")
        finding_status = ai_val.get("finding_status")
        
        if pred_type == "sink":
            return 0.85, 1.00, "LIKELY_VULNERABLE_SINK"
        elif pred_type == "source":
            return 0.75, 1.00, "INPUT_SOURCE_PRESENT"
        elif pred_type in ["taint-propagator", "propagator"]:
            return 0.70, 0.95, "PROPAGATION_DETECTED"
        elif pred_type == "none" or finding_status == "SUSPECTED_FALSE_POSITIVE":
            raw_sev = str(getattr(finding, "severity", "UNKNOWN") if not isinstance(finding, dict) else finding.get("severity", "UNKNOWN")).upper()
            if raw_sev in ["CRITICAL", "ERROR"] or effective_sev >= 0.85:
                return 0.20, 0.70, "NEEDS_REVIEW_CRITICAL_PROTECTED"
            elif raw_sev in ["HIGH", "WARNING", "MEDIUM"] or effective_sev >= 0.70:
                return 0.30, 0.60, "POTENTIAL_BENIGN_CONTEXT"
            return 0.20, 0.35, "SUSPECTED_FALSE_POSITIVE"

        # Invariant 3: Neutral Unknowns
        return 0.50, 1.00, "NEUTRAL_UNKNOWN"

    def score(self, finding: Any) -> ScoreBreakdownV2:
        base_s, cwe_mod, effective_s = self.calculate_static_severity(finding)
        p_score = self.calculate_precision(finding)
        e_score = self.calculate_exploitability(finding)
        ai_score, penalty, verdict = self.evaluate_ai_evidence(finding, e_score, effective_s)

        raw_score = 100.0 * (
            self.w_s * effective_s +
            self.w_p * p_score +
            self.w_a * ai_score +
            self.w_e * e_score
        )

        calculated_score = raw_score * penalty
        raw_sev = str(getattr(finding, "severity", "UNKNOWN") if not isinstance(finding, dict) else finding.get("severity", "UNKNOWN")).upper()

        # Invariant 5 & 6: High/Critical Safety Floor & Demotion Protection
        safety_floor_applied = False
        if (raw_sev in ["CRITICAL", "ERROR"] or effective_s >= 0.85):
            if calculated_score < 40.0:
                final_score = 40.0
                safety_floor_applied = True
            else:
                final_score = round(max(0.0, min(100.0, calculated_score)), 1)
        elif (raw_sev == "HIGH" or effective_s >= 0.70):
            # High findings are protected by Safety Guard >= 30.0 (cannot drop to Informational)
            if calculated_score < 30.0:
                final_score = 30.0
                safety_floor_applied = True
            else:
                final_score = round(max(0.0, min(100.0, calculated_score)), 1)
        else:
            final_score = round(max(0.0, min(100.0, calculated_score)), 1)

        risk_level = "Low"
        risk_desc = ""
        for low, high, level, desc in RISK_BANDS:
            if low <= final_score <= high:
                risk_level = level
                risk_desc = desc
                break

        # Invariant 6: Critical finding can NEVER be demoted to Informational or Low
        if (raw_sev in ["CRITICAL", "ERROR"] or effective_s >= 0.85) and risk_level in ["Informational", "Low"]:
            risk_level = "Medium"
            risk_desc = "Critical severity protected by Safety Floor >= 40.0"

        # Invariant 6: High finding can NEVER be demoted to Informational
        if (raw_sev == "HIGH" or effective_s >= 0.70) and risk_level == "Informational":
            risk_level = "Low"
            risk_desc = "High severity protected from Informational demotion (Safety Guard >= 30.0)"

        return ScoreBreakdownV2(
            static_severity_score=round(base_s, 2),
            cwe_impact_modifier=round(cwe_mod, 2),
            effective_severity=round(effective_s, 2),
            rule_precision_score=round(p_score, 2),
            ai_confidence_score=round(ai_score, 2),
            exploitability_score=round(e_score, 2),
            raw_score=round(raw_score, 1),
            penalty_factor=round(penalty, 2),
            final_score=round(final_score, 1),
            risk_level=risk_level,
            risk_description=risk_desc,
            ai_verdict=verdict,
            safety_floor_applied=safety_floor_applied
        )

_ENGINE = SASTScoringEngineV2()

def score_finding_v2(finding: Any) -> Dict[str, Any]:
    b = _ENGINE.score(finding)
    cwe_id = _ENGINE.extract_cwe(finding)
    
    components = {
        "static_severity": b.static_severity_score,
        "cwe_impact_modifier": b.cwe_impact_modifier,
        "effective_severity": b.effective_severity,
        "rule_precision": b.rule_precision_score,
        "ai_confidence": b.ai_confidence_score,
        "exploitability": b.exploitability_score,
        "raw_score": b.raw_score,
        "penalty_factor": b.penalty_factor,
        "safety_floor_applied": b.safety_floor_applied,
    }

    evidence = {
        "cwe": cwe_id,
        "ai_verdict": b.ai_verdict,
        "safety_floor_applied": b.safety_floor_applied,
        "safety_invariants": [
            "Invariant 1: Corroborating Evidence",
            "Invariant 2: Absence of Dataflow is not Safety",
            "Invariant 3: Neutral Unknowns",
            "Invariant 4: Flow Precedence",
            "Invariant 5: Audit Trail Preservation",
            "Invariant 6: Critical Safety Floor >= 40.0"
        ]
    }

    explanation = (
        f"Score {b.final_score:.1f}/100 ({b.risk_level}); "
        f"Effective Severity {b.effective_severity}; "
        f"AI Verdict {b.ai_verdict} (penalty {b.penalty_factor}); "
        f"Exploitability {b.exploitability_score}. {b.risk_description}"
    )

    return {
        "risk_score": int(round(b.final_score)),
        "risk_level": b.risk_level,
        "score_version": SCORING_VERSION,
        "score_components": components,
        "score_evidence": evidence,
        "score_explanation": explanation,
        "breakdown": asdict(b)
    }
