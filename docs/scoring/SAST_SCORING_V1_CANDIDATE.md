# SAST Scoring V1 — Candidate Specification

Version: NTK-EVIDENCE-V1-CANDIDATE
Status: EXPERIMENTAL / NOT LOCKED

## Purpose

Provide deterministic, explainable finding prioritization
based on evidence already available in merged reports.

Not CVSS, a calibrated probability, or vulnerability ground truth.

## Formula

Score = clip(S + C + V, 0, 100)

S: normalized static severity
- Critical: 82
- High: 65
- Medium: 45
- Low: 25
- Unknown: 45, explicitly recorded

C: limited CWE-family prioritization heuristic
- CWE-78, CWE-89: +5
- CWE-22, CWE-23, CWE-79: +3
- Other or missing CWE: +0

The CWE adjustment is a research hypothesis,
not measured exploitability or business impact.

V: IRIS posthoc evidence
- Positive and reported path_count > 0: +10
- Positive without reported positive path_count: +4
- Explicit negative: -22
- Unknown or absent verdict: 0

Posthoc labels are model/pipeline verdicts,
not external ground truth.

## Bands

Critical: score >= 85
High: score >= 70
Medium: score >= 40
Low: score < 40

## Excluded from V1 candidate score

- Numeric LLM confidence: unavailable in observed report
- OpenGrep precision: constant very-high in observed sample
- Duplicate count: not independent vulnerability evidence
- Number of paths beyond positive presence
- Path length
- OpenGrep/IRIS co-presence without robust matching provenance

These signals may be recorded, but must not
silently contribute to the candidate score.

## Missing evidence

Absence of IRIS verdict implies V=0,
not a false-positive finding.

Unknown severity is mapped to 45 and reported.

No missing signal is represented as
an invented probability or exploitable path.

## Output

- risk_score: integer 0-100
- risk_level: Critical/High/Medium/Low
- score_version
- score_components
- score_evidence
- score_explanation

Do not replace finding identity or status fields.

## Acceptance tests

- Determinism and valid bounds
- Severity monotonicity, all other inputs fixed
- Positive evidence increases score
- Negative verdict decreases score
- Missing evidence handled without artificial penalty
- Irrelevant counts do not influence score
- Same evidence produces same score
- No artificial scoring benefit from analyzer co-presence
- Historical report remains unmodified
- Distribution and weight sensitivity reviewed
- Differential vulnerable/fixed validation before final release

## Research limitations

Weights are not calibrated.
Improved discrimination is not yet established.
External ground-truth ranking validation is pending.
No claim of improved accuracy, precision, recall or AUC.

## State

SCORING_V1_LOCKED=False
PRODUCTION_BASELINE_UNCHANGED=True
