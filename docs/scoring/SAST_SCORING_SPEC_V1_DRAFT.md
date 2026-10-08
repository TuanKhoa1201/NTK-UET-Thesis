# SAST_SCORING_SPEC_V1 — DRAFT

Status: RESEARCH DRAFT / NOT LOCKED
Method: Evidence-Aware SAST Finding Prioritization

## 1. Purpose

Rank SAST findings using observable analysis evidence.

This index is NOT CVSS, a calibrated probability,
or a claim that an LLM-positive result is ground truth.

## 2. Existing baseline

Production commit:
ee5ac1c76bec3e7d952354debf81d699eddebe0e

Observed OWASP report:
- Findings: 2760
- Scores of 100: 1340
- Ranking adjacent violations: 397
- Numeric confidence coverage: 0/2760
- OpenGrep findings: 1876
- IRIS posthoc-positive findings: 1534
- IRIS posthoc-negative findings: 65

This report is post-evaluation regression evidence,
not a ground-truth scoring benchmark.

## 3. Candidate component mapping

All component values use [0,1].

S = Static Severity:
Critical=1.0, High=0.8, Medium=0.55,
Low=0.25, Unknown=0.5

P = OpenGrep Rule Precision:
very-high=1.0, high=0.8, medium=0.6,
low=0.4, missing/unknown=0.5

These values are ordinal heuristic mappings,
not calibrated probabilities.

D = Dataflow/Posthoc Evidence:
1.0 = posthoc positive AND path_count > 0
0.5 = unknown/unavailable/incomplete

Posthoc negative is handled by the penalty below
rather than counted twice.

R = Corroboration Evidence:
0.75 = OpenGrep and IRIS present,
       posthoc positive
0.50 = unknown, absent or not verified

R=0.75 denotes limited location-associated evidence;
it does NOT prove semantic equivalence of findings.

## 4. Candidate formula

RawScore = 100 * (
    0.50*S +
    0.15*P +
    0.25*D +
    0.10*R
)

Penalty:
0.25 if IRIS posthoc verdict is explicitly negative
1.00 otherwise

FinalScore = round(RawScore * Penalty, 1)

Candidate bands:
85-100 Critical
70-84.9 High
40-69.9 Medium
0-39.9 Low

Bands are research hypotheses, NOT finalized.

## 5. Unknown evidence policy

Missing numeric LLM confidence must not be fabricated.

No IRIS enrichment is not proof of a safe finding.
Not every CWE belongs to IRIS's supported enrichment scope.

Posthoc positive is not ground truth.
Posthoc negative is not definitive proof of a false positive.

No independent Impact or Exploitability value will
be fabricated from CWE or raw path count.

## 6. Scientific validation requirements

- Compare against previous heuristic baseline.
- Check score bounds and monotonicity.
- Check saturation and discrimination.
- Check posthoc-negative penalty.
- Check missing evidence behavior.
- Check agreement/disagreement behavior.
- Test vulnerable/fixed differential ranking.
- Report sensitivity to chosen weights.
- Avoid optimizing against locked holdout.
- Keep locked evaluation metrics unchanged.
- Revisit R with stricter analyzer matching provenance.

## 7. Output requirements

Proposed fields:
risk_score
risk_level
score_components
score_evidence
score_version
score_explanation

Required exports:
JSON, CSV, SARIF, HTML.

## 8. Research references

MITRE CWSS:
https://cwe.mitre.org/cwss/

FIRST CVSS user guide:
https://www.first.org/cvss/user-guide

## 9. Status

SAST_SCORING_SPEC_V1_LOCKED=False
IMPLEMENTATION_NOT_STARTED=True
PRODUCTION_BASELINE_UNCHANGED=True
