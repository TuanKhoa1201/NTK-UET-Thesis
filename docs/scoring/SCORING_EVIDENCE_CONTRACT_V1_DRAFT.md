# NTK Scoring Evidence Contract V1 — Draft

Status: DRAFT / NOT LOCKED

Production baseline:
`ee5ac1c76bec3e7d952354debf81d699eddebe0e`

## 1. Evidence observed

- Final findings: 2760
- Raw OpenGrep results: 1876
- Numeric LLM confidence values: 0
- OpenGrep rule precision: {'very-high': 60}
- Finding statuses: {'IRIS Posthoc Positive': 1534, 'OpenGrep Only': 1161, 'IRIS Posthoc Negative': 65}

Selected single-run IRIS path evidence:

{
  "022": {
    "results": 965,
    "surviving": 943,
    "multi_location_paths": 1812
  },
  "078": {
    "results": 215,
    "surviving": 154,
    "multi_location_paths": 514
  },
  "079": {
    "results": 35,
    "surviving": 35,
    "multi_location_paths": 87
  },
  "089": {
    "results": 405,
    "surviving": 397,
    "multi_location_paths": 828
  }
}

These are post-evaluation artifacts.
They are not mapped ground-truth measurements.

## 2. Input evidence sources

A. OpenGrep raw SARIF:
- Rule ID
- CWE
- Severity
- Rule precision metadata
- Code location

B. IRIS SARIF:
- Finding location
- Surviving codeFlows
- ThreadFlow locations
- Path structure

C. IRIS verdict:
- Posthoc decision
- Reasoning where available
- Path count
- CWE and associated location

D. Finding fusion:
- OpenGrep presence
- IRIS SARIF presence
- Correlation status
- Matching-location provenance

## 3. Interpretation constraints

- Numeric LLM confidence is not required.
- Rule precision is ordinal, not a calibrated
  probability of true-positive detection.
- Posthoc-positive does not establish ground truth.
- Posthoc-negative does not prove a safe finding.
- IRIS absence does not mean rejection.
- More paths do not automatically imply
  higher exploitability.
- Longer paths do not automatically imply
  greater vulnerability impact.
- Analyzer co-presence alone is not sufficient
  proof of independent corroboration.
- Matching by filename alone is weak evidence.
- Unsupported CWE enrichment must not be
  interpreted as negative evidence.

## 4. Proposed deterministic output contract

Each finding should expose:

- risk_score
- risk_level
- score_version
- score_components
- score_evidence
- score_explanation

Score components require explicit provenance
and documented missing-value behavior.

## 5. Implementation constraints

- Preserve production baseline/tag.
- Implement on ntk-sast-scoring-v1.
- Prefer report-layer integration.
- Avoid Stage3 changes or additional LLM calls.
- Do not change locked evaluation metrics.
- Do not retrain to fix report engineering.
- Preserve existing finding identities.
- Validate JSON, CSV, SARIF and HTML exports.

## 6. Scientific validation

Required:
- Score bounds and determinism
- Monotonicity tests
- Missing-evidence handling
- Analyzer agreement/disagreement tests
- Posthoc-negative behavior
- Ranking correctness
- Weight sensitivity analysis
- Vulnerable/fixed differential validation
- Evidence-based scoring explanations

## 7. Research status

EVIDENCE_BASELINE_AVAILABLE=True
SCORING_SPEC_LOCKED=False
SCORING_IMPLEMENTATION_PASS=False
