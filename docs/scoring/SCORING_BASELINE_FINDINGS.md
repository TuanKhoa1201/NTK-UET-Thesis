# NTK SAST Scoring — Baseline Findings

Status: RESEARCH EVIDENCE / NOT A LOCKED SCORING SPEC

## Production baseline

Commit:
ee5ac1c76bec3e7d952354debf81d699eddebe0e

The original heuristic scorer is retained in the
immutable production baseline.

## Observed dataset

OWASP post-evaluation regression report:
2760 findings.

This dataset has no mapped ground truth in this
scoring audit. It must not be used to claim
precision, recall or calibrated risk.

## Baseline score observations

Old scoring:
- 1340 findings scored 100
- 8 distinct score values
- 397 adjacent ordering violations

Candidate offline scoring:
- 0 findings scored 100
- 6 distinct score values
- Four basic property checks passed

The candidate removes saturation but does not
establish better ranking quality.

## Available evidence

- OpenGrep present: 1876
- IRIS present: 1599
- Both indicators present: 715
- Posthoc positive: 1534
- Posthoc negative: 65
- Numeric confidence: 0
- Reasoning available: 1599
- Positive path count: 1599

## OpenGrep precision

Raw SARIF:
- 60 rules
- 1876 findings
- Every observed rule precision is very-high

Precision has no discriminative variation within
this particular sample.

## Important limitations

1. Analyzer co-presence does not prove exact
   independent corroboration.

2. Posthoc positive does not establish ground truth.

3. Posthoc negative is a model verdict, not a
   definitive false-positive oracle.

4. Numeric confidence is not available here.

5. No verified exploitability or environment-specific
   business impact measure has been established.

6. More unique scores do not necessarily imply
   a scientifically better prioritization.

7. The scoring formula must not be optimized
   using the locked holdout.

8. Missing IRIS analysis must be distinguished
   from explicit IRIS rejection.

9. A CWE importance heuristic is not itself
   proof of actual technical impact.

## Research design requirements

- Deterministic normalization
- Evidence provenance per component
- Explicit handling of missing evidence
- Conservative corroboration policy
- Transparent scoring formula and thresholds
- No unsupported probability interpretation
- Minimal source changes
- Unit and regression tests
- Vulnerable/fixed validation
- Sensitivity analysis of weights
- Final implementation versioning

## References

MITRE CWSS
https://cwe.mitre.org/cwss/

FIRST CVSS User Guide
https://www.first.org/cvss/user-guide

## State

BASELINE_EVIDENCE_RECORDED=True
SCORING_SPEC_LOCKED=False
SCORING_IMPLEMENTATION_VALIDATED=False
