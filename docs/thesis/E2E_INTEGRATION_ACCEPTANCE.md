# NTK Thesis - E2E Integration Acceptance

**Status: COMPLETED / VERIFIED**

## 1. Scope

End-to-end integration of:

OpenGrep -> IRIS/CodeQL -> Local Ollama LLM
-> SAST Scoring V2.2 -> JSON/CSV/SARIF/HTML.

Environment: WSL2 Ubuntu, Python 3.10.

Fixture: mini_vulnerable_java_CVE-89_1.0.

IRIS query: cwe-089wLLM.

Model: qwen2.5-coder:1.5b (Base).

## 2. E2E Execution

- Pipeline exit code: 0.
- OpenGrep: 60 Java rules, 11 Java files.
- OpenGrep findings: 3.
- Detected CWEs: CWE-89, CWE-611, CWE-328.
- IRIS: 1 successfully executed CWE-89 job.
- IRIS stages 1-9 executed.
- Stage 3: 83 API labeling requests.
- Stage 4: 19 function labeling requests.
- CodeQL: 1 alert with 2 dataflow paths.
- Posthoc: 2 positive path verdicts.

## 3. Fusion Path-Count Repair

The original reporting logic derived path_count
from one selected posthoc verdict.

The repaired logic preserves the number of
surviving dataflow paths from effective IRIS SARIF.

Original result:
- CWE-89 path_count: 1.
- CWE-89 risk score: 86.

Repaired result:
- CWE-89 path_count: 2.
- CWE-89 risk score: 87 (Critical).

Other findings:
- CWE-611: 50 (Medium).
- CWE-328: 47 (Medium).

All 3 findings and their fingerprints were preserved.

Verified fusion repair commit:
022cb3983761cf85c85ad03edd8cff16e9cc93f8

## 4. Regression Verification

- Fusion path-count regression: 8 tests PASS.
- Integration Scoring V2.2: 9 tests PASS.
- SAST scoring safety: 7 tests PASS.
- Total: 24/24 PASS.
- JSON/CSV/SARIF consistency: PASS.
- Original E2E artifacts: 367/367 SHA-256 PASS.
- Scoring V2.2 source: unchanged.

Original evidence manifest SHA-256:

7d7b819b5ed535ceab034ccc324c2a6c175cd5cdb48c9d1a1bbd1b3261453a0d

Detailed execution artifacts are preserved
in a separate local research evidence archive.

## 5. Scientific Limitations

- Evaluation scope: one vulnerable Java fixture.
- The Base LLM showed API-role overclassification.
- Source labels: 44; sink labels: 39.
- Taint-propagator labels: 0.
- Recall@Method: unavailable.
- No generalized precision, recall or F1 claim.
- QLoRA performance is not established by this run.
- Dataset quality requires separate evaluation.
- Broader scoring validation remains necessary.

## 6. Acceptance Decision

**E2E INTEGRATION: COMPLETED / VERIFIED**

This acceptance covers the operational integration,
regression testing, corrected dataflow path accounting,
report consistency, and preserved experiment evidence.
