# NTK Batch 38R1 - Scanner environment recovery and separated coverage gates

This is a replacement tool folder for B38 A/B/C/D. It does not patch `~/iris`,
the pinned scanner, LoRA adapters, or the B37 website. Keep the old failed run.

## Why R1 exists

The uploaded B38A run stopped because the B38 runner set XDG_CONFIG_HOME to
`opengrep/.config` before creating that directory. OpenGrep 1.25.0 checks it at
startup and fails. This is a runner regression, not a Java fixture/model failure.

A second issue was found during review: D's callsite coverage gate required all
16 files to match EACH rule because it reused the dataflow expectation matrix.
R1 separates these: four callsite files per CWE, including its two controls;
16 dataflow test cases per CWE remain unchanged. No positive/negative labels,
Java files, model prompts, QL queries, or scoring algorithm are edited.

## First run on WSL

1. Save/extract the R1 ZIP into a new directory under the existing NTK work folder.
2. Set `NTK_IRIS_PYTHON` to the existing IRIS interpreter, as for B38.
3. From the extracted package run:

```bash
bash run_all.sh epoch_1
```

`run_all.sh` validates package hashes and runs all 93 unit tests in fresh per-module
processes with time limits (no skips). It then runs the
REAL pinned local OpenGrep (under inherited seccomp) on A, B, C, SQL, and D before
starting the A/B/C/D hybrid sequence. No CodeQL or model is loaded during that
scanner preflight. Preflight checks every scanner profile and packages all
failure logs together. It does not create any semantic PASS receipt.

There are no install/download commands in this recovery. The existing pinned
OpenGrep, CodeQL, JDK, model files and B33 ZIP are still required as in B38.

Keep the B37 website on port 8765, but do not run a B37 GPU scan concurrently.
The B38 website remains on port 8766 and is started only after the real D gate.

## Expected control flow (not measured authoring results)

```
B38R1_SCANNER_PREFLIGHT_PROFILE=A
B38R1_SCANNER_PROFILE_RESULT=A PASS
... B, C, SQL, D ...
===== B38R1 SCANNER PREFLIGHT RESULT =====
STATUS=B38R1_SCANNER_PREFLIGHT_PASS
CODEQL_DATAFLOW=NOT_EXECUTED
MODEL_INFERENCE=NOT_EXECUTED
OUTPUT_ZIP=...

===== RUN PHASE A WITH epoch_1 =====
... original hybrid A, then B, C, D with their own real checks ...
```

A scanner preflight failure prevents the hybrid chain from starting. A phase
BLOCKED or NEEDS_REVIEW still stops the chain. No fallback to manual sinks,
no forced PASS and no removal of original OpenGrep findings are introduced.

## Inspect only the scanner infrastructure

```bash
W="$HOME/migration/ntk_stage3_verified_v5_work"
"$W/.ntk_v5_lora_venv/bin/python" -B -u preflight_scanner.py
```

The resulting ZIP contains per-profile raw/canonical JSON (if available), actual
commands, environment proof, isolation proof, stderr/stdout and coverage checks.
The runtime directories `.config`, `.cache`, `.tmp`, `.state`, `.semgrep` and
uploaded Java source directories are not exported in the evidence ZIP.

## Resume a specific phase after review

```bash
bash run.sh --phase A --arm epoch_1
bash run.sh --phase B --arm epoch_1
bash run.sh --phase C --arm epoch_1
bash run.sh --phase D --arm epoch_1
```

These commands do not bypass any original model/dataflow gate. D requires A/B/C
receipts from the same implementation. The implementation fingerprint now also
includes the fixture/scanner coverage contract. Do not copy old receipts into a
new implementation. The old B38A blocked run did not create a PASS receipt.

After the D gate has passed:

```bash
bash serve.sh
```

Open `http://127.0.0.1:8766` and submit a new ZIP for web acceptance.

## Files for review

- B38A_FAILURE_AUDIT.json / .md: uploaded run integrity and diagnosis.
- B38R1_CHANGES.diff: existing-file edits. New code is in scanner_environment.py
  and preflight_scanner.py. run_selftests.py isolates unit test modules.
- R1_UNCHANGED_INPUTS.json: source/model/query/scoring/fixture invariants.
- R1_RULE_EQUIVALENCE.json: all five emitted OpenGrep configurations unchanged.
- AUTHORING_CHECKS.json and AUTHORING_SELFTEST.log: actual authoring checks,
  including explicitly identified fake processes.
- history/: original B38 authoring records and full scope documentation.

## Limits

No new real OpenGrep binary, CodeQL database/query, or LoRA inference has been
run in the authoring environment. All such acceptance remains on WSL. New tests
cover actual OS directory initialization and inherited seccomp in child processes,
but use a FAKE scanner for finding output. Never label mock output as research
results. All originals are retained under history or in the old tool ZIP.

B38 still targets JDK-only <=24-file projects; getenv sources for 22/78/89 are
explicit threat-model choices, not discoveries made by the model. CWE79 is the
narrow direct JDK HTTP/HTML profile. No Stage4, general Java/Servlet/Spring
coverage, independent-gold evaluation, or final scientific release is claimed.
