# NTK SAST — Batch 38DPA Engineering Release

## Project

Local Java vulnerability analysis using OpenGrep, IRIS Stage 3,
fine-tuned Qwen2.5-Coder-0.5B LoRA, CodeQL, semantic validation,
and SAST evidence-priority scoring V2.2.

## Engineering scope

- Java 21, JDK-only, 1–24 Java source files.
- No Maven/Gradle or general Servlet/Spring coverage.
- All inference is local; no cloud LLM is required.
- The uploaded Java application is not executed.
- Stage 3 is integrated; the full IRIS SAPipeline.run()
  and Stage 4 are not claimed as completed.

## CWE support

| CWE | Evidence origin | Status |
|---|---|---|
| 22 | LoRA sink + semantic checks + CodeQL | Scoped integration tested |
| 78 | LoRA sink + semantic checks + CodeQL | Scoped integration tested |
| 79 | HTTP/HTML contextual CodeQL policy + encoding analysis | Policy-assisted; LoRA XSS gate NOT granted |
| 89 | LoRA sink + semantic checks + CodeQL | Scoped integration tested |

## Verified prototype

The development fixture contains 24 Java files.

- 24 OpenGrep findings retained.
- 6 model-derived qualified dataflow paths.
- 2 policy-assisted qualified CWE-79 paths.
- 7 raw CWE-79 policy paths retained for audit.
- Results available through localhost web, JSON, SARIF and evidence.
- SAST scores represent review priority, not vulnerability probability.

These fixture results are NOT independent accuracy, precision,
recall, F1 or exploitability measurements.

## Source and launch

Published implementation:
`ntk_hybrid/b38_policy/`

Entrypoints:
- `run_c4d.sh` — C4/DPA engineering checks
- `serve_policy.sh` — local four-CWE web on port 8766

See `ntk_hybrid/b38_policy/README.md` for exact prerequisites.

Running the project requires separately provisioned local
model weights, CodeQL, OpenGrep, JDK and pinned research artifacts.
Weights, CodeQL databases and user scan results are not stored
in this public repository.

## Research limitations

The source and transfer policies are declared by the analysis
system and must not be attributed to the LLM.

The original model-derived CWE-79 gate remains unpassed.
Contextual XSS handling is intentionally limited and does not
prove arbitrary sanitizers, aliases or web frameworks safe.

Independent held-out evaluation, benchmark ablation and
training/runtime resource studies remain future work.
