# Local Hybrid SAST - validated system status (2026-10-21)

The current NTK proof-of-concept combines OpenGrep OSS, real CodeQL dataflow, native IRIS Stage 3, local Qwen2.5-Coder-0.5B LoRA fine-tuning adapters and SAST priority scoring V2.2. The original scoped site and its website gate remain unchanged; a separate localhost workbench provides four-arm experiments and persistent results.

## Training and runtime phases

- Training: silver/weak data 950 rows, weak validation 137 rows; local LoRA Epoch 1 and Epoch 2 adapters (weights NOT committed). Epoch 1 remains the site checkpoint. The weak validation cannot assess sink recall for CWE-78/79 due to zero sink support. The repository's older 1.5B/QLoRA text describes historical experiments, not this run.
- Operation: input Java ZIP -> OpenGrep -> CodeQL compiler-resolved API candidates and taint paths -> native IRIS Stage 3 -> local strict-response LLM -> exact semantic guards -> SAST V2.2 review priority -> JSON/SARIF/UI. Full native IRIS Stage 4 / SAPipeline.run was not verified.
- Comparison: OpenGrep-only, Base, Epoch 1 and Epoch 2. Base strict output predominantly abstains; accepted API roles do not equal confirmed vulnerabilities. CWE-79 qualified output uses declared CodeQL contextual policy and neutral AI score; not a learned LoRA XSS sink.
- Scope: Java 21 JDK-only, CWE-22, CWE-78, CWE-79, CWE-89; not arbitrary Maven/Spring projects, full SAST coverage or proven package-isolated fresh install. Local inference does not establish whole-machine network isolation.

## Validation snapshot

An operator-approved AI-assisted synthetic holdout of 24 Java files (12 positive/12 negative) had its source/labels locked before its own predictions. It is NOT independent human gold. Model-derived/policy qualified detection (case-CWE) on that holdout: Base 1 TP, 0 FP, 11 FN; Epoch 1 and Epoch 2 each 10 TP, 3 FP, 2 FN, 9 TN (F1 0.8). The 10 true positives include one policy-assisted CWE-79 case; 9 are model-derived. Unfiltered OpenGrep retained all 24 findings and has raw-alert recall 1.0 / F1 2/3; qualified evidence and raw-alert signals have different semantics.

The ranking tie-aware expected AP was roughly OpenGrep-only 0.551, Base 0.631, Epoch 1/2 0.711. These are small, synthetic results, not an independently reviewed external benchmark. Known limitations: false positives on root-checked/allowlisted paths and fixed-command data arguments, false negatives for HTML attribute/script contexts. No threshold or score weight was tuned to hide these failures. The SAST score is review priority, NOT a probability or a CVSS replacement.

## Repository layout

- `ntk_hybrid/b38_policy/`: previously published local scoped prototype and policy web.
- `ntk_hybrid/local_hybrid_cli/`: audited four-arm local OpenGrep/CodeQL/IRIS CLI sources.
- `ntk_hybrid/local_workbench/`: localhost UI with persistent result history and JSON/SARIF exports.
- `evaluation/dataset_sast/`: dataset and SAST evaluator.
- `evaluation/label_review/`: development-only AI-assisted operator review helper.
- `evaluation/locked_holdout/`: pre-prediction-locked synthetic Java cases and evaluator.
- `evaluation/evidence_closeout/`: offline source/metric and exported-result integrity checker.

## Reproduction and publication limits

This Git update publishes **selected source code, public synthetic Java fixtures and explanatory documentation**. It deliberately omits the local trained weights, raw training/validation data, operators' scanned projects, prompt/response bodies, local run directories, private CodeQL databases, audit ZIP archives, private evidence, tokens and WSL machine configuration. Fresh cloning this repository is **not** a claim that the complete observed environment is installed or that all experiments rerun from scratch.

The validated research environment was an existing WSL Conda setup with frozen IRIS commit `51c2aafaf2746a6246ab057752791cc397c272d4` and repository baseline commit `9f8f1a7977423edabc262a06b39ce39965f58df8`. The original experiment inputs and local frozen baselines should remain unchanged after this Git publication. This work is built from existing upstream IRIS and other open-source components, with provenance retained in the source tree.
