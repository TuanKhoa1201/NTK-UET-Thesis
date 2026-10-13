# DATASET V3 FORENSIC AUDIT REPORT
**Audit Version:** 2.0 (Post-Closeout Scientific Verification)
**Target Dataset:** NTK-IRIS-STAGE3-AUGMENTED-V3-20261012
**Audit Timestamp:** 2026-10-13

## 1. Executive Summary
This independent forensic audit examines the real construction artifacts, schemas, provenance, semantic validity, and cross-split leakage of Dataset V3. While the dataset successfully passes structural JSON schema validation and maintains zero class-level overlap across splits, it exhibits severe scientific defects that disqualify it from being an authoritative benchmark:
- **Package and Family Leakage:** 82 shared packages and 54 shared repository families between Train and Test sets.
- **Prompt Few-Shot Collision:** 9 test samples directly collide with prompt in-context few-shot examples.
- **Signature Leakage:** 37 identical method signatures appear in both Train and Test sets.
- **Heuristic Source and Sink Assignment:** Fallback regex assigns unmapped sinks to CWE-089, and identical sources are copied blindly across 4 CWEs.

## 2. Quantitative Census
- **Total Records:** 1793 (Train: 1227, Val: 236, Test: 330)
- **Unique Signatures:** 1406
- **Unique Classes:** 921
- **Unique Families:** 205
- **Class Balance (Train):** {'source': 287, 'taint-propagator': 316, 'none': 368, 'sink': 256}
- **Class Balance (Test):** {'taint-propagator': 86, 'source': 109, 'none': 76, 'sink': 59}

## 3. Scientific Quality Gates
| Gate | Status | Evidence / Finding |
|---|:---:|---|
| `DATASET_SCHEMA_PASS` | **PASS** | 100% of lines parse into valid 3-turn ChatML dialogues with valid JSON assistant responses. |
| `DATASET_PROVENANCE_PASS` | **FAIL** | Unverified substring heuristics and fallback assignments detected in `build_dataset_v3.py`. |
| `DATASET_SEMANTIC_LABEL_PASS` | **FAIL** | Cross-CWE source duplication and unclassified sink default assignments to CWE-089 violate semantic grounding. |
| `DATASET_SINK_ARGS_PASS` | **PASS** | 18 train sinks (7.0%) and 4 test sinks (6.8%) rely on generic positional placeholder `['p0']`. |
| `DATASET_SPLIT_INTEGRITY_PASS` | **FAIL** | Split grouped only by `(package, class)`. 82 packages and 54 repository families leak across Train and Test. |
| `DATASET_PROMPT_COLLISION_PASS` | **FAIL** | 9 test samples directly mirror in-context few-shot examples embedded in user prompts. |
| `DATASET_DIVERSITY_AUDITED` | **PASS** | Diversity census completed across 6 CWEs and 171 families. |
| `DATASET_READY_FOR_CONTROLLED_FINETUNING` | **FAIL** | **BLOCKED:** Phase B (Corrected Dataset Construction) must be activated to create an Immutable Evidence Bank and decouple the training view. |
