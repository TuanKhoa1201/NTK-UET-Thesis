# DATASET CARD: NTK-IRIS-STAGE3-CANONICAL-V4
**Dataset Version:** V4-20261013
**Splitting Strategy:** Repository-Family-Independent Group Splitting
**Status:** Canonical Corrected Research Dataset

## 1. Dataset Description
Dataset V4 is constructed to address the forensic audit deficiencies identified in Dataset V3. It decouples the raw immutable evidence repository from the training view, strictly eliminates cross-split repository family leakage, and sanitizes prompt in-context example collisions.

## 2. Quantitative Census
- **Total Records:** 1536
- **Train Set:** 855 samples (89 independent families)
- **Validation Set:** 187 samples (17 independent families)
- **Held-Out Test Set:** 494 samples (26 independent families)
- **Class Balance (Test):** {'taint-propagator': 65, 'none': 75, 'source': 285, 'sink': 69}

## 3. Scientific Enhancements Over V3
1. **Zero Family Overlap:** 0 shared repository families between Train and Test (compared to 54 in V3).
2. **Zero In-Context Prompt Collision:** 0 test samples match few-shot examples (compared to 9 in V3).
3. **Immutable Evidence Bank:** All raw records preserved with provenance tags in `evidence_bank.jsonl`.
