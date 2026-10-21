# Offline evidence integrity verification

CPU-only audit of the locked holdout, dataset and saved JSON/SARIF evidence. Recomputes detection and SAST ranking; preserves the three false-positive and two false-negative cases as known limitations. Never changes frozen model, scorer, source, web gate or review labels. Requires original local private export bytes, which are not in this repository.

**Provenance:** code is preserved from verified local experiment packages. Keep existing internal module names, pinned hashes and release metadata intact; new public directory names describe functionality rather than experiment IDs.
