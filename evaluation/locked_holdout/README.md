# Pre-prediction locked synthetic holdout

24 synthetic JDK-only Java cases, 6 per CWE, balanced 12 POSITIVE / 12 NEGATIVE. Source and AI-assisted operator-approved labels were locked before this holdout run's predictions, but the cases were designed after earlier behavior had been observed. Not independent human gold.

Legacy run_and_evaluate.sh has a known Python -I import issue for metric_core; the audited WSL evaluation was recovered with an explicit SHA-verified module path, without repeating inference. Preserve the source as historical evidence; do not claim this script has a verified fresh-install experience.

**Provenance:** code is preserved from verified local experiment packages. Keep existing internal module names, pinned hashes and release metadata intact; new public directory names describe functionality rather than experiment IDs.
