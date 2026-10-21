# Dataset and SAST evaluation

CPU-only saved-result evaluator: train/validation distribution and overlap checks, strict source-to-finding mapping, reviewed label lock, case-CWE detection precision/recall/F1 and SAST ranking AP/NDCG/tie-aware metrics. No model inference or scanning when evaluating existing results.

Dataset stats: train 950 weak/silver, validation 137 weak; validation includes zero sink examples for CWE-78/CWE-79. No independent gold claim. Research execution relies on pinned local snapshots, result ZIPs and workspaces that are deliberately excluded from public Git.

**Provenance:** code is preserved from verified local experiment packages. Keep existing internal module names, pinned hashes and release metadata intact; new public directory names describe functionality rather than experiment IDs.
