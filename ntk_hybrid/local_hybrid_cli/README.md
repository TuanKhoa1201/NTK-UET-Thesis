# Local hybrid analysis CLI

OpenGrep OSS + one new CodeQL database + native IRIS Stage 3 with local Qwen2.5-Coder-0.5B Base/Epoch-1/Epoch-2 + conservative semantic guards + frozen SAST priority scoring.

The source is preserved from the audited research runner and requires the original WSL environment, pinned artifacts, installed local model and frozen upstream IRIS tree. This directory is NOT a fresh-install deployment or a general Java project scanner.

Scope: Java 21, JDK-only, CWE-22/78/79/89; CWE-79 policy-derived evidence is not LoRA sink evidence. Do not run example application code. The sample ZIP contains intentionally unsafe Java for static analysis.

For a scan of an operator-selected Java ZIP use the existing research run_hybrid.py interface, after locally verifying pinned prerequisites. Do not use this copy to replace the audited local tool directory.

**Provenance:** code is preserved from verified local experiment packages. Keep existing internal module names, pinned hashes and release metadata intact; new public directory names describe functionality rather than experiment IDs.
