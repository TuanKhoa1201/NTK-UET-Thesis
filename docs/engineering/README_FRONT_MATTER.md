# NTK SAST - Local OpenGrep + IRIS + LLM prototype

The current scoped prototype combines **OpenGrep OSS, CodeQL, native IRIS Stage 3, locally fine-tuned Qwen2.5-Coder-0.5B LoRA, and SAST V2.2 priority scoring**. It supports a Java 21 JDK-only research scope across CWE-22, CWE-78, CWE-79 and CWE-89. CWE-79 qualified paths remain **policy-assisted, not model-derived LoRA XSS sinks**.

Current engineering state, results and limits: [`docs/engineering/LOCAL_HYBRID_STATUS.md`](docs/engineering/LOCAL_HYBRID_STATUS.md). Source components are organized by their functionality in `ntk_hybrid/local_hybrid_cli/`, `ntk_hybrid/local_workbench/`, and `evaluation/`.

The held-out 24-file synthetic evaluation is **not independently human-labelled gold**. Historical benchmark and earlier 1.5B/QLoRA descriptions appear below for historical context, not as claims about this current 0.5B system. Local model checkpoints, scanned projects and private evidence are not stored in the public repository.

---
