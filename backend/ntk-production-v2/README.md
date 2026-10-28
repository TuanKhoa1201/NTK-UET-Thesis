# NTK Java Neuro-Symbolic Vulnerability Scanner Backend (Production Source Release)

> **VNU-UET Graduation Thesis — Nguyen Tuan Khoa**
> **Production Architecture:** OpenGrep OSS v1.25.0 + OpenJDK 17 `JavacTask` AST Intra-Procedural Dataflow + Fine-Tuned `Qwen2.5-Coder-0.5B-Instruct` LoRA (`eo06_vnext31_trackb_main`) + Heuristic SAST Evidence Fusion V1.2 + 10-Stage Live Telemetry & SQLite-Indexed REST Backend.

---

## 1. Relationship to Earlier `TuanKhoa1201/NTK-UET-Thesis` Repository

The existing public repository `TuanKhoa1201/NTK-UET-Thesis` (branch `ntk-thesis-dataset-ft-scientific-repair`, HEAD `a704f8327f728a0eceee2a272f13b82d9f0d2320`) contains the earlier research phase (CodeQL / Qwen2.5-Coder-1.5B QLoRA / SAST V2.2 / Phase 6B).

This package (`NTK_PUBLIC_SOURCE_20261028.zip`) contains the **current production backend system** verified end-to-end during the EO06 and Pre-Web P0 audits:
- **Stage 01 - 02:** Safe GitHub repository shallow clone / ZIP intake and Java `.java` source discovery.
- **Stage 03:** OpenGrep OSS v1.25.0 candidate detection (`NTK_OPENGREP_JAVA_RULESET_V1.4` covering `CWE-089`, `CWE-078`, `CWE-022`, `CWE-079`).
- **Stage 04 - 05:** Real OpenJDK 17 `JavacTask` AST parsing (`NtkJavacAstExtractor.java`) and intra-procedural dataflow/guard extraction (`ntk_alert_verification.py`).
- **Stage 06:** Fine-tuned `Qwen/Qwen2.5-Coder-0.5B-Instruct` LoRA (`eo06_vnext31_trackb_main`, Epoch 3 `best_checkpoint`) 4-class API security role classification (`source`, `sink`, `taint-propagator`, `none`).
- **Stage 07 - 09:** Evidence fusion (`NTK_EVIDENCE_FUSION_V1.2`), SAST risk scoring (`NTK_SAST_SCORING_V1.2`), and alert verification (`REPORT`, `REVIEW`, `SUPPRESS`).
- **Stage 10:** Report synthesis, atomic JSON persistence, and SQLite finding pagination index (`NtkScanResultIndex`).

---

## 2. Repository Structure

- `scripts/ntk_web_backend_service.py`: Main HTTP REST backend service and 10-stage scan orchestrator.
- `scripts/ntk_pipeline_telemetry_and_datasets.py`: Real-time 10-stage monotonic telemetry (`PipelineStageTracker`), async job queue (`ScanJobManager`), verified EO06 dataset catalog (`VerifiedDatasetCatalog`), and SQLite result index (`NtkScanResultIndex`).
- `scripts/ntk_alert_verification.py`: Intra-procedural Java AST dataflow & guard verifier (`NTK_ALERT_VERIFIER_V1.2`).
- `scripts/ntk_iris_shared.py`: Prompt formatting, canonical 4-class label normalization, and CWE compatibility helpers.
- `scripts/eo06_main_train_eval_e2e_pipeline.py`: EO06 LoRA fine-tuning, evaluation, and checkpoint selection pipeline.
- `scripts/javac_ast_bridge/NtkJavacAstExtractor.java`: OpenJDK 17 `JavacTask` AST method/call/sink/guard extractor.
- `scripts/rebuild_scan_index.py`: Offline CLI utility to rebuild `scan_result_index.sqlite3` from persisted scan JSON files.
- `scripts/verify_public_smoke.py`: Self-contained smoke test for module imports, AST bridge, and OpenGrep ruleset.
- `rules/ntk_opengrep_java_ruleset_v1_4.yaml`: Standalone OpenGrep Java ruleset (`CWE-089`, `CWE-078`, `CWE-022`, `CWE-079`).
- `fixtures/mini-vulnerable-java/`: Small redistributable 4-file Java vulnerability test fixture.
- `docs/`: OpenAPI 3.0 specification, Finding Schema V2, Web API contract, Live Progress API contract, and AST Dataflow Safety Audit.
- `config/ntk_backend.env.example`: Portable environment variable template.
- `environment/`: `requirements.txt` and `conda_env_iris.yml`.
- `bin/`: `start_ntk_backend.sh`, `stop_ntk_backend.sh`, `verify_ntk_smoke.sh`, `rebuild_scan_index.sh`, `compile_javac_ast_bridge.sh`.

---

## 3. Quick Start on Laptop (Linux / WSL2 Ubuntu)

1. **Install System Prerequisites:**
   - Python `3.10+` (Conda env `iris` recommended)
   - OpenJDK `17` (`sudo apt install openjdk-17-jdk`)
   - OpenGrep `v1.25.0` (`/usr/local/bin/opengrep`)
   - Git `2.34+`

2. **Extract Private Reproduction & Results Archives (Outside Git Repo):**
   ```bash
   tar -xzf NTK_PRIVATE_REPRO_20261028.tar.gz -C ~/ntk_private_repro
   tar -xzf NTK_PRIVATE_RESULTS_20261028.tar.gz -C ~/ntk_persisted_api_store
   ```

3. **Configure Environment:**
   ```bash
   cp config/ntk_backend.env.example config/ntk_backend.env
   # Edit config/ntk_backend.env to point NTK_BASE_MODEL_PATH, NTK_BEST_ADAPTER_PATH,
   # NTK_DATASET_DIR, and NTK_STORAGE_DIR to your local paths.
   ```

4. **Run Smoke Verification & Start Backend:**
   ```bash
   ./bin/verify_ntk_smoke.sh
   ./bin/rebuild_scan_index.sh ~/ntk_persisted_api_store
   ./bin/start_ntk_backend.sh
   ```
