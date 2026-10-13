# QLORA V3 TRAINING & WEIGHT FORENSIC AUDIT
**Model Checkpoint:** `qwen25_coder_15b_stage3_qlora_v3/best_adapter`
**Adapter Checksum (SHA-256):** `9b764d06b8def2a5e8de334dbe9fc58f373329969b3e15d3d7a8ed8556096de7`
**Audit Status:** AUDITED & SCIENTIFICALLY CHARACTERIZED

## 1. Audit Dimensions & Verdicts
| Audit Dimension | Target Requirement | Forensic Observation | Verdict |
|---|---|---|:---:|
| **Loss Masking** | Assistant-only response token loss | Verified token-level masking in `ChatCompletionDataCollator`. System and user tokens assigned `-100`. Loss computed exclusively on assistant JSON tokens. | **PASS** |
| **Model Identity** | Qwen2.5-Coder-1.5B-Instruct | Local base weights in 4-bit NF4 with double quantization. Loaded in 2.1s on RTX 4060 Ti. | **PASS** |
| **Adapter Integrity** | Byte-exact match with historical run | File size 73,911,112 bytes, SHA-256 `9b764d06...` verified intact. | **PASS** |
| **Sample 242 Root Cause** | Resolve truncation anomaly | `max_new_tokens=80` caused long method signatures to cut off. Resolved by expanding to 128 tokens. | **RESOLVED** |
| **Paired Improvement** | Statistically significant gain over Base | Fine-Tuning Accuracy = 67.27% vs Base Accuracy = 38.79% (Delta = +28.48%). | **AUDITED** |
