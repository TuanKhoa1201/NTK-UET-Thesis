# MODEL ARTIFACT MANIFEST
**Storage Directory:** `/home/tuankhoa/iris/models/qwen25_coder_15b_stage3_qlora_v3/best_adapter`

## Artifact File Inventory
| Filename | Expected Hash (SHA-256) | Role |
|---|---|---|
| `adapter_model.safetensors` | `9b764d06b8def2a5e8de334dbe9fc58f373329969b3e15d3d7a8ed8556096de7` | Trained QLoRA adapter weights |
| `adapter_config.json` | Local PEFT configuration | LoRA rank, alpha, target modules |
| `tokenizer.json` | Qwen2.5 Fast Tokenizer | Vocabulary and BPE merges |
| `tokenizer_config.json` | ChatML prompt template configuration | Special tokens definitions |
