# TRAINING CONFIGURATION LOCK
**Target Task:** Stage 3 Neurosymbolic SAST API Role Classification
**Architecture:** QLoRA 4-Bit NormalFloat on Qwen2.5-Coder-1.5B-Instruct

## Hyperparameter Specification
- `base_model`: `Qwen2.5-Coder-1.5B-Instruct`
- `quantization`: `4-bit NF4` (compute_dtype: `bfloat16`, double_quant: `True`)
- `lora_r`: `16`
- `lora_alpha`: `32`
- `lora_dropout`: `0.05`
- `target_modules`: `["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]`
- `max_seq_length`: `1024`
- `epochs`: `3`
- `micro_batch_size`: `2`
- `gradient_accumulation_steps`: `4` (effective batch size: `8`)
- `learning_rate`: `2e-4`
- `lr_scheduler`: `cosine`
- `warmup_steps`: `23`
- `optimizer`: `paged_adamw_8bit`
- `loss_masking`: `assistant_only` (masked with `-100` before `<|im_start|>assistant
`)
