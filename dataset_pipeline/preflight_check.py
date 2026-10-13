import os
import sys
import json
import torch
from transformers import AutoTokenizer

MODEL_DIR = "/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct"
DATASET_DIR = "/home/tuankhoa/migration/dataset_v3_augmented_20261012"

print("=" * 65)
print("  QLoRA Preflight Diagnostic & Token Distribution Audit")
print("=" * 65)

# 1. Hardware Check
print("\n[1] Hardware & Environment:")
if torch.cuda.is_available():
    props = torch.cuda.get_device_properties(0)
    total_mem = props.total_memory / (1024**3)
    print(f"  [✓] GPU Device: {props.name}")
    print(f"  [✓] VRAM: {total_mem:.2f} GB")
    print(f"  [✓] CUDA Capability: {props.major}.{props.minor}")
    print(f"  [✓] PyTorch CUDA Version: {torch.version.cuda}")
else:
    print("  [-] CUDA NOT AVAILABLE")

# 2. Tokenizer Check
print("\n[2] Tokenizer Diagnostic:")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, use_fast=True)
print(f"  [✓] Vocab Size: {len(tokenizer)}")
print(f"  [✓] Chat Template: {bool(tokenizer.chat_template)}")

# 3. Dataset Token Length Audit
print("\n[3] Dataset Token Length Audit (ChatML Encoded):")
for split in ["train.jsonl", "validation.jsonl", "test.jsonl"]:
    path = os.path.join(DATASET_DIR, split)
    lengths = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            full_text = tokenizer.apply_chat_template(obj["messages"], tokenize=False)
            token_ids = tokenizer.encode(full_text, add_special_tokens=False)
            lengths.append(len(token_ids))
    print(f"  Split: {split}")
    print(f"    Total Rows: {len(lengths)}")
    print(f"    Min Length: {min(lengths)} tokens")
    print(f"    Avg Length: {sum(lengths)/len(lengths):.1f} tokens")
    print(f"    Max Length: {max(lengths)} tokens")
    print(f"    > 1024 tokens: {sum(1 for l in lengths if l > 1024)} (will be truncated if max_len=1024)")

print("\n[✓] PREFLIGHT CHECK COMPLETED!")
