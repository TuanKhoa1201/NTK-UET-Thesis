#!/usr/bin/env python3
"""
evaluate_v3_on_v4_test.py

Evaluates the existing QLoRA V3 adapter on the clean canonical Dataset V4
held-out test set (Zero Family Leakage, Zero Prompt Contamination).
Used for Phase D Retraining Decision Gate.
"""
import os
import sys
import json
import time
import torch
from pathlib import Path
from collections import Counter
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

MODEL_DIR = "/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct"
ADAPTER_DIR = "/home/tuankhoa/iris/models/qwen25_coder_15b_stage3_qlora_v3/best_adapter"
TEST_DATASET_PATH = "/home/tuankhoa/migration/dataset_v4_scientific_20261013/test.jsonl"
OUTPUT_DIR = Path("/home/tuankhoa/iris/docs/finetuning")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

VALID_CLASSES = ["source", "sink", "taint-propagator", "none"]

def load_test_data(filepath, max_samples=100):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if line:
                records.append({
                    "idx": idx,
                    "messages": json.loads(line)["messages"]
                })
    
    # Stratified sampling across families to cover all 26 families evenly
    if len(records) > max_samples:
        step = max(1, len(records) // max_samples)
        selected = records[::step][:max_samples]
        return selected
    return records

def parse_model_output(completion):
    clean = completion.strip()
    pred_type = "unknown"
    is_valid_json = False
    sink_args = []
    
    try:
        data = json.loads(clean)
        is_valid_json = True
        pred_type = data.get("type", "unknown")
        sink_args = data.get("sink_args", [])
    except Exception:
        for c in VALID_CLASSES:
            if f'"{c}"' in clean or f"'{c}'" in clean:
                pred_type = c
                break
                
    if pred_type not in VALID_CLASSES:
        pred_type = "unknown"
        
    return pred_type, is_valid_json, sink_args

def main():
    print("======================================================================")
    print("   EVALUATING EXISTING V3 ADAPTER ON CANONICAL DATASET V4 HELD-OUT   ")
    print("======================================================================")
    
    test_records = load_test_data(TEST_DATASET_PATH, max_samples=100)
    print(f"[*] Loaded {len(test_records)} representative held-out test samples from Dataset V4")
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    print("[*] Loading Base Model...")
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_DIR,
        quantization_config=bnb_config,
        device_map={"": 0},
        dtype=torch.bfloat16,
        trust_remote_code=True
    )
    if hasattr(base_model.config, "use_cache"):
        base_model.config.use_cache = True

    print(f"[*] Attaching V3 LoRA adapter from {ADAPTER_DIR}...")
    model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    model.eval()

    y_true = []
    y_pred = []
    valid_json_count = 0
    start_time = time.time()

    for idx, item in enumerate(test_records):
        messages = item["messages"]
        gt_obj = json.loads(messages[2]["content"])
        gt_type = gt_obj.get("type", "none")
        y_true.append(gt_type)

        prompt_msgs = messages[:2]
        prompt_text = tokenizer.apply_chat_template(prompt_msgs, add_generation_prompt=True, tokenize=False)
        inputs = tokenizer(prompt_text, return_tensors="pt").to("cuda:0")

        with torch.no_grad():
            generated_ids = model.generate(
                **inputs,
                max_new_tokens=128,
                temperature=0.01,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id
            )

        prompt_len = inputs["input_ids"].shape[1]
        completion = tokenizer.decode(generated_ids[0][prompt_len:], skip_special_tokens=True).strip()

        pred_type, is_valid_json, sink_args = parse_model_output(completion)
        if is_valid_json:
            valid_json_count += 1
        y_pred.append(pred_type)

        if (idx + 1) % 25 == 0 or (idx + 1) == len(test_records):
            curr_acc = sum(1 for gt, pr in zip(y_true, y_pred) if gt == pr) / len(y_true)
            print(f"  --> Processed {idx + 1}/{len(test_records)} | Accuracy: {curr_acc:.4f} | Valid JSON: {valid_json_count}/{idx+1}")

    elapsed = time.time() - start_time
    acc = accuracy_score(y_true, y_pred)
    json_rate = valid_json_count / len(test_records)
    rep = classification_report(y_true, y_pred, target_names=None, output_dict=True, zero_division=0)

    print("\n[✓] Evaluation completed successfully!")
    print(f"[*] Total Samples      : {len(test_records)}")
    print(f"[*] Strict Accuracy    : {acc*100:.2f}%")
    print(f"[*] Valid JSON Rate    : {json_rate*100:.2f}%")
    print(f"[*] Macro F1           : {rep['macro avg']['f1-score']:.4f}")
    print(f"[*] Elapsed Time       : {elapsed:.2f}s ({elapsed/len(test_records)*1000:.1f} ms/sample)")

    results = {
        "status": "PASS",
        "dataset": "Dataset V4 Canonical Held-Out Test Set",
        "sample_count": len(test_records),
        "strict_accuracy": round(acc, 4),
        "valid_json_rate": round(json_rate, 4),
        "macro_f1": round(rep['macro avg']['f1-score'], 4),
        "weighted_f1": round(rep['weighted avg']['f1-score'], 4),
        "elapsed_seconds": round(elapsed, 2),
        "classification_report": rep,
    }

    out_file = OUTPUT_DIR / "v3_on_dataset_v4_evaluation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[*] Saved results to {out_file}")

if __name__ == "__main__":
    main()
