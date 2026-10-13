#!/usr/bin/env python3
"""
evaluate_repaired_v4_test.py

Evaluates existing QLoRA V3 adapter on the clean, unexposed Held-Out Test Set
from Dataset V4.1-REPAIRED (128 samples).
Separates:
- Strict JSON Validity
- Fully Valid Structured Prediction Accuracy
- Lenient Label Extraction Accuracy
- Per-class Precision, Recall, F1
- Sink_args exactness
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
CLEAN_TEST_PATH = "/home/tuankhoa/migration/dataset_v4_repaired_20261013/test_clean_heldout.jsonl"
OUTPUT_DIR = Path("/home/tuankhoa/iris/docs/finetuning")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

VALID_CLASSES = ["source", "sink", "taint-propagator", "none"]

def load_clean_test_data(filepath):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if line:
                records.append({
                    "idx": idx,
                    "messages": json.loads(line)["messages"]
                })
    return records

def parse_model_output(completion):
    clean = completion.strip()
    is_valid_json = False
    full_schema_valid = False
    strict_pred_type = "unknown"
    lenient_pred_type = "unknown"
    sink_args = []
    
    # 1. Strict JSON Parse
    try:
        data = json.loads(clean)
        is_valid_json = True
        # Check required schema keys
        if all(k in data for k in ["package", "class", "method", "signature", "sink_args", "type"]):
            full_schema_valid = True
            strict_pred_type = data.get("type", "unknown")
            sink_args = data.get("sink_args", [])
            lenient_pred_type = strict_pred_type
    except Exception:
        pass
        
    # 2. Lenient Extraction Fallback (diagnostic only)
    if lenient_pred_type == "unknown":
        for c in VALID_CLASSES:
            if f'"{c}"' in clean or f"'{c}'" in clean:
                lenient_pred_type = c
                break
                
    return {
        "is_valid_json": is_valid_json,
        "full_schema_valid": full_schema_valid,
        "strict_type": strict_pred_type,
        "lenient_type": lenient_pred_type,
        "sink_args": sink_args,
        "raw": clean
    }

def main():
    print("=" * 70)
    print("  EVALUATION OF QLoRA V3 ON CLEAN UNEXPOSED HELD-OUT TEST (V4.1-REPAIRED)")
    print("=" * 70)
    print(f"[*] Base Model : {MODEL_DIR}")
    print(f"[*] Adapter    : {ADAPTER_DIR}")
    print(f"[*] Clean Test : {CLEAN_TEST_PATH}")
    
    test_records = load_clean_test_data(CLEAN_TEST_PATH)
    print(f"[*] Loaded {len(test_records)} clean held-out evaluation samples.")
    
    # Ground truth extraction
    gt_types = []
    gt_objects = []
    for r in test_records:
        asst = json.loads(r["messages"][2]["content"])
        gt_types.append(asst["type"])
        gt_objects.append(asst)
    print(f"[*] Ground truth class distribution: {Counter(gt_types)}")
    
    print("\n[+] Loading Model with 4-bit NF4 Quantization...")
    t0 = time.time()
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True
    )
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, trust_remote_code=True)
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_DIR,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True
    )
    model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    model.eval()
    print(f"[+] Model loaded in {time.time() - t0:.2f}s on {torch.cuda.get_device_name(0)}")
    
    results = []
    strict_preds = []
    lenient_preds = []
    valid_json_count = 0
    full_schema_count = 0
    sink_args_matches = 0
    sink_total = 0
    
    print("\n[+] Running GPU Inference...")
    start_eval = time.time()
    for idx, r in enumerate(test_records):
        prompt_msgs = r["messages"][:2]
        prompt_text = tokenizer.apply_chat_template(
            prompt_msgs,
            tokenize=False,
            add_generation_prompt=True
        )
        
        inputs = tokenizer(prompt_text, return_tensors="pt").to(model.device)
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=128,
                temperature=0.01,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id
            )
            
        gen_tokens = outputs[0][inputs.input_ids.shape[1]:]
        completion = tokenizer.decode(gen_tokens, skip_special_tokens=True)
        parsed = parse_model_output(completion)
        
        if parsed["is_valid_json"]:
            valid_json_count += 1
        if parsed["full_schema_valid"]:
            full_schema_count += 1
            
        strict_preds.append(parsed["strict_type"])
        lenient_preds.append(parsed["lenient_type"])
        
        gt_obj = gt_objects[idx]
        if gt_obj["type"] == "sink":
            sink_total += 1
            if parsed["sink_args"] == gt_obj.get("sink_args", []):
                sink_args_matches += 1
                
        results.append({
            "idx": idx,
            "gt": gt_obj,
            "parsed": parsed,
            "is_strict_correct": parsed["strict_type"] == gt_obj["type"]
        })
        
        if (idx + 1) % 25 == 0 or (idx + 1) == len(test_records):
            print(f"    Processed {idx + 1}/{len(test_records)} samples...")
            
    total_time = time.time() - start_eval
    avg_latency = (total_time / len(test_records)) * 1000
    
    strict_acc = accuracy_score(gt_types, strict_preds)
    lenient_acc = accuracy_score(gt_types, lenient_preds)
    valid_json_rate = valid_json_count / len(test_records)
    full_schema_rate = full_schema_count / len(test_records)
    sink_args_acc = (sink_args_matches / sink_total) if sink_total > 0 else 1.0
    
    clf_report = classification_report(
        gt_types,
        strict_preds,
        labels=VALID_CLASSES,
        output_dict=True,
        zero_division=0
    )
    
    print("\n" + "=" * 70)
    print("                     EVALUATION METRICS SUMMARY                       ")
    print("=" * 70)
    print(f"Total Samples                     : {len(test_records)}")
    print(f"Strict JSON Validity Rate         : {valid_json_rate * 100:.2f}% ({valid_json_count}/{len(test_records)})")
    print(f"Full Schema Validity Rate         : {full_schema_rate * 100:.2f}% ({full_schema_count}/{len(test_records)})")
    print(f"Strict Structured Prediction Acc  : {strict_acc * 100:.2f}%")
    print(f"Lenient Extraction Accuracy       : {lenient_acc * 100:.2f}%")
    print(f"Sink Args Match Accuracy (on sink): {sink_args_acc * 100:.2f}% ({sink_args_matches}/{sink_total})")
    print(f"Macro F1 Score                    : {clf_report['macro avg']['f1-score']:.4f}")
    print(f"Weighted F1 Score                 : {clf_report['weighted avg']['f1-score']:.4f}")
    print(f"Average Inference Latency         : {avg_latency:.2f} ms/sample")
    print("----------------------------------------------------------------------")
    print("Per-Class Metrics:")
    for cls in VALID_CLASSES:
        m = clf_report[cls]
        print(f"  [{cls.upper():<16}] Precision: {m['precision']:.4f} | Recall: {m['recall']:.4f} | F1: {m['f1-score']:.4f} | Support: {m['support']}")
    print("=" * 70)
    
    output_data = {
        "dataset_version": "NTK-IRIS-STAGE3-CANONICAL-V4.1-REPAIRED",
        "evaluation_partition": "clean_heldout_unexposed_test",
        "sample_count": len(test_records),
        "strict_json_validity_rate": valid_json_rate,
        "full_schema_validity_rate": full_schema_rate,
        "strict_structured_accuracy": strict_acc,
        "lenient_extraction_accuracy": lenient_acc,
        "sink_args_accuracy": sink_args_acc,
        "macro_f1": clf_report['macro avg']['f1-score'],
        "weighted_f1": clf_report['weighted avg']['f1-score'],
        "avg_latency_ms": avg_latency,
        "classification_report": clf_report,
        "sample_details": results
    }
    
    out_file = OUTPUT_DIR / "v3_on_clean_repaired_v4_test_evaluation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"[✓] Saved evaluation report to {out_file}")

if __name__ == "__main__":
    main()
