#!/usr/bin/env python3
"""
paired_evaluation.py
Paired LLM Benchmark: Base Model (Qwen2.5-Coder-1.5B-Instruct) vs Fine-Tuned QLoRA V3.
Strict evaluator requiring:
- is_valid_json
- full_schema_valid
- type_match
- exact package, class, method, signature match
- exact sink_args match
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

def load_test_records(filepath):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if line:
                d = json.loads(line)
                asst = json.loads(d["messages"][2]["content"])
                records.append({
                    "idx": idx,
                    "messages": d["messages"],
                    "gt": asst
                })
    return records

def parse_model_output(completion):
    clean = completion.strip()
    is_valid_json = False
    full_schema_valid = False
    strict_pred_type = "unknown"
    lenient_pred_type = "unknown"
    sink_args = []
    pred_pkg = ""
    pred_cls = ""
    pred_meth = ""
    pred_sig = ""
    
    try:
        data = json.loads(clean)
        is_valid_json = True
        if all(k in data for k in ["package", "class", "method", "signature", "sink_args", "type"]):
            full_schema_valid = True
            strict_pred_type = str(data.get("type", "unknown")).lower().strip()
            sink_args = data.get("sink_args", [])
            pred_pkg = str(data.get("package", "")).strip()
            pred_cls = str(data.get("class", "")).strip()
            pred_meth = str(data.get("method", "")).strip()
            pred_sig = str(data.get("signature", "")).strip()
            lenient_pred_type = strict_pred_type
    except Exception:
        pass
        
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
        "package": pred_pkg,
        "class": pred_cls,
        "method": pred_meth,
        "signature": pred_sig,
        "raw": clean
    }

def evaluate_model_on_records(model, tokenizer, records, model_name):
    print(f"\n--- Running Evaluation: {model_name} ---")
    start_time = time.time()
    results = []
    
    valid_json = 0
    full_schema = 0
    strict_role_correct = 0
    full_exact_match = 0
    
    gt_types = [r["gt"]["type"] for r in records]
    pred_types = []
    
    for r in records:
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
        
        gt = r["gt"]
        gt_type = gt["type"]
        is_sink = (gt_type == "sink")
        
        if parsed["is_valid_json"]:
            valid_json += 1
        if parsed["full_schema_valid"]:
            full_schema += 1
            
        role_match = (parsed["strict_type"] == gt_type)
        if role_match:
            strict_role_correct += 1
        pred_types.append(parsed["strict_type"])
        
        # Args match
        if is_sink:
            args_match = (parsed["sink_args"] == gt.get("sink_args", []))
        else:
            args_match = (parsed["sink_args"] == [])
            
        # Identity match (Package + Class + Method + Signature)
        ident_match = (
            parsed["package"] == gt.get("package", "") and
            parsed["class"] == gt.get("class", "") and
            parsed["method"] == gt.get("method", "") and
            parsed["signature"] == gt.get("signature", "")
        )
        
        # Strict full exact match
        is_full_exact = (
            parsed["is_valid_json"] and
            parsed["full_schema_valid"] and
            role_match and
            ident_match and
            args_match
        )
        if is_full_exact:
            full_exact_match += 1
            
        results.append({
            "idx": r["idx"],
            "gt": gt,
            "parsed": parsed,
            "role_match": role_match,
            "ident_match": ident_match,
            "args_match": args_match,
            "full_exact_match": is_full_exact
        })
        
    duration = time.time() - start_time
    total = len(records)
    
    report = classification_report(
        gt_types,
        pred_types,
        labels=VALID_CLASSES,
        output_dict=True,
        zero_division=0
    )
    
    summary = {
        "model_name": model_name,
        "total_samples": total,
        "duration_seconds": round(duration, 2),
        "ms_per_sample": round((duration / total) * 1000, 2),
        "valid_json_count": valid_json,
        "valid_json_rate": round(valid_json / total, 4),
        "full_schema_valid_count": full_schema,
        "full_schema_valid_rate": round(full_schema / total, 4),
        "strict_role_accuracy": round(strict_role_correct / total, 4),
        "strict_role_correct": strict_role_correct,
        "full_exact_match_count": full_exact_match,
        "full_exact_match_rate": round(full_exact_match / total, 4),
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
        "per_class": {
            cls: {
                "precision": round(report[cls]["precision"], 4),
                "recall": round(report[cls]["recall"], 4),
                "f1": round(report[cls]["f1-score"], 4),
                "support": report[cls]["support"]
            }
            for cls in VALID_CLASSES
        },
        "results": results
    }
    
    print(f"Results for {model_name}:")
    print(f"  JSON Validity : {valid_json}/{total} ({summary['valid_json_rate']*100:.2f}%)")
    print(f"  Schema Valid  : {full_schema}/{total} ({summary['full_schema_valid_rate']*100:.2f}%)")
    print(f"  Role Accuracy : {strict_role_correct}/{total} ({summary['strict_role_accuracy']*100:.2f}%)")
    print(f"  Strict Exact  : {full_exact_match}/{total} ({summary['full_exact_match_rate']*100:.2f}%)")
    print(f"  Macro-F1      : {summary['macro_f1']}")
    print(f"  Weighted-F1   : {summary['weighted_f1']}")
    for cls in VALID_CLASSES:
        p = summary["per_class"][cls]
        print(f"    - {cls:16s}: P={p['precision']:.4f}, R={p['recall']:.4f}, F1={p['f1']:.4f}, N={p['support']}")
        
    return summary

def main():
    print("=" * 70)
    print("  PAIRED BENCHMARK: BASE MODEL VS QLoRA V3 ON 42 HELD-OUT SAMPLES")
    print("=" * 70)
    
    records = load_test_records(CLEAN_TEST_PATH)
    print(f"[*] Loaded {len(records)} test records from {CLEAN_TEST_PATH}")
    gt_counts = Counter(r["gt"]["type"] for r in records)
    print(f"[*] Ground truth distribution: {dict(gt_counts)}")
    
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True
    )
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, trust_remote_code=True)
    
    # 1. Base Model Evaluation
    print("\n[1/2] Loading Base Model (Zero LoRA)...")
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_DIR,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True
    )
    base_model.eval()
    base_summary = evaluate_model_on_records(base_model, tokenizer, records, "Base Model (Qwen2.5-Coder-1.5B-Instruct)")
    
    # 2. Fine-Tuned Model Evaluation
    print("\n[2/2] Loading Fine-Tuned QLoRA V3 Adapter...")
    ft_model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    ft_model.eval()
    ft_summary = evaluate_model_on_records(ft_model, tokenizer, records, "Fine-Tuned (QLoRA V3 Adapter)")
    
    comparison = {
        "benchmark_name": "PAIRED_LLM_STAGE3_EVALUATION",
        "dataset_status": "CONSUMED_HELD_OUT_EVIDENCE",
        "test_path": CLEAN_TEST_PATH,
        "sample_count": len(records),
        "ground_truth_distribution": dict(gt_counts),
        "base_model": {
            "name": base_summary["model_name"],
            "valid_json_rate": base_summary["valid_json_rate"],
            "full_schema_valid_rate": base_summary["full_schema_valid_rate"],
            "strict_role_accuracy": base_summary["strict_role_accuracy"],
            "full_exact_match_rate": base_summary["full_exact_match_rate"],
            "macro_f1": base_summary["macro_f1"],
            "weighted_f1": base_summary["weighted_f1"],
            "per_class": base_summary["per_class"]
        },
        "fine_tuned_model": {
            "name": ft_summary["model_name"],
            "valid_json_rate": ft_summary["valid_json_rate"],
            "full_schema_valid_rate": ft_summary["full_schema_valid_rate"],
            "strict_role_accuracy": ft_summary["strict_role_accuracy"],
            "full_exact_match_rate": ft_summary["full_exact_match_rate"],
            "macro_f1": ft_summary["macro_f1"],
            "weighted_f1": ft_summary["weighted_f1"],
            "per_class": ft_summary["per_class"]
        },
        "delta": {
            "json_validity_delta": round(ft_summary["valid_json_rate"] - base_summary["valid_json_rate"], 4),
            "role_accuracy_delta": round(ft_summary["strict_role_accuracy"] - base_summary["strict_role_accuracy"], 4),
            "strict_exact_delta": round(ft_summary["full_exact_match_rate"] - base_summary["full_exact_match_rate"], 4),
            "macro_f1_delta": round(ft_summary["macro_f1"] - base_summary["macro_f1"], 4),
            "weighted_f1_delta": round(ft_summary["weighted_f1"] - base_summary["weighted_f1"], 4)
        },
        "base_details": base_summary["results"],
        "fine_tuned_details": ft_summary["results"]
    }
    
    out_file = OUTPUT_DIR / "paired_base_vs_ft_v3_evaluation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False)
        
    print("\n" + "=" * 70)
    print("  PAIRED BENCHMARK COMPARISON SUMMARY")
    print("=" * 70)
    print(f"Metric                 Base Model       Fine-Tuned (V3)      Delta")
    print(f"----------------------------------------------------------------------")
    print(f"JSON Validity Rate     {base_summary['valid_json_rate']*100:6.2f}%          {ft_summary['valid_json_rate']*100:6.2f}%         {comparison['delta']['json_validity_delta']*100:+6.2f}%")
    print(f"Schema Keyset Rate     {base_summary['full_schema_valid_rate']*100:6.2f}%          {ft_summary['full_schema_valid_rate']*100:6.2f}%         {(ft_summary['full_schema_valid_rate'] - base_summary['full_schema_valid_rate'])*100:+6.2f}%")
    print(f"Role Label Accuracy    {base_summary['strict_role_accuracy']*100:6.2f}%          {ft_summary['strict_role_accuracy']*100:6.2f}%         {comparison['delta']['role_accuracy_delta']*100:+6.2f}%")
    print(f"Strict Exact Match     {base_summary['full_exact_match_rate']*100:6.2f}%          {ft_summary['full_exact_match_rate']*100:6.2f}%         {comparison['delta']['strict_exact_delta']*100:+6.2f}%")
    print(f"Macro F1               {base_summary['macro_f1']:6.4f}           {ft_summary['macro_f1']:6.4f}          {comparison['delta']['macro_f1_delta']:+6.4f}")
    print(f"Weighted F1            {base_summary['weighted_f1']:6.4f}           {ft_summary['weighted_f1']:6.4f}          {comparison['delta']['weighted_f1_delta']:+6.4f}")
    print(f"\n[✓] Paired report saved to {out_file}")

if __name__ == "__main__":
    main()
