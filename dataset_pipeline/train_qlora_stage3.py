#!/usr/bin/env python3
"""
train_qlora_stage3.py

Complete, Production-Grade QLoRA Fine-Tuning Pipeline for Qwen2.5-Coder-1.5B
Designed for IRIS Neurosymbolic SAST Stage 3 API Classification.

Hardware target: NVIDIA GeForce RTX 4060 Ti 16GB VRAM
Dataset: NTK-IRIS-STAGE3-AUGMENTED-V3-20261012
"""

import os
import sys
import json
import torch
import numpy as np
from typing import Any, Dict, List
from collections import Counter
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    TaskType,
)
from datasets import Dataset

import transformers.trainer
import transformers.utils.import_utils

# Allow trusted local checkpoint loading for PyTorch 2.5
transformers.trainer.check_torch_load_is_safe = lambda: None
transformers.utils.import_utils.check_torch_load_is_safe = lambda: None

_orig_torch_load = torch.load
def _custom_torch_load(*args, **kwargs):
    kwargs["weights_only"] = False
    return _orig_torch_load(*args, **kwargs)
torch.load = _custom_torch_load


# =====================================================================
# 1. CONFIGURATION & HYPERPARAMETERS
# =====================================================================
MODEL_DIR = "/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct"
DATASET_DIR = "/home/tuankhoa/migration/dataset_v3_augmented_20261012"
OUTPUT_DIR = "/home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3"

MAX_SEQ_LENGTH = 1024
EPOCHS = 3
MICRO_BATCH_SIZE = 2
GRAD_ACCUM_STEPS = 4  # Effective batch size = 2 * 4 = 8
LEARNING_RATE = 2e-4
WARMUP_RATIO = 0.05
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.05
TARGET_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj"
]

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =====================================================================
# 2. DATASET LOADER & COMPLETION MASKING COLLATOR
# =====================================================================
def load_jsonl_dataset(filepath):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records

class ChatCompletionDataCollator:
    """
    Data collator that tokenizes ChatML dialogues and masks all prompt tokens
    with -100 so that cross-entropy loss is computed exclusively on the
    assistant's JSON classification response.
    """
    def __init__(self, tokenizer, max_length=1024):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.response_template = "<|im_start|>assistant\n"
        self.response_token_ids = self.tokenizer.encode(self.response_template, add_special_tokens=False)

    def __call__(self, batch: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        input_ids_list = []
        labels_list = []
        attention_mask_list = []

        for item in batch:
            messages = item["messages"]
            full_text = self.tokenizer.apply_chat_template(messages, tokenize=False)
            tokenized = self.tokenizer(
                full_text,
                truncation=True,
                max_length=self.max_length,
                add_special_tokens=False
            )
            input_ids = tokenized["input_ids"]
            attention_mask = tokenized["attention_mask"]

            # Initialize labels with -100 (masked)
            labels = [-100] * len(input_ids)

            # Find the position where assistant message starts
            for i in range(len(input_ids) - len(self.response_token_ids) + 1):
                if input_ids[i:i + len(self.response_token_ids)] == self.response_token_ids:
                    start_idx = i + len(self.response_token_ids)
                    labels[start_idx:] = input_ids[start_idx:]
                    break

            input_ids_list.append(input_ids)
            labels_list.append(labels)
            attention_mask_list.append(attention_mask)

        # Pad to max length in this batch
        max_batch_len = max(len(ids) for ids in input_ids_list)
        padded_input_ids = []
        padded_labels = []
        padded_attention_mask = []

        pad_token_id = self.tokenizer.pad_token_id or self.tokenizer.eos_token_id

        for ids, lbls, mask in zip(input_ids_list, labels_list, attention_mask_list):
            pad_len = max_batch_len - len(ids)
            padded_input_ids.append(ids + [pad_token_id] * pad_len)
            padded_labels.append(lbls + [-100] * pad_len)
            padded_attention_mask.append(mask + [0] * pad_len)

        return {
            "input_ids": torch.tensor(padded_input_ids, dtype=torch.long),
            "labels": torch.tensor(padded_labels, dtype=torch.long),
            "attention_mask": torch.tensor(padded_attention_mask, dtype=torch.long),
        }

# =====================================================================
# 3. POST-TRAINING TEST SET EVALUATOR
# =====================================================================
def evaluate_on_test_set(model, tokenizer, test_records, output_dir):
    print("\n" + "=" * 70, flush=True)
    print("  RUNNING COMPREHENSIVE BENCHMARK ON HELD-OUT TEST SET (330 SAMPLES)", flush=True)
    print("=" * 70, flush=True)

    model.eval()
    if hasattr(model.config, "use_cache"):
        model.config.use_cache = True
    y_true = []
    y_pred = []
    raw_results = []
    valid_classes = ["source", "sink", "taint-propagator", "none"]

    for idx, record in enumerate(test_records):
        messages = record["messages"]
        # Ground truth
        gt_obj = json.loads(messages[2]["content"])
        gt_type = gt_obj["type"]
        y_true.append(gt_type)

        # Prompt input (system + user)
        prompt_msgs = messages[:2]
        prompt_text = tokenizer.apply_chat_template(prompt_msgs, add_generation_prompt=True, tokenize=False)
        inputs = tokenizer(prompt_text, return_tensors="pt").to("cuda:0")

        with torch.no_grad():
            generated_ids = model.generate(
                **inputs,
                max_new_tokens=80,
                temperature=0.01,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id
            )

        # Decode generated completion only
        prompt_len = inputs["input_ids"].shape[1]
        completion = tokenizer.decode(generated_ids[0][prompt_len:], skip_special_tokens=True).strip()

        # Parse JSON
        pred_type = "unknown"
        try:
            parsed = json.loads(completion)
            pred_type = parsed.get("type", "unknown")
        except Exception:
            # Fallback regex search for type
            for c in valid_classes:
                if f'"{c}"' in completion or f"'{c}'" in completion:
                    pred_type = c
                    break

        y_pred.append(pred_type)
        raw_results.append({
            "idx": idx,
            "ground_truth": gt_type,
            "prediction": pred_type,
            "raw_output": completion
        })

        if (idx + 1) % 50 == 0 or (idx + 1) == len(test_records):
            curr_acc = accuracy_score(y_true, y_pred)
            print(f"  --> Processed {idx + 1}/{len(test_records)} test samples | Current Accuracy: {curr_acc:.4f}")

    # Generate Metrics Report
    acc = accuracy_score(y_true, y_pred)
    clf_report = classification_report(y_true, y_pred, labels=valid_classes, output_dict=True, zero_division=0)
    clf_text = classification_report(y_true, y_pred, labels=valid_classes, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=valid_classes).tolist()

    report_payload = {
        "accuracy": acc,
        "classification_report": clf_report,
        "confusion_matrix": {
            "labels": valid_classes,
            "matrix": cm
        },
        "total_test_samples": len(test_records),
        "raw_results": raw_results
    }

    report_path = os.path.join(output_dir, "test_evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    text_report_path = os.path.join(output_dir, "test_classification_report.txt")
    with open(text_report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  NTK/IRIS STAGE 3 - HELD-OUT TEST EVALUATION REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Total Test Samples: {len(test_records)}\n")
        f.write(f"Overall Accuracy:   {acc:.4f} ({acc*100:.2f}%)\n\n")
        f.write("Classification Report:\n")
        f.write(clf_text + "\n\n")
        f.write("Confusion Matrix:\n")
        f.write(f"Labels: {valid_classes}\n")
        for row, label in zip(cm, valid_classes):
            f.write(f"{label:18}: {row}\n")

    print("\n" + "=" * 70)
    print("  FINAL HELD-OUT TEST METRICS:")
    print("=" * 70)
    print(clf_text)
    print(f"[✓] Evaluation report saved to {report_path}")
    print(f"[✓] Text classification report saved to {text_report_path}")

# =====================================================================
# 4. TRAINING ENGINE
# =====================================================================
def main():
    print("=" * 70)
    print("  NTK/IRIS QLoRA Stage 3 Fine-Tuning Engine (Qwen2.5-Coder-1.5B)")
    print("=" * 70)

    # 1. Check GPU & CUDA
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available. GPU is required for QLoRA training.")
    device_name = torch.cuda.get_device_name(0)
    total_vram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
    print(f"[*] Target GPU: {device_name} ({total_vram:.1f} GB VRAM)")

    # 2. Load Tokenizer
    print(f"[*] Loading Tokenizer from {MODEL_DIR}...")
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_DIR,
        use_fast=True,
        trust_remote_code=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 3. Configure 4-Bit NormalFloat Quantization (BitsAndBytes)
    print("[*] Configuring 4-Bit NF4 Quantization with double quantization...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    # 4. Load Base Model in 4-Bit
    print(f"[*] Loading Base CausalLM in 4-bit NF4...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_DIR,
        quantization_config=bnb_config,
        device_map={"": 0},
        dtype=torch.bfloat16,
        trust_remote_code=True,
    )
    model.config.use_cache = False

    # 5. Prepare for K-Bit Training & Gradient Checkpointing
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False}
    )

    # 6. Apply LoRA Adapter Config
    print(f"[*] Attaching PEFT/LoRA Adapter (r={LORA_R}, alpha={LORA_ALPHA}, dropout={LORA_DROPOUT})...")
    lora_config = LoraConfig(
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
        target_modules=TARGET_MODULES,
    )
    model = get_peft_model(model, lora_config)
    print("[✓] Trainable Parameters:")
    model.print_trainable_parameters()

    # 7. Load Datasets
    train_file = os.path.join(DATASET_DIR, "train.jsonl")
    val_file = os.path.join(DATASET_DIR, "validation.jsonl")
    test_file = os.path.join(DATASET_DIR, "test.jsonl")

    print(f"[*] Loading Dataset Splits from {DATASET_DIR}...")
    train_raw = load_jsonl_dataset(train_file)
    val_raw = load_jsonl_dataset(val_file)
    test_raw = load_jsonl_dataset(test_file)

    train_ds = Dataset.from_list(train_raw)
    val_ds = Dataset.from_list(val_raw)

    print(f"    Train size: {len(train_ds)}")
    print(f"    Validation size: {len(val_ds)}")
    print(f"    Test size: {len(test_raw)}")

    data_collator = ChatCompletionDataCollator(tokenizer, max_length=MAX_SEQ_LENGTH)

    # 8. Training Arguments
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=MICRO_BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM_STEPS,
        per_device_eval_batch_size=MICRO_BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        lr_scheduler_type="cosine",
        warmup_steps=23,
        max_grad_norm=1.0,
        weight_decay=0.01,
        bf16=True,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=50,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        optim="paged_adamw_8bit",
        gradient_checkpointing=True,
        remove_unused_columns=False,
        report_to="none",
        seed=42,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=data_collator,
    )

    # Check for previous checkpoint to resume
    resume_from_checkpoint = None
    if os.path.isdir(OUTPUT_DIR):
        ckpt_dirs = [
            os.path.join(OUTPUT_DIR, d)
            for d in os.listdir(OUTPUT_DIR)
            if d.startswith("checkpoint-") and os.path.isdir(os.path.join(OUTPUT_DIR, d))
        ]
        if ckpt_dirs:
            ckpt_dirs.sort(key=lambda x: int(x.split("-")[-1]))
            latest_ckpt = ckpt_dirs[-1]
            state_file = os.path.join(latest_ckpt, "trainer_state.json")
            if os.path.exists(state_file):
                print(f"[✓] Auto-detected intact checkpoint: {latest_ckpt}", flush=True)
                print(f"[*] Resuming QLoRA fine-tuning seamlessly from step {latest_ckpt.split('-')[-1]}...", flush=True)
                resume_from_checkpoint = latest_ckpt

    print("\n" + "=" * 70, flush=True)
    print("  STARTING QLORA FINE-TUNING EXECUTION", flush=True)
    print("=" * 70, flush=True)
    train_result = trainer.train(resume_from_checkpoint=resume_from_checkpoint)

    print("\n[✓] Training completed successfully!")
    metrics = train_result.metrics
    trainer.log_metrics("train", metrics)
    trainer.save_metrics("train", metrics)

    # 9. Save Best Model Adapter & Tokenizer
    best_adapter_dir = os.path.join(OUTPUT_DIR, "best_adapter")
    print(f"[*] Saving best QLoRA adapter to {best_adapter_dir}...")
    trainer.save_model(best_adapter_dir)
    tokenizer.save_pretrained(best_adapter_dir)

    # 10. Run Full Test Set Evaluation
    evaluate_on_test_set(trainer.model, tokenizer, test_raw, OUTPUT_DIR)

    print("\n[✓] ALL DONE! Model adapter and graduation evaluation reports generated successfully!")

if __name__ == "__main__":
    main()
