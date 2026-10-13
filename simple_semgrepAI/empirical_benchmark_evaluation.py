#!/usr/bin/env python3
"""
Empirical Benchmark and Scientific Evaluation (Phase F).
Đồ án Tốt nghiệp: Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp
                  phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn.

NGUYÊN TẮC KHOA HỌC BẮT BUỘC:
1. Ground Truth độc lập với Model Predictions.
2. Không định sẵn nhãn dự đoán của AI dựa trên Ground Truth.
3. Báo cáo trung thực kết quả thực nghiệm, không làm đẹp số liệu.
4. Phân tích chi tiết ma trận nhầm lẫn (Confusion Matrix), mẫu ngoại lệ và các hạn chế.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List
from collections import Counter
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

TEST_REPORT_PATH = Path("/home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/test_evaluation_report.json")
OUTPUT_DIR = Path("/home/tuankhoa/iris/docs/evaluation")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def run_empirical_evaluation():
    print("======================================================================")
    print("       EMPIRICAL BENCHMARK & SCIENTIFIC EVALUATION AUDIT              ")
    print("======================================================================")
    
    if not TEST_REPORT_PATH.exists():
        print(f"[-] Error: Held-out test evaluation report not found at {TEST_REPORT_PATH}")
        sys.exit(1)

    with open(TEST_REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_results = data.get("raw_results", [])
    total_samples = len(raw_results)
    print(f"[*] Total Held-Out Test Samples Analyzed: {total_samples}")

    ground_truths = [r.get("ground_truth") for r in raw_results]
    predictions = [r.get("prediction") for r in raw_results]

    gt_counts = Counter(ground_truths)
    pred_counts = Counter(predictions)

    print("\n--- Ground Truth Class Distribution ---")
    for cls, count in gt_counts.items():
        print(f"  - {cls:<18}: {count} ({count/total_samples*100:.2f}%)")

    print("\n--- Model Prediction Class Distribution ---")
    for cls, count in pred_counts.items():
        print(f"  - {cls:<18}: {count} ({count/total_samples*100:.2f}%)")

    # Audit unknown / malformed predictions
    unknown_samples = [r for r in raw_results if r.get("prediction") not in ["source", "sink", "taint-propagator", "none"]]
    print(f"\n[*] Unknown / Non-standard Predictions Count: {len(unknown_samples)}")
    for u in unknown_samples:
        print(f"  [!] Sample idx {u.get('idx')}: GT = {u.get('ground_truth')}, Pred = {u.get('prediction')}")
        print(f"      Raw output: {u.get('raw_output')}")

    # Standard 4 classes metrics
    labels = ["source", "sink", "taint-propagator", "none"]
    # For samples where pred is unknown, map to 'unknown' for complete accounting
    all_labels = ["source", "sink", "taint-propagator", "none", "unknown"]
    
    # Calculate exact confusion matrix including unknown
    cm_all = confusion_matrix(ground_truths, predictions, labels=all_labels)
    
    # 4-class confusion matrix (excluding unknown from prediction columns)
    # To handle 330 samples rigorously:
    # If prediction is unknown, it counts as an error for that ground truth class
    report_text = classification_report(ground_truths, predictions, labels=labels, zero_division=0)
    
    # Calculate strict accuracy
    correct = sum(1 for gt, pred in zip(ground_truths, predictions) if gt == pred)
    accuracy = correct / total_samples

    print(f"\n[*] Strict Empirical Accuracy across {total_samples} samples: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\n--- Classification Report ---")
    print(report_text)

    # Save empirical benchmark report
    summary = {
        "evaluation_name": "Stage 3 QLoRA Held-Out Test Empirical Evaluation",
        "total_samples": total_samples,
        "strict_accuracy": round(accuracy, 4),
        "ground_truth_distribution": dict(gt_counts),
        "prediction_distribution": dict(pred_counts),
        "unknown_predictions_count": len(unknown_samples),
        "unknown_samples_detail": unknown_samples,
        "labels": labels,
        "classification_report_text": report_text,
        "confusion_matrix_4x4": confusion_matrix(ground_truths, predictions, labels=labels).tolist(),
        "confusion_matrix_all_labels": all_labels,
        "confusion_matrix_all": cm_all.tolist()
    }

    report_json_path = OUTPUT_DIR / "empirical_test_results.json"
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[✓] Saved empirical evaluation JSON: {report_json_path}")

    return summary

if __name__ == "__main__":
    run_empirical_evaluation()
