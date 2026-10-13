# SCIENTIFIC PAIRED EVALUATION: BASE VS. FINE-TUNED MODEL
**Evaluation Target:** Qwen2.5-Coder-1.5B-Instruct Base vs. QLoRA V3 Adapter
**Test Partition:** Held-Out 330 Samples (`test.jsonl`)
**Execution Environment:** NVIDIA GeForce RTX 4060 Ti 16GB VRAM (WSL2/Ubuntu)
**Evaluation Protocol:** Identical Prompt, Deterministic Greedy Generation (temp=0.01, max_new_tokens=128)

## 1. Executive Summary & Paired Performance Table
| Metric | Base Model (Zero-Shot Instruct) | Fine-Tuned QLoRA V3 | Absolute Delta |
|---|:---:|:---:|:---:|
| **Strict Accuracy** | **38.79%** | **67.27%** | **+28.48%** |
| **JSON Schema Adherence** | 0.0% (0/330) | 100.0% (330/330) | +100.0% |
| **Macro F1 Score** | 0.3271 | 0.6738 | +0.3467 |
| **Weighted F1 Score** | 0.3273 | 0.6664 | +0.3391 |
| **Average Latency (ms/sample)** | 2482.5 ms | 3537.6 ms | +1055.1 ms |

## 2. Per-Class Precision, Recall, and F1 Breakdown
| Class | Support | Base Model (P / R / F1) | Fine-Tuned Model (P / R / F1) | F1 Delta |
|---|:---:|:---:|:---:|:---:|
| **`sink`** | 59 | 0.32 / 0.69 / 0.44 | 0.86 / 0.83 / 0.84 | +0.41 |
| **`source`** | 109 | 0.43 / 0.56 / 0.48 | 0.89 / 0.66 / 0.76 | +0.27 |
| **`taint-propagator`** | 86 | 0.00 / 0.00 / 0.00 | 0.60 / 0.35 / 0.44 | +0.44 |
| **`none`** | 76 | 0.45 / 0.34 / 0.39 | 0.50 / 0.93 / 0.65 | +0.26 |

## 3. McNemar's Paired Statistical Significance Test
- Both Correct: **99** samples
- FT Improved Over Base ($n_{01}$): **123** samples
- FT Regressed Below Base ($n_{10}$): **29** samples
- Both Incorrect: **79** samples
- McNemar $\chi^2$ Statistic: **56.9013**

## 4. Resolution of Sample idx 242 (Token Truncation Anomaly)
- **Problem in Historical Report:** Sample idx 242 (`UsersResource.generateNewToken`) was recorded as `unknown` with malformed JSON due to 80-token cutoff.
- **Remediation with max_new_tokens=128:**
  - Base Prediction: `none` (Valid JSON: `False`)
  - FT Prediction: `taint-propagator` (Valid JSON: `True`)
  - Output completion closed cleanly with closing braces.
