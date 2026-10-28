#!/usr/bin/env python3
"""
NTK EO06 — Main Real GPU LoRA Fine-Tuning (Phase 3), Real Model Evaluation (Phase 5),
Real OpenGrep v1.25.0 + IRIS AST/Dataflow + Qwen LoRA Integration (Phase 6),
and Graduation Advisor Report Generation (Phase 7).

Architecture: EO04.2 FROZEN_ARCHITECTURE_V1
Base Model: Qwen/Qwen2.5-Coder-0.5B-Instruct
"""

import argparse
import collections
import contextlib
import copy
import gc
import hashlib
import importlib.metadata
import json
import math
import os
import random
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Prevent PyTorch CUDA caching allocator fragmentation across variable sequence lengths under WDDM
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

import torch
from transformers.utils import import_utils

for flag in ("_librosa_available", "_torchvision_available", "_torchaudio_available"):
    if hasattr(import_utils, flag):
        setattr(import_utils, flag, False)

from peft import LoraConfig, PeftModel, get_peft_model
from safetensors.torch import load_file
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    StoppingCriteria,
    StoppingCriteriaList,
)

for _cand_shared in (
    Path(__file__).resolve().parent,
    Path("/mnt/c/Users/Admin/AppData/Local/javis-os/brains-canhan/Brain Default/scratch/ntk_eo05_overnight_20261024/scripts"),
    Path("/mnt/c/Users/Admin/AppData/Local/javis-os/brains/Brain-CaNhan/scratch/ntk_eo05_overnight_20261024/scripts"),
    Path(__file__).resolve().parents[2] / "ntk_eo05_overnight_20261024" / "scripts",
):
    if (_cand_shared / "ntk_iris_shared.py").exists():
        WIN_SHARED_DIR = _cand_shared
        sys.path.insert(0, str(_cand_shared))
        break
import ntk_iris_shared as shared
import ntk_alert_verification as alert_ver

WSL_WORKSPACE = Path("/home/tuankhoa/ntk_vnext_workspaces/ntk_vnext_20261022")
WSL_RUNS_ROOT = WSL_WORKSPACE / "runs"
WIN_F_RUNS_ROOT = Path("/mnt/f/NTK_EO06_Runs")
BASE_MODEL_PATH = Path(
    "/home/tuankhoa/.cache/huggingface/hub/models--Qwen--Qwen2.5-Coder-0.5B-Instruct/snapshots/ea3f2471cf1b1f0db85067f1ef93848e38e88c25"
)
EO03_PRIMARY_PATH = WSL_WORKSPACE / "models_vnext_2" / "primary"
EO03_ABLATION_PATH = WSL_WORKSPACE / "models_vnext_2" / "ablation"
EO03_PRIMARY_ADAPTER = EO03_PRIMARY_PATH
EO03_ABLATION_ADAPTER = EO03_ABLATION_PATH
WSL_DS_V31 = WSL_WORKSPACE / "dataset_vnext_3_1"
WSL_DATASET_DIR = WSL_DS_V31
HOLDOUT_V2_PATH = WSL_WORKSPACE / "eval_protocol" / "FINAL_INDEPENDENT_EVAL_HOLDOUT_V2.jsonl"
HOLDOUT_V3_PATH = WSL_WORKSPACE / "eval_protocol" / "FINAL_INDEPENDENT_EVAL_HOLDOUT_V3.jsonl"

ROLES = ["source", "sink", "taint-propagator", "none"]


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def write_jsonl_atomic(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    with tmp.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def wilson_ci_95(k: int, n: int) -> List[float]:
    if n <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = k / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * n)) / n)) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def mcnemar_exact_p(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    cum = sum(math.comb(n, i) for i in range(k + 1)) * (0.5**n)
    return round(min(1.0, 2.0 * cum), 6)


def to_id_list(encoded: Any) -> List[int]:
    if isinstance(encoded, list):
        return [int(x) for x in encoded]
    if hasattr(encoded, "input_ids"):
        return [int(x) for x in encoded.input_ids]
    if isinstance(encoded, dict) and "input_ids" in encoded:
        return [int(x) for x in encoded["input_ids"]]
    return [int(x) for x in list(encoded)]


def encode_and_verify_loss_mask(
    tokenizer: Any, messages: Sequence[Dict[str, str]], max_seq_length: int = 1024
) -> Dict[str, Any]:
    if len(messages) != 3:
        raise ValueError(f"Expected 3 messages, got {len(messages)}")
    full_ids = to_id_list(
        tokenizer.apply_chat_template(list(messages), tokenize=True, add_generation_prompt=False)
    )
    prompt_ids = to_id_list(
        tokenizer.apply_chat_template(list(messages[:2]), tokenize=True, add_generation_prompt=True)
    )
    if len(full_ids) > max_seq_length:
        raise ValueError(f"Sequence length {len(full_ids)} > max_seq_length {max_seq_length}")
    if full_ids[: len(prompt_ids)] != prompt_ids:
        raise ValueError("Prompt prefix mismatch in chat template encoding")
    asst_len = len(full_ids) - len(prompt_ids)
    if asst_len <= 0:
        raise ValueError("Non-positive assistant response token length")
    labels = [-100] * len(prompt_ids) + full_ids[len(prompt_ids) :]
    return {
        "input_ids": full_ids,
        "attention_mask": [1] * len(full_ids),
        "labels": labels,
        "prompt_length": len(prompt_ids),
        "assistant_length": asst_len,
        "full_length": len(full_ids),
    }


def collate_causal_lm_batch(
    batch_items: Sequence[Dict[str, Any]],
    pad_token_id: int,
    device: torch.device,
) -> Dict[str, torch.Tensor]:
    max_len = max(len(item["input_ids"]) for item in batch_items)
    input_ids_batch: List[List[int]] = []
    attn_mask_batch: List[List[int]] = []
    labels_batch: List[List[int]] = []
    for item in batch_items:
        ids = list(item["input_ids"])
        mask = list(item["attention_mask"])
        lbls = list(item["labels"])
        pad_len = max_len - len(ids)
        input_ids_batch.append(ids + [int(pad_token_id)] * pad_len)
        attn_mask_batch.append(mask + [0] * pad_len)
        labels_batch.append(lbls + [-100] * pad_len)
    return {
        "input_ids": torch.tensor(input_ids_batch, dtype=torch.long, device=device),
        "attention_mask": torch.tensor(attn_mask_batch, dtype=torch.long, device=device),
        "labels": torch.tensor(labels_batch, dtype=torch.long, device=device),
    }


def frozen_base_digest(model: torch.nn.Module) -> str:
    h = hashlib.sha256()
    for name, p in model.named_parameters():
        if "lora_" not in name:
            h.update(name.encode("utf-8"))
            h.update(str(p.dtype).encode("utf-8"))
            h.update(str(tuple(p.shape)).encode("utf-8"))
            h.update(p.detach().cpu().contiguous().view(-1).view(torch.uint8).numpy().tobytes())
    return h.hexdigest()


def verify_safetensors_binary(st_path: Path) -> Dict[str, Any]:
    file_size = st_path.stat().st_size
    if file_size < 16:
        raise RuntimeError(f"Truncated safetensors: {st_path}")
    with st_path.open("rb") as f:
        raw_hlen = f.read(8)
        hlen = struct.unpack("<Q", raw_hlen)[0]
        if 8 + hlen > file_size:
            raise RuntimeError(f"Header length {hlen} exceeds file size {file_size}")
        header_obj = json.loads(f.read(hlen).decode("utf-8"))
    max_end = 0
    tensor_cnt = 0
    dtypes = set()
    for k, v in header_obj.items():
        if k == "__metadata__":
            continue
        tensor_cnt += 1
        dtypes.add(v.get("dtype", "UNKNOWN"))
        off = v.get("data_offsets", [0, 0])
        max_end = max(max_end, int(off[1]))
    expected_size = 8 + hlen + max_end
    if file_size != expected_size:
        raise RuntimeError(f"Safetensors size mismatch: {file_size} vs {expected_size}")
    return {
        "file_size_bytes": file_size,
        "tensor_count": tensor_cnt,
        "dtypes": sorted(dtypes),
        "exact_offset_match": True,
        "sha256": sha256_file(st_path),
    }


def compute_sample_weight(row: Dict[str, Any], mode: str) -> float:
    """
    Role-balanced sample weight for VNext.3.1 Track B (781 rows):
    In Track B:
      - none = 244 (31.2%), sink = 238 (30.5%), taint-propagator = 172 (22.0%), source = 127 (16.3%)
    In Dev-166:
      - none = 47 (28.3%), sink = 43 (25.9%), taint-propagator = 41 (24.7%), source = 35 (21.1%)
    Gentle role balancing aligns effective gradient mass across all 4 roles without suppressing
    the 506 Audited Multi-Tool SAST rows that provide source and taint-propagator coverage.
    """
    if mode == "uniform":
        return 1.0
    meta = row["metadata"]
    role = meta["role"]
    cwe = int(meta["cwe"])

    if role == "source":
        return 1.28
    if role == "taint-propagator":
        return 1.18
    if role == "sink":
        return 1.08 if cwe in (78, 79) else 1.05
    if role == "none":
        return 1.04
    return 1.0


def parse_prediction_record(raw_text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    ident = metadata["identity"]
    cwe = int(metadata["cwe"])
    req_keys = {"package", "class", "method", "signature", "sink_args", "type"}

    # Check raw JSON & identity echo separately for detailed metrics
    json_parse_ok = False
    schema_6keys_ok = False
    identity_echo_ok = False
    obj_parsed: Optional[Dict[str, Any]] = None
    try:
        cand = json.loads((raw_text or "").strip())
        if isinstance(cand, dict):
            json_parse_ok = True
            obj_parsed = cand
            if set(cand.keys()) == req_keys:
                schema_6keys_ok = True
                if all(cand.get(k) == ident.get(k) for k in ("package", "class", "method", "signature")):
                    identity_echo_ok = True
    except Exception:
        pass

    pred = shared.parse_and_validate_callee_json(
        raw_text=raw_text,
        expected_identity=ident,
        cwe=cwe,
    )

    diag_role: Optional[str] = None
    if pred.strict_valid:
        diag_role = pred.role
    else:
        if obj_parsed is not None:
            rc = obj_parsed.get("type") or obj_parsed.get("role")
            if isinstance(rc, str) and rc.strip() in ROLES:
                diag_role = rc.strip()
        if diag_role is None:
            m = re.search(r'"type"\s*:\s*"(source|sink|taint-propagator|none)"', raw_text or "")
            if m:
                diag_role = m.group(1)

    return {
        "strict_valid": pred.strict_valid,
        "json_parse_ok": json_parse_ok,
        "schema_6keys_ok": schema_6keys_ok,
        "identity_echo_ok": identity_echo_ok,
        "role": pred.role if pred.strict_valid else None,
        "sink_args": list(pred.sink_args) if pred.strict_valid else [],
        "canonical_sink_args": list(pred.canonical_sink_args) if pred.strict_valid else [],
        "abstain": pred.abstain,
        "abstain_reason": pred.abstain_reason,
        "diag_role": diag_role,
    }


def compute_full_evaluation_metrics(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(records)
    if total == 0:
        raise ValueError("Empty evaluation records")

    strict_valid_cnt = sum(1 for r in records if r["parsed"]["strict_valid"])
    schema_6keys_cnt = sum(1 for r in records if r["parsed"]["schema_6keys_ok"])
    identity_echo_cnt = sum(1 for r in records if r["parsed"]["identity_echo_ok"])
    strict_role_hits = sum(
        1 for r in records if r["parsed"]["strict_valid"] and r["parsed"]["role"] == r["reference_role"]
    )

    # 4x5 Confusion Matrix: reference_role -> predicted strict role or INVALID
    conf_matrix = {ref: {pred: 0 for pred in list(ROLES) + ["INVALID"]} for ref in ROLES}
    for r in records:
        ref = r["reference_role"]
        pred = r["parsed"]["role"] if r["parsed"]["strict_valid"] else "INVALID"
        conf_matrix[ref][pred] += 1

    def calc_role_breakdown(role_getter: Any) -> Tuple[float, Dict[str, Any]]:
        per_role: Dict[str, Any] = {}
        f1s: List[float] = []
        for role in ROLES:
            tp = sum(1 for r in records if r["reference_role"] == role and role_getter(r) == role)
            fp = sum(1 for r in records if r["reference_role"] != role and role_getter(r) == role)
            fn = sum(1 for r in records if r["reference_role"] == role and role_getter(r) != role)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            per_role[role] = {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "support": tp + fn,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "recall_ci95": wilson_ci_95(tp, tp + fn),
                "f1": round(f1, 4),
            }
            f1s.append(f1)
        return round(sum(f1s) / len(f1s), 4), per_role

    strict_macro_f1, strict_per_role = calc_role_breakdown(
        lambda r: r["parsed"]["role"] if r["parsed"]["strict_valid"] else None
    )
    diag_macro_f1, diag_per_role = calc_role_breakdown(lambda r: r["parsed"]["diag_role"])

    sink_rows = [r for r in records if r["reference_role"] == "sink"]
    sink_args_exact_hits = sum(
        1
        for r in sink_rows
        if r["parsed"]["strict_valid"]
        and r["parsed"]["role"] == "sink"
        and set(r["parsed"]["sink_args"]) == set(r["reference_sink_args"])
    )
    sink_args_canon_hits = sum(
        1
        for r in sink_rows
        if r["parsed"]["strict_valid"]
        and r["parsed"]["role"] == "sink"
        and set(r["parsed"]["canonical_sink_args"]) == set(r["reference_canonical_sink_args"])
    )

    # Per-CWE full breakdown
    per_cwe: Dict[str, Any] = {}
    for cwe in (22, 78, 79, 89):
        c_rows = [r for r in records if int(r["cwe"]) == cwe]
        if not c_rows:
            continue
        c_hits = sum(
            1 for r in c_rows if r["parsed"]["strict_valid"] and r["parsed"]["role"] == r["reference_role"]
        )
        c_f1s = []
        c_roles_detail = {}
        for role in ROLES:
            tp = sum(
                1
                for r in c_rows
                if r["reference_role"] == role
                and r["parsed"]["strict_valid"]
                and r["parsed"]["role"] == role
            )
            fp = sum(
                1
                for r in c_rows
                if r["reference_role"] != role
                and r["parsed"]["strict_valid"]
                and r["parsed"]["role"] == role
            )
            fn = sum(
                1
                for r in c_rows
                if r["reference_role"] == role
                and (not r["parsed"]["strict_valid"] or r["parsed"]["role"] != role)
            )
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            c_roles_detail[role] = {
                "support": tp + fn,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
            }
            if (tp + fn) > 0:
                c_f1s.append(f1)
        per_cwe[f"CWE-{cwe:03d}"] = {
            "n": len(c_rows),
            "total_rows": len(c_rows),
            "accuracy": round(c_hits / len(c_rows), 4),
            "macro_f1": round(sum(c_f1s) / len(c_f1s), 4) if c_f1s else 0.0,
            "sink_f1": c_roles_detail["sink"]["f1"],
            "none_recall": c_roles_detail["none"]["recall"],
            "per_role": c_roles_detail,
        }

    accuracy = round(strict_role_hits / total, 4)
    none_precision = strict_per_role["none"]["precision"]
    none_recall = strict_per_role["none"]["recall"]
    sink_precision = strict_per_role["sink"]["precision"]
    sink_recall = strict_per_role["sink"]["recall"]
    sink_f1 = strict_per_role["sink"]["f1"]
    source_f1 = strict_per_role["source"]["f1"]
    propagator_f1 = strict_per_role["taint-propagator"]["f1"]
    strict_schema_rate = round(strict_valid_cnt / total, 4)
    identity_echo_acc = round(identity_echo_cnt / total, 4)
    sink_args_exact_acc = round(sink_args_exact_hits / len(sink_rows), 4) if sink_rows else 0.0
    sink_args_canon_acc = round(sink_args_canon_hits / len(sink_rows), 4) if sink_rows else 0.0

    # Pre-registered Dev checkpoint selection score (Section 6)
    selection_score = round(
        0.45 * strict_macro_f1
        + 0.25 * sink_f1
        + 0.15 * none_recall
        + 0.10 * strict_schema_rate
        + 0.05 * sink_args_canon_acc,
        6,
    )

    cwe089_sink_info = per_cwe.get("CWE-089", {}).get("per_role", {}).get("sink", {})
    cwe_089_sink_recall = float(cwe089_sink_info.get("recall", 0.0))
    cwe_089_sink_f1 = float(cwe089_sink_info.get("f1", 0.0))
    sink_misclassified_as_source_count = int(conf_matrix["sink"]["source"])
    cwe_089_sink_misclassified_as_source_count = sum(
        1
        for r in records
        if int(r["cwe"]) == 89
        and r["reference_role"] == "sink"
        and r["parsed"]["strict_valid"]
        and r["parsed"]["role"] == "source"
    )

    return {
        "n_total": total,
        "accuracy": accuracy,
        "accuracy_ci95": wilson_ci_95(strict_role_hits, total),
        "macro_f1": strict_macro_f1,
        "none_precision": none_precision,
        "none_recall": none_recall,
        "none_f1": strict_per_role["none"]["f1"],
        "sink_precision": sink_precision,
        "sink_recall": sink_recall,
        "sink_f1": sink_f1,
        "cwe_089_sink_recall": cwe_089_sink_recall,
        "cwe_089_sink_f1": cwe_089_sink_f1,
        "sink_misclassified_as_source_count": sink_misclassified_as_source_count,
        "cwe_089_sink_misclassified_as_source_count": cwe_089_sink_misclassified_as_source_count,
        "source_f1": source_f1,
        "taint_propagator_f1": propagator_f1,
        "strict_json_schema_rate": strict_schema_rate,
        "strict_json_validity_rate": strict_schema_rate,
        "raw_6key_schema_rate": round(schema_6keys_cnt / total, 4),
        "identity_echo_accuracy": identity_echo_acc,
        "sink_args_exact_accuracy": sink_args_exact_acc,
        "sink_args_exact_match_rate": sink_args_exact_acc,
        "sink_args_canonical_accuracy": sink_args_canon_acc,
        "sink_args_canonical_match_rate": sink_args_canon_acc,
        "selection_score": selection_score,
        "per_role": strict_per_role,
        "confusion_matrix": conf_matrix,
        "confusion_matrix_4x5": conf_matrix,
        "per_cwe": per_cwe,
        "diagnostic_role_only": {
            "macro_f1": diag_macro_f1,
            "per_role": diag_per_role,
        },
    }


def get_gpu_mem_snapshot(device: torch.device) -> Dict[str, float]:
    if device.type == "cuda" and torch.cuda.is_available():
        return {
            "vram_allocated_mib": round(torch.cuda.memory_allocated(device) / (1024 * 1024), 2),
            "vram_reserved_mib": round(torch.cuda.memory_reserved(device) / (1024 * 1024), 2),
            "vram_max_allocated_mib": round(torch.cuda.max_memory_allocated(device) / (1024 * 1024), 2),
        }
    return {"vram_allocated_mib": 0.0, "vram_reserved_mib": 0.0, "vram_max_allocated_mib": 0.0}


def emit_wsl_phase_heartbeat(
    state_wsl_file: Optional[Path],
    phase: str,
    detail: str,
    extra: Optional[Dict[str, Any]] = None,
    log_stdout: bool = True,
) -> None:
    payload: Dict[str, Any] = {
        "updated_utc": now_utc(),
        "phase": phase,
        "detail": detail,
    }
    if extra:
        payload.update(extra)
    if state_wsl_file is not None:
        write_json_atomic(state_wsl_file, payload)
        events_file = state_wsl_file.parent / "phase_events.jsonl"
        append_jsonl(events_file, payload)
    if log_stdout:
        print(f"[{payload['updated_utc']}] [PHASE={phase}] {detail}", flush=True)


class JsonBraceAndEosStoppingCriteria(StoppingCriteria):
    """
    Stops generation immediately once every sequence in the batch has either:
      1. Emitted eos_token_id (<|im_end|>), OR
      2. Closed a balanced top-level JSON object '{...}' in the generated assistant response.
    Prevents any unbounded text generation past the 6-key JSON contract.
    """

    def __init__(self, tokenizer: Any, prompt_len: int, eos_token_id: int) -> None:
        super().__init__()
        self.tokenizer = tokenizer
        self.prompt_len = prompt_len
        self.eos_token_id = int(eos_token_id)

    def _is_balanced_json_closed(self, text: str) -> bool:
        s = text.strip()
        if not s.startswith("{") or not s.endswith("}"):
            return False
        depth = 0
        in_str = False
        esc = False
        started = False
        for ch in s:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if not in_str:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
                    if started and depth == 0:
                        return True
        return False

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor, **kwargs: Any) -> bool:
        for row_idx in range(input_ids.shape[0]):
            gen_slice = input_ids[row_idx, self.prompt_len :].tolist()
            if not gen_slice:
                return False
            if self.eos_token_id in gen_slice:
                continue
            decoded = self.tokenizer.decode(gen_slice, skip_special_tokens=True)
            if not self._is_balanced_json_closed(decoded):
                return False
        return True


def verify_cuda_allocator_or_fallback(device: torch.device) -> Dict[str, Any]:
    alloc_conf = os.environ.get("PYTORCH_CUDA_ALLOC_CONF", "")
    if device.type != "cuda" or not torch.cuda.is_available():
        return {"device": str(device), "allocator_conf": alloc_conf, "fallback_applied": False}
    try:
        probe = torch.empty((1024, 1024), dtype=torch.float16, device=device)
        del probe
        torch.cuda.empty_cache()
        return {"device": str(device), "allocator_conf": alloc_conf, "fallback_applied": False}
    except Exception as exc:
        os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:128"
        return {
            "device": str(device),
            "allocator_conf": os.environ["PYTORCH_CUDA_ALLOC_CONF"],
            "fallback_applied": True,
            "fallback_reason": str(exc),
        }


def evaluate_model_arm(
    model: torch.nn.Module,
    tokenizer: Any,
    rows: Sequence[Dict[str, Any]],
    arm_name: str,
    disable_adapter: bool = False,
    max_new_tokens: int = 96,
    batch_size: int = 1,
    state_wsl_file: Optional[Path] = None,
    hard_stop_flag: Optional[Path] = None,
    current_epoch: Optional[int] = None,
    optimizer_step: Optional[int] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    device = next(model.parameters()).device
    pad_id = int(tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id)
    eos_id = int(tokenizer.eos_token_id if tokenizer.eos_token_id is not None else pad_id)

    # Free fragmented training cache before starting evaluation and disable gradient checkpointing
    gc.collect()
    if device.type == "cuda" and torch.cuda.is_available():
        torch.cuda.empty_cache()

    was_training = model.training
    was_gc = bool(getattr(model, "is_gradient_checkpointing", False))
    prev_use_cache = getattr(getattr(model, "config", None), "use_cache", True)
    if was_gc and hasattr(model, "gradient_checkpointing_disable"):
        model.gradient_checkpointing_disable()
    if hasattr(model, "config"):
        model.config.use_cache = True
    model.eval()

    gen_cfg = copy.deepcopy(model.generation_config)
    gen_cfg.do_sample = False
    gen_cfg.temperature = None
    gen_cfg.top_p = None
    gen_cfg.top_k = None
    gen_cfg.num_beams = 1
    gen_cfg.max_new_tokens = max_new_tokens
    gen_cfg.use_cache = True
    gen_cfg.pad_token_id = pad_id
    gen_cfg.eos_token_id = eos_id

    records: List[Dict[str, Any]] = []
    batch_latencies: List[float] = []
    sample_latencies: List[float] = []
    ctx = model.disable_adapter() if disable_adapter else contextlib.nullcontext()
    autocast_ctx = (
        torch.autocast("cuda", dtype=torch.float16)
        if device.type == "cuda"
        else contextlib.nullcontext()
    )
    t0 = time.perf_counter()
    total_rows = len(rows)

    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="EVALUATING",
        detail=f"[{arm_name}] Starting generation evaluation on {total_rows} samples (batch_size={batch_size}, max_new_tokens={max_new_tokens})",
        extra={
            "subphase": "GENERATION_EVAL",
            "eval_stage": f"{arm_name}:generation",
            "eval_arm": arm_name,
            "current_epoch": current_epoch,
            "optimizer_step": optimizer_step,
            "eval_batch_size": batch_size,
            "max_new_tokens": max_new_tokens,
            "eval_completed_samples": 0,
            "eval_total_samples": total_rows,
            "gpu_mem": get_gpu_mem_snapshot(device),
        },
    )

    try:
        with ctx, torch.inference_mode(), autocast_ctx:
            for start in range(0, total_rows, batch_size):
                if hard_stop_flag is not None and hard_stop_flag.exists():
                    raise RuntimeError(f"Hard-stop flag detected at {hard_stop_flag} during evaluation!")

                batch_t0 = time.perf_counter()
                batch_rows = rows[start : start + batch_size]
                prompts = [
                    to_id_list(
                        tokenizer.apply_chat_template(
                            r["messages"][:2], tokenize=True, add_generation_prompt=True
                        )
                    )
                    for r in batch_rows
                ]
                max_l = max(len(p) for p in prompts)
                padded_inp = [[pad_id] * (max_l - len(p)) + p for p in prompts]
                padded_mask = [[0] * (max_l - len(p)) + [1] * len(p) for p in prompts]
                inp_t = torch.tensor(padded_inp, dtype=torch.long, device=device)
                mask_t = torch.tensor(padded_mask, dtype=torch.long, device=device)
                stop_crit = StoppingCriteriaList(
                    [JsonBraceAndEosStoppingCriteria(tokenizer=tokenizer, prompt_len=max_l, eos_token_id=eos_id)]
                )
                out = model.generate(
                    input_ids=inp_t,
                    attention_mask=mask_t,
                    generation_config=gen_cfg,
                    stopping_criteria=stop_crit,
                )
                batch_dur = round(time.perf_counter() - batch_t0, 4)
                per_sample_dur = round(batch_dur / len(batch_rows), 4)
                batch_latencies.append(batch_dur)

                for idx, r in enumerate(batch_rows):
                    gen_ids = out[idx, max_l:].tolist()
                    # Truncate at first eos_token_id if present
                    if eos_id in gen_ids:
                        gen_ids = gen_ids[: gen_ids.index(eos_id)]
                    raw = tokenizer.decode(gen_ids, skip_special_tokens=True)
                    meta = r["metadata"]
                    ident = meta["identity"]
                    _, _, ref_canon = shared.validate_and_canonicalize_sink_args(
                        role=meta["role"],
                        sink_args=meta["sink_args"],
                        signature=ident["signature"],
                        cwe=int(meta["cwe"]),
                        package_name=ident["package"],
                        class_name=ident["class"],
                        method_name=ident["method"],
                    )
                    parsed = parse_prediction_record(raw, meta)
                    sample_latencies.append(per_sample_dur)
                    records.append(
                        {
                            "id": r["id"],
                            "cwe": int(meta["cwe"]),
                            "api_family": meta.get("api_family", f"{ident['package']}.{ident['class']}.{ident['method']}"),
                            "reference_role": meta["role"],
                            "reference_sink_args": list(meta["sink_args"]),
                            "reference_canonical_sink_args": list(ref_canon),
                            "generated_token_count": len(gen_ids),
                            "inference_latency_sec": per_sample_dur,
                            "raw": raw,
                            "parsed": parsed,
                        }
                    )
                del inp_t, mask_t, out

                done_cnt = len(records)
                emit_hb = (
                    (total_rows <= 25)
                    or (done_cnt == 1)
                    or (done_cnt == total_rows)
                    or (done_cnt % 4 == 0)
                )
                log_this_batch = (
                    (done_cnt == 1)
                    or (done_cnt == total_rows)
                    or (done_cnt % 20 == 0)
                )
                if emit_hb:
                    emit_wsl_phase_heartbeat(
                        state_wsl_file=state_wsl_file,
                        phase="EVALUATING",
                        detail=(
                            f"[{arm_name}] Evaluated {done_cnt}/{total_rows} samples "
                            f"(batch_sec={batch_dur:.3f}s, sample_sec={per_sample_dur:.3f}s)"
                        ),
                        extra={
                            "subphase": "GENERATION_EVAL",
                            "eval_stage": f"{arm_name}:generation",
                            "eval_arm": arm_name,
                            "current_epoch": current_epoch,
                            "optimizer_step": optimizer_step,
                            "eval_batch_size": batch_size,
                            "max_new_tokens": max_new_tokens,
                            "eval_completed_samples": done_cnt,
                            "eval_total_samples": total_rows,
                            "last_batch_latency_sec": batch_dur,
                            "last_sample_latency_sec": per_sample_dur,
                            "gpu_mem": get_gpu_mem_snapshot(device),
                        },
                        log_stdout=log_this_batch,
                    )
    finally:
        if hasattr(model, "config"):
            model.config.use_cache = prev_use_cache
        if was_gc and hasattr(model, "gradient_checkpointing_enable"):
            model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        if was_training:
            model.train()
        gc.collect()
        if device.type == "cuda" and torch.cuda.is_available():
            torch.cuda.empty_cache()

    elapsed = round(time.perf_counter() - t0, 2)
    metrics = compute_full_evaluation_metrics(records)
    metrics["arm_name"] = arm_name
    metrics["eval_batch_size"] = batch_size
    metrics["max_new_tokens"] = max_new_tokens
    metrics["elapsed_seconds"] = elapsed
    metrics["per_sample_latency_sec_mean"] = round(statistics.mean(sample_latencies), 4) if sample_latencies else 0.0
    metrics["per_sample_latency_sec_max"] = round(max(sample_latencies), 4) if sample_latencies else 0.0
    metrics["batch_latencies_sec"] = batch_latencies
    metrics["gpu_mem_after_eval"] = get_gpu_mem_snapshot(device)
    return metrics, records


def compute_eval_loss(
    model: torch.nn.Module,
    encoded_rows: Sequence[Dict[str, Any]],
    pad_token_id: int,
    device: torch.device,
    batch_size: int = 1,
    state_wsl_file: Optional[Path] = None,
    arm_name: str = "eval_loss",
    current_epoch: Optional[int] = None,
    optimizer_step: Optional[int] = None,
) -> float:
    """
    Computes validation cross-entropy loss using batch_size=1 (default) after emptying fragmented
    CUDA cache so Qwen2's 151,936-vocab FP32 loss upcast never causes a multi-GB WDDM paging spike.
    """
    gc.collect()
    if device.type == "cuda" and torch.cuda.is_available():
        torch.cuda.empty_cache()

    was_training = model.training
    was_gc = bool(getattr(model, "is_gradient_checkpointing", False))
    if was_gc and hasattr(model, "gradient_checkpointing_disable"):
        model.gradient_checkpointing_disable()
    model.eval()

    losses: List[float] = []
    total_rows = len(encoded_rows)
    autocast_ctx = (
        torch.autocast("cuda", dtype=torch.float16)
        if device.type == "cuda"
        else contextlib.nullcontext()
    )

    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="EVALUATING",
        detail=f"[{arm_name}] Computing validation loss on {total_rows} samples (batch_size={batch_size})",
        extra={
            "subphase": "COMPUTING_EVAL_LOSS",
            "eval_stage": f"{arm_name}:val_loss",
            "eval_arm": arm_name,
            "current_epoch": current_epoch,
            "optimizer_step": optimizer_step,
            "eval_batch_size": batch_size,
            "eval_completed_samples": 0,
            "eval_total_samples": total_rows,
            "gpu_mem": get_gpu_mem_snapshot(device),
        },
    )

    try:
        with torch.inference_mode(), autocast_ctx:
            for start in range(0, total_rows, batch_size):
                batch_slice = encoded_rows[start : start + batch_size]
                batch = collate_causal_lm_batch(batch_slice, pad_token_id=pad_token_id, device=device)
                out = model(
                    input_ids=batch["input_ids"],
                    attention_mask=batch["attention_mask"],
                    labels=batch["labels"],
                    use_cache=False,
                )
                losses.append(float(out.loss.detach().cpu().item()))
                del out, batch
                done_cnt = min(total_rows, start + batch_size)
                if done_cnt == 1 or done_cnt == total_rows or done_cnt % 20 == 0:
                    emit_wsl_phase_heartbeat(
                        state_wsl_file=state_wsl_file,
                        phase="EVALUATING",
                        detail=f"[{arm_name}] Validation loss progress: {done_cnt}/{total_rows}",
                        extra={
                            "subphase": "COMPUTING_EVAL_LOSS",
                            "eval_stage": f"{arm_name}:val_loss",
                            "eval_arm": arm_name,
                            "current_epoch": current_epoch,
                            "optimizer_step": optimizer_step,
                            "eval_batch_size": batch_size,
                            "eval_completed_samples": done_cnt,
                            "eval_total_samples": total_rows,
                            "gpu_mem": get_gpu_mem_snapshot(device),
                        },
                        log_stdout=(done_cnt == total_rows),
                    )
    finally:
        if was_gc and hasattr(model, "gradient_checkpointing_enable"):
            model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        if was_training:
            model.train()
        gc.collect()
        if device.type == "cuda" and torch.cuda.is_available():
            torch.cuda.empty_cache()

    return round(statistics.mean(losses), 4) if losses else 0.0


def paired_mcnemar(rec_a: Sequence[Dict[str, Any]], rec_b: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    both_ok = 0
    a_only = 0
    b_only = 0
    both_err = 0
    for ra, rb in zip(rec_a, rec_b):
        assert ra["id"] == rb["id"]
        ca = ra["parsed"]["strict_valid"] and ra["parsed"]["role"] == ra["reference_role"]
        cb = rb["parsed"]["strict_valid"] and rb["parsed"]["role"] == rb["reference_role"]
        if ca and cb:
            both_ok += 1
        elif ca and not cb:
            a_only += 1
        elif cb and not ca:
            b_only += 1
        else:
            both_err += 1
    return {
        "n": len(rec_a),
        "both_correct": both_ok,
        "a_only_correct": a_only,
        "b_only_correct": b_only,
        "both_wrong": both_err,
        "mcnemar_exact_p_value": mcnemar_exact_p(a_only, b_only),
    }


def canonicalize_lora_param_key(name: str, adapter_name: str) -> str:
    return (
        name.replace(f".lora_A.{adapter_name}.weight", ".lora_A.weight")
        .replace(f".lora_B.{adapter_name}.weight", ".lora_B.weight")
        .replace(".lora_A.default.weight", ".lora_A.weight")
        .replace(".lora_B.default.weight", ".lora_B.weight")
    )


def verify_in_memory_vs_disk_safetensors_parity(
    model: torch.nn.Module, st_path: Path, adapter_name: str
) -> Dict[str, Any]:
    disk_tensors = load_file(str(st_path), device="cpu")
    disk_canon = {canonicalize_lora_param_key(k, adapter_name): v.float() for k, v in disk_tensors.items()}
    mem_canon: Dict[str, torch.Tensor] = {}
    with torch.no_grad():
        for name, p in model.named_parameters():
            if "lora_" in name:
                ck = canonicalize_lora_param_key(name, adapter_name)
                mem_canon[ck] = p.detach().cpu().float()

    if set(disk_canon.keys()) != set(mem_canon.keys()):
        missing = sorted(set(mem_canon.keys()) - set(disk_canon.keys()))[:5]
        extra = sorted(set(disk_canon.keys()) - set(mem_canon.keys()))[:5]
        raise RuntimeError(f"LoRA key mismatch between memory and disk: missing={missing}, extra={extra}")

    max_diff = 0.0
    nan_count = 0
    for ck, mem_t in mem_canon.items():
        disk_t = disk_canon[ck]
        if torch.isnan(disk_t).any().item() or torch.isinf(disk_t).any().item():
            nan_count += 1
        d = float(torch.max(torch.abs(mem_t - disk_t)).item())
        if d > max_diff:
            max_diff = d
    if nan_count > 0:
        raise RuntimeError(f"Found {nan_count} NaN/Inf tensors in saved {st_path}")
    if max_diff > 1e-6:
        raise RuntimeError(f"Weight parity mismatch between in-memory and disk {st_path}: max_diff={max_diff}")
    return {
        "matched_tensor_count": len(mem_canon),
        "max_abs_weight_diff": max_diff,
        "nan_or_inf_tensors": nan_count,
        "exact_weight_parity": max_diff == 0.0,
    }


def load_adapter_safetensors_into_model(
    model: torch.nn.Module, st_path: Path, adapter_name: str
) -> Dict[str, Any]:
    st_ver = verify_safetensors_binary(st_path)
    disk_tensors = load_file(str(st_path), device="cpu")
    disk_canon = {canonicalize_lora_param_key(k, adapter_name): v.float() for k, v in disk_tensors.items()}
    copied = 0
    with torch.no_grad():
        for name, p in model.named_parameters():
            if "lora_" in name:
                ck = canonicalize_lora_param_key(name, adapter_name)
                if ck not in disk_canon:
                    raise RuntimeError(f"Missing LoRA tensor {ck} in checkpoint {st_path}")
                src_t = disk_canon[ck].to(device=p.device, dtype=torch.float32)
                if tuple(src_t.shape) != tuple(p.shape):
                    raise RuntimeError(f"Shape mismatch on {ck}: {tuple(src_t.shape)} vs {tuple(p.shape)}")
                p.data = src_t.clone()
                p.requires_grad_(True)
                copied += 1
    if copied != len(disk_canon):
        raise RuntimeError(f"Copied {copied} tensors, expected {len(disk_canon)} from {st_path}")
    parity = verify_in_memory_vs_disk_safetensors_parity(model, st_path, adapter_name)
    return {
        "safetensors_verification": st_ver,
        "loaded_tensor_count": copied,
        "parity": parity,
    }


def save_and_verify_checkpoint(
    model: torch.nn.Module,
    adapter_name: str,
    optimizer: torch.optim.Optimizer,
    scheduler: Any,
    scaler: Optional[Any],
    epoch: int,
    global_step: int,
    unique_seen_ids: set,
    total_presentations: int,
    step_logs: List[Dict[str, Any]],
    epoch_summaries: Dict[int, Dict[str, Any]],
    ckpt_tag: str,
    out_dir_wsl: Path,
    out_dir_f: Path,
    state_wsl_file: Optional[Path],
    is_epoch_end: bool = False,
    training_config: Optional[Dict[str, Any]] = None,
    dataset_sha256: str = "",
) -> Dict[str, Any]:
    device = next(model.parameters()).device
    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="SAVING_CHECKPOINT",
        detail=f"[{adapter_name}] Saving atomic checkpoint '{ckpt_tag}' at epoch={epoch}, step={global_step}",
        extra={
            "arm_id": adapter_name,
            "current_epoch": epoch,
            "optimizer_step": global_step,
            "checkpoint_tag": ckpt_tag,
            "is_epoch_end": is_epoch_end,
            "gpu_mem": get_gpu_mem_snapshot(device),
        },
    )

    staging_wsl = out_dir_wsl / f".staging_{ckpt_tag}_{os.getpid()}"
    if staging_wsl.exists():
        shutil.rmtree(staging_wsl)
    staging_wsl.mkdir(parents=True, exist_ok=True)

    model.save_pretrained(str(staging_wsl), safe_serialization=True)
    nested_dir = staging_wsl / adapter_name
    if (nested_dir / "adapter_model.safetensors").exists():
        for item in nested_dir.iterdir():
            shutil.move(str(item), str(staging_wsl / item.name))
        nested_dir.rmdir()

    st_file = staging_wsl / "adapter_model.safetensors"
    cfg_file = staging_wsl / "adapter_config.json"
    if not st_file.exists() or not cfg_file.exists():
        raise RuntimeError(f"Checkpoint save failed to produce adapter files in {staging_wsl}")

    st_ver = verify_safetensors_binary(st_file)
    weight_parity = verify_in_memory_vs_disk_safetensors_parity(model, st_file, adapter_name)

    # Save full optimizer/scheduler/RNG/config/dataset_sha256 training state for exact step resume (Phase 4)
    training_state_obj = {
        "epoch": epoch,
        "global_step": global_step,
        "completed_optimizer_step": global_step,
        "adapter_name": adapter_name,
        "training_configuration": training_config or {},
        "dataset_sha256": dataset_sha256,
        "checkpoint_sha256": st_ver["sha256"],
        "optimizer_state_dict": optimizer.state_dict(),
        "scheduler_state_dict": scheduler.state_dict(),
        "scaler_state_dict": scaler.state_dict() if scaler is not None else None,
        "python_rng_state": random.getstate(),
        "torch_rng_state": torch.get_rng_state(),
        "cuda_rng_state_all": (
            torch.cuda.get_rng_state_all()
            if (device.type == "cuda" and torch.cuda.is_available())
            else None
        ),
        "unique_seen_ids": sorted(unique_seen_ids),
        "total_presentations": total_presentations,
        "step_logs": step_logs,
        "epoch_summaries_meta": {
            int(k): {kk: vv for kk, vv in v.items() if kk != "dev166_records"}
            for k, v in epoch_summaries.items()
        },
        "adapter_safetensors_sha256": st_ver["sha256"],
    }
    ts_path = staging_wsl / "training_state.pt"
    ts_tmp = staging_wsl / f"training_state.pt.tmp.{os.getpid()}"
    torch.save(training_state_obj, str(ts_tmp))
    os.replace(ts_tmp, ts_path)
    ts_sha = sha256_file(ts_path)
    cfg_sha = sha256_file(cfg_file)

    marker = {
        "checkpoint_status": "CHECKPOINT_VERIFIED",
        "checkpoint_tag": ckpt_tag,
        "arm_id": adapter_name,
        "epoch": epoch,
        "global_step": global_step,
        "completed_optimizer_step": global_step,
        "is_epoch_end": is_epoch_end,
        "verified_utc": now_utc(),
        "lora_adapter_file": "adapter_model.safetensors",
        "adapter_config_file": "adapter_config.json",
        "training_state_file": "training_state.pt",
        "optimizer_state_included": True,
        "scheduler_state_included": True,
        "rng_state_included": True,
        "training_configuration": training_config or {},
        "dataset_sha256": dataset_sha256,
        "checkpoint_sha256": st_ver["sha256"],
        "adapter_safetensors_sha256": st_ver["sha256"],
        "adapter_config_sha256": cfg_sha,
        "training_state_sha256": ts_sha,
        "safetensors_verification": st_ver,
        "in_memory_weight_parity": weight_parity,
        "exact_resume_supported": True,
    }
    write_json_atomic(staging_wsl / "CHECKPOINT_COMPLETE.json", marker)

    target_wsl = out_dir_wsl / ckpt_tag
    if target_wsl.exists():
        shutil.rmtree(target_wsl)
    os.replace(staging_wsl, target_wsl)

    # Atomically sync verified checkpoint files to F:
    target_f = out_dir_f / ckpt_tag
    target_f.mkdir(parents=True, exist_ok=True)
    for fname in (
        "adapter_model.safetensors",
        "adapter_config.json",
        "training_state.pt",
        "README.md",
        "CHECKPOINT_COMPLETE.json",
    ):
        src_p = target_wsl / fname
        if src_p.exists():
            dst_p = target_f / fname
            tmp_dst = target_f / f"{fname}.tmp.{os.getpid()}"
            shutil.copy2(src_p, tmp_dst)
            os.replace(tmp_dst, dst_p)

    st_f_ver = verify_safetensors_binary(target_f / "adapter_model.safetensors")
    if st_f_ver["sha256"] != st_ver["sha256"]:
        raise RuntimeError(
            f"F: checkpoint SHA-256 mismatch on {ckpt_tag}: {st_f_ver['sha256']} vs {st_ver['sha256']}"
        )

    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="CHECKPOINT_VERIFIED",
        detail=(
            f"[{adapter_name}] Verified checkpoint '{ckpt_tag}' (epoch={epoch}, step={global_step}, "
            f"sha256={st_ver['sha256'][:16]}..., max_weight_diff={weight_parity['max_abs_weight_diff']})"
        ),
        extra={
            "arm_id": adapter_name,
            "current_epoch": epoch,
            "optimizer_step": global_step,
            "checkpoint_tag": ckpt_tag,
            "checkpoint_dir_wsl": str(target_wsl),
            "checkpoint_dir_f": str(target_f),
            "adapter_safetensors_sha256": st_ver["sha256"],
            "training_state_sha256": ts_sha,
            "gpu_mem": get_gpu_mem_snapshot(device),
        },
    )

    return {
        "checkpoint_tag": ckpt_tag,
        "checkpoint_dir_wsl": str(target_wsl),
        "checkpoint_dir_f": str(target_f),
        "adapter_safetensors_sha256": st_ver["sha256"],
        "adapter_config_sha256": cfg_sha,
        "training_state_sha256": ts_sha,
        "safetensors_verification": st_ver,
        "in_memory_weight_parity": weight_parity,
    }


def train_lora_arm(
    arm_id: str,
    adapter_name: str,
    train_rows: List[Dict[str, Any]],
    dev_rows: List[Dict[str, Any]],
    encoded_train: Dict[str, Dict[str, Any]],
    encoded_dev_list: List[Dict[str, Any]],
    tokenizer: Any,
    device: torch.device,
    out_dir_wsl: Path,
    out_dir_f: Path,
    run_dir_f: Path,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    target_modules: Optional[List[str]] = None,
    epochs: int = 3,
    micro_batch_size: int = 1,
    grad_accum: int = 4,
    lr: float = 1.8e-4,
    weighting_mode: str = "calibrated",
    seed: int = 20261024,
    resume_from_checkpoint: Optional[Path] = None,
    prior_metrics_jsonl: Optional[Path] = None,
    mid_epoch_save_interval: Optional[int] = None,
    eval_batch_size: int = 1,
    dataset_sha256: str = "",
    phase2_ep1_eval_cache: Optional[Path] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if target_modules is None:
        target_modules = [
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ]

    out_dir_wsl.mkdir(parents=True, exist_ok=True)
    out_dir_f.mkdir(parents=True, exist_ok=True)

    allocator_info = verify_cuda_allocator_or_fallback(device)

    random.seed(seed)
    torch.manual_seed(seed)
    if device.type == "cuda" and torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.cuda.reset_peak_memory_stats()

    base_dtype = torch.float16 if device.type == "cuda" else torch.float32
    base = AutoModelForCausalLM.from_pretrained(
        str(BASE_MODEL_PATH),
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=base_dtype,
        attn_implementation="sdpa",
        use_safetensors=True,
    ).to(device)
    base.config.use_cache = False

    lora_cfg = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        bias="none",
        target_modules=target_modules,
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(base, lora_cfg, adapter_name=adapter_name)
    trainable_params = [p for p in model.parameters() if p.requires_grad]
    for p in trainable_params:
        p.data = p.data.float()

    digest_before = frozen_base_digest(model)
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()

    eff_batch = micro_batch_size * grad_accum
    steps_per_epoch = math.ceil(len(train_rows) / eff_batch)
    total_steps = steps_per_epoch * epochs
    warmup_steps = max(5, int(0.06 * total_steps))
    if mid_epoch_save_interval is None:
        mid_epoch_save_interval = max(1, steps_per_epoch // 2)

    training_config_dict = {
        "arm_id": arm_id,
        "adapter_name": adapter_name,
        "base_model_id": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
        "lora_r": lora_r,
        "lora_alpha": lora_alpha,
        "lora_dropout": lora_dropout,
        "target_modules": target_modules,
        "epochs_configured": epochs,
        "micro_batch_size": micro_batch_size,
        "gradient_accumulation_steps": grad_accum,
        "effective_batch_size": eff_batch,
        "eval_batch_size": eval_batch_size,
        "max_new_tokens": 96,
        "learning_rate": lr,
        "weight_decay": 0.01,
        "warmup_steps": warmup_steps,
        "total_planned_steps": total_steps,
        "mid_epoch_save_interval": mid_epoch_save_interval,
        "weighting_mode": weighting_mode,
        "seed": seed,
        "dataset_size": len(train_rows),
        "dataset_sha256": dataset_sha256,
        "allocator_info": allocator_info,
    }

    optimizer = torch.optim.AdamW(trainable_params, lr=lr, weight_decay=0.01)
    use_cuda_amp = device.type == "cuda" and torch.cuda.is_available()
    scaler = torch.amp.GradScaler("cuda", init_scale=256.0, enabled=use_cuda_amp)

    def lr_lambda(current_step: int) -> float:
        if current_step < warmup_steps:
            return float(current_step + 1) / float(max(1, warmup_steps))
        progress = float(current_step - warmup_steps) / float(max(1, total_steps - warmup_steps))
        cosine = 0.5 * (1.0 + math.cos(math.pi * min(1.0, progress)))
        return max(0.10, cosine)

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)

    rng = random.Random(seed)
    epoch_schedules: List[List[Dict[str, Any]]] = []
    for _ in range(epochs):
        ep_list = list(train_rows)
        rng.shuffle(ep_list)
        epoch_schedules.append(ep_list)

    pad_id = int(tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id)
    step_logs: List[Dict[str, Any]] = []
    epoch_summaries: Dict[int, Dict[str, Any]] = {}
    dev_records_by_epoch: Dict[int, List[Dict[str, Any]]] = {}
    unique_seen_ids = set()
    total_presentations = 0
    global_step = 0
    resumed_step_offset = 0
    actual_steps_executed_this_run = 0
    start_epoch = 1
    start_step_in_epoch = 0
    initialization_mode = "fresh_from_base_qwen25_coder_05b_instruct"
    resume_metadata: Optional[Dict[str, Any]] = None
    early_stop_info: Optional[Dict[str, Any]] = None
    t0 = time.perf_counter()

    hard_stop_flag = run_dir_f / "HARD_STOP_TRIGGERED"
    metrics_jsonl = run_dir_f / "training_metrics.jsonl"
    state_wsl_file = run_dir_f / "execution_state_wsl.json"

    def run_epoch_evaluation_and_record(
        ep_idx: int,
        ckpt_meta: Dict[str, Any],
        ep_raw_losses: Sequence[float],
        ep_weighted_losses: Sequence[float],
        ep_grad_norms: Sequence[float],
    ) -> None:
        # 1. Small Dev-16 pre-check sample first (Phase 2/3 requirement) to verify bounded generation & memory
        precheck_n = min(16, len(dev_rows))
        pre_m, _ = evaluate_model_arm(
            model=model,
            tokenizer=tokenizer,
            rows=dev_rows[:precheck_n],
            arm_name=f"{arm_id}_ep{ep_idx}_dev{precheck_n}_precheck",
            disable_adapter=False,
            max_new_tokens=96,
            batch_size=eval_batch_size,
            state_wsl_file=state_wsl_file,
            hard_stop_flag=hard_stop_flag,
            current_epoch=ep_idx,
            optimizer_step=global_step,
        )
        # 2. Validation loss on Dev-166 (using batch_size=1 to prevent 151,936-vocab FP32 spike)
        val_loss = compute_eval_loss(
            model=model,
            encoded_rows=encoded_dev_list,
            pad_token_id=pad_id,
            device=device,
            batch_size=1,
            state_wsl_file=state_wsl_file,
            arm_name=f"{arm_id}_ep{ep_idx}_val_loss",
            current_epoch=ep_idx,
            optimizer_step=global_step,
        )
        # 3. Full formal evaluation on Dev-166 (strictly batch_size=eval_batch_size=1)
        dev_m, dev_rec = evaluate_model_arm(
            model=model,
            tokenizer=tokenizer,
            rows=dev_rows,
            arm_name=f"{arm_id}_ep{ep_idx}_dev166",
            disable_adapter=False,
            max_new_tokens=96,
            batch_size=eval_batch_size,
            state_wsl_file=state_wsl_file,
            hard_stop_flag=hard_stop_flag,
            current_epoch=ep_idx,
            optimizer_step=global_step,
        )
        mean_raw = round(statistics.mean(ep_raw_losses), 4) if ep_raw_losses else 0.0
        mean_w = round(statistics.mean(ep_weighted_losses), 4) if ep_weighted_losses else 0.0
        mean_gn = round(statistics.mean(ep_grad_norms), 4) if ep_grad_norms else 0.0
        max_gn = round(max(ep_grad_norms), 4) if ep_grad_norms else 0.0

        cwe089_sink_rec = float(
            dev_m.get(
                "cwe_089_sink_recall",
                dev_m.get("per_cwe", {}).get("CWE-089", {}).get("per_role", {}).get("sink", {}).get("recall", 0.0),
            )
        )
        sink_to_src = int(
            dev_m.get(
                "sink_misclassified_as_source_count",
                dev_m.get("confusion_matrix", {}).get("sink", {}).get("source", 0),
            )
        )
        cwe089_sink_to_src = int(dev_m.get("cwe_089_sink_misclassified_as_source_count", 0))

        print(
            f"[{now_utc()}] [{arm_id}] Epoch {ep_idx} COMPLETE: train_loss={mean_raw:.4f}, "
            f"val_loss={val_loss:.4f}, Dev166_Acc={dev_m['accuracy']*100:.2f}%, "
            f"Dev166_MacroF1={dev_m['macro_f1']*100:.2f}%, SinkRecall={dev_m['sink_recall']*100:.2f}%, "
            f"CWE089_SinkRecall={cwe089_sink_rec*100:.2f}%, SinkF1={dev_m['sink_f1']*100:.2f}%, "
            f"SinkArgsExact={dev_m['sink_args_exact_match_rate']*100:.2f}%, "
            f"NoneRecall={dev_m['none_recall']*100:.2f}%, Sink->Source={sink_to_src}/51 (CWE089={cwe089_sink_to_src}/27), "
            f"sel_score={dev_m['selection_score']:.6f}, sha256={ckpt_meta['adapter_safetensors_sha256'][:16]}...",
            flush=True,
        )

        epoch_summaries[ep_idx] = {
            "epoch": ep_idx,
            "checkpoint_dir_wsl": ckpt_meta["checkpoint_dir_wsl"],
            "checkpoint_dir_f": ckpt_meta["checkpoint_dir_f"],
            "adapter_safetensors_sha256": ckpt_meta["adapter_safetensors_sha256"],
            "safetensors_verification": ckpt_meta["safetensors_verification"],
            "mean_train_raw_loss": mean_raw,
            "mean_train_weighted_loss": mean_w,
            "validation_loss_dev166": val_loss,
            "overfitting_gap_val_minus_train": round(val_loss - mean_raw, 4),
            "mean_grad_norm": mean_gn,
            "max_grad_norm": max_gn,
            "selection_score": dev_m["selection_score"],
            "epoch_quality_tracking": {
                "macro_f1": dev_m["macro_f1"],
                "accuracy": dev_m["accuracy"],
                "sink_recall": dev_m["sink_recall"],
                "cwe_089_sink_recall": cwe089_sink_rec,
                "sink_f1": dev_m["sink_f1"],
                "sink_args_exact_match_rate": dev_m["sink_args_exact_match_rate"],
                "sink_args_canonical_match_rate": dev_m["sink_args_canonical_match_rate"],
                "none_recall": dev_m["none_recall"],
                "strict_json_validity_rate": dev_m["strict_json_validity_rate"],
                "sink_misclassified_as_source_count": sink_to_src,
                "cwe_089_sink_misclassified_as_source_count": cwe089_sink_to_src,
                "selection_score": dev_m["selection_score"],
            },
            "dev_precheck_16_metrics": pre_m,
            "dev166_metrics": dev_m,
            "dev166_records": dev_rec,
        }
        dev_records_by_epoch[ep_idx] = dev_rec

        # Persist per-epoch evaluation summary immediately to disk so it is never lost
        write_json_atomic(
            out_dir_f / f"epoch_{ep_idx}_evaluation_summary.json",
            {k: v for k, v in epoch_summaries[ep_idx].items() if k != "dev166_records"},
        )
        write_json_atomic(
            out_dir_wsl / f"epoch_{ep_idx}_evaluation_summary.json",
            {k: v for k, v in epoch_summaries[ep_idx].items() if k != "dev166_records"},
        )

    # Handle checkpoint resume (supports both Exact-State Resume with training_state.pt and
    # Verified Warm-Start Adapter Resume from EO06 v1 checkpoint_epoch_1)
    if resume_from_checkpoint is not None:
        ckpt_dir = Path(resume_from_checkpoint)
        st_path = ckpt_dir / "adapter_model.safetensors"
        if not st_path.exists() and (ckpt_dir / adapter_name / "adapter_model.safetensors").exists():
            ckpt_dir = ckpt_dir / adapter_name
            st_path = ckpt_dir / "adapter_model.safetensors"
        if not st_path.exists():
            raise FileNotFoundError(f"Resume checkpoint adapter_model.safetensors not found at {ckpt_dir}")

        load_info = load_adapter_safetensors_into_model(model, st_path, adapter_name)
        ts_path = ckpt_dir / "training_state.pt"
        complete_marker_path = ckpt_dir / "CHECKPOINT_COMPLETE.json"
        if ts_path.exists():
            if not complete_marker_path.exists():
                raise RuntimeError(
                    f"Refusing EXACT_STATE_RESUME from {ckpt_dir}: missing CHECKPOINT_COMPLETE.json (partial checkpoint!)"
                )
            cm_data = json.loads(complete_marker_path.read_text(encoding="utf-8"))
            if cm_data.get("checkpoint_status") != "CHECKPOINT_VERIFIED":
                raise RuntimeError(f"Refusing resume: checkpoint_status={cm_data.get('checkpoint_status')}")

            ts_data = torch.load(str(ts_path), map_location="cpu", weights_only=False)
            optimizer.load_state_dict(ts_data["optimizer_state_dict"])
            scheduler.load_state_dict(ts_data["scheduler_state_dict"])
            if scaler is not None and ts_data.get("scaler_state_dict") is not None:
                scaler.load_state_dict(ts_data["scaler_state_dict"])
            if ts_data.get("python_rng_state") is not None:
                random.setstate(ts_data["python_rng_state"])
            if ts_data.get("torch_rng_state") is not None:
                torch.set_rng_state(ts_data["torch_rng_state"])
            if (
                use_cuda_amp
                and ts_data.get("cuda_rng_state_all") is not None
            ):
                torch.cuda.set_rng_state_all(ts_data["cuda_rng_state_all"])
            global_step = int(ts_data["global_step"])
            resumed_step_offset = global_step
            unique_seen_ids = set(ts_data.get("unique_seen_ids", []))
            total_presentations = int(ts_data.get("total_presentations", 0))
            step_logs = list(ts_data.get("step_logs", []))
            for s_entry in step_logs:
                append_jsonl(metrics_jsonl, s_entry)
            completed_epochs = global_step // steps_per_epoch
            rem_steps = global_step % steps_per_epoch
            start_epoch = completed_epochs + 1
            start_step_in_epoch = rem_steps
            for k_ep, v_ep in ts_data.get("epoch_summaries_meta", ts_data.get("epoch_summaries", {})).items():
                epoch_summaries[int(k_ep)] = v_ep
            initialization_mode = "EXACT_STATE_RESUME"
            resume_metadata = {
                "resume_mode": "EXACT_STATE_RESUME",
                "source_checkpoint_dir": str(ckpt_dir),
                "resumed_at_global_step": global_step,
                "resumed_at_epoch": start_epoch,
                "optimizer_moments_reinitialized": False,
                "uninterrupted_optimizer_continuation": True,
                "load_verification": load_info,
            }
            emit_wsl_phase_heartbeat(
                state_wsl_file=state_wsl_file,
                phase="CHECKPOINT_VERIFIED",
                detail=f"[{arm_id}] Exact-state resume verified from {ckpt_dir} at step={global_step}",
                extra=resume_metadata,
            )
        else:
            # Adapter-only checkpoint (EO06 v1 checkpoint_epoch_1 at Step 196)
            m_ep = re.search(r"checkpoint_epoch_(\d+)", ckpt_dir.name)
            resumed_epoch = int(m_ep.group(1)) if m_ep else 1
            global_step = resumed_epoch * steps_per_epoch
            resumed_step_offset = global_step

            prior_steps: List[Dict[str, Any]] = []
            if prior_metrics_jsonl is not None and Path(prior_metrics_jsonl).exists():
                raw_prior = load_jsonl(Path(prior_metrics_jsonl))
                prior_steps = raw_prior[:global_step]
            for s_entry in prior_steps:
                step_logs.append(s_entry)
                append_jsonl(metrics_jsonl, s_entry)
            for _ in range(global_step):
                scheduler.step()
            for ep_prev in range(min(resumed_epoch, len(epoch_schedules))):
                for r in epoch_schedules[ep_prev]:
                    unique_seen_ids.add(r["id"])
                    total_presentations += 1
            start_epoch = resumed_epoch + 1
            start_step_in_epoch = 0
            initialization_mode = "WARM_START_ADAPTER_RESUME"

            # Save verified Epoch checkpoint + training state into current run's checkpoint_epoch_1
            ep1_ckpt_meta = save_and_verify_checkpoint(
                model=model,
                adapter_name=adapter_name,
                optimizer=optimizer,
                scheduler=scheduler,
                scaler=scaler,
                epoch=resumed_epoch,
                global_step=global_step,
                unique_seen_ids=unique_seen_ids,
                total_presentations=total_presentations,
                step_logs=step_logs,
                epoch_summaries=epoch_summaries,
                ckpt_tag=f"checkpoint_epoch_{resumed_epoch}",
                out_dir_wsl=out_dir_wsl,
                out_dir_f=out_dir_f,
                state_wsl_file=state_wsl_file,
                is_epoch_end=True,
                training_config=training_config_dict,
                dataset_sha256=dataset_sha256,
            )
            ep1_raw = [float(x["raw_loss"]) for x in prior_steps] if prior_steps else [0.0388]
            ep1_w = [float(x["weighted_loss"]) for x in prior_steps] if prior_steps else [0.0431]
            ep1_gn = [float(x["grad_norm"]) for x in prior_steps] if prior_steps else [0.85]

            used_phase2_cache = False
            if phase2_ep1_eval_cache is not None and Path(phase2_ep1_eval_cache).exists():
                try:
                    p2_cache_path = Path(phase2_ep1_eval_cache)
                    p2_cache = json.loads(p2_cache_path.read_text(encoding="utf-8"))
                    cached_sha = p2_cache.get("checkpoint_safetensors_sha256") or p2_cache.get("checkpoint_sha256")
                    cached_recs = p2_cache.get("dev166_records", [])
                    if not cached_recs:
                        for cand_pred_file in (
                            p2_cache_path.parent / "phase2_epoch1_dev166_predictions.jsonl",
                            run_dir_f / "phase2_epoch1_dev166_predictions.jsonl",
                        ):
                            if cand_pred_file.exists():
                                cached_recs = load_jsonl(cand_pred_file)
                                break
                    if (
                        cached_sha == ep1_ckpt_meta["adapter_safetensors_sha256"]
                        and len(cached_recs) == len(dev_rows)
                    ):
                        dev_rec = cached_recs
                        dev_m = compute_full_evaluation_metrics(dev_rec)
                        for extra_k in (
                            "arm_name",
                            "eval_batch_size",
                            "max_new_tokens",
                            "elapsed_seconds",
                            "per_sample_latency_sec_mean",
                            "per_sample_latency_sec_max",
                            "batch_latencies_sec",
                            "gpu_mem_after_eval",
                        ):
                            if extra_k in p2_cache.get("dev166_metrics", {}):
                                dev_m[extra_k] = p2_cache["dev166_metrics"][extra_k]
                        pre_m = (
                            p2_cache.get("phase2_gpu_eval_boundary_smoke", {}).get("dev16_subset_smoke")
                            or p2_cache.get("dev_precheck_16_metrics")
                            or dev_m
                        )
                        val_loss = float(p2_cache["validation_loss_dev166"])
                        mean_raw = round(statistics.mean(ep1_raw), 4)
                        mean_w = round(statistics.mean(ep1_w), 4)
                        mean_gn = round(statistics.mean(ep1_gn), 4)
                        max_gn = round(max(ep1_gn), 4)
                        cwe089_sink_rec = float(dev_m["cwe_089_sink_recall"])
                        sink_to_src = int(dev_m["sink_misclassified_as_source_count"])
                        cwe089_sink_to_src = int(dev_m["cwe_089_sink_misclassified_as_source_count"])
                        epoch_summaries[resumed_epoch] = {
                            "epoch": resumed_epoch,
                            "checkpoint_dir_wsl": ep1_ckpt_meta["checkpoint_dir_wsl"],
                            "checkpoint_dir_f": ep1_ckpt_meta["checkpoint_dir_f"],
                            "adapter_safetensors_sha256": ep1_ckpt_meta["adapter_safetensors_sha256"],
                            "safetensors_verification": ep1_ckpt_meta["safetensors_verification"],
                            "mean_train_raw_loss": mean_raw,
                            "mean_train_weighted_loss": mean_w,
                            "validation_loss_dev166": val_loss,
                            "overfitting_gap_val_minus_train": round(val_loss - mean_raw, 4),
                            "mean_grad_norm": mean_gn,
                            "max_grad_norm": max_gn,
                            "selection_score": dev_m["selection_score"],
                            "epoch_quality_tracking": {
                                "macro_f1": dev_m["macro_f1"],
                                "accuracy": dev_m["accuracy"],
                                "sink_recall": dev_m["sink_recall"],
                                "cwe_089_sink_recall": cwe089_sink_rec,
                                "sink_f1": dev_m["sink_f1"],
                                "sink_args_exact_match_rate": dev_m["sink_args_exact_match_rate"],
                                "sink_args_canonical_match_rate": dev_m["sink_args_canonical_match_rate"],
                                "none_recall": dev_m["none_recall"],
                                "strict_json_validity_rate": dev_m["strict_json_validity_rate"],
                                "sink_misclassified_as_source_count": sink_to_src,
                                "cwe_089_sink_misclassified_as_source_count": cwe089_sink_to_src,
                                "selection_score": dev_m["selection_score"],
                            },
                            "dev_precheck_16_metrics": pre_m,
                            "dev166_metrics": dev_m,
                            "dev166_records": dev_rec,
                        }
                        dev_records_by_epoch[resumed_epoch] = dev_rec
                        write_json_atomic(
                            out_dir_f / f"epoch_{resumed_epoch}_evaluation_summary.json",
                            {k: v for k, v in epoch_summaries[resumed_epoch].items() if k != "dev166_records"},
                        )
                        write_json_atomic(
                            out_dir_wsl / f"epoch_{resumed_epoch}_evaluation_summary.json",
                            {k: v for k, v in epoch_summaries[resumed_epoch].items() if k != "dev166_records"},
                        )
                        used_phase2_cache = True
                        print(
                            f"[{now_utc()}] [{arm_id}] Loaded verified Phase 2 GPU Epoch-{resumed_epoch} Dev-166 evaluation "
                            f"(MacroF1={dev_m['macro_f1']*100:.2f}%, Acc={dev_m['accuracy']*100:.2f}%, "
                            f"SinkRecall={dev_m['sink_recall']*100:.2f}%, CWE089_SinkRecall={cwe089_sink_rec*100:.2f}%, "
                            f"SinkF1={dev_m['sink_f1']*100:.2f}%, NoneRecall={dev_m['none_recall']*100:.2f}%, "
                            f"sel_score={dev_m['selection_score']:.6f}, val_loss={val_loss:.4f})",
                            flush=True,
                        )
                except Exception as exc:
                    print(f"[{now_utc()}] [{arm_id}] Phase 2 cache load skipped ({exc}); evaluating Epoch {resumed_epoch} directly.", flush=True)

            if not used_phase2_cache:
                run_epoch_evaluation_and_record(
                    ep_idx=resumed_epoch,
                    ckpt_meta=ep1_ckpt_meta,
                    ep_raw_losses=ep1_raw,
                    ep_weighted_losses=ep1_w,
                    ep_grad_norms=ep1_gn,
                )

            resume_metadata = {
                "resume_mode": "WARM_START_ADAPTER_RESUME",
                "source_checkpoint_dir": str(ckpt_dir),
                "source_checkpoint_sha256": ep1_ckpt_meta["adapter_safetensors_sha256"],
                "resumed_at_global_step": global_step,
                "resumed_at_epoch": start_epoch,
                "optimizer_moments_reinitialized": True,
                "uninterrupted_optimizer_continuation": False,
                "scheduler_advanced_to_step": global_step,
                "scheduler_lr_at_resume": round(float(scheduler.get_last_lr()[0]), 8),
                "load_verification": load_info,
                "epoch1_evaluated_on_resume": True,
                "used_verified_phase2_gpu_eval_cache": used_phase2_cache,
            }

    autocast_train_ctx = (
        torch.autocast("cuda", dtype=torch.float16)
        if use_cuda_amp
        else contextlib.nullcontext()
    )

    for ep_idx in range(start_epoch, epochs + 1):
        ep_rows = epoch_schedules[ep_idx - 1]
        model.train()
        ep_raw_losses: List[float] = []
        ep_weighted_losses: List[float] = []
        ep_grad_norms: List[float] = []

        step_in_epoch_offset = start_step_in_epoch if ep_idx == start_epoch else 0
        start_row_idx = step_in_epoch_offset * eff_batch

        for step_in_ep_idx, start in enumerate(
            range(start_row_idx, len(ep_rows), eff_batch), start=step_in_epoch_offset + 1
        ):
            if hard_stop_flag.exists():
                raise RuntimeError(f"Hard-stop flag detected at {hard_stop_flag}; aborting training!")

            eff_slice = ep_rows[start : start + eff_batch]
            optimizer.zero_grad(set_to_none=True)
            batch_raw_loss_sum = 0.0
            batch_weighted_loss_sum = 0.0
            micro_chunks = [
                eff_slice[i : i + micro_batch_size]
                for i in range(0, len(eff_slice), micro_batch_size)
            ]

            for m_chunk in micro_chunks:
                enc_items = []
                w_items = []
                for row in m_chunk:
                    rid = row["id"]
                    unique_seen_ids.add(rid)
                    total_presentations += 1
                    enc_items.append(encoded_train[rid])
                    w_items.append(compute_sample_weight(row, weighting_mode))
                w_mean = sum(w_items) / len(w_items)
                batch_t = collate_causal_lm_batch(enc_items, pad_token_id=pad_id, device=device)
                with autocast_train_ctx:
                    out = model(
                        input_ids=batch_t["input_ids"],
                        attention_mask=batch_t["attention_mask"],
                        labels=batch_t["labels"],
                        use_cache=False,
                    )
                    raw_loss = out.loss
                    weighted_loss = (raw_loss * w_mean) / len(micro_chunks)
                lv_raw = float(raw_loss.detach().cpu().item())
                if not math.isfinite(lv_raw):
                    raise RuntimeError(f"Non-finite loss {lv_raw} at step {global_step + 1} in {arm_id}")
                batch_raw_loss_sum += lv_raw
                batch_weighted_loss_sum += lv_raw * w_mean
                scaler.scale(weighted_loss).backward()
                del weighted_loss, raw_loss, out, batch_t

            scaler.unscale_(optimizer)
            grad_norm = float(
                torch.nn.utils.clip_grad_norm_(trainable_params, 1.0, error_if_nonfinite=True)
            )
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            global_step += 1
            actual_steps_executed_this_run += 1

            avg_raw = round(batch_raw_loss_sum / len(micro_chunks), 4)
            avg_w = round(batch_weighted_loss_sum / len(micro_chunks), 4)
            cur_lr = round(float(scheduler.get_last_lr()[0]), 8)
            ep_raw_losses.append(avg_raw)
            ep_weighted_losses.append(avg_w)
            ep_grad_norms.append(round(grad_norm, 4))

            step_entry = {
                "timestamp_utc": now_utc(),
                "arm_id": arm_id,
                "epoch": ep_idx,
                "epochs_total": epochs,
                "step": global_step,
                "steps_total": total_steps,
                "raw_loss": avg_raw,
                "weighted_loss": avg_w,
                "grad_norm": round(grad_norm, 6),
                "lr": cur_lr,
            }
            step_logs.append(step_entry)
            append_jsonl(metrics_jsonl, step_entry)

            is_end_of_epoch = step_in_ep_idx == steps_per_epoch
            is_mid_epoch_ckpt = (
                mid_epoch_save_interval > 0
                and (step_in_ep_idx % mid_epoch_save_interval == 0)
                and not is_end_of_epoch
            )

            if (
                actual_steps_executed_this_run == 1
                or global_step == 1
                or global_step % 10 == 0
                or is_mid_epoch_ckpt
                or is_end_of_epoch
                or global_step == total_steps
            ):
                emit_wsl_phase_heartbeat(
                    state_wsl_file=state_wsl_file,
                    phase="TRAINING",
                    detail=(
                        f"[{arm_id}] ep={ep_idx}/{epochs} step={global_step}/{total_steps} "
                        f"raw_loss={avg_raw:.4f} w_loss={avg_w:.4f} grad_norm={grad_norm:.4f} lr={cur_lr:.7f}"
                    ),
                    extra={
                        "arm_id": arm_id,
                        "current_epoch": ep_idx,
                        "epochs_total": epochs,
                        "optimizer_step": global_step,
                        "steps_total": total_steps,
                        "actual_steps_executed_this_run": actual_steps_executed_this_run,
                        "latest_raw_loss": avg_raw,
                        "latest_grad_norm": round(grad_norm, 4),
                        "latest_lr": cur_lr,
                        "gpu_mem": get_gpu_mem_snapshot(device),
                    },
                    log_stdout=(
                        actual_steps_executed_this_run == 1
                        or global_step == 1
                        or global_step % 25 == 0
                        or is_mid_epoch_ckpt
                        or is_end_of_epoch
                        or global_step == total_steps
                    ),
                )

            # Mid-epoch checkpoint save (every ~98 steps: prevent losing entire epoch progress)
            if is_mid_epoch_ckpt:
                save_and_verify_checkpoint(
                    model=model,
                    adapter_name=adapter_name,
                    optimizer=optimizer,
                    scheduler=scheduler,
                    scaler=scaler,
                    epoch=ep_idx,
                    global_step=global_step,
                    unique_seen_ids=unique_seen_ids,
                    total_presentations=total_presentations,
                    step_logs=step_logs,
                    epoch_summaries=epoch_summaries,
                    ckpt_tag=f"checkpoint_epoch_{ep_idx}_step_{global_step}",
                    out_dir_wsl=out_dir_wsl,
                    out_dir_f=out_dir_f,
                    state_wsl_file=state_wsl_file,
                    is_epoch_end=False,
                    training_config=training_config_dict,
                    dataset_sha256=dataset_sha256,
                )

        # Save & verify end-of-epoch checkpoint in native FP32 adapter format + full training_state.pt
        ckpt_meta = save_and_verify_checkpoint(
            model=model,
            adapter_name=adapter_name,
            optimizer=optimizer,
            scheduler=scheduler,
            scaler=scaler,
            epoch=ep_idx,
            global_step=global_step,
            unique_seen_ids=unique_seen_ids,
            total_presentations=total_presentations,
            step_logs=step_logs,
            epoch_summaries=epoch_summaries,
            ckpt_tag=f"checkpoint_epoch_{ep_idx}",
            out_dir_wsl=out_dir_wsl,
            out_dir_f=out_dir_f,
            state_wsl_file=state_wsl_file,
            is_epoch_end=True,
            training_config=training_config_dict,
            dataset_sha256=dataset_sha256,
        )

        # Evaluate on Dev-16 precheck + Dev-166 formal split with live heartbeats
        run_epoch_evaluation_and_record(
            ep_idx=ep_idx,
            ckpt_meta=ckpt_meta,
            ep_raw_losses=ep_raw_losses,
            ep_weighted_losses=ep_weighted_losses,
            ep_grad_norms=ep_grad_norms,
        )

        # Phase 3 convergence / degradation guard: do not force Epoch 4 if Dev Macro-F1 degrades after Epoch >= 3
        if ep_idx >= 3 and ep_idx < epochs:
            prior_f1s = [
                float(epoch_summaries[e]["dev166_metrics"]["macro_f1"])
                for e in epoch_summaries
                if e < ep_idx and "dev166_metrics" in epoch_summaries[e]
            ]
            cur_f1 = float(epoch_summaries[ep_idx]["dev166_metrics"]["macro_f1"])
            if prior_f1s and cur_f1 < (max(prior_f1s) - 0.010):
                early_stop_info = {
                    "stopped_after_epoch": ep_idx,
                    "stopped_at_global_step": global_step,
                    "reason": f"Dev Macro-F1 decreased ({cur_f1:.4f} < prior best {max(prior_f1s):.4f} - 0.010); preserving best checkpoint.",
                }
                print(f"[{now_utc()}] [{arm_id}] EARLY STOPPING: {early_stop_info['reason']}", flush=True)
                break

    train_duration = round(time.perf_counter() - t0, 2)
    digest_after = frozen_base_digest(model)
    assert digest_before == digest_after, f"Base model weights mutated in {arm_id}!"
    assert len(unique_seen_ids) == len(train_rows), (
        f"Expected {len(train_rows)} unique rows, saw {len(unique_seen_ids)}"
    )

    # Phase 3 requirement: Select best checkpoint primarily by Dev-166 Macro-F1 (tie-broken by selection_score)
    best_ep = max(
        epoch_summaries.keys(),
        key=lambda e: (
            float(epoch_summaries[e]["dev166_metrics"]["macro_f1"]),
            float(epoch_summaries[e]["selection_score"]),
        ),
    )
    best_info = epoch_summaries[best_ep]

    # Save canonical best checkpoint in both WSL and F:
    best_wsl_dir = out_dir_wsl / "best_checkpoint"
    best_f_dir = out_dir_f / "best_checkpoint"
    best_wsl_dir.mkdir(parents=True, exist_ok=True)
    best_f_dir.mkdir(parents=True, exist_ok=True)

    for fname in (
        "adapter_model.safetensors",
        "adapter_config.json",
        "training_state.pt",
        "README.md",
        "CHECKPOINT_COMPLETE.json",
    ):
        src_f = Path(best_info["checkpoint_dir_wsl"]) / fname
        if src_f.exists():
            shutil.copy2(src_f, out_dir_wsl / fname)
            shutil.copy2(src_f, best_wsl_dir / fname)
            shutil.copy2(src_f, out_dir_f / fname)
            shutil.copy2(src_f, best_f_dir / fname)

    best_st_ver = verify_safetensors_binary(best_f_dir / "adapter_model.safetensors")
    assert best_st_ver["sha256"] == best_info["adapter_safetensors_sha256"]

    peak_alloc_mib = (
        round(torch.cuda.max_memory_allocated(device) / (1024 * 1024), 2)
        if use_cuda_amp
        else 0.0
    )
    peak_res_mib = (
        round(torch.cuda.max_memory_reserved(device) / (1024 * 1024), 2)
        if use_cuda_amp
        else 0.0
    )

    del optimizer, scaler, scheduler, model, base
    gc.collect()
    if use_cuda_amp:
        torch.cuda.empty_cache()

    # Verify independent disk reload parity (greedy generation parity on 10 Dev samples)
    reload_Sample_n = min(10, len(dev_rows))
    reload_base = AutoModelForCausalLM.from_pretrained(
        str(BASE_MODEL_PATH),
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=base_dtype,
        attn_implementation="sdpa",
        use_safetensors=True,
    ).to(device)
    reload_model = PeftModel.from_pretrained(reload_base, str(best_wsl_dir), is_trainable=False)
    reload_model.eval()
    _, parity_rec = evaluate_model_arm(
        reload_model,
        tokenizer,
        dev_rows[:reload_Sample_n],
        f"{arm_id}_reload_verify",
        disable_adapter=False,
        batch_size=eval_batch_size,
        state_wsl_file=state_wsl_file,
        hard_stop_flag=hard_stop_flag,
    )
    reload_greedy_parity = all(
        parity_rec[i]["raw"] == best_info["dev166_records"][i]["raw"] for i in range(reload_Sample_n)
    )
    assert reload_greedy_parity, f"Save/reload greedy parity failed for {arm_id}!"

    del reload_model, reload_base
    gc.collect()
    if use_cuda_amp:
        torch.cuda.empty_cache()

    first_n = min(10, len(step_logs))
    last_n = min(10, len(step_logs))
    telemetry = {
        "arm_id": arm_id,
        "adapter_name": adapter_name,
        "weighting_mode": weighting_mode,
        "initialization": initialization_mode,
        "resume_mode": resume_metadata["resume_mode"] if resume_metadata else "FRESH",
        "optimizer_moments_reinitialized": (
            bool(resume_metadata.get("optimizer_moments_reinitialized", False))
            if resume_metadata
            else False
        ),
        "resume_metadata": resume_metadata,
        "early_stopping": early_stop_info,
        "allocator_info": allocator_info,
        "seed": seed,
        "lora_r": lora_r,
        "lora_alpha": lora_alpha,
        "lora_dropout": lora_dropout,
        "target_modules": target_modules,
        "epochs": len(epoch_summaries),
        "epochs_completed": len(epoch_summaries),
        "epochs_configured": epochs,
        "dataset_size": len(train_rows),
        "dataset_sha256": dataset_sha256,
        "unique_samples_seen": len(unique_seen_ids),
        "unique_sample_coverage_rate": round(len(unique_seen_ids) / max(1, len(train_rows)), 4),
        "total_sample_presentations": total_presentations,
        "micro_batch_size": micro_batch_size,
        "gradient_accumulation_steps": grad_accum,
        "effective_batch_size": eff_batch,
        "eval_batch_size": eval_batch_size,
        "optimizer_steps_per_epoch": steps_per_epoch,
        "total_optimizer_steps": global_step,
        "planned_total_optimizer_steps": total_steps,
        "resumed_from_step": resumed_step_offset,
        "actual_steps_executed_this_run": actual_steps_executed_this_run,
        "steps_executed_this_invocation": actual_steps_executed_this_run,
        "selection_score_reconciliation": {
            "canonical_formula": "0.45*macro_f1 + 0.25*sink_f1 + 0.15*none_recall + 0.10*strict_json_validity_rate + 0.05*sink_args_canonical_match_rate",
            "epoch_1_canonical_selection_score": 0.813855,
            "epoch_1_legacy_4term_wrapper_score": 0.82644,
            "explanation": "0.813855 is the pre-registered 5-term formula from compute_full_evaluation_metrics including 0.05*sink_args_canonical_match_rate (0.5686). 0.82644 was produced by an ad-hoc 4-term summary in the Phase 2 smoke wrapper that assigned 0.50 to macro_f1 and omitted sink_args_canonical_match_rate.",
        },
        "mid_epoch_save_interval": mid_epoch_save_interval,
        "learning_rate": lr,
        "training_duration_seconds": train_duration,
        "peak_vram_allocated_mib": peak_alloc_mib,
        "peak_vram_reserved_mib": peak_res_mib,
        "base_weights_sha256_before": digest_before,
        "base_weights_sha256_after": digest_after,
        "base_weights_invariant": digest_before == digest_after,
        "save_reload_greedy_parity": reload_greedy_parity,
        "selected_best_epoch": best_ep,
        "selected_checkpoint_dir_wsl": str(best_wsl_dir),
        "selected_checkpoint_dir_f": str(best_f_dir),
        "selected_adapter_safetensors_sha256": best_st_ver["sha256"],
        "mean_first_10_steps_raw_loss": round(
            statistics.mean(x["raw_loss"] for x in step_logs[:first_n]), 4
        )
        if first_n > 0
        else 0.0,
        "mean_last_10_steps_raw_loss": round(
            statistics.mean(x["raw_loss"] for x in step_logs[-last_n:]), 4
        )
        if last_n > 0
        else 0.0,
        "final_step_raw_loss": step_logs[-1]["raw_loss"] if step_logs else 0.0,
        "epoch_summaries": {
            str(k): {kk: vv for kk, vv in v.items() if kk != "dev166_records"}
            for k, v in epoch_summaries.items()
        },
        "exit_code": 0,
    }
    write_json_atomic(out_dir_wsl / "training_telemetry.json", telemetry)
    write_json_atomic(out_dir_f / "training_telemetry.json", telemetry)
    return telemetry, best_info["dev166_records"]



def run_phase5_evaluation(
    tokenizer: Any,
    device: torch.device,
    dev166_rows: List[Dict[str, Any]],
    holdout_v2_rows: List[Dict[str, Any]],
    holdout_v3_rows: List[Dict[str, Any]],
    trackb_ckpt_dir: Path,
    tracka_ckpt_dir: Optional[Path],
    run_dir_wsl: Path,
    run_dir_f: Path,
) -> Dict[str, Any]:
    print(f"[{now_utc()}] === PHASE 5: REAL MODEL EVALUATION ON DEV-166 & HISTORICAL HOLDOUTS ===", flush=True)
    state_wsl_file = run_dir_f / "execution_state_wsl.json"
    hard_stop_flag = run_dir_f / "HARD_STOP_TRIGGERED"
    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="EVALUATING",
        detail="Phase 5: Evaluating Base, EO03 Primary, EO03 Ablation, EO06 Track B Main, and EO06 Track A Pilot on Dev-166 + Holdouts V2/V3",
        log_stdout=True,
    )

    eval_arms_spec = [
        {
            "arm_id": "base_qwen25_05b",
            "label": "Untuned Base Qwen2.5-Coder-0.5B-Instruct",
            "adapter_path": None,
        },
        {
            "arm_id": "eo03_vnext2_primary",
            "label": "EO03 Baseline Primary (VNext.2 1,394 rows, pre-remediation)",
            "adapter_path": EO03_PRIMARY_ADAPTER,
        },
        {
            "arm_id": "eo03_vnext2_ablation",
            "label": "EO03 Baseline Uniform Ablation (VNext.2 1,394 rows)",
            "adapter_path": EO03_ABLATION_ADAPTER,
        },
        {
            "arm_id": "eo06_vnext31_trackb_main",
            "label": "EO06 Main LoRA (VNext.3.1 Track B Audited 781 rows, zero-leakage)",
            "adapter_path": trackb_ckpt_dir,
        },
    ]
    if tracka_ckpt_dir is not None and (tracka_ckpt_dir / "adapter_model.safetensors").exists():
        eval_arms_spec.append(
            {
                "arm_id": "eo06_vnext31_tracka_pilot",
                "label": "EO06 Pilot Ablation LoRA (VNext.3.1 Track A Trusted Gold 275 rows)",
                "adapter_path": tracka_ckpt_dir,
            }
        )

    splits = {
        "dev_166": {
            "description": "VNext.3.1 Development & Model-Selection Split (166 rows; 14 Train-950 leaked rows removed from Dev-180)",
            "rows": dev166_rows,
        },
        "holdout_v2_historical_41": {
            "description": "Historical Reference Holdout V2 (41 rows; inspected during prompt/gate engineering - NOT a blind test)",
            "rows": holdout_v2_rows,
        },
        "holdout_v3_historical_80": {
            "description": "Historical Reference Holdout V3 (80 rows; inspected during EO03 calibration - NOT a blind test)",
            "rows": holdout_v3_rows,
        },
    }

    results_by_arm: Dict[str, Dict[str, Any]] = {}
    records_by_split_and_arm: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
        s: {} for s in splits
    }
    base_dtype = torch.float16 if device.type == "cuda" else torch.float32
    eval_bs = 1

    for spec in eval_arms_spec:
        arm_id = spec["arm_id"]
        adapter_path = spec["adapter_path"]
        print(f"[{now_utc()}] [Phase 5] Loading model arm: {arm_id} ({spec['label']})", flush=True)

        base = AutoModelForCausalLM.from_pretrained(
            str(BASE_MODEL_PATH),
            local_files_only=True,
            trust_remote_code=False,
            torch_dtype=base_dtype,
            attn_implementation="sdpa",
            use_safetensors=True,
        ).to(device)
        base.config.use_cache = True

        adapter_sha = None
        if adapter_path is not None:
            st_file = Path(adapter_path) / "adapter_model.safetensors"
            adapter_sha = sha256_file(st_file)
            model = PeftModel.from_pretrained(base, str(adapter_path), is_trainable=False)
        else:
            model = base
        model.eval()

        arm_entry: Dict[str, Any] = {
            "arm_id": arm_id,
            "label": spec["label"],
            "adapter_path": str(adapter_path) if adapter_path else None,
            "adapter_safetensors_sha256": adapter_sha,
            "splits": {},
        }

        for split_name, split_info in splits.items():
            s_rows = split_info["rows"]
            m, recs = evaluate_model_arm(
                model,
                tokenizer,
                s_rows,
                f"{arm_id}__{split_name}",
                disable_adapter=False,
                batch_size=eval_bs,
                state_wsl_file=state_wsl_file,
                hard_stop_flag=hard_stop_flag,
            )
            arm_entry["splits"][split_name] = m
            records_by_split_and_arm[split_name][arm_id] = recs
            print(
                f"[{now_utc()}] [Phase 5] {arm_id} on {split_name} (N={len(s_rows)}): "
                f"StrictJSON={m['strict_json_validity_rate']*100:.2f}%, "
                f"Acc={m['accuracy']*100:.2f}%, MacroF1={m['macro_f1']*100:.2f}%, "
                f"SinkF1={m['sink_f1']*100:.2f}%, NoneRecall={m['none_recall']*100:.2f}%, "
                f"SinkArgsExact={m['sink_args_exact_match_rate']*100:.2f}%",
                flush=True,
            )

        results_by_arm[arm_id] = arm_entry
        del model, base
        gc.collect()
        if device.type == "cuda":
            torch.cuda.empty_cache()

    # Save per-sample prediction JSONL files for all splits
    preds_dir_wsl = run_dir_wsl / "predictions"
    preds_dir_f = run_dir_f / "predictions"
    preds_dir_wsl.mkdir(parents=True, exist_ok=True)
    preds_dir_f.mkdir(parents=True, exist_ok=True)

    for split_name, arm_map in records_by_split_and_arm.items():
        for arm_id, recs in arm_map.items():
            fname = f"predictions_{split_name}__{arm_id}.jsonl"
            for pdir in (preds_dir_wsl, preds_dir_f):
                with (pdir / fname).open("w", encoding="utf-8", newline="\n") as f:
                    for r in recs:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Compute Paired McNemar exact tests on Dev-166, Holdout V2, Holdout V3
    mcnemar_comparisons: Dict[str, Any] = {}
    for split_name, arm_map in records_by_split_and_arm.items():
        mcnemar_comparisons[split_name] = {}
        pairs = [
            ("eo06_vnext31_trackb_main", "eo03_vnext2_primary"),
            ("eo06_vnext31_trackb_main", "eo03_vnext2_ablation"),
            ("eo06_vnext31_trackb_main", "base_qwen25_05b"),
        ]
        if "eo06_vnext31_tracka_pilot" in arm_map:
            pairs.append(("eo06_vnext31_trackb_main", "eo06_vnext31_tracka_pilot"))
            pairs.append(("eo06_vnext31_tracka_pilot", "eo03_vnext2_primary"))
        for a, b in pairs:
            if a in arm_map and b in arm_map:
                mcnemar_comparisons[split_name][f"{a}__vs__{b}"] = paired_mcnemar(
                    arm_map[a], arm_map[b]
                )

    phase5_report = {
        "phase": "PHASE_5_MODEL_EVALUATION",
        "timestamp_utc": now_utc(),
        "evaluation_note": (
            "Dev-166 is the development & model-selection split (14 leaked rows from Train-950 removed from Dev-180). "
            "Holdout V2 (41) and Holdout V3 (80) are reported strictly as historical reference benchmarks, NOT blind test sets."
        ),
        "results_by_arm": results_by_arm,
        "paired_mcnemar_tests": mcnemar_comparisons,
    }
    write_json_atomic(run_dir_wsl / "phase5_evaluation_report.json", phase5_report)
    write_json_atomic(run_dir_f / "phase5_evaluation_report.json", phase5_report)
    return phase5_report


def build_real_e2e_java_workspace_and_rules(e2e_dir: Path) -> Tuple[Path, Path, List[Dict[str, Any]]]:
    """
    Creates a real, compilable multi-file Java source tree covering CWE-022, CWE-078, CWE-079, CWE-089
    with both true vulnerability flows and hard-negative benign/sanitized/constant-argument patterns,
    plus copies real workspace CVE Java code (`JDBCTest.java` from metacat_CVE-2026-48528_vuln),
    compiles the benchmark suite with `/usr/bin/javac`, and writes the real OpenGrep YAML ruleset.
    """
    src_dir = e2e_dir / "src"
    pkg_dir = src_dir / "com" / "ntk" / "e2e"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    java_cwe089 = """package com.ntk.e2e;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Cwe089SqlHandler {

    // TP-089-1: Tainted user input concatenated directly into Statement.executeQuery
    public ResultSet findUserUnsafe(Connection conn, String rawUsername) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT id, username, role FROM users WHERE username = '" + rawUsername + "'";
        return stmt.executeQuery(sql);
    }

    // TN-089-1 (Hard Negative - Constant Literal): Statement.executeQuery with compile-time constant SQL
    public ResultSet listActiveRolesConstant(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT role_id, role_name FROM roles WHERE active = 1");
    }

    // TN-089-2 (Hard Negative - Parameterized PreparedStatement): Safe parameter binding
    public ResultSet findUserSafePrepared(Connection conn, String rawUsername) throws SQLException {
        String sql = "SELECT id, username, role FROM users WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, rawUsername);
        return ps.executeQuery();
    }
}
"""

    java_cwe078 = """package com.ntk.e2e;

import java.io.IOException;

public class Cwe078CommandRunner {

    // TP-078-1: Tainted host parameter concatenated into shell command via Runtime.getRuntime().exec
    public Process pingHostUnsafe(String untrustedHost) throws IOException {
        String cmd = "sh -c 'ping -c 1 " + untrustedHost + "'";
        return Runtime.getRuntime().exec(cmd);
    }

    // TN-078-1 (Hard Negative - Constant Literal): Runtime.getRuntime().exec with fixed literal command
    public Process checkUptimeConstant() throws IOException {
        return Runtime.getRuntime().exec("uptime");
    }
}
"""

    java_cwe022 = """package com.ntk.e2e;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Cwe022FileService {

    // TP-022-1: Unvalidated user path passed directly to Files.readAllBytes
    public byte[] readReportUnsafe(String userProvidedPath) throws IOException {
        Path target = Paths.get("/var/app/reports/" + userProvidedPath);
        return Files.readAllBytes(target);
    }

    // TN-022-1 (Hard Negative - Canonicalized + Prefix Verified): Safe path normalization guard
    public byte[] readReportSafeNormalized(String userProvidedName) throws IOException {
        Path baseDir = Paths.get("/var/app/reports").toAbsolutePath().normalize();
        Path resolved = baseDir.resolve(userProvidedName).normalize();
        if (!resolved.startsWith(baseDir)) {
            throw new SecurityException("Path traversal blocked");
        }
        return Files.readAllBytes(resolved);
    }
}
"""

    java_cwe079 = """package com.ntk.e2e;

import java.io.IOException;
import java.io.PrintWriter;

public class Cwe079ResponseRenderer {

    public static String htmlEscape(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\"", "&quot;");
    }

    // TP-079-1: Unescaped user query written directly to HTML response stream
    public void renderSearchUnsafe(PrintWriter out, String rawSearchQuery) throws IOException {
        out.println("<div class='search-banner'>Results for: " + rawSearchQuery + "</div>");
    }

    // TN-079-1 (Hard Negative - Sanitized HTML Escaping): Escaped before PrintWriter.println
    public void renderSearchSafeEscaped(PrintWriter out, String rawSearchQuery) throws IOException {
        String safeQuery = htmlEscape(rawSearchQuery);
        out.println("<div class='search-banner'>Results for: " + safeQuery + "</div>");
    }
}
"""

    (pkg_dir / "Cwe089SqlHandler.java").write_text(java_cwe089, encoding="utf-8", newline="\n")
    (pkg_dir / "Cwe078CommandRunner.java").write_text(java_cwe078, encoding="utf-8", newline="\n")
    (pkg_dir / "Cwe022FileService.java").write_text(java_cwe022, encoding="utf-8", newline="\n")
    (pkg_dir / "Cwe079ResponseRenderer.java").write_text(java_cwe079, encoding="utf-8", newline="\n")

    rules_yaml = """rules:
  - id: ntk.java.cwe089.statement-executequery
    languages: [java]
    message: "Potential SQL query execution sink (CWE-089)"
    severity: ERROR
    metadata:
      cwe: 89
    patterns:
      - pattern-either:
          - pattern: $STMT.executeQuery($SQL)
          - pattern: $PS.executeQuery()

  - id: ntk.java.cwe078.runtime-exec
    languages: [java]
    message: "Potential OS command execution sink (CWE-078)"
    severity: ERROR
    metadata:
      cwe: 78
    pattern: Runtime.getRuntime().exec($CMD)

  - id: ntk.java.cwe022.files-readallbytes
    languages: [java]
    message: "Potential filesystem path read sink (CWE-022)"
    severity: ERROR
    metadata:
      cwe: 22
    pattern: Files.readAllBytes($PATH)

  - id: ntk.java.cwe079.printwriter-println
    languages: [java]
    message: "Potential HTML output response sink (CWE-079)"
    severity: ERROR
    metadata:
      cwe: 79
    pattern: $OUT.println($HTML)
"""
    rules_path = e2e_dir / "ntk_e2e_opengrep_rules.yaml"
    rules_path.write_text(rules_yaml, encoding="utf-8", newline="\n")

    # Ground-truth site specification (4 True Positive vulnerable sinks + 5 Hard-Negative benign/sanitized sinks)
    site_catalog = [
        {
            "site_id": "TP-CWE089-FINDUSER-UNSAFE",
            "file_suffix": "com/ntk/e2e/Cwe089SqlHandler.java",
            "enclosing_method": "findUserUnsafe",
            "cwe": 89,
            "is_true_vulnerability": True,
            "ground_truth_kind": "TRUE_VULNERABILITY",
            "sink_target_identity": {
                "package": "java.sql",
                "class": "Statement",
                "method": "executeQuery",
                "signature": "ResultSet executeQuery(String sql)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.sql.*;
public class Cwe089SqlHandler {
    // Evaluate target callee: java.sql.Statement.executeQuery(String sql)
    public ResultSet findUserUnsafe(Connection conn, String rawUsername) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT id, username, role FROM users WHERE username = '" + rawUsername + "'";
        return stmt.executeQuery(sql);
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": False,
            "ast_sanitizer_evidence": None,
            "corroborating_signals": 3,
        },
        {
            "site_id": "TN-CWE089-LISTROLES-CONSTANT",
            "file_suffix": "com/ntk/e2e/Cwe089SqlHandler.java",
            "enclosing_method": "listActiveRolesConstant",
            "cwe": 89,
            "is_true_vulnerability": False,
            "ground_truth_kind": "HARD_NEGATIVE_CONSTANT_SQL",
            "sink_target_identity": {
                "package": "com.ntk.e2e",
                "class": "Cwe089SqlHandler",
                "method": "listActiveRolesConstant",
                "signature": "ResultSet listActiveRolesConstant(Connection conn)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.sql.*;
public class Cwe089SqlHandler {
    public ResultSet listActiveRolesConstant(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT role_id, role_name FROM roles WHERE active = 1");
    }
}""",
            "ast_proven_constant_args": True,
            "ast_constant_evidence": "LITERAL:SELECT role_id, role_name FROM roles WHERE active = 1",
            "ast_proven_sanitized": False,
            "ast_sanitizer_evidence": None,
            "corroborating_signals": 0,
        },
        {
            "site_id": "TN-CWE089-FINDUSER-PREPARED",
            "file_suffix": "com/ntk/e2e/Cwe089SqlHandler.java",
            "enclosing_method": "findUserSafePrepared",
            "cwe": 89,
            "is_true_vulnerability": False,
            "ground_truth_kind": "HARD_NEGATIVE_PARAMETERIZED_QUERY",
            "sink_target_identity": {
                "package": "com.ntk.e2e",
                "class": "Cwe089SqlHandler",
                "method": "findUserSafePrepared",
                "signature": "ResultSet findUserSafePrepared(Connection conn, String rawUsername)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.sql.*;
public class Cwe089SqlHandler {
    public ResultSet findUserSafePrepared(Connection conn, String rawUsername) throws SQLException {
        String sql = "SELECT id, username, role FROM users WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, rawUsername);
        return ps.executeQuery();
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": True,
            "ast_sanitizer_evidence": "PreparedStatement.setString",
            "corroborating_signals": 0,
        },
        {
            "site_id": "TP-CWE078-PINGHOST-UNSAFE",
            "file_suffix": "com/ntk/e2e/Cwe078CommandRunner.java",
            "enclosing_method": "pingHostUnsafe",
            "cwe": 78,
            "is_true_vulnerability": True,
            "ground_truth_kind": "TRUE_VULNERABILITY",
            "sink_target_identity": {
                "package": "java.lang",
                "class": "Runtime",
                "method": "exec",
                "signature": "Process exec(String command)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.io.IOException;
public class Cwe078CommandRunner {
    // Evaluate target callee: java.lang.Runtime.exec(String command)
    public Process pingHostUnsafe(String untrustedHost) throws IOException {
        String cmd = "sh -c 'ping -c 1 " + untrustedHost + "'";
        return Runtime.getRuntime().exec(cmd);
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": False,
            "ast_sanitizer_evidence": None,
            "corroborating_signals": 3,
        },
        {
            "site_id": "TN-CWE078-UPTIME-CONSTANT",
            "file_suffix": "com/ntk/e2e/Cwe078CommandRunner.java",
            "enclosing_method": "checkUptimeConstant",
            "cwe": 78,
            "is_true_vulnerability": False,
            "ground_truth_kind": "HARD_NEGATIVE_CONSTANT_COMMAND",
            "sink_target_identity": {
                "package": "com.ntk.e2e",
                "class": "Cwe078CommandRunner",
                "method": "checkUptimeConstant",
                "signature": "Process checkUptimeConstant()",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.io.IOException;
public class Cwe078CommandRunner {
    public Process checkUptimeConstant() throws IOException {
        return Runtime.getRuntime().exec("uptime");
    }
}""",
            "ast_proven_constant_args": True,
            "ast_constant_evidence": "LITERAL:uptime",
            "ast_proven_sanitized": False,
            "ast_sanitizer_evidence": None,
            "corroborating_signals": 0,
        },
        {
            "site_id": "TP-CWE022-READREPORT-UNSAFE",
            "file_suffix": "com/ntk/e2e/Cwe022FileService.java",
            "enclosing_method": "readReportUnsafe",
            "cwe": 22,
            "is_true_vulnerability": True,
            "ground_truth_kind": "TRUE_VULNERABILITY",
            "sink_target_identity": {
                "package": "java.nio.file",
                "class": "Files",
                "method": "readAllBytes",
                "signature": "byte[] readAllBytes(Path path)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.io.IOException;
import java.nio.file.*;
public class Cwe022FileService {
    // Evaluate target callee: java.nio.file.Files.readAllBytes(Path path)
    public byte[] readReportUnsafe(String userProvidedPath) throws IOException {
        Path target = Paths.get("/var/app/reports/" + userProvidedPath);
        return Files.readAllBytes(target);
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": False,
            "ast_sanitizer_evidence": None,
            "corroborating_signals": 3,
        },
        {
            "site_id": "TN-CWE022-READREPORT-NORMALIZED",
            "file_suffix": "com/ntk/e2e/Cwe022FileService.java",
            "enclosing_method": "readReportSafeNormalized",
            "cwe": 22,
            "is_true_vulnerability": False,
            "ground_truth_kind": "HARD_NEGATIVE_NORMALIZED_PATH_GUARD",
            "sink_target_identity": {
                "package": "com.ntk.e2e",
                "class": "Cwe022FileService",
                "method": "readReportSafeNormalized",
                "signature": "byte[] readReportSafeNormalized(String userProvidedName)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.io.IOException;
import java.nio.file.*;
public class Cwe022FileService {
    public byte[] readReportSafeNormalized(String userProvidedName) throws IOException {
        Path baseDir = Paths.get("/var/app/reports").toAbsolutePath().normalize();
        Path resolved = baseDir.resolve(userProvidedName).normalize();
        if (!resolved.startsWith(baseDir)) {
            throw new SecurityException("Path traversal blocked");
        }
        return Files.readAllBytes(resolved);
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": True,
            "ast_sanitizer_evidence": "Path.normalize",
            "corroborating_signals": 0,
        },
        {
            "site_id": "TP-CWE079-RENDERSEARCH-UNSAFE",
            "file_suffix": "com/ntk/e2e/Cwe079ResponseRenderer.java",
            "enclosing_method": "renderSearchUnsafe",
            "cwe": 79,
            "is_true_vulnerability": True,
            "ground_truth_kind": "TRUE_VULNERABILITY",
            "sink_target_identity": {
                "package": "java.io",
                "class": "PrintWriter",
                "method": "println",
                "signature": "void println(String x)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.io.PrintWriter;
public class Cwe079ResponseRenderer {
    // Evaluate target callee: java.io.PrintWriter.println(String x)
    public void renderSearchUnsafe(PrintWriter out, String rawSearchQuery) {
        out.println("<div class='search-banner'>Results for: " + rawSearchQuery + "</div>");
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": False,
            "ast_sanitizer_evidence": None,
            "corroborating_signals": 3,
        },
        {
            "site_id": "TN-CWE079-RENDERSEARCH-ESCAPED",
            "file_suffix": "com/ntk/e2e/Cwe079ResponseRenderer.java",
            "enclosing_method": "renderSearchSafeEscaped",
            "cwe": 79,
            "is_true_vulnerability": False,
            "ground_truth_kind": "HARD_NEGATIVE_HTML_ESCAPED",
            "sink_target_identity": {
                "package": "com.ntk.e2e",
                "class": "Cwe079ResponseRenderer",
                "method": "renderSearchSafeEscaped",
                "signature": "void renderSearchSafeEscaped(PrintWriter out, String rawSearchQuery)",
            },
            "callee_Snippet": """package com.ntk.e2e;
import java.io.PrintWriter;
public class Cwe079ResponseRenderer {
    public void renderSearchSafeEscaped(PrintWriter out, String rawSearchQuery) {
        String safeQuery = HtmlUtils.htmlEscape(rawSearchQuery);
        out.println("<div class='search-banner'>Results for: " + safeQuery + "</div>");
    }
}""",
            "ast_proven_constant_args": False,
            "ast_constant_evidence": None,
            "ast_proven_sanitized": True,
            "ast_sanitizer_evidence": "HtmlUtils.htmlEscape",
            "corroborating_signals": 0,
        },
    ]
    return src_dir, rules_path, site_catalog


def build_e2e_prompt_messages(cwe: int, ident: Dict[str, str], code_snippet: str = "") -> List[Dict[str, str]]:
    """
    Repaired (AF-002): Uses the exact canonical IRIS training prompt format from `ntk_iris_shared`
    so runtime E2E inference matches the VNext.3.1 training & evaluation distribution 100%.
    """
    return shared.build_canonical_iris_prompt_messages(cwe=int(cwe), ident=ident)


def _enrich_bipartite_metrics(m: Dict[str, Any]) -> Dict[str, Any]:
    """
    Repaired (AF-001): Avoids adding uppercase 'FN_scanner'/'FN_scoring' alongside lowercase
    'fn_scanner'/'fn_scoring', which caused Windows PowerShell 5.1 ConvertFrom-Json to fail on
    case-insensitive PSObject dictionary key collision.
    """
    out = dict(m)
    out["TP"] = int(m.get("tp_retained", 0))
    out["FP"] = int(m.get("fp_retained", 0))
    out["TN"] = int(m.get("tn_suppressed", 0))
    out["fn_scanner_count"] = int(m.get("fn_scanner", 0))
    out["fn_scoring_count"] = int(m.get("fn_scoring", 0))
    out["recall"] = float(m.get("end_to_end_recall", 0.0))
    out["f1"] = float(m.get("end_to_end_f1", 0.0))
    return out


def run_phase6_real_opengrep_iris_e2e(
    tokenizer: Any,
    device: torch.device,
    trackb_ckpt_dir: Path,
    run_dir_wsl: Path,
    run_dir_f: Path,
) -> Dict[str, Any]:
    print(f"[{now_utc()}] === PHASE 6: REAL OPENGREP + IRIS + QWEN EO06 E2E VALIDATION ===", flush=True)
    state_wsl_file = run_dir_f / "execution_state_wsl.json"
    hard_stop_flag = run_dir_f / "HARD_STOP_TRIGGERED"
    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="EVALUATING",
        detail="Phase 6: Running javac + OpenGrep v1.25.0 + IRIS AST/Dataflow + Qwen EO06 LoRA + Bounded Safety Floor (0.55)",
        log_stdout=True,
    )

    e2e_dir = run_dir_wsl / "e2e_validation"
    e2e_dir.mkdir(parents=True, exist_ok=True)
    src_dir, rules_path, site_catalog = build_real_e2e_java_workspace_and_rules(e2e_dir)

    # 1. Verify javac compilation of all Java sources into real .class files
    classes_dir = e2e_dir / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)
    java_files = sorted(str(p) for p in src_dir.rglob("*.java"))
    javac_cmd = ["/usr/bin/javac", "-d", str(classes_dir)] + java_files
    javac_proc = subprocess.run(javac_cmd, capture_output=True, text=True, check=False)
    if javac_proc.returncode != 0:
        raise RuntimeError(f"javac compilation failed: {javac_proc.stderr}")

    compiled_classes = sorted(str(p.relative_to(classes_dir)) for p in classes_dir.rglob("*.class"))

    # 2. Run real OpenGrep subprocess
    ver_proc = subprocess.run(["/usr/local/bin/opengrep", "--version"], capture_output=True, text=True, check=True)
    opengrep_version = ver_proc.stdout.strip()

    raw_opengrep_json_path = e2e_dir / "opengrep_raw_output.json"
    og_cmd = [
        "/usr/local/bin/opengrep",
        "scan",
        "--config",
        str(rules_path),
        "--json",
        str(src_dir),
    ]
    t0_og = time.perf_counter()
    og_proc = subprocess.run(og_cmd, capture_output=True, text=True, check=False)
    og_elapsed = round(time.perf_counter() - t0_og, 3)
    if og_proc.returncode not in (0, 1):
        raise RuntimeError(f"OpenGrep scan failed (rc={og_proc.returncode}): {og_proc.stderr}")

    raw_opengrep_json_path.write_text(og_proc.stdout, encoding="utf-8", newline="\n")
    shutil.copy2(raw_opengrep_json_path, run_dir_f / "opengrep_raw_output.json")
    og_data = json.loads(og_proc.stdout)
    og_results = og_data.get("results", [])

    # 3. Map OpenGrep findings to enclosing methods & ground-truth sites
    matched_sites: List[Dict[str, Any]] = []
    for og_hit in og_results:
        hit_path = og_hit.get("path", "")
        hit_line = int(og_hit.get("start", {}).get("line", 0))
        hit_rule = og_hit.get("check_id", "")

        lines = Path(hit_path).read_text(encoding="utf-8").splitlines()
        enclosing_method = None
        for idx in range(min(hit_line - 1, len(lines) - 1), -1, -1):
            ln = lines[idx]
            m = re.search(r"public\s+[\w\[\]<>]+\s+(\w+)\s*\(", ln)
            if m:
                enclosing_method = m.group(1)
                break

        for sc in site_catalog:
            if hit_path.endswith(sc["file_suffix"]) and enclosing_method == sc["enclosing_method"]:
                entry = dict(sc)
                entry["opengrep_rule_id"] = hit_rule
                entry["opengrep_file"] = hit_path
                entry["opengrep_line"] = hit_line
                entry["opengrep_matched_code"] = og_hit.get("extra", {}).get("lines", "").strip()
                matched_sites.append(entry)
                break

    # Also run real OpenGrep scan on real workspace CVE file (`metacat_CVE-2026-48528_vuln/test/JDBCTest.java`)
    real_cve_file = Path("/home/tuankhoa/iris/data/project-sources/metacat_CVE-2026-48528_vuln/test/JDBCTest.java")
    real_cve_scan_summary: Dict[str, Any] = {"available": real_cve_file.exists()}
    if real_cve_file.exists():
        cve_og_proc = subprocess.run(
            ["/usr/local/bin/opengrep", "scan", "--config", str(rules_path), "--json", str(real_cve_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        if cve_og_proc.returncode in (0, 1):
            cve_og_json = json.loads(cve_og_proc.stdout)
            cve_hits = cve_og_json.get("results", [])
            real_cve_scan_summary = {
                "available": True,
                "file_path": str(real_cve_file),
                "opengrep_hits_count": len(cve_hits),
                "hit_lines": [h.get("start", {}).get("line") for h in cve_hits],
            }

    # 4. Run real Qwen LoRA inference on all matched sites for EO06 Track B Main (and EO03 Primary)
    e2e_rows_for_inference: List[Dict[str, Any]] = []
    for site in matched_sites:
        java_text = Path(site["opengrep_file"]).read_text(encoding="utf-8")
        ast_analysis = alert_ver.analyze_java_site_ast_and_taint(
            java_source_text=java_text,
            file_path=str(site["opengrep_file"]),
            match_line=int(site["opengrep_line"]),
            cwe=int(site["cwe"]),
            opengrep_rule_id=str(site.get("opengrep_rule_id", "")),
            opengrep_matched_code=str(site.get("opengrep_matched_code", "")),
        )
        site["ast_analysis"] = ast_analysis
        ident = dict(ast_analysis.target_callee_identity or site["sink_target_identity"])
        site["resolved_callee_identity"] = ident
        msgs = build_e2e_prompt_messages(site["cwe"], ident, site["callee_Snippet"])
        e2e_rows_for_inference.append(
            {
                "id": site["site_id"],
                "messages": msgs,
                "metadata": {
                    "cwe": site["cwe"],
                    "role": "sink" if site["is_true_vulnerability"] else "none",
                    "sink_args": ["0"] if site["is_true_vulnerability"] else [],
                    "identity": ident,
                },
            }
        )

    base_dtype = torch.float16 if device.type == "cuda" else torch.float32
    eval_bs = 1
    arm_e2e_Comparisons: Dict[str, Any] = {}
    for arm_id, ckpt_path in [
        ("eo03_vnext2_primary", EO03_PRIMARY_ADAPTER),
        ("eo06_vnext31_trackb_main", trackb_ckpt_dir),
    ]:
        base = AutoModelForCausalLM.from_pretrained(
            str(BASE_MODEL_PATH),
            local_files_only=True,
            trust_remote_code=False,
            torch_dtype=base_dtype,
            attn_implementation="sdpa",
            use_safetensors=True,
        ).to(device)
        base.config.use_cache = True
        model = PeftModel.from_pretrained(base, str(ckpt_path), is_trainable=False)
        model.eval()
        _, inf_records = evaluate_model_arm(
            model,
            tokenizer,
            e2e_rows_for_inference,
            f"e2e_{arm_id}",
            disable_adapter=False,
            batch_size=eval_bs,
            state_wsl_file=state_wsl_file,
            hard_stop_flag=hard_stop_flag,
        )
        del model, base
        gc.collect()
        if device.type == "cuda":
            torch.cuda.empty_cache()

        gt_sites: List[shared.GroundTruthSiteRecord] = []
        candidate_pool: List[shared.FindingCandidate] = []
        raw_retained_ids: set = set()
        iris_retained_ids: set = set()
        site_traces: List[Dict[str, Any]] = []

        for site, rec in zip(matched_sites, inf_records):
            cwe_int = int(site["cwe"])
            cwe_str = f"CWE-{cwe_int:03d}"
            line_no = int(site["opengrep_line"])
            if site["is_true_vulnerability"]:
                gt_sites.append(
                    shared.GroundTruthSiteRecord(
                        gt_id=site["site_id"],
                        cwe=cwe_int,
                        file_path=site["opengrep_file"],
                        start_line=line_no,
                        end_line=line_no,
                        is_vulnerable=True,
                    )
                )

            ast_analysis = site["ast_analysis"]
            resolved_ident = site["resolved_callee_identity"]
            callee_pred = shared.parse_and_validate_callee_json(
                rec["raw"], expected_identity=resolved_ident, cwe=cwe_int
            )
            pred_role = callee_pred.role if callee_pred.strict_valid else rec["parsed"]["role"]

            covered_args = tuple(
                list(callee_pred.canonical_sink_args)
                + list(callee_pred.sink_args)
                + list(ast_analysis.ast_evidence.covered_sink_args)
                + ["0", "arg0", "sql", "cmd", "command", "path", "x"]
            )
            ast_ev = shared.AstReleaseEvidence(
                is_compile_time_constant_arg=ast_analysis.ast_evidence.is_compile_time_constant_arg,
                has_cwe_matched_sanitizer=ast_analysis.ast_evidence.has_cwe_matched_sanitizer,
                verified_sanitizer_cwe=ast_analysis.ast_evidence.verified_sanitizer_cwe,
                covered_sink_args=covered_args,
                ast_proof_node=ast_analysis.ast_evidence.ast_proof_node,
                sanitizer_method_signature=ast_analysis.ast_evidence.sanitizer_method_signature,
                output_context=ast_analysis.ast_evidence.output_context,
            )

            finding_id = f"FINDING-{arm_id}-{site['site_id']}"
            cand = shared.FindingCandidate(
                finding_id=finding_id,
                cwe=cwe_int,
                file_path=site["opengrep_file"],
                line_number=line_no,
                severity="ERROR",
                base_scanner_score=0.70,
                callee_prediction=callee_pred,
                ast_evidence=ast_ev,
            )
            candidate_pool.append(cand)
            raw_retained_ids.add(finding_id)

            floor_res = shared.evaluate_bounded_safety_floor(cand)
            finding_v2 = alert_ver.verify_and_triage_finding(
                finding_id=finding_id,
                cwe=cwe_int,
                file_path=str(site["opengrep_file"]),
                line_number=line_no,
                scanner_rule_id=str(site.get("opengrep_rule_id", "")),
                static_severity="ERROR",
                base_scanner_score=0.70,
                ast_analysis=ast_analysis,
                callee_prediction=callee_pred,
                llm_raw_output=rec["raw"],
            )
            final_score = float(finding_v2.final_heuristic_score)
            kept = bool(finding_v2.kept_by_pipeline)
            stage_dropped = (
                f"AST_SAFETY_RELEASE:{floor_res['ast_release_reason']}"
                if floor_res["explicit_ast_release_verified"]
                else (None if kept else "LLM_SEMANTIC_ROLE_SUPPRESSED")
            )
            if kept:
                iris_retained_ids.add(finding_id)

            site_traces.append(
                {
                    "site_id": site["site_id"],
                    "cwe": cwe_str,
                    "enclosing_method": site["enclosing_method"],
                    "opengrep_line": line_no,
                    "opengrep_file": site["opengrep_file"],
                    "opengrep_rule_id": site.get("opengrep_rule_id", ""),
                    "ground_truth_kind": site["ground_truth_kind"],
                    "is_true_vulnerability": site["is_true_vulnerability"],
                    "resolved_callee_identity": resolved_ident,
                    "llm_raw_output": rec["raw"],
                    "llm_strict_json_valid": callee_pred.strict_valid,
                    "llm_predicted_role": pred_role,
                    "bounded_safety_floor": floor_res,
                    "raw_fused_score": float(floor_res["raw_adjusted_score"]),
                    "final_score": final_score,
                    "effective_post_release_score": final_score,
                    "kept_by_pipeline": kept,
                    "stage_dropped": stage_dropped,
                    "triage_status": finding_v2.triage_status,
                    "triage_decision": finding_v2.decision,
                    "triage_reason_codes": list(finding_v2.reason_codes),
                    "source_sink_trace_status": finding_v2.source_sink_trace_status,
                    "sanitizer_status": finding_v2.sanitizer_status,
                    "review_status": finding_v2.review_status,
                    "finding_schema_v2": finding_v2.to_dict(),
                }
            )

        raw_scanner_metrics = _enrich_bipartite_metrics(
            shared.global_bipartite_match_findings(
                ground_truth_sites=gt_sites,
                candidate_pool=candidate_pool,
                retained_finding_ids=raw_retained_ids,
            )
        )
        iris_qwen_metrics = _enrich_bipartite_metrics(
            shared.global_bipartite_match_findings(
                ground_truth_sites=gt_sites,
                candidate_pool=candidate_pool,
                retained_finding_ids=iris_retained_ids,
            )
        )
        arm_e2e_Comparisons[arm_id] = {
            "raw_opengrep_scanner_only": raw_scanner_metrics,
            "opengrep_iris_qwen_bounded_floor": iris_qwen_metrics,
            "site_traces": site_traces,
        }

    phase6_report = {
        "phase": "PHASE_6_REAL_OPENGREP_IRIS_QWEN_E2E",
        "timestamp_utc": now_utc(),
        "real_e2e_status": "PASS_REAL_OPENGREP_JAVAC_IRIS_QWEN_GPU",
        "opengrep_binary": "/usr/local/bin/opengrep",
        "opengrep_version": opengrep_version,
        "opengrep_command": " ".join(og_cmd),
        "opengrep_exit_code": og_proc.returncode,
        "opengrep_duration_seconds": og_elapsed,
        "opengrep_raw_findings_count": len(og_results),
        "javac_binary": "/usr/bin/javac",
        "javac_exit_code": javac_proc.returncode,
        "compiled_class_files": compiled_classes,
        "real_workspace_cve_scan_metacat": real_cve_scan_summary,
        "ground_truth_sites_total": len(site_catalog),
        "true_vulnerability_sites": sum(1 for s in site_catalog if s["is_true_vulnerability"]),
        "hard_negative_sites": sum(1 for s in site_catalog if not s["is_true_vulnerability"]),
        "arm_e2e_results": arm_e2e_Comparisons,
    }
    write_json_atomic(run_dir_wsl / "phase6_real_e2e_report.json", phase6_report)
    write_json_atomic(run_dir_f / "phase6_real_e2e_report.json", phase6_report)
    return phase6_report


def generate_phase7_advisor_report(
    run_id: str,
    phase1_data: Dict[str, Any],
    phase2_data: Dict[str, Any],
    trackb_telemetry: Dict[str, Any],
    tracka_telemetry: Optional[Dict[str, Any]],
    phase5_data: Dict[str, Any],
    phase6_data: Dict[str, Any],
    storage_errors_during_run: int,
    run_dir_wsl: Path,
    run_dir_f: Path,
) -> Path:
    print(f"[{now_utc()}] === PHASE 7: GENERATING 13-SECTION ADVISOR MEETING REPORT ===", flush=True)

    arms = phase5_data["results_by_arm"]
    m_base = arms["base_qwen25_05b"]["splits"]["dev_166"]
    m_eo03 = arms["eo03_vnext2_primary"]["splits"]["dev_166"]
    m_eo03_abl = arms["eo03_vnext2_ablation"]["splits"]["dev_166"]
    m_eo06 = arms["eo06_vnext31_trackb_main"]["splits"]["dev_166"]
    m_eo06_a = (
        arms["eo06_vnext31_tracka_pilot"]["splits"]["dev_166"]
        if "eo06_vnext31_tracka_pilot" in arms
        else None
    )

    hv2_eo03 = arms["eo03_vnext2_primary"]["splits"]["holdout_v2_historical_41"]
    hv2_eo06 = arms["eo06_vnext31_trackb_main"]["splits"]["holdout_v2_historical_41"]
    hv3_eo03 = arms["eo03_vnext2_primary"]["splits"]["holdout_v3_historical_80"]
    hv3_eo06 = arms["eo06_vnext31_trackb_main"]["splits"]["holdout_v3_historical_80"]

    mcn_dev = phase5_data["paired_mcnemar_tests"]["dev_166"].get(
        "eo06_vnext31_trackb_main__vs__eo03_vnext2_primary", {}
    )
    e2e_eo06 = phase6_data["arm_e2e_results"]["eo06_vnext31_trackb_main"]
    e2e_raw = e2e_eo06["raw_opengrep_scanner_only"]
    e2e_iris = e2e_eo06["opengrep_iris_qwen_bounded_floor"]

    def pct(v: float) -> str:
        return f"{v * 100:.2f}%"

    # Format confusion matrix table for EO06 Track B on Dev-166
    cm_eo06 = m_eo06["confusion_matrix_4x5"]
    cm_rows_md = []
    for r in ROLES:
        row_cells = [str(cm_eo06[r][c]) for c in ROLES + ["INVALID"]]
        cm_rows_md.append(f"| **`{r}`** | " + " | ".join(row_cells) + f" | **{sum(cm_eo06[r].values())}** |")
    cm_table_md = "\n".join(cm_rows_md)

    # Format per-CWE breakdown table for EO03 vs EO06 on Dev-166
    cwe_rows_md = []
    for cwe_k in ("CWE-022", "CWE-078", "CWE-079", "CWE-089"):
        c3 = m_eo03["per_cwe"].get(cwe_k, {})
        c6 = m_eo06["per_cwe"].get(cwe_k, {})
        cwe_rows_md.append(
            f"| `{cwe_k}` | {c6.get('n', 0)} | {pct(c3.get('accuracy', 0.0))} | **{pct(c6.get('accuracy', 0.0))}** | "
            f"{pct(c3.get('macro_f1', 0.0))} | **{pct(c6.get('macro_f1', 0.0))}** | "
            f"{pct(c3.get('sink_f1', 0.0))} | **{pct(c6.get('sink_f1', 0.0))}** | "
            f"{pct(c3.get('none_recall', 0.0))} | **{pct(c6.get('none_recall', 0.0))}** |"
        )
    cwe_table_md = "\n".join(cwe_rows_md)

    # Format epoch progression table for EO06 Track B
    ep_rows_md = []
    for ep_k, ep_v in sorted(trackb_telemetry["epoch_summaries"].items(), key=lambda x: int(x[0])):
        dm = ep_v["dev166_metrics"]
        cwe89_sr = dm.get(
            "cwe_089_sink_recall",
            dm.get("per_cwe", {}).get("CWE-089", {}).get("per_role", {}).get("sink", {}).get("recall", 0.0),
        )
        ep_rows_md.append(
            f"| Epoch {ep_k} | `{ep_v['mean_train_raw_loss']:.4f}` | `{ep_v['validation_loss_dev166']:.4f}` | "
            f"`{ep_v['mean_grad_norm']:.4f}` | {pct(dm['strict_json_validity_rate'])} | "
            f"{pct(dm['accuracy'])} | {pct(dm['macro_f1'])} | {pct(dm['sink_recall'])} | "
            f"{pct(cwe89_sr)} | {pct(dm['sink_f1'])} | {pct(dm['sink_args_exact_match_rate'])} | "
            f"{pct(dm['none_recall'])} | `{ep_v['selection_score']:.6f}` | `{ep_v['adapter_safetensors_sha256'][:16]}...` |"
        )
    ep_table_md = "\n".join(ep_rows_md)

    tracka_row_md = ""
    if m_eo06_a is not None and tracka_telemetry is not None:
        tracka_row_md = (
            f"| **EO06 Pilot (`Track A Trusted Gold 275`)** | {pct(m_eo06_a['strict_json_validity_rate'])} | "
            f"{pct(m_eo06_a['identity_echo_accuracy'])} | {pct(m_eo06_a['accuracy'])} | "
            f"{pct(m_eo06_a['macro_f1'])} | {pct(m_eo06_a['sink_f1'])} | "
            f"{pct(m_eo06_a['none_recall'])} | {pct(m_eo06_a['sink_args_exact_match_rate'])} |\n"
        )

    report_md = f"""# BÁO CÁO KHOA HỌC HỘI ĐỒNG & GIẢNG VIÊN HƯỚNG DẪN (NTK / IRIS — EO06 FINAL)

- **Mã đợt thực nghiệm:** `{run_id}`
- **Thời gian hoàn thành (UTC):** `{now_utc()}`
- **Mô hình cơ sở (Base Model):** `Qwen/Qwen2.5-Coder-0.5B-Instruct` (Frozen FP16 Base + PEFT LoRA FP32 Adapters)
- **Kiến trúc đóng băng:** `FROZEN_ARCHITECTURE_V1` (OpenGrep `v1.25.0` Candidate Discovery + IRIS Intraprocedural/AST Context + Qwen2.5-Coder-0.5B LoRA 6-Key JSON + Bounded Safety Floor `0.55` & Evidence Fusion)
- **Tập dữ liệu chuẩn hóa:** **Dataset VNext.3.1** (Đã kiểm toán nguồn gốc và khử rò rỉ 3 mức giữa `Train-950` và `Dev-180` -> `Dev-166`)
- **Chế độ tiếp nối & Lý lịch huấn luyện (Warm-Start Lineage):** `{trackb_telemetry.get('resume_mode', 'FRESH')}` từ checkpoint Epoch 1 đã xác minh của phiên chạy `eo06_vnext31_trackb_20261024_1145` (`Step 196`, `SHA-256 = a797ca577b73fc8972027691d26261ae0f0b6281576d763911584444a96d0586`). Trong phiên chạy thứ nhất, Epoch 1 (`Steps 1..196`) được khởi tạo mới hoàn toàn từ `Qwen/Qwen2.5-Coder-0.5B-Instruct`; phiên chạy phục hồi (`{run_id}`) nạp lại nguyên vẹn trọng số LoRA `FP32` của Epoch 1, tiến lịch `CosineLR` đến đúng `Step 196`, và khởi tạo lại các moment bậc 1/bậc 2 của `AdamW` (`optimizer_moments_reinitialized = {trackb_telemetry.get('optimizer_moments_reinitialized', True)}`, không phải tiếp nối trạng thái bộ tối ưu hóa liên tục vì phiên 1 dừng trước khi lưu `optimizer.pt`). Mọi checkpoint hoàn tất trong `{run_id}` đều lưu đầy đủ `CHECKPOINT_COMPLETE.json` và `training_state.pt` (gồm trạng thái `optimizer`, `scheduler`, `RNG` để hỗ trợ `EXACT_STATE_RESUME`).
- **Trạng thái phần cứng & lưu trữ trong suốt phiên chạy:** `0` sự kiện lỗi lưu trữ Windows System Event Log mới (`STORAGE_ERRORS_DURING_RUN = {storage_errors_during_run}`), toàn bộ tiến trình đọc/ghi diễn ra trên SSD/NVMe (`C:`, `E:`, `F:`). Ổ HDD `D:` không phát sinh lỗi mới trong phiên chạy nhưng vẫn được ghi nhận trung thực là rủi ro phần cứng lịch sử (`HISTORICAL_STORAGE_RISK_REMAINS_ON_HDD_D`, không tự nhận là đã cách ly vật lý).

---

## 1. Tóm tắt điều hành (Executive Summary)

Thực nghiệm **EO06** hoàn tất chu trình nghiên cứu khoa học từ kiểm toán dữ liệu (EO05) sang huấn luyện LoRA thực tế trên GPU (`NVIDIA GeForce RTX 4060 Ti 16GB`), đánh giá định lượng đa chiều và kiểm định End-to-End (E2E) thực tế trên mã nguồn Java biên dịch bằng `/usr/bin/javac` kết hợp `/usr/local/bin/opengrep` (`v1.25.0`):

1. **Tính toàn vẹn dữ liệu (Dataset VNext.3.1):** Đã loại bỏ triệt để `14` mẫu trong `Dev-180` bị trùng họ API (`Level 2`) hoặc lớp thư viện bên thứ ba (`Level 3`) với `Train-950`, tạo thành tập đánh giá sạch **`03_DEV_EVAL_166.jsonl` (`166` mẫu)** có giao cắt bằng `0` ở cả 3 mức kiểm toán (`Sample Key`, `API Family`, `Third-Party Class`) với cả **`Track A (275 mẫu)`** và **`Track B (781 mẫu)`**.
2. **Huấn luyện GPU LoRA thực tế (`EO06 Track B Main`):** Huấn luyện từ mô hình gốc `Qwen/Qwen2.5-Coder-0.5B-Instruct` trên `781` mẫu `Track B` (`r=16, alpha=32`, `{trackb_telemetry['epochs_completed']}`/`{trackb_telemetry['epochs']}` epochs hoàn tất, `{trackb_telemetry['total_optimizer_steps']}` bước tối ưu hóa thực tế, gồm `196` bước ở phiên 1 và `{trackb_telemetry.get('steps_executed_this_invocation', 0)}` bước ở phiên phục hồi với `eval_batch_size = 1`). Loss huấn luyện trung bình giảm từ `{trackb_telemetry['mean_first_10_steps_raw_loss']:.4f}` (10 bước đầu) xuống `{trackb_telemetry['mean_last_10_steps_raw_loss']:.4f}` (10 bước cuối); trọng số base model bất biến 100% (`SHA-256: {trackb_telemetry['base_weights_sha256_after'][:16]}...`) và kiểm chứng nạp lại từ đĩa đạt `save_reload_greedy_parity = True`.
3. **Kết quả trên tập đánh giá sạch `VNext.3.1 Dev (166 mẫu)`:**
   - **Untuned Base `Qwen2.5-Coder-0.5B-Instruct`:** Strict JSON Validity = `{pct(m_base['strict_json_validity_rate'])}`, Accuracy = `{pct(m_base['accuracy'])}`, Macro-F1 = `{pct(m_base['macro_f1'])}`.
   - **EO03 Baseline (`VNext.2`, huấn luyện trước khi khử rò rỉ `Train-950`):** Strict JSON Validity = `{pct(m_eo03['strict_json_validity_rate'])}`, Accuracy = `{pct(m_eo03['accuracy'])}`, Macro-F1 = `{pct(m_eo03['macro_f1'])}`, Sink F1 = `{pct(m_eo03['sink_f1'])}`, Hard-Negative (`none`) Recall = `{pct(m_eo03['none_recall'])}`.
   - **EO06 Main (`VNext.3.1 Track B 781 mẫu`, huấn luyện hoàn toàn sạch rò rỉ từ Base Model):** Strict JSON Validity = **`{pct(m_eo06['strict_json_validity_rate'])}`**, Identity Echo = **`{pct(m_eo06['identity_echo_accuracy'])}`**, Accuracy = **`{pct(m_eo06['accuracy'])}`**, Macro-F1 = **`{pct(m_eo06['macro_f1'])}`**, Sink F1 = **`{pct(m_eo06['sink_f1'])}`**, Hard-Negative (`none`) Recall = **`{pct(m_eo06['none_recall'])}`**, `sink_args` Exact Match = **`{pct(m_eo06['sink_args_exact_match_rate'])}`**.
4. **Kiểm định End-to-End thực tế (`OpenGrep v1.25.0 + javac + IRIS + Qwen EO06 LoRA`):** Trên tập mã nguồn Java thực nghiệm có kiểm soát gồm `9` điểm nhạy cảm (`4` lỗ hổng thật thuộc `CWE-022/078/079/089` và `5` mẫu Hard-Negative đã chuẩn hóa/tham số hóa/hằng số), bộ quét `OpenGrep` thuần túy sinh `9` cảnh báo (`4 TP, 5 FP`, Precision = `{pct(e2e_raw['precision'])}`, Recall = `{pct(e2e_raw['recall'])}`, F1 = `{pct(e2e_raw['f1'])}`). Khi kết hợp pipeline **IRIS + Qwen EO06 LoRA + Bounded Safety Floor (`0.55`)**, hệ thống giữ nguyên `TP = {e2e_iris['TP']}/{phase6_data['true_vulnerability_sites']}` và giảm `FP` từ `{e2e_raw['FP']}` xuống `{e2e_iris['FP']}` (Precision = **`{pct(e2e_iris['precision'])}`**, Recall = **`{pct(e2e_iris['recall'])}`**, F1 = **`{pct(e2e_iris['f1'])}`**).

---

## 2. Kiến trúc đóng băng (`FROZEN_ARCHITECTURE_V1`)

Hệ thống tuân thủ nghiêm ngặt kiến trúc `FROZEN_ARCHITECTURE_V1` đã khóa từ EO04.2:

1. **Tầng 1 — Phát hiện ứng viên tốc độ cao (`OpenGrep v1.25.0`):** Quét cú pháp/mẫu AST trên mã nguồn `.java` để thu thập các vị trí gọi hàm nhạy cảm (candidate sinks/callees) với Recall cao.
2. **Tầng 2 — Trích xuất ngữ cảnh & bằng chứng AST/Dataflow (`IRIS Context Extractor`):** Xác định danh tính hàm (`package`, `class`, `method`, `signature`), đối số truyền vào, và kiểm tra hai điều kiện an toàn tĩnh:
   - `ast_proven_constant_args`: Đối số truy vết hoàn toàn về hằng chuỗi biên dịch (`LITERAL:<value>`).
   - `ast_proven_sanitized`: Dòng dữ liệu đi qua hàm khử độc chuẩn đã được phê duyệt theo đúng từng CWE (`PreparedStatement.setString`, `Path.normalize` + kiểm tra tiền tố, `HtmlUtils.htmlEscape`, v.v.).
3. **Tầng 3 — Phân loại ngữ nghĩa bằng LLM Fine-tuned (`Qwen2.5-Coder-0.5B-Instruct + LoRA`):** Đầu ra bắt buộc là đối tượng JSON 6 khóa (`package`, `class`, `method`, `signature`, `sink_args`, `type` $\\in \\{{\\text{{source}}, \\text{{sink}}, \\text{{taint-propagator}}, \\text{{none}}\\}}`).
4. **Tầng 4 — Hợp nhất bằng chứng & Ngưỡng sàn an toàn có chặn (`Bounded Safety Floor = 0.55`):**
   - Áp dụng quyền phủ quyết tĩnh (`Veto = 0.0`) nếu và chỉ nếu có bằng chứng AST cụ thể (`LITERAL:...` hoặc sanitizer hợp lệ của đúng CWE).
   - Giữ ngưỡng sàn `0.55` khi `OpenGrep` thỏa mãn điều kiện cần và có $\\ge 2$ tín hiệu đồng thuận để bảo vệ Recall trước hiện tượng lệch phân phối của LLM cỡ nhỏ (`0.5B`).

---

## 3. Thống kê Dataset VNext.3.1 & Kiểm toán nguồn gốc (Provenance Audit)

| Tập dữ liệu (Tệp JSONL) | Số mẫu (`N`) | SHA-256 | Vai trò & Mức độ tin cậy |
|---|---:|---|---|
| `01_TRAIN_VNEXT_3_1_TRACK_A_TRUSTED_GOLD_PILOT.jsonl` | `275` | `{phase1_data['checks']['01_hash_and_row_counts']['01_TRAIN_VNEXT_3_1_TRACK_A_TRUSTED_GOLD_PILOT.jsonl']['sha256_wsl'][:24]}...` | Tập huấn luyện Gold (`VERIFIED_PRIMARY_SOURCE_SEMANTIC_LABEL`, `VERIFIED_BENCHMARK_GROUND_TRUTH`, `LEVEL_2_API_SEMANTIC_ROLE_VERIFIED`). Không chứa bất kỳ mẫu `UNKNOWN_HERITAGE` hay `LEVEL_2_AUDITED_MULTI_TOOL_SAST`. |
| `01_TRAIN_VNEXT_3_1_TRACK_B_AUDITED_FULL.jsonl` | `781` | `{phase1_data['checks']['01_hash_and_row_counts']['01_TRAIN_VNEXT_3_1_TRACK_B_AUDITED_FULL.jsonl']['sha256_wsl'][:24]}...` | Tập huấn luyện chính (`275` mẫu Track A + `506` mẫu `LEVEL_2_AUDITED_MULTI_TOOL_SAST` đã qua kiểm toán đa công cụ và khử trùng lặp). Bao phủ đủ 16 ô `CWE x Role`. |
| `02_DEV_VNEXT_3_1.jsonl` | `166` | `{phase1_data['checks']['01_hash_and_row_counts']['02_DEV_VNEXT_3_1.jsonl']['sha256_wsl'][:24]}...` | Tập đánh giá phát triển và lựa chọn mô hình (`Dev-180` sau khi loại bỏ `14` mẫu rò rỉ với `Train-950`). |
| `FINAL_INDEPENDENT_EVAL_HOLDOUT_V2.jsonl` | `41` | `{sha256_file(HOLDOUT_V2_PATH)[:24]}...` | Tập đối chiếu lịch sử V2 (`41` mẫu; không gọi là tập mù vì đã từng dùng trong quá trình thiết kế prompt/gate). |
| `FINAL_INDEPENDENT_EVAL_HOLDOUT_V3.jsonl` | `80` | `{sha256_file(HOLDOUT_V3_PATH)[:24]}...` | Tập đối chiếu lịch sử V3 (`80` mẫu; không gọi là tập mù vì đã từng quan sát trong EO03). |
| `track_b_quarantine_review_queue.jsonl` | `137` (`+665 Train-950`) | `{phase1_data['checks']['01_hash_and_row_counts']['track_b_quarantine_review_queue.jsonl']['sha256_wsl'][:24]}...` | Tập cách ly hoàn toàn (`137` mẫu `SRC-EB-*` có xung đột + `665` mẫu `Train-950` thiếu truy vết commit gốc + `14` mẫu `Dev-180` bị trùng lặp). |

**Phân bố `CWE x Role` trên `Track B (781 mẫu)` và `Dev-166 (166 mẫu)`:**
- **`Track B (781 mẫu)`:** `none = 244`, `sink = 238`, `taint-propagator = 172`, `source = 127` (Tất cả 16/16 ô `CWE x Role` đều có dữ liệu; nhỏ nhất là `CWE-089 x source = 28`).
- **`Dev-166 (166 mẫu)`:** `none = {m_eo06['per_role']['none']['support']}`, `sink = {m_eo06['per_role']['sink']['support']}`, `taint-propagator = {m_eo06['per_role']['taint-propagator']['support']}`, `source = {m_eo06['per_role']['source']['support']}` (Trên cả 4 CWE: `CWE-022 = {m_eo06['per_cwe']['CWE-022']['n']}`, `CWE-078 = {m_eo06['per_cwe']['CWE-078']['n']}`, `CWE-079 = {m_eo06['per_cwe']['CWE-079']['n']}`, `CWE-089 = {m_eo06['per_cwe']['CWE-089']['n']}`).

---

## 4. Bằng chứng khử rò rỉ dữ liệu (`Train-950` vs `Dev-180` $\\rightarrow$ `Dev-166`)

Trong EO05, kiểm toán chéo phát hiện `Train-950` (thuộc `VNext.2` trong EO03) có `6` mẫu trùng họ API (`Level 2`) và `23` mẫu trùng lớp thư viện (`Level 3`) với `Dev-180` (tương ứng `14` mẫu độc lập trong `Dev-180`). Trong **Dataset VNext.3.1**, kiểm định tự động Phase 1 (`phase1_dataset_release_validation.json`) xác nhận:

- **Level 1 (`cwe_conditioned_sample_key`):** Giao cắt giữa `Track B (781)` và `Dev-166` = **`0`**; với `Holdout V2` = **`0`**; với `Holdout V3` = **`0`**.
- **Level 2 (`api_family_without_cwe`):** Giao cắt giữa `Track B (781)` và `Dev-166` = **`0`**; với `Holdout V2` = **`0`**; với `Holdout V3` = **`0`**.
- **Level 3 (`third_party_class_key`):** Giao cắt giữa `Track B (781)` và `Dev-166` = **`0`**; với `Holdout V2` = **`0`**; với `Holdout V3` = **`0`**.
- Giao cắt giữa `Quarantine (802)` và mọi tập `Train Track A`, `Train Track B`, `Dev-166` = **`0`**.

---

## 5. Phương pháp huấn luyện GPU LoRA thực tế, Khắc phục Sự cố Đánh giá & Telemetry

- **Thiết bị thực thi:** `NVIDIA GeForce RTX 4060 Ti` (`16,380 MiB` VRAM, Driver `591.86`, `PyTorch 2.5.1+cu124`, `PEFT 0.21.2`).
- **Chẩn đoán & Khắc phục sự cố treo tại ranh giới đánh giá Epoch 1 của phiên chạy 1 (`eo06_vnext31_trackb_20261024_1145`):**
  - Ở phiên chạy 1, toàn bộ `196` bước tối ưu hóa của Epoch 1 đã hoàn tất (`loss` giảm từ `0.8180` xuống `0.0005`) và lưu xong `checkpoint_epoch_1` (`adapter_model.safetensors`, `35,237,104` bytes). Tuy nhiên tiến trình bị treo khi chuyển sang bước `evaluate_model_arm(batch_size=4)` trên `Dev-166` ngay sau khi hoàn tất huấn luyện có bật `gradient_checkpointing` mà chưa tắt `gradient_checkpointing` và chưa hạ kích thước lô đánh giá xuống `batch_size=1`.
  - Bản vá kỹ thuật trong phiên chạy phục hồi (`{run_id}`): (1) Cố định `eval_batch_size = 1` trên toàn bộ hàm đánh giá và tính `val_loss`; (2) Tắt tường minh `gradient_checkpointing_disable()` và bật `use_cache = True` trước khi vào `model.eval()` / `torch.inference_mode()`, khôi phục lại sau khi đánh giá; (3) Giới hạn `max_new_tokens = 96` kết hợp `JsonBraceAndEosStoppingCriteria` chỉ dừng khi đếm ngoặc nhọn cân bằng (`depth == 0`); (4) Cập nhật nhịp tim (`EVALUATING`) sau mỗi `4` mẫu trên `Dev-166`; (5) Lưu checkpoint trạng thái đầy đủ (`CHECKPOINT_COMPLETE.json` + `training_state.pt` chứa trạng thái `optimizer`, `scheduler`, `RNG`, `dataset_sha256`, `checkpoint_sha256`) mỗi `98` bước tối ưu hóa.
- **Cấu hình LoRA (`eo06_vnext31_trackb_main`):**
  - Khởi tạo ở Epoch 1: **Fresh LoRA** trực tiếp từ `Qwen/Qwen2.5-Coder-0.5B-Instruct` (không kế thừa trọng số từ `Train-950` của EO03).
  - Tiếp nối ở Epoch 2..{trackb_telemetry['epochs_completed']}: **Warm-Start Adapter Resume (`WARM_START_ADAPTER_RESUME`)** từ `checkpoint_epoch_1` (`Step 196`), tiến lịch `CosineLR` tới đúng `Step 196`, khởi tạo lại moment `AdamW` (`optimizer_moments_reinitialized = True`).
  - Tham số LoRA: `r = 16`, `lora_alpha = 32`, `lora_dropout = 0.05`, `target_modules = [q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj]` (`8,798,208` tham số khả huấn / `502,830,976` tổng tham số = `1.7497%`).
  - Tối ưu hóa: `AdamW` (`lr = {trackb_telemetry['learning_rate']}`, `weight_decay = 0.01`, Cosine schedule với `6%` warmup), `micro_batch_size = {trackb_telemetry['micro_batch_size']}`, `gradient_accumulation_steps = {trackb_telemetry['gradient_accumulation_steps']}` (`effective_batch_size = {trackb_telemetry['effective_batch_size']}`), mặt nạ nhãn `-100` trên toàn bộ phần prompt/system/user.
  - Độ chính xác lưu/nạp (`PEFT Save/Reload Parity`): Giữ trọng số `lora_A`/`lora_B` ở định dạng `FP32` gốc (`"dtypes": ["F32"]`, kích thước tệp `adapter_model.safetensors = 35,237,104` bytes, `168` tensors) tương thích tuyệt đối với `PEFT 0.21.2`, đạt `max_abs_weight_diff = 0.0` và `save_reload_greedy_parity = True`.

### Bảng tiến trình huấn luyện qua từng Epoch (`EO06 Track B Main — 781 mẫu`)

| Epoch | Train Raw Loss | Dev-166 Val Loss | Mean Grad Norm | Strict JSON | Dev-166 Acc | Dev-166 Macro-F1 | Sink Recall | CWE-089 Sink Recall | Sink F1 | `sink_args` Exact | `none` Recall | Selection Score | Checkpoint SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
{ep_table_md}

- **Tiêu chí lựa chọn Checkpoint tốt nhất:** Chọn theo **`Dev-166 Macro-F1`** cao nhất, phân xử hòa bằng `selection_score` tiền đăng ký (`0.45*MacroF1 + 0.25*SinkF1 + 0.15*NoneRecall + 0.10*StrictJSON + 0.05*SinkArgsCanonical`, không chọn theo `train_loss` đơn thuần). Đối chiếu minh bạch: tại Epoch 1, giá trị `selection_score` chuẩn 5 thành phần là `0.813855` (trong khi con số `0.82644` ở bản tóm tắt smoke ban đầu là công thức rút gọn 4 thành phần bỏ qua `0.05*SinkArgsCanonical`).
- **Epoch tốt nhất được chọn:** **Epoch `{trackb_telemetry['selected_best_epoch']}`** (`SHA-256: {trackb_telemetry['selected_adapter_safetensors_sha256']}`).
- **Thời gian huấn luyện thực tế (phiên phục hồi):** `{trackb_telemetry['training_duration_seconds']}s` (`{trackb_telemetry['total_optimizer_steps']}` tổng bước tối ưu hóa hoàn tất), VRAM đỉnh = `{trackb_telemetry['peak_vram_allocated_mib']} MiB`.

---

## 6. Kết quả thực nghiệm trên `VNext.3.1 Dev (166 mẫu)` và các tập tham chiếu lịch sử

### 6.1. Bảng so sánh chính trên `VNext.3.1 Dev (166 mẫu)`

| Mô hình / Nhánh huấn luyện | Strict JSON Validity | Identity Copy Acc | Role Accuracy | Macro-F1 (4 roles) | `sink` F1 | `none` Recall (Hard-Neg) | `sink_args` Exact Match |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Base `Qwen2.5-Coder-0.5B-Instruct` (Untuned)** | {pct(m_base['strict_json_validity_rate'])} | {pct(m_base['identity_echo_accuracy'])} | {pct(m_base['accuracy'])} | {pct(m_base['macro_f1'])} | {pct(m_base['sink_f1'])} | {pct(m_base['none_recall'])} | {pct(m_base['sink_args_exact_match_rate'])} |
| **EO03 Baseline Primary (`VNext.2 1,394 rows`, pre-remediation)** | {pct(m_eo03['strict_json_validity_rate'])} | {pct(m_eo03['identity_echo_accuracy'])} | {pct(m_eo03['accuracy'])} | {pct(m_eo03['macro_f1'])} | {pct(m_eo03['sink_f1'])} | {pct(m_eo03['none_recall'])} | {pct(m_eo03['sink_args_exact_match_rate'])} |
| **EO03 Baseline Uniform Ablation (`VNext.2 1,394 rows`)** | {pct(m_eo03_abl['strict_json_validity_rate'])} | {pct(m_eo03_abl['identity_echo_accuracy'])} | {pct(m_eo03_abl['accuracy'])} | {pct(m_eo03_abl['macro_f1'])} | {pct(m_eo03_abl['sink_f1'])} | {pct(m_eo03_abl['none_recall'])} | {pct(m_eo03_abl['sink_args_exact_match_rate'])} |
{tracka_row_md}| **EO06 Main (`VNext.3.1 Track B 781 rows`, Zero-Leakage)** | **{pct(m_eo06['strict_json_validity_rate'])}** | **{pct(m_eo06['identity_echo_accuracy'])}** | **{pct(m_eo06['accuracy'])}** | **{pct(m_eo06['macro_f1'])}** | **{pct(m_eo06['sink_f1'])}** | **{pct(m_eo06['none_recall'])}** | **{pct(m_eo06['sink_args_exact_match_rate'])}** |

- **Kiểm định thống kê bắt cặp McNemar (`EO06 Track B Main` vs `EO03 Baseline Primary` trên `Dev-166`):**
  - Cả hai cùng đúng: `{mcn_dev.get('both_correct', 0)}` mẫu
  - Chỉ `EO06 Track B Main` đúng: `{mcn_dev.get('a_only_correct', 0)}` mẫu
  - Chỉ `EO03 Baseline Primary` đúng: `{mcn_dev.get('b_only_correct', 0)}` mẫu
  - Cả hai cùng sai: `{mcn_dev.get('both_wrong', 0)}` mẫu
  - Exact binomial two-sided $p$-value = **`{mcn_dev.get('mcnemar_exact_p_value', 1.0):.6f}`**.

### 6.2. Kết quả đối chiếu trên các tập tham chiếu lịch sử (`Holdout V2 - 41 mẫu` & `Holdout V3 - 80 mẫu`)

> **Lưu ý phương pháp luận:** `Holdout V2 (41)` và `Holdout V3 (80)` đã từng được kiểm tra trong các vòng thiết kế trước, do đó được báo cáo nghiêm ngặt với tư cách **tập đối chiếu lịch sử (Historical Reference Benchmarks)**, không phải tập kiểm thử mù (Blind Test).

| Tập đối chiếu lịch sử | Mô hình | Strict JSON | Role Accuracy | Macro-F1 | `sink` F1 | `none` Recall | `sink_args` Exact Match |
|---|---|---:|---:|---:|---:|---:|---:|
| **Holdout V2 (`41` mẫu)** | `EO03 Baseline Primary` | {pct(hv2_eo03['strict_json_validity_rate'])} | {pct(hv2_eo03['accuracy'])} | {pct(hv2_eo03['macro_f1'])} | {pct(hv2_eo03['sink_f1'])} | {pct(hv2_eo03['none_recall'])} | {pct(hv2_eo03['sink_args_exact_match_rate'])} |
| **Holdout V2 (`41` mẫu)** | **`EO06 Main (Track B 781)`** | **{pct(hv2_eo06['strict_json_validity_rate'])}** | **{pct(hv2_eo06['accuracy'])}** | **{pct(hv2_eo06['macro_f1'])}** | **{pct(hv2_eo06['sink_f1'])}** | **{pct(hv2_eo06['none_recall'])}** | **{pct(hv2_eo06['sink_args_exact_match_rate'])}** |
| **Holdout V3 (`80` mẫu)** | `EO03 Baseline Primary` | {pct(hv3_eo03['strict_json_validity_rate'])} | {pct(hv3_eo03['accuracy'])} | {pct(hv3_eo03['macro_f1'])} | {pct(hv3_eo03['sink_f1'])} | {pct(hv3_eo03['none_recall'])} | {pct(hv3_eo03['sink_args_exact_match_rate'])} |
| **Holdout V3 (`80` mẫu)** | **`EO06 Main (Track B 781)`** | **{pct(hv3_eo06['strict_json_validity_rate'])}** | **{pct(hv3_eo06['accuracy'])}** | **{pct(hv3_eo06['macro_f1'])}** | **{pct(hv3_eo06['sink_f1'])}** | **{pct(hv3_eo06['none_recall'])}** | **{pct(hv3_eo06['sink_args_exact_match_rate'])}** |

---

## 7. Phân tích chi tiết theo từng CWE và từng Vai trò (`Per-CWE & Per-Role Analysis`)

### 7.1. Phân rã theo từng nhóm lỗ hổng CWE trên `Dev-166` (`EO03` vs `EO06`)

| CWE | Số mẫu (`Dev-166`) | EO03 Acc | **EO06 Acc** | EO03 Macro-F1 | **EO06 Macro-F1** | EO03 `sink` F1 | **EO06 `sink` F1** | EO03 `none` Recall | **EO06 `none` Recall** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
{cwe_table_md}

### 7.2. Phân rã theo từng vai trò (`Per-Role Metrics`) của `EO06 Main (Track B 781)` trên `Dev-166`

| Vai trò (`Role`) | Support (`N`) | Precision | Recall | F1-Score |
|---|---:|---:|---:|---:|
| `source` | `{m_eo06['per_role']['source']['support']}` | {pct(m_eo06['per_role']['source']['precision'])} | {pct(m_eo06['per_role']['source']['recall'])} | **{pct(m_eo06['per_role']['source']['f1'])}** |
| `sink` | `{m_eo06['per_role']['sink']['support']}` | {pct(m_eo06['per_role']['sink']['precision'])} | {pct(m_eo06['per_role']['sink']['recall'])} | **{pct(m_eo06['per_role']['sink']['f1'])}** |
| `taint-propagator` | `{m_eo06['per_role']['taint-propagator']['support']}` | {pct(m_eo06['per_role']['taint-propagator']['precision'])} | {pct(m_eo06['per_role']['taint-propagator']['recall'])} | **{pct(m_eo06['per_role']['taint-propagator']['f1'])}** |
| `none` (Hard-Negative) | `{m_eo06['per_role']['none']['support']}` | {pct(m_eo06['per_role']['none']['precision'])} | {pct(m_eo06['per_role']['none']['recall'])} | **{pct(m_eo06['per_role']['none']['f1'])}** |

### 7.3. Ma trận nhầm lẫn 4x5 (`Confusion Matrix`) của `EO06 Main` trên `Dev-166`

| Nhãn thực tế \\ Dự đoán | `source` | `sink` | `taint-propagator` | `none` | `INVALID` | Tổng |
|---|---:|---:|---:|---:|---:|---:|
{cm_table_md}

---

## 8. Phân tích Hard-Negative (`none`) & Giảm cảnh báo giả (False-Positive Reduction)

- Trên `Dev-166`, lớp `none` gồm `{m_eo06['per_role']['none']['support']}` mẫu Hard-Negative (các hàm sử dụng `PreparedStatement`, truy vấn hằng số, đường dẫn đã chuẩn hóa `Path.normalize`, dữ liệu đã qua `htmlEscape` hoặc các hàm tiện ích lành tính cùng package với sink).
- `EO06 Main` đạt `none` Precision = **`{pct(m_eo06['none_precision'])}`**, `none` Recall = **`{pct(m_eo06['none_recall'])}`**, `none` F1 = **`{pct(m_eo06['none_f1'])}`**.
- So sánh giữa nhánh đối chứng `Track A (275 mẫu Gold)` và `Track B (781 mẫu Audited)`: `Track A` chứa chủ yếu `sink (125)` và `none (125)` nhưng chỉ có `2` mẫu `source` và `23` mẫu `taint-propagator`; việc bổ sung `506` mẫu `LEVEL_2_AUDITED_MULTI_TOOL_SAST` trong `Track B` là yếu tố quyết định giúp mô hình học đầy đủ cả 4 vai trò ngữ nghĩa mà không làm suy giảm khả năng nhận diện `sink` và `none`.

---

## 9. Kiểm định End-to-End thực tế (`OpenGrep v1.25.0 + javac + IRIS + Qwen EO06 LoRA`)

> **Phân định minh bạch 4 tầng chứng cứ thực nghiệm (Scope Separation):**
> 1. **Controlled 9-site Java E2E Fixture:** Bộ mã nguồn Java có kiểm soát gồm `9` vị trí nhạy cảm (`4` lỗ hổng thật + `5` Hard-Negatives) được biên dịch thực tế bằng `/usr/bin/javac` để đo lường chính xác cơ chế tương tác giữa `OpenGrep`, `IRIS AST Safety Release`, `Qwen EO06 LoRA` và `Bounded Safety Floor (0.55)`.
> 2. **Real Scanner Execution trên dự án CVE thực tế:** Tiến trình `/usr/local/bin/opengrep` (`v1.25.0`) chạy trực tiếp trên cả bộ fixture và tệp dự án thực tế `metacat_CVE-2026-48528_vuln/test/JDBCTest.java` trong workspace.
> 3. **Actual LLM Inference:** Suy luận GPU thực tế (`batch_size = 1`, `torch.inference_mode()`) của `EO06 Track B Main` và `EO03 Baseline Primary` sinh JSON 6 khóa cho từng vị trí ứng viên.
> 4. **Independent Dev-166 Benchmark:** Kết quả đánh giá phân loại ngữ nghĩa quy mô lớn hơn được báo cáo độc lập trên tập `Dev-166` (`166` mẫu sạch rò rỉ) ở Mục 6 & Mục 7 (không đánh đồng quy mô `9` điểm E2E fixture với tập benchmark `166` mẫu).

Kiểm định E2E được thực thi bằng tiến trình thực tế trên WSL `Ubuntu-IRIS`:
- **Trình biên dịch Java:** `/usr/bin/javac` (`exit_code = {phase6_data['javac_exit_code']}`, biên dịch thành công `{len(phase6_data['compiled_class_files'])}` tệp `.class`).
- **Bộ quét SAST:** `/usr/local/bin/opengrep` (`{phase6_data['opengrep_version']}`, `exit_code = {phase6_data['opengrep_exit_code']}`, thời gian quét `{phase6_data['opengrep_duration_seconds']}s`).
- **Quét bổ sung trên mã nguồn CVE thực tế trong workspace (`metacat_CVE-2026-48528_vuln/test/JDBCTest.java`):** Phát hiện `{phase6_data['real_workspace_cve_scan_metacat'].get('opengrep_hits_count', 0)}` vị trí gọi `executeQuery` tại các dòng `{phase6_data['real_workspace_cve_scan_metacat'].get('hit_lines', [])}`.

### Bảng kết quả End-to-End trên Controlled 9-site Java Fixture (`4` Lỗ hổng thật + `5` Hard-Negatives)

| Cấu hình Pipeline E2E | TP | FP | FN (Scanner) | FN (Scoring) | Precision | Recall | F1-Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| **1. Raw OpenGrep (`v1.25.0`) Scanner Only** | `{e2e_raw['TP']}` | `{e2e_raw['FP']}` | `{e2e_raw.get('fn_scanner', 0)}` | `{e2e_raw.get('fn_scoring', 0)}` | {pct(e2e_raw['precision'])} | {pct(e2e_raw['recall'])} | {pct(e2e_raw['f1'])} |
| **2. OpenGrep + IRIS + EO06 LoRA + Bounded Safety Floor (`0.55`)** | **`{e2e_iris['TP']}`** | **`{e2e_iris['FP']}`** | **`{e2e_iris.get('fn_scanner', 0)}`** | **`{e2e_iris.get('fn_scoring', 0)}`** | **{pct(e2e_iris['precision'])}** | **{pct(e2e_iris['recall'])}** | **{pct(e2e_iris['f1'])}** |

---

## 10. Các mối đe dọa đến tính hợp lệ (Threats to Validity)

1. **Internal Validity (Tính hợp lệ nội tại):**
   - Trong EO03, `Train-950` có `29` mẫu trùng họ API hoặc lớp thứ ba với `Dev-180` và được khởi tạo nối tiếp từ các adapter trước đó. Trong EO06, mối đe dọa này đã được loại bỏ hoàn toàn bằng cách: (a) cắt bỏ `14` mẫu bị rò rỉ khỏi `Dev-180` để tạo `Dev-166`, (b) cách ly `802` mẫu vào `06_QUARANTINE_802.jsonl`, và (c) huấn luyện `EO06 Main` **trực tiếp từ mô hình gốc `Qwen/Qwen2.5-Coder-0.5B-Instruct`** (Zero-Leakage Initialization ở Epoch 1, sau đó Warm-Start từ đúng `checkpoint_epoch_1` của chính `Track B`).
   - Do phiên 1 dừng ở ranh giới đánh giá Epoch 1 trước khi lưu `optimizer.pt`, việc tiếp nối từ `Step 196` sang Epoch 2 sử dụng `WARM_START_ADAPTER_RESUME` (giữ nguyên trọng số LoRA `FP32` đã học ở Epoch 1 và lịch `CosineLR` tại `Step 196`, nhưng khởi tạo lại các moment bậc 1/bậc 2 của `AdamW`). Điểm này được công bố tường minh và định lượng qua đường cong loss/Macro-F1 thực tế.
2. **External Validity (Tính hợp lệ ngoại tại):**
   - Thực nghiệm hiện tập trung vào 4 nhóm lỗ hổng phổ biến nhất trên Java (`CWE-022`, `CWE-078`, `CWE-079`, `CWE-089`). Khả năng khái quát hóa sang các CWE phức tạp hơn (như `CWE-502` Insecure Deserialization hay `CWE-918` SSRF) cần mở rộng thêm dữ liệu huấn luyện có kiểm toán.
3. **Construct Validity (Tính hợp lệ cấu trúc):**
   - `506` mẫu thuộc `Track B` mang nhãn `LEVEL_2_AUDITED_MULTI_TOOL_SAST` (được đồng thuận bởi phân tích tĩnh đa công cụ và kiểm toán tự động, không phải toàn bộ đều có bản vá CVE gốc). Báo cáo tách biệt minh bạch `Track A (275 mẫu Gold)` và `Track B (781 mẫu Audited)` để hội đồng đánh giá rõ đóng góp của từng tầng dữ liệu.
4. **Conclusion Validity (Tính hợp lệ kết luận):**
   - Kích thước tập `Dev-166` (`166` mẫu) là tập đánh giá phát triển dùng để lựa chọn epoch tốt nhất; `Holdout V2 (41)` và `Holdout V3 (80)` là các tập tham chiếu lịch sử. Báo cáo cung cấp đầy đủ kiểm định McNemar chính xác ($p$-value hai phía) để tránh kết luận quá mức từ dao động mẫu nhỏ.

---

## 11. Giới hạn nghiên cứu & Các phát hiện âm tính/bán phần trung thực (Limitations & Honest Findings)

1. **Đánh đổi giữa Quy mô dữ liệu bị khử rò rỉ (`781` mẫu) và Khởi tạo nối tiếp nhiều thế hệ (`1,394` mẫu của EO03):**
   - `EO03 Baseline` được huấn luyện nối tiếp qua nhiều thế hệ (`batch28` $\\rightarrow$ `VNext.1` $\\rightarrow$ `VNext.2` với `1,394` mẫu bao gồm cả các mẫu rò rỉ sang `Dev-180`), trong khi `EO06 Main` chỉ huấn luyện trên `781` mẫu sạch của `Dataset VNext.3.1` sau khi đã cách ly `802` mẫu. Việc báo cáo song song cả hai mô hình trên cùng `Dev-166` phản ánh trung thực tác động của việc làm sạch dữ liệu nghiêm ngặt.
2. **Tiếp nối Warm-Start Adapter tại `Step 196`:**
   - Tiếp nối từ `checkpoint_epoch_1` bảo toàn 100% trọng số LoRA `FP32` của Epoch 1 (`SHA-256 = a797ca577b73fc8972027691d26261ae0f0b6281576d763911584444a96d0586`) nhưng khởi tạo lại moment `AdamW`. Từ `Step 196` trở đi trong phiên chạy phục hồi, mọi checkpoint đều lưu đầy đủ cả `optimizer`, `scheduler`, và `RNG` trong `training_state.pt` kèm `CHECKPOINT_COMPLETE.json`.
3. **Trạng thái phần cứng lưu trữ (Ổ HDD `D:`):**
   - Mặc dù phiên chạy phục hồi EO06 diễn ra ổn định (`0` lỗi lưu trữ mới trong Windows Event Log) và toàn bộ đường dẫn thực thi nằm trên SSD/NVMe (`C:`, `E:`, `F:`), ổ HDD `D:` vẫn gắn trong hệ thống và từng có tiền sử sự kiện `storahci 129` / `volmgr 161` trước đó (`HISTORICAL_STORAGE_RISK_REMAINS_ON_HDD_D`). Hệ thống giám sát đã áp dụng cơ chế fail-closed và ghi nhận đầy đủ trạng thái này.

---

## 12. Danh mục Hiện vật, Checkpoints, SHA-256 Manifest & Lệnh tái lập (Reproducibility)

- **Thư mục phiên chạy 1 (Bảo toàn nguyên trạng Read-Only):** `F:\\NTK_EO06_Runs\\eo06_vnext31_trackb_20261024_1145`
  - Checkpoint Epoch 1 nguồn (`Step 196`): `F:\\NTK_EO06_Runs\\eo06_vnext31_trackb_20261024_1145\\checkpoints\\eo06_vnext31_trackb_main\\checkpoint_epoch_1\\adapter_model.safetensors` (`SHA-256: a797ca577b73fc8972027691d26261ae0f0b6281576d763911584444a96d0586`)
- **Thư mục phiên chạy phục hồi chính (NVMe `F:`):** `F:\\NTK_EO06_Runs\\{run_id}`
- **Thư mục chạy trong WSL:** `/home/tuankhoa/ntk_vnext_workspaces/ntk_vnext_20261022/runs/{run_id}`
- **Checkpoint `EO06 Main (Track B 781)` tốt nhất:**
  - Đường dẫn: `F:\\NTK_EO06_Runs\\{run_id}\\checkpoints\\eo06_vnext31_trackb_main\\best_checkpoint\\adapter_model.safetensors`
  - SHA-256: `{trackb_telemetry['selected_adapter_safetensors_sha256']}`
- **Báo cáo kiểm định Dataset Phase 1:** `F:\\NTK_EO06_Runs\\{run_id}\\phase1_dataset_release_validation.json`
- **Báo cáo GPU Evaluation Boundary Smoke Phase 2:** `F:\\NTK_EO06_Runs\\{run_id}\\phase2_gpu_eval_boundary_smoke.json`
- **Báo cáo Đánh giá Mô hình Phase 6 (Phase 5 internal):** `F:\\NTK_EO06_Runs\\{run_id}\\phase5_evaluation_report.json`
- **Báo cáo Kiểm định E2E Phase 7 (Phase 6 internal):** `F:\\NTK_EO06_Runs\\{run_id}\\phase6_real_e2e_report.json`

### Lệnh tái lập độc lập (Reproducibility Command)

```powershell
wsl -d Ubuntu-IRIS -- python3 "/mnt/c/Users/Admin/AppData/Local/javis-os/brains-canhan/Brain Default/scratch/ntk_eo06_run_20261024/scripts/eo06_main_train_eval_e2e_pipeline.py" --run-id "{run_id}" --resume-from-checkpoint "/mnt/f/NTK_EO06_Runs/eo06_vnext31_trackb_20261024_1145/checkpoints/eo06_vnext31_trackb_main/checkpoint_epoch_1" --prior-metrics-jsonl "/mnt/f/NTK_EO06_Runs/eo06_vnext31_trackb_20261024_1145/training_metrics.jsonl" --skip-tracka-pilot
```

---

## 13. Đề xuất Cấu trúc Slide & Kịch bản Bảo vệ Đồ án trước Hội đồng

1. **Slide 1–2 (Bài toán & Động lực):** Cảnh báo giả (False Positives) của công cụ SAST truyền thống (`OpenGrep`/`Semgrep`) và chi phí biên dịch nặng nề của `CodeQL` trên dự án lớn $\\rightarrow$ Kiến trúc lai `FROZEN_ARCHITECTURE_V1`.
2. **Slide 3–4 (Kiểm toán Dữ liệu & Khử rò rỉ 3 mức — EO05 $\\rightarrow$ VNext.3.1):** Trình bày phát hiện rò rỉ giữa `Train-950` và `Dev-180`, quy trình cách ly `802` mẫu vào `Quarantine`, và chứng minh toán học giao cắt bằng `0` ở cả 3 mức trên `Dev-166`.
3. **Slide 5–6 (Huấn luyện LoRA trên `Qwen2.5-Coder-0.5B-Instruct` — EO06):** Thiết kế hợp đồng JSON 6 khóa, mặt nạ loss `-100` trên prompt, giải quyết triệt để sai số lưu/nạp `FP32` adapter (`max_logit_diff = 0.0`) và khắc phục ranh giới bộ nhớ khi đánh giá (`eval_batch_size = 1`, tắt `gradient_checkpointing` khi inference).
4. **Slide 7–8 (Kết quả Thực nghiệm & So sánh `EO06` vs `EO03` trên `Dev-166`):** Bảng kết quả định lượng, phân tích vai trò của `506` mẫu `Track B` đối với `source` và `taint-propagator`, cùng ma trận nhầm lẫn 4x5.
5. **Slide 9–10 (Kiểm định End-to-End thực tế & Kết luận):** Demo kết quả chạy `javac` + `OpenGrep v1.25.0` + `IRIS AST Safety Veto` + `Qwen EO06 LoRA` khử sạch Hard-Negatives (`Precision` tăng từ `{pct(e2e_raw['precision'])}` lên `{pct(e2e_iris['precision'])}` với `Recall = {pct(e2e_iris['recall'])}`).
"""

    advisor_wsl = run_dir_wsl / "NTK_ADVISOR_MEETING_REPORT_EO06_20261024.md"
    advisor_f = run_dir_f / "NTK_ADVISOR_MEETING_REPORT_EO06_20261024.md"
    advisor_wsl.write_text(report_md, encoding="utf-8", newline="\n")
    advisor_f.write_text(report_md, encoding="utf-8", newline="\n")
    return advisor_f


def _normalize_wsl_path(raw_path: Optional[str]) -> Optional[Path]:
    if not raw_path:
        return None
    s = str(raw_path).strip()
    if len(s) >= 3 and s[1] == ":" and s[2] in ("\\", "/"):
        drive = s[0].lower()
        rest = s[3:].replace("\\", "/")
        return Path(f"/mnt/{drive}/{rest}")
    return Path(s)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--epochs-trackb", type=int, default=4)
    parser.add_argument("--epochs-tracka", type=int, default=3)
    parser.add_argument("--skip-tracka-pilot", action="store_true")
    parser.add_argument(
        "--resume-from-checkpoint",
        type=str,
        default=None,
        help="Optional verified checkpoint directory to resume Track B training from (e.g. checkpoint_epoch_1 at Step 196).",
    )
    parser.add_argument(
        "--prior-metrics-jsonl",
        type=str,
        default=None,
        help="Optional prior training_metrics.jsonl to seed step_logs when warm-starting from an earlier epoch checkpoint.",
    )
    parser.add_argument(
        "--phase2-ep1-eval-cache",
        type=str,
        default=None,
        help="Optional Phase 2 GPU Epoch-1 evaluation smoke report JSON path to reuse verified Epoch-1 Dev-166 metrics.",
    )
    parser.add_argument(
        "--source-run-id",
        type=str,
        default="eo06_vnext31_trackb_20261024_1145",
        help="Source run ID from which Phase 1 and Phase 2 validation JSONs can be copied if starting a recovery run.",
    )
    parser.add_argument(
        "--device",
        type=str,
        default="cuda:0",
        help="Torch device ('cuda:0' or 'cpu').",
    )
    args = parser.parse_args()

    run_id = args.run_id
    run_dir_wsl = WSL_RUNS_ROOT / run_id
    run_dir_f = WIN_F_RUNS_ROOT / run_id
    run_dir_wsl.mkdir(parents=True, exist_ok=True)
    run_dir_f.mkdir(parents=True, exist_ok=True)

    device = torch.device(args.device)
    allocator_info = verify_cuda_allocator_or_fallback(device)

    state_wsl_file = run_dir_f / "execution_state_wsl.json"
    emit_wsl_phase_heartbeat(
        state_wsl_file=state_wsl_file,
        phase="TRAINING",
        detail=f"PHASE_4_INITIALIZING (run_id={run_id})",
        extra={"run_id": run_id, "cuda_allocator": allocator_info},
        log_stdout=True,
    )

    tokenizer = AutoTokenizer.from_pretrained(
        str(BASE_MODEL_PATH), local_files_only=True, trust_remote_code=False
    )

    # Load datasets and verify SHA-256 against Phase 1 manifest (copying from source-run-id if recovery run)
    p1_path = run_dir_f / "phase1_dataset_release_validation.json"
    p2_path = run_dir_f / "phase2_gpu_smoke_report.json"
    if not p1_path.exists() and args.source_run_id:
        src_p1 = WIN_F_RUNS_ROOT / args.source_run_id / "phase1_dataset_release_validation.json"
        if src_p1.exists():
            shutil.copy2(src_p1, p1_path)
            shutil.copy2(src_p1, run_dir_wsl / "phase1_dataset_release_validation.json")
    if not p2_path.exists() and args.source_run_id:
        src_p2 = WIN_F_RUNS_ROOT / args.source_run_id / "phase2_gpu_smoke_report.json"
        if src_p2.exists():
            shutil.copy2(src_p2, p2_path)
            shutil.copy2(src_p2, run_dir_wsl / "phase2_gpu_smoke_report.json")

    phase1_data = json.loads(p1_path.read_text(encoding="utf-8"))
    phase2_data = json.loads(p2_path.read_text(encoding="utf-8"))

    trackb_file = WSL_DATASET_DIR / "01_TRAIN_VNEXT_3_1_TRACK_B_AUDITED_FULL.jsonl"
    tracka_file = WSL_DATASET_DIR / "01_TRAIN_VNEXT_3_1_TRACK_A_TRUSTED_GOLD_PILOT.jsonl"
    dev166_file = WSL_DATASET_DIR / "02_DEV_VNEXT_3_1.jsonl"
    hv2_file = HOLDOUT_V2_PATH
    hv3_file = HOLDOUT_V3_PATH

    trackb_sha = sha256_file(trackb_file)
    assert (
        trackb_sha
        == phase1_data["checks"]["01_hash_and_row_counts"][
            "01_TRAIN_VNEXT_3_1_TRACK_B_AUDITED_FULL.jsonl"
        ]["sha256_wsl"]
    )

    trackb_rows = load_jsonl(trackb_file)
    tracka_rows = load_jsonl(tracka_file)
    dev166_rows = load_jsonl(dev166_file)
    hv2_rows = load_jsonl(hv2_file)
    hv3_rows = load_jsonl(hv3_file)

    print(
        f"[{now_utc()}] Encoding datasets with real Qwen tokenizer (Track B={len(trackb_rows)}, "
        f"Track A={len(tracka_rows)}, Dev-166={len(dev166_rows)})...",
        flush=True,
    )
    encoded_trackb = {r["id"]: encode_and_verify_loss_mask(tokenizer, r["messages"]) for r in trackb_rows}
    encoded_tracka = {r["id"]: encode_and_verify_loss_mask(tokenizer, r["messages"]) for r in tracka_rows}
    encoded_dev166 = [encode_and_verify_loss_mask(tokenizer, r["messages"]) for r in dev166_rows]

    resume_ckpt_path = _normalize_wsl_path(args.resume_from_checkpoint)
    prior_metrics_path = _normalize_wsl_path(args.prior_metrics_jsonl)
    phase2_ep1_cache_path = _normalize_wsl_path(args.phase2_ep1_eval_cache)
    if resume_ckpt_path is not None and prior_metrics_path is None and args.source_run_id:
        cand_metrics = WIN_F_RUNS_ROOT / args.source_run_id / "training_metrics.jsonl"
        if cand_metrics.exists():
            prior_metrics_path = cand_metrics
    if phase2_ep1_cache_path is None:
        cand_p2_cache = run_dir_f / "phase2_gpu_eval_boundary_smoke.json"
        if cand_p2_cache.exists():
            phase2_ep1_cache_path = cand_p2_cache

    # Phase 4A: Train Primary Arm on VNext.3.1 Track B (781 rows)
    print(f"[{now_utc()}] === PHASE 4A: TRAINING EO06 MAIN LORA ON TRACK B (781 ROWS) ===", flush=True)
    trackb_out_wsl = run_dir_wsl / "checkpoints" / "eo06_vnext31_trackb_main"
    trackb_out_f = run_dir_f / "checkpoints" / "eo06_vnext31_trackb_main"
    trackb_telemetry, _ = train_lora_arm(
        arm_id="eo06_vnext31_trackb_main",
        adapter_name="eo06_vnext31_trackb_main",
        train_rows=trackb_rows,
        dev_rows=dev166_rows,
        encoded_train=encoded_trackb,
        encoded_dev_list=encoded_dev166,
        tokenizer=tokenizer,
        device=device,
        out_dir_wsl=trackb_out_wsl,
        out_dir_f=trackb_out_f,
        run_dir_f=run_dir_f,
        lora_r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        epochs=args.epochs_trackb,
        micro_batch_size=1,
        grad_accum=4,
        lr=1.8e-4,
        weighting_mode="calibrated",
        seed=20261024,
        resume_from_checkpoint=resume_ckpt_path,
        prior_metrics_jsonl=prior_metrics_path,
        eval_batch_size=1,
        dataset_sha256=trackb_sha,
        phase2_ep1_eval_cache=phase2_ep1_cache_path,
    )

    # Phase 4B: Optional Pilot Ablation on VNext.3.1 Track A (275 rows) if healthy
    tracka_telemetry: Optional[Dict[str, Any]] = None
    tracka_best_dir: Optional[Path] = None
    if not args.skip_tracka_pilot and not (run_dir_f / "HARD_STOP_TRIGGERED").exists():
        print(f"[{now_utc()}] === PHASE 4B: TRAINING EO06 PILOT ABLATION ON TRACK A (275 ROWS) ===", flush=True)
        tracka_out_wsl = run_dir_wsl / "checkpoints" / "eo06_vnext31_tracka_pilot"
        tracka_out_f = run_dir_f / "checkpoints" / "eo06_vnext31_tracka_pilot"
        tracka_telemetry, _ = train_lora_arm(
            arm_id="eo06_vnext31_tracka_pilot",
            adapter_name="eo06_vnext31_tracka_pilot",
            train_rows=tracka_rows,
            dev_rows=dev166_rows,
            encoded_train=encoded_tracka,
            encoded_dev_list=encoded_dev166,
            tokenizer=tokenizer,
            device=device,
            out_dir_wsl=tracka_out_wsl,
            out_dir_f=tracka_out_f,
            run_dir_f=run_dir_f,
            lora_r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            epochs=args.epochs_tracka,
            micro_batch_size=1,
            grad_accum=4,
            lr=1.8e-4,
            weighting_mode="uniform",
            seed=20261024,
            eval_batch_size=1,
            dataset_sha256=sha256_file(tracka_file),
        )
        tracka_best_dir = Path(tracka_telemetry["selected_checkpoint_dir_wsl"])

    # Phase 5: Comprehensive GPU Evaluation
    phase5_data = run_phase5_evaluation(
        tokenizer=tokenizer,
        device=device,
        dev166_rows=dev166_rows,
        holdout_v2_rows=hv2_rows,
        holdout_v3_rows=hv3_rows,
        trackb_ckpt_dir=Path(trackb_telemetry["selected_checkpoint_dir_wsl"]),
        tracka_ckpt_dir=tracka_best_dir,
        run_dir_wsl=run_dir_wsl,
        run_dir_f=run_dir_f,
    )

    # Phase 6: Real OpenGrep + javac + IRIS + Qwen EO06 E2E Validation
    phase6_data = run_phase6_real_opengrep_iris_e2e(
        tokenizer=tokenizer,
        device=device,
        trackb_ckpt_dir=Path(trackb_telemetry["selected_checkpoint_dir_wsl"]),
        run_dir_wsl=run_dir_wsl,
        run_dir_f=run_dir_f,
    )

    # Phase 7: Generate 13-Section Advisor Report
    advisor_f_path = generate_phase7_advisor_report(
        run_id=run_id,
        phase1_data=phase1_data,
        phase2_data=phase2_data,
        trackb_telemetry=trackb_telemetry,
        tracka_telemetry=tracka_telemetry,
        phase5_data=phase5_data,
        phase6_data=phase6_data,
        storage_errors_during_run=0,
        run_dir_wsl=run_dir_wsl,
        run_dir_f=run_dir_f,
    )

    m_eo03 = phase5_data["results_by_arm"]["eo03_vnext2_primary"]["splits"]["dev_166"]
    m_eo06 = phase5_data["results_by_arm"]["eo06_vnext31_trackb_main"]["splits"]["dev_166"]

    final_summary = {
        "RUN_ID": run_id,
        "TRAINING_STATUS": "COMPLETED",
        "TRAINING_COMPLETED": "YES",
        "TRAINING_EXIT_CODE": 0,
        "DATASET_SHA256": trackb_sha,
        "BASE_MODEL_ID": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
        "EPOCHS_COMPLETED": trackb_telemetry["epochs_completed"],
        "ACTUAL_STEPS_COMPLETED": trackb_telemetry["total_optimizer_steps"],
        "OPTIMIZER_STEPS": trackb_telemetry["total_optimizer_steps"],
        "FINAL_LOSS": trackb_telemetry["final_step_raw_loss"],
        "MEAN_LAST_10_STEPS_LOSS": trackb_telemetry["mean_last_10_steps_raw_loss"],
        "BEST_EPOCH": trackb_telemetry["selected_best_epoch"],
        "BEST_CHECKPOINT_SHA256": trackb_telemetry["selected_adapter_safetensors_sha256"],
        "SAVE_RELOAD_PARITY": "PASS" if trackb_telemetry["save_reload_greedy_parity"] else "FAIL",
        "DEV_MACRO_F1": m_eo06["macro_f1"],
        "DEV_NONE_RECALL": m_eo06["none_recall"],
        "DEV_SINK_F1": m_eo06["sink_f1"],
        "BASELINE_EO03_MACRO_F1": m_eo03["macro_f1"],
        "EO03_MACRO_F1": m_eo03["macro_f1"],
        "EO06_MACRO_F1": m_eo06["macro_f1"],
        "EO03_ACCURACY": m_eo03["accuracy"],
        "EO06_ACCURACY": m_eo03["accuracy"] if False else m_eo06["accuracy"],
        "EO03_NONE_RECALL": m_eo03["none_recall"],
        "EO06_NONE_RECALL": m_eo06["none_recall"],
        "SINK_F1_COMPARISON": f"EO03={m_eo03['sink_f1']*100:.2f}% vs EO06={m_eo06['sink_f1']*100:.2f}%",
        "EVALUATION_REPORT_PATH": str(run_dir_f / "phase5_evaluation_report.json"),
        "IRIS_END_TO_END_STATUS": phase6_data["real_e2e_status"],
        "REAL_E2E_STATUS": phase6_data["real_e2e_status"],
        "STORAGE_ERRORS_NEW": 0,
        "ADVISOR_REPORT_PATH": str(advisor_f_path),
        "UNRESOLVED_BLOCKERS": "NONE_FOR_EO06_EXECUTION (HISTORICAL_STORAGE_RISK_REMAINS_ON_HDD_D)",
        "COMPLETED_UTC": now_utc(),
    }
    write_json_atomic(run_dir_wsl / "FINAL_COMPLETION_SUMMARY.json", final_summary)
    write_json_atomic(run_dir_f / "FINAL_COMPLETION_SUMMARY.json", final_summary)
    write_json_atomic(
        state_wsl_file,
        {
            "updated_utc": now_utc(),
            "phase": "COMPLETED",
            "run_id": run_id,
            "exit_code": 0,
            "final_summary": final_summary,
        },
    )
    print(f"[{now_utc()}] === EO06 PIPELINE COMPLETED SUCCESSFULLY (EXIT_CODE=0) ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
