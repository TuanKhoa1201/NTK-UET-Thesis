"""
Local LoRA AI Verifier for SAST Findings.
Đồ án Tốt nghiệp NTK / IRIS - Giai đoạn 3.

Nạp trực tiếp trọng số LoRA đã fine-tune (best_adapter: 73.9 MB)
kết hợp Qwen2.5-Coder-1.5B-Instruct trên GPU RTX 4060 Ti cục bộ.
Không gửi bất kỳ dữ liệu mã nguồn nào lên đám mây (100% On-Premise Privacy).
"""

import os
import sys
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
import torch

MODEL_DIR = "/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct"
ADAPTER_DIR = "/home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/best_adapter"

CWE_DESCRIPTIONS = {
    "CWE-089": (
        "SQL injection (SQLi) occurs when untrusted user input is directly concatenated or interpolated into a SQL statement, "
        "allowing attackers to view, modify, or delete database records or execute administrative operations."
    ),
    "CWE-078": (
        "OS command injection allows an attacker to execute arbitrary operating system commands on the server "
        "running an application, typically leading to full system compromise."
    ),
    "CWE-022": (
        "Path traversal (directory traversal) allows an attacker to access files and directories outside of the "
        "intended root folder by manipulating file path references with sequences like '../'."
    ),
    "CWE-502": (
        "Deserialization of untrusted data occurs when an application deserializes malicious object streams, "
        "often leading to remote code execution (RCE) via gadget chains."
    ),
    "CWE-079": (
        "Cross-site scripting (XSS) occurs when untrusted user input is included in web pages without proper sanitization, "
        "allowing execution of malicious scripts in victims' browsers."
    ),
    "CWE-611": (
        "Improper Restriction of XML External Entity Reference (XXE) allows attackers to disclose internal files, "
        "perform SSRF, or cause denial of service via malicious XML payloads."
    )
}

SYSTEM_PROMPT = """You are a security expert.
You will receive exactly ONE API and must classify it for the requested CWE.

Return exactly ONE JSON object with this format:
{
  "package": "<package name>",
  "class": "<class name>",
  "method": "<method name>",
  "signature": "<signature>",
  "sink_args": [],
  "type": "<source, sink, taint-propagator, or none>"
}

Use:
- source only when the API can introduce attacker-controlled data.
- sink only when the API can directly consume tainted data in a way relevant to the requested CWE.
- taint-propagator only when it propagates tainted data without sanitizing it.
- none when the API does not satisfy any of the above for the requested CWE.

For a sink, sink_args must contain only the argument names/positions that consume tainted data.
For every other type, sink_args must be an empty list.

Do not classify an API merely because it is security-sensitive in some unrelated context.
Do not output anything except the JSON object."""

class LocalLoRAVerifier:
    """
    Module thẩm định cảnh báo bảo mật cục bộ sử dụng mô hình Qwen2.5-Coder LoRA.
    """

    def __init__(
        self,
        model_dir: str = MODEL_DIR,
        adapter_dir: str = ADAPTER_DIR,
        device: str = "cuda:0",
        lazy_load: bool = False
    ):
        self.model_dir = model_dir
        self.adapter_dir = adapter_dir
        self.device = device
        self.model = None
        self.tokenizer = None
        self.is_loaded = False

        if not lazy_load:
            self.load_model()

    def load_model(self):
        """Khởi tạo và nạp trọng số QLoRA 4-bit lên GPU."""
        if self.is_loaded:
            return

        print(f"[*] Đang nạp Tokenizer từ {self.adapter_dir}...", flush=True)
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel

        self.tokenizer = AutoTokenizer.from_pretrained(self.adapter_dir, use_fast=True)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "left"

        print(f"[*] Đang nạp Base Model {self.model_dir} (4-bit NF4)...", flush=True)
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16
        )

        base_model = AutoModelForCausalLM.from_pretrained(
            self.model_dir,
            quantization_config=bnb_config,
            device_map={"": 0} if torch.cuda.is_available() else "auto"
        )

        print(f"[*] Đang gắn LoRA Adapter từ {self.adapter_dir}...", flush=True)
        self.model = PeftModel.from_pretrained(base_model, self.adapter_dir)
        self.model.eval()
        if hasattr(self.model.config, "use_cache"):
            self.model.config.use_cache = True

        self.is_loaded = True
        print("[✓] Mô hình LoRA cục bộ đã sẵn sàng thẩm định cảnh báo!", flush=True)

    def extract_api_info_from_finding(self, finding: Dict[str, Any]) -> tuple[str, str, str, str]:
        """
        Trích xuất (package, class, method, signature) từ finding code snippet hoặc path.
        """
        code = finding.get("code", "")
        path = finding.get("path", "")
        message = finding.get("message", "")

        # Trích xuất class từ path
        class_name = "UnknownClass"
        if path:
            p = Path(path)
            class_name = p.stem

        # Mặc định package
        package_name = "org.app.security"
        if "/java/" in path:
            sub = path.split("/java/")[-1]
            parts = sub.split("/")
            if len(parts) > 1:
                package_name = ".".join(parts[:-1])

        # Phân tích method name từ code
        method_name = "handleRequest"
        signature = f"void {method_name}()"

        # Regex tìm lời gọi hàm Java trong dòng có chứa >>> hoặc code
        matches = re.findall(r"([a-zA-Z0-9_]+)\s*\(([^)]*)\)", code)
        if matches:
            # Chọn lời gọi hàm đáng ngờ nhất (exec, executeQuery, write, getParameter...)
            priority_names = ["exec", "execute", "executeQuery", "executeUpdate", "query", "getParameter", "eval"]
            chosen = matches[0]
            for m in matches:
                if any(p in m[0] for p in priority_names):
                    chosen = m
                    break
            method_name = chosen[0]
            signature = f"Object {chosen[0]}({chosen[1]})"

        return package_name, class_name, method_name, signature

    def build_verification_prompt(self, finding: Dict[str, Any]) -> str:
        """Tạo prompt chuẩn hóa khớp với phân phối huấn luyện Dataset V3."""
        # Xác định CWE
        cwe_raw = finding.get("metadata", {}).get("cwe")
        cwe_key = "CWE-089"
        if cwe_raw:
            m = re.search(r"CWE[-_\s]?0*(\d+)", str(cwe_raw), re.IGNORECASE)
            if m:
                cwe_num = int(m.group(1))
                cwe_key = f"CWE-{cwe_num:03d}" if cwe_num < 100 else f"CWE-{cwe_num}"

        cwe_desc = CWE_DESCRIPTIONS.get(cwe_key, CWE_DESCRIPTIONS["CWE-089"])
        pkg, cls, mtd, sig = self.extract_api_info_from_finding(finding)

        user_content = (
            f"{cwe_desc}\n\n"
            f"Among the following methods, assuming that the arguments passed to the given function is malicious, "
            f"what are the functions that are potential source, sink, or taint-propagators to {cwe_key} attack?\n\n"
            f"Package,Class,Method,Signature\n"
            f"{pkg},{cls},{mtd},{sig}\n"
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

        return self.tokenizer.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)

    def verify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Thẩm định một cảnh báo đơn lẻ qua mô hình LoRA.
        Trả về cấu trúc ai_validation chuẩn hóa.
        """
        if not self.is_loaded:
            self.load_model()

        prompt_text = self.build_verification_prompt(finding)
        inputs = self.tokenizer([prompt_text], return_tensors="pt").to(self.device)

        with torch.no_grad():
            out_ids = self.model.generate(
                **inputs,
                max_new_tokens=80,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id
            )

        input_len = inputs["input_ids"].shape[1]
        completion = self.tokenizer.decode(out_ids[0][input_len:], skip_special_tokens=True).strip()

        # Parse JSON output
        pred_type = "none"
        try:
            parsed = json.loads(completion)
            pred_type = parsed.get("type", "none").lower()
        except Exception:
            for cand in ["sink", "source", "taint-propagator", "none"]:
                if f'"{cand}"' in completion or f"'{cand}'" in completion:
                    pred_type = cand
                    break

        # Đánh giá True/False Positive
        if pred_type in ["sink", "source"]:
            is_valid = True
            verdict = "TRUE_POSITIVE"
            confidence = 0.92
            justification = f"Mô hình AI LoRA đã xác nhận phương thức đóng vai trò {pred_type.upper()} nhạy cảm trong luồng dữ liệu bảo mật."
        elif pred_type == "taint-propagator":
            is_valid = True
            verdict = "TRUE_POSITIVE"
            confidence = 0.82
            justification = f"Mô hình AI LoRA xác định phương thức đóng vai trò TAINT-PROPAGATOR truyền vết dữ liệu bẩn."
        else:
            is_valid = False
            verdict = "FALSE_POSITIVE"
            confidence = 0.88
            justification = "Mô hình AI LoRA phân loại phương thức là hàm vô hại (NONE) đối với lớp lỗ hổng này; xác định là báo động giả."

        ai_validation = {
            "is_valid": is_valid,
            "verdict": verdict,
            "confidence": confidence,
            "predicted_type": pred_type,
            "raw_completion": completion,
            "justification": justification,
            "model_version": "Qwen2.5-Coder-1.5B-QLoRA-V3-Local"
        }

        finding["ai_validation"] = ai_validation
        return finding

    def verify_findings_batch(self, findings: List[Dict[str, Any]], batch_size: int = 4) -> List[Dict[str, Any]]:
        """
        Thẩm định danh sách cảnh báo theo batch để tối ưu tốc độ suy luận GPU.
        """
        if not self.is_loaded:
            self.load_model()

        if not findings:
            return []

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batch_prompts = [self.build_verification_prompt(f) for f in batch]
            inputs = self.tokenizer(batch_prompts, return_tensors="pt", padding=True, truncation=True, max_length=1024).to(self.device)

            with torch.no_grad():
                out_ids = self.model.generate(
                    **inputs,
                    max_new_tokens=80,
                    do_sample=False,
                    pad_token_id=self.tokenizer.pad_token_id
                )

            input_len = inputs["input_ids"].shape[1]
            for j, f in enumerate(batch):
                completion = self.tokenizer.decode(out_ids[j][input_len:], skip_special_tokens=True).strip()
                pred_type = "none"
                try:
                    parsed = json.loads(completion)
                    pred_type = parsed.get("type", "none").lower()
                except Exception:
                    for cand in ["sink", "source", "taint-propagator", "none"]:
                        if f'"{cand}"' in completion or f"'{cand}'" in completion:
                            pred_type = cand
                            break

                if pred_type in ["sink", "source"]:
                    is_valid = True
                    verdict = "TRUE_POSITIVE"
                    confidence = 0.92
                    justification = f"Mô hình AI LoRA đã xác nhận phương thức là {pred_type.upper()} nhạy cảm trong luồng dữ liệu bảo mật."
                elif pred_type == "taint-propagator":
                    is_valid = True
                    verdict = "TRUE_POSITIVE"
                    confidence = 0.82
                    justification = f"Mô hình AI LoRA xác định phương thức là TAINT-PROPAGATOR."
                else:
                    is_valid = False
                    verdict = "FALSE_POSITIVE"
                    confidence = 0.88
                    justification = "Mô hình AI LoRA phân loại phương thức là hàm vô hại (NONE); xác định là báo động giả."

                f["ai_validation"] = {
                    "is_valid": is_valid,
                    "verdict": verdict,
                    "confidence": confidence,
                    "predicted_type": pred_type,
                    "raw_completion": completion,
                    "justification": justification,
                    "model_version": "Qwen2.5-Coder-1.5B-QLoRA-V3-Local"
                }

        return findings
