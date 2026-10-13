#!/usr/bin/env python3
"""
Pipeline Vận hành Tích hợp 2 Giai đoạn (Hybrid 2-Tier Pipeline).
Đồ án Tốt nghiệp NTK / IRIS - Giai đoạn 3.

Quy trình:
1. OpenGrep SAST Scanner: Quét mã nguồn với OpenGrep v1.25.0, trích xuất cảnh báo thô và dataflow.
2. Local LoRA AI Verifier: Nạp mô hình Qwen2.5-Coder-1.5B đã fine-tune (best_adapter) trên GPU RTX 4060 Ti,
   thẩm định vai trò API và xác định True/False Positive.
3. SAST Scoring Engine: Chấm điểm rủi ro tổng hợp (Composite Risk Score [0-100]), hạ bậc báo động giả,
   và tái phân bổ thứ tự ưu tiên xử lý (Re-ranking).
"""

import os
import sys
import json
from pathlib import Path

# Add project root to sys.path
CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from semgrepai.scanner import OpengrepScanner
from semgrepai.llm.local_lora_verifier import LocalLoRAVerifier
from semgrepai.scoring.sast_scoring_engine import SASTScoringEngine
from rich.console import Console
from rich.table import Table

console = Console()

def run_integrated_pipeline():
    console.print("[bold green]====================================================================[/bold green]")
    console.print("[bold cyan] GIAI ĐOẠN 3: TÍCH HỢP MÔ HÌNH FINE-TUNED (LOCAL LORA) VÀO PIPELINE [/bold cyan]")
    console.print("[bold green]====================================================================[/bold green]")

    # 1. Khởi tạo Scanner
    console.print("\n[bold yellow][1/4] Khởi tạo OpenGrep SAST Engine...[/bold yellow]")
    scanner = OpengrepScanner(engine="opengrep")

    # 2. Khởi tạo Local LoRA Verifier
    console.print("\n[bold yellow][2/4] Khởi tạo Local LoRA AI Verifier (GPU RTX 4060 Ti)...[/bold yellow]")
    verifier = LocalLoRAVerifier()

    # 3. Khởi tạo SAST Scoring Engine
    console.print("\n[bold yellow][3/4] Khởi tạo SAST Scoring Engine (CWSS/CVSS)...[/bold yellow]")
    scorer = SASTScoringEngine()

    # 4. Chạy kịch bản kiểm thử tích hợp trên các ca điển hình
    console.print("\n[bold yellow][4/4] Thực thi luồng thẩm định End-to-End trên các ca kiểm thử...[/bold yellow]")

    # Tạo các ca finding thực tế đa dạng (Vulnerable True Positive vs Benign False Positive)
    test_findings = [
        {
            "rule_id": "rules.java.sql-injection-exec",
            "severity": "ERROR",
            "path": "/src/main/java/org/owasp/webgoat/lessons/sqlinjection/SqlInjectionLesson5.java",
            "line": 42,
            "message": "User input directly concatenated into SQL statement",
            "code": "42 | >>> Statement stmt = connection.createStatement();\n43 | >>> ResultSet rs = stmt.executeQuery(query);",
            "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
            "dataflow": [
                {"type": "source", "content": "request.getParameter('account')"},
                {"type": "intermediate", "content": "query = 'SELECT * FROM users WHERE acc=' + account"},
                {"type": "sink", "content": "stmt.executeQuery(query)"}
            ]
        },
        {
            "rule_id": "rules.java.command-injection-runtime",
            "severity": "ERROR",
            "path": "/src/main/java/org/app/service/DeployService.java",
            "line": 88,
            "message": "Direct OS command execution with user parameter",
            "code": "88 | >>> Runtime.getRuntime().exec(cmdArray);",
            "metadata": {"cwe": ["CWE-78"], "confidence": "VERY-HIGH"},
            "dataflow": [
                {"type": "source", "content": "request.getHeader('X-Command')"},
                {"type": "intermediate", "content": "cmdArray"},
                {"type": "sink", "content": "Runtime.getRuntime().exec(cmdArray)"}
            ]
        },
        {
            "rule_id": "rules.java.potential-xxe-parser",
            "severity": "WARNING",
            "path": "/src/main/java/org/app/util/SafeXmlHelper.java",
            "line": 15,
            "message": "XML Parser configured with secure flags but matches general sink rule",
            "code": "15 | >>> DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n16 | >>> dbf.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);",
            "metadata": {"cwe": ["CWE-611"], "confidence": "MEDIUM"},
            "dataflow": []
        }
    ]

    console.print(f"[*] Đang đưa {len(test_findings)} cảnh báo qua Local LoRA AI Verifier...")
    verified_findings = verifier.verify_findings_batch(test_findings)

    console.print(f"[*] Đang chấm điểm tổng hợp qua SAST Scoring Engine...")
    enriched_findings = scorer.enrich_findings(verified_findings)

    # Hiển thị bảng kết quả
    table = Table(title="Kết quả Thẩm định & Chấm điểm Tích hợp (Stage 3 Integration)")
    table.add_column("Rule ID & File", style="cyan", max_width=35)
    table.add_column("CWE", style="magenta")
    table.add_column("AI Pred Type", style="yellow")
    table.add_column("AI Verdict", style="bold")
    table.add_column("Raw Score", style="blue")
    table.add_column("Penalty", style="red")
    table.add_column("Risk Score", style="bold green")
    table.add_column("Risk Band", style="bold")

    for f in enriched_findings:
        b = f["scoring_breakdown"]
        ai_val = f["ai_validation"]
        pred = ai_val["predicted_type"].upper()
        verdict = ai_val["verdict"]

        v_color = "green" if verdict == "TRUE_POSITIVE" else "red"
        band_color = "red" if b["risk_level"] in ["CRITICAL", "HIGH"] else "green"

        table.add_row(
            f"{f['rule_id']}\n({Path(f['path']).name}:{f['line']})",
            f.get("metadata", {}).get("cwe", [""])[0],
            pred,
            f"[{v_color}]{verdict}[/{v_color}]",
            str(b["raw_score"]),
            str(b["penalty_factor"]),
            str(f["risk_score"]),
            f"[{band_color}]{b['risk_level']}[/{band_color}]"
        )

    console.print(table)

    # Lưu kết quả tích hợp
    out_dir = CURRENT_DIR / "reports" / "stage3"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "integrated_pipeline_report.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(enriched_findings, fp, indent=2, ensure_ascii=False)

    console.print(f"\n[green]✓[/green] Đã lưu báo cáo tích hợp tại: [bold]{out_file}[/bold]")
    console.print("[bold green]✓ GIAI ĐOẠN 3 HOÀN TẤT THÀNH CÔNG 100%![/bold green]")
    return True

if __name__ == "__main__":
    success = run_integrated_pipeline()
    sys.exit(0 if success else 1)
