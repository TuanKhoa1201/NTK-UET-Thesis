#!/usr/bin/env python3
"""
Integrated Operation Pipeline Runner (NTK / IRIS / simple_semgrepAI).
Đồ án Tốt nghiệp: Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp
                  phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn.

Luồng vận hành chuẩn hóa (Operation Pipeline):
Target Java Code
  -> OpenGrep OSS Scan (100% On-Premise)
  -> Findings / SARIF Normalization
  -> Local LLM Semantic Enrichment (Stage 3 QLoRA on GPU / Ollama)
  -> Observable Evidence SAST Scoring (V2.1 Conservative Demotion)
  -> Multi-format Reporting (JSON, CSV, SARIF, HTML Dashboard)
"""

import os
import sys
import json
import csv
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Set local-only enforcement
os.environ["THESIS_LOCAL_ONLY_MODE"] = "true"

CURRENT_DIR = Path(__file__).resolve().parent
REPO_DIR = CURRENT_DIR.parent
sys.path.insert(0, str(CURRENT_DIR))

from semgrepai.scanner import SemgrepScanner
from semgrepai.llm.local_lora_verifier import LocalLoRAVerifier
from semgrepai.scoring.sast_scoring_engine import SASTScoringEngine
from semgrepai.html_dashboard import HTMLDashboardReporter

DEFAULT_TARGET = REPO_DIR / "data" / "project-sources" / "mini_vulnerable_java_CVE-89_1.0" / "src"
DEFAULT_RULES = REPO_DIR / "integration" / "rules" / "opengrep" / "p-java-pinned-20260929" / "5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1" / "p-java.yaml"
DEFAULT_OUTPUT_DIR = CURRENT_DIR / "reports" / "operation_run"

def run_operation_pipeline(
    target_path: Optional[Path] = None,
    rules_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    use_gpu_lora: bool = True
) -> Dict[str, Any]:
    target = Path(target_path) if target_path else DEFAULT_TARGET
    rules = Path(rules_path) if rules_path else DEFAULT_RULES
    out_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    print("======================================================================")
    print("      NTK/IRIS SAST + LOCAL LLM INTEGRATED OPERATION PIPELINE         ")
    print("======================================================================")
    print(f"[*] Target Directory  : {target}")
    print(f"[*] OpenGrep Rules    : {rules}")
    print(f"[*] Output Directory  : {out_dir}")
    print(f"[*] Timestamp         : {datetime.now().isoformat()}")
    print(f"[*] Local Privacy Mode: THESIS_LOCAL_ONLY_MODE=true (Fail-Closed)")
    print("----------------------------------------------------------------------")

    # Step 1: OpenGrep OSS Scanning
    print("\n[Stage 1/4] Running OpenGrep OSS Static Analysis...")
    raw_json_path = out_dir / "opengrep_raw.json"
    raw_sarif_path = out_dir / "opengrep_raw.sarif"

    cmd_json = ["opengrep", "scan", "--config", str(rules), "--json", "--output", str(raw_json_path), str(target)]
    cmd_sarif = ["opengrep", "scan", "--config", str(rules), "--sarif", "--output", str(raw_sarif_path), str(target)]

    res_json = subprocess.run(cmd_json, capture_output=True, text=True)
    res_sarif = subprocess.run(cmd_sarif, capture_output=True, text=True)

    if res_json.returncode not in [0, 1] or not raw_json_path.exists():
        raise RuntimeError(f"OpenGrep scan failed: {res_json.stderr}")

    with open(raw_json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    scanner = SemgrepScanner(engine="opengrep")
    findings = scanner._process_results({"json": raw_data})
    print(f"[✓] OpenGrep completed successfully: {len(findings)} raw findings detected.")

    # Step 2: Local LLM Semantic Enrichment
    print("\n[Stage 2/4] Semantic Enrichment via Local QLoRA / Ollama...")
    if findings and use_gpu_lora:
        try:
            print("[*] Initializing LocalLoRAVerifier on GPU...")
            verifier = LocalLoRAVerifier()
            findings = verifier.verify_findings_batch(findings, batch_size=4)
            print("[✓] Local LLM semantic verification finished.")
        except Exception as e:
            print(f"[!] Warning: GPU LoRA verification encountered error ({e}), setting neutral audit fallback.")
            for f in findings:
                f["ai_validation"] = {
                    "is_valid": None,
                    "verdict": "NEEDS_REVIEW",
                    "evidence_weight": "UNKNOWN",
                    "api_role": "unknown",
                    "justification": f"Fallback: {e}"
                }
    else:
        print("[*] No findings to enrich or GPU LoRA disabled.")

    # Step 3: SAST Observable Evidence Risk Scoring
    print("\n[Stage 3/4] Calculating Observable Evidence Risk Scores (V2.1)...")
    scorer = SASTScoringEngine()
    enriched_findings = scorer.enrich_findings(findings)
    print(f"[✓] Scored and ranked {len(enriched_findings)} findings.")

    # Step 4: Multi-format Reporting
    print("\n[Stage 4/4] Exporting Multi-format Reports (JSON, CSV, SARIF, HTML)...")
    # 4.1 JSON
    scored_json_path = out_dir / "sast_scored_findings.json"
    with open(scored_json_path, "w", encoding="utf-8") as f:
        json.dump(enriched_findings, f, indent=2, ensure_ascii=False)
    print(f"  [+] Scored JSON : {scored_json_path}")

    # 4.2 CSV
    scored_csv_path = out_dir / "sast_scored_findings.csv"
    if enriched_findings:
        fieldnames = ["id", "rule_id", "severity", "risk_score", "risk_level", "path", "line", "ai_verdict", "penalty_factor", "message"]
        with open(scored_csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for ef in enriched_findings:
                row = {
                    "id": ef.get("id"),
                    "rule_id": ef.get("rule_id"),
                    "severity": ef.get("severity"),
                    "risk_score": ef.get("risk_score"),
                    "risk_level": ef.get("risk_level"),
                    "path": ef.get("path"),
                    "line": ef.get("line"),
                    "ai_verdict": ef.get("score_breakdown", {}).get("ai_verdict"),
                    "penalty_factor": ef.get("score_breakdown", {}).get("penalty_factor"),
                    "message": ef.get("message")
                }
                writer.writerow(row)
        print(f"  [+] CSV Summary : {scored_csv_path}")

    # 4.3 HTML Dashboard
    html_report_path = out_dir / "sast_dashboard.html"
    reporter = HTMLDashboardReporter(template_title="Báo cáo Thẩm định An toàn Mã nguồn NTK/IRIS (Đồ án Tốt nghiệp)")
    reporter.generate_html_report(enriched_findings, str(target), html_report_path)
    print(f"  [+] HTML Report : {html_report_path}")

    print("\n======================================================================")
    print("               OPERATION PIPELINE COMPLETED SUCCESSFULLY!              ")
    print("======================================================================")
    return {
        "status": "PASS",
        "total_findings": len(enriched_findings),
        "raw_json": str(raw_json_path),
        "raw_sarif": str(raw_sarif_path),
        "scored_json": str(scored_json_path),
        "scored_csv": str(scored_csv_path),
        "html_report": str(html_report_path)
    }

if __name__ == "__main__":
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_operation_pipeline(target_arg)
