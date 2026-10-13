#!/usr/bin/env python3
"""
Integrated Operation Pipeline Runner (NTK / IRIS / simple_semgrepAI).
Đồ án Tốt nghiệp: Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp
                  phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn.
Phiên bản Chuẩn hóa Khoa học & Vận hành Thực tế V2.2.

Luồng vận hành chuẩn hóa (Operation Pipeline):
Target Java Code
  -> OpenGrep OSS Scan (100% On-Premise, bắt mã lỗi thực thụ, không || true)
  -> Findings / SARIF Normalization
  -> Local LLM Semantic Enrichment (Stage 3 QLoRA on GPU / Local, Decoupled API Role)
  -> Observable Evidence SAST Scoring (V2.2 với 6 Safety Invariants & Floor >= 40.0)
  -> Multi-format Reporting (JSON, CSV, Scored SARIF, Escaped HTML Dashboard)
"""

import os
import sys
import json
import csv
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Cưỡng chế chạy hoàn toàn cục bộ (Local-Only Fail-Closed)
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

def export_scored_sarif(raw_sarif_path: Path, enriched_findings: List[Dict[str, Any]], output_path: Path):
    """
    Sinh Scored SARIF thực thụ bằng cách nhúng trực tiếp điểm rủi ro,
    phân loại ưu tiên và thông tin thẩm định AI vào từng result trong SARIF.
    """
    if not raw_sarif_path.exists():
        return

    with open(raw_sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    # Lập bản đồ tra cứu finding theo (ruleId, file_path, line)
    finding_map = {}
    for ef in enriched_findings:
        p = ef.get("path", "")
        l = ef.get("line", 0)
        rid = ef.get("rule_id", "")
        finding_map[(rid, p, l)] = ef

    runs = sarif_data.get("runs", [])
    if runs:
        results = runs[0].get("results", [])
        for r in results:
            rid = r.get("ruleId", "")
            locs = r.get("locations", [])
            file_uri = ""
            line_no = 0
            if locs:
                ploc = locs[0].get("physicalLocation", {})
                file_uri = ploc.get("artifactLocation", {}).get("uri", "")
                line_no = ploc.get("region", {}).get("startLine", 0)

            # Khớp finding
            matched_ef = None
            for (m_rid, m_path, m_line), ef in finding_map.items():
                if rid == m_rid and (file_uri.endswith(Path(m_path).name) or m_path.endswith(file_uri)):
                    matched_ef = ef
                    break

            if matched_ef:
                props = r.setdefault("properties", {})
                props["ntk_sast_scoring"] = {
                    "risk_score": matched_ef.get("risk_score"),
                    "risk_level": matched_ef.get("risk_level"),
                    "scoring_breakdown": matched_ef.get("scoring_breakdown"),
                    "ai_validation": matched_ef.get("ai_validation"),
                    "spec_version": "NTK-SAST-SCORING-V2.2-SAFETY-INVARIANTS"
                }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2, ensure_ascii=False)

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
    print("           (Scientific Operation Specification V2.2)                 ")
    print("======================================================================")
    print(f"[*] Target Directory  : {target}")
    print(f"[*] OpenGrep Rules    : {rules}")
    print(f"[*] Output Directory  : {out_dir}")
    print(f"[*] Timestamp         : {datetime.now().isoformat()}")
    print(f"[*] Local Privacy Mode: THESIS_LOCAL_ONLY_MODE=true (Fail-Closed)")
    print("----------------------------------------------------------------------")

    # Step 1: OpenGrep OSS Scanning (Bắt mã lỗi thực thụ, không || true)
    print("\n[Stage 1/4] Running OpenGrep OSS Static Analysis...")
    raw_json_path = out_dir / "opengrep_raw.json"
    raw_sarif_path = out_dir / "opengrep_raw.sarif"

    cmd_json = ["opengrep", "scan", "--config", str(rules), "--json", "--output", str(raw_json_path), str(target)]
    cmd_sarif = ["opengrep", "scan", "--config", str(rules), "--sarif", "--output", str(raw_sarif_path), str(target)]

    res_json = subprocess.run(cmd_json, capture_output=True, text=True)
    res_sarif = subprocess.run(cmd_sarif, capture_output=True, text=True)

    # Kiểm tra mã trả về: 0 = sạch, 1 = có findings, >= 2 = lỗi scanner
    if res_json.returncode not in [0, 1]:
        raise RuntimeError(f"OpenGrep scan failed with exit code {res_json.returncode}: {res_json.stderr}")
    if not raw_json_path.exists():
        raise RuntimeError(f"OpenGrep JSON output was not generated: {res_json.stderr}")

    with open(raw_json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    scanner = SemgrepScanner(engine="opengrep")
    findings = scanner._process_results({"json": raw_data})
    print(f"[✓] OpenGrep completed successfully: {len(findings)} raw findings detected.")

    # Step 2: Local LLM Semantic Enrichment (Stage 3 QLoRA)
    print("\n[Stage 2/4] Semantic Enrichment via Local QLoRA (Decoupled Evidence)...")
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
                    "parse_status": "DEGRADED_MODE",
                    "justification": f"Degraded fallback: {e}"
                }
    else:
        print("[*] No findings to enrich or GPU LoRA disabled.")

    # Step 3: SAST Observable Evidence Risk Scoring (V2.2 với Safety Invariants)
    print("\n[Stage 3/4] Calculating Observable Evidence Risk Scores (V2.2 Safety Invariants)...")
    scorer = SASTScoringEngine()
    enriched_findings = scorer.enrich_findings(findings)
    print(f"[✓] Scored and ranked {len(enriched_findings)} findings.")

    # Step 4: Multi-format Reporting
    print("\n[Stage 4/4] Exporting Multi-format Reports (JSON, CSV, Scored SARIF, Escaped HTML)...")
    
    # 4.1 JSON
    scored_json_path = out_dir / "sast_scored_findings.json"
    with open(scored_json_path, "w", encoding="utf-8") as f:
        json.dump(enriched_findings, f, indent=2, ensure_ascii=False)
    print(f"  [+] Scored JSON   : {scored_json_path}")

    # 4.2 CSV
    scored_csv_path = out_dir / "sast_scored_findings.csv"
    if enriched_findings:
        fieldnames = ["id", "rule_id", "severity", "risk_score", "risk_level", "path", "line", "ai_verdict", "api_role", "penalty_factor", "safety_floor_applied", "message"]
        with open(scored_csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for ef in enriched_findings:
                sb = ef.get("score_breakdown", {})
                av = ef.get("ai_validation", {})
                row = {
                    "id": ef.get("id"),
                    "rule_id": ef.get("rule_id"),
                    "severity": ef.get("severity"),
                    "risk_score": ef.get("risk_score"),
                    "risk_level": ef.get("risk_level"),
                    "path": ef.get("path"),
                    "line": ef.get("line"),
                    "ai_verdict": sb.get("ai_verdict", av.get("verdict")),
                    "api_role": av.get("api_role"),
                    "penalty_factor": sb.get("penalty_factor"),
                    "safety_floor_applied": sb.get("safety_floor_applied", False),
                    "message": ef.get("message")
                }
                writer.writerow(row)
        print(f"  [+] CSV Summary   : {scored_csv_path}")

    # 4.3 Scored SARIF
    scored_sarif_path = out_dir / "sast_scored_findings.sarif"
    export_scored_sarif(raw_sarif_path, enriched_findings, scored_sarif_path)
    print(f"  [+] Scored SARIF  : {scored_sarif_path}")

    # 4.4 HTML Dashboard (XSS-protected)
    html_report_path = out_dir / "sast_dashboard.html"
    reporter = HTMLDashboardReporter(template_title="Báo cáo Thẩm định An toàn Mã nguồn NTK/IRIS (Đồ án Tốt nghiệp)")
    reporter.generate_html_report(enriched_findings, str(target), html_report_path)
    print(f"  [+] HTML Report   : {html_report_path}")

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
        "scored_sarif": str(scored_sarif_path),
        "html_report": str(html_report_path)
    }

if __name__ == "__main__":
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_operation_pipeline(target_arg)
