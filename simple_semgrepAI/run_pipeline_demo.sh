#!/usr/bin/env bash
# ==============================================================================
# Script Khởi chạy Tự động 1-Lệnh (One-Click Demo Runner)
# Đồ án Tốt nghiệp: Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp
#                   phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn.
# Tác giả: Tuấn Khoa
# ==============================================================================

set -e

TARGET_DIR="${1:-/home/tuankhoa/iris/data/project-sources/jeecgboot_CVE-2025-51825_vuln}"
RULES_FILE="${2:-/home/tuankhoa/iris/integration/rules/opengrep/p-java-pinned-20260929/5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1/p-java.yaml}"
OUTPUT_DIR="/home/tuankhoa/simple_semgrepAI/reports/demo"

mkdir -p "$OUTPUT_DIR"

echo "======================================================================"
echo "    KHỞI CHẠY DEMO HỆ THỐNG HYBRID SAST + LOCAL LLM (NTK/IRIS)"
echo "======================================================================"
echo "[*] Mục tiêu quét: $TARGET_DIR"
echo "[*] Tệp quy tắc: $RULES_FILE"
echo "[*] Thư mục kết quả: $OUTPUT_DIR"
echo ""

# 1. Chạy OpenGrep Scan
echo "[Bước 1/3] Quét tĩnh tốc độ cao với OpenGrep v1.25.0..."
opengrep scan --config "$RULES_FILE" --json --output "$OUTPUT_DIR/opengrep_raw.json" "$TARGET_DIR" || true
opengrep scan --config "$RULES_FILE" --sarif --output "$OUTPUT_DIR/opengrep_raw.sarif" "$TARGET_DIR" || true

# 2. Chạy Pipeline Thẩm định AI & Chấm điểm
echo ""
echo "[Bước 2/3] Thẩm định ngữ nghĩa bằng Mô hình Fine-tuned LoRA & Chấm điểm SAST..."
cd /home/tuankhoa/simple_semgrepAI
python -c "
import json
from pathlib import Path
from semgrepai.scanner import OpengrepScanner
from semgrepai.llm.local_lora_verifier import LocalLoRAVerifier
from semgrepai.scoring.sast_scoring_engine import SASTScoringEngine
from semgrepai.html_dashboard import HTMLDashboardReporter

scanner = OpengrepScanner(engine='opengrep')
scorer = SASTScoringEngine()
reporter = HTMLDashboardReporter(template_title='Báo cáo Thẩm định Bảo mật NTK/IRIS - Đồ án Tốt nghiệp')

raw_json = Path('$OUTPUT_DIR/opengrep_raw.json')
findings = []
if raw_json.exists():
    with open(raw_json, 'r') as fp:
        data = json.load(fp)
        findings = scanner._process_results({'json': data})

print(f'[*] Đã nạp {len(findings)} cảnh báo từ OpenGrep.')
if findings:
    verifier = LocalLoRAVerifier()
    verified = verifier.verify_findings_batch(findings)
    enriched = scorer.enrich_findings(verified)
else:
    enriched = []

# Xuất file kết quả
out_json = Path('$OUTPUT_DIR/integrated_results.json')
with open(out_json, 'w', encoding='utf-8') as fp:
    json.dump(enriched, fp, indent=2, ensure_ascii=False)

out_html = Path('$OUTPUT_DIR/demo_dashboard.html')
reporter.generate_html_report(enriched, '$TARGET_DIR', out_html)
print(f'[✓] Đã tạo thành công Web Dashboard tại: {out_html}')
"

echo ""
echo "[Bước 3/3] Nghiệm thu sản phẩm hoàn tất!"
echo "----------------------------------------------------------------------"
echo "  Artifacts đã được xuất bản:"
echo "  - Raw SARIF report:  $OUTPUT_DIR/opengrep_raw.sarif"
echo "  - Raw JSON report:   $OUTPUT_DIR/opengrep_raw.json"
echo "  - AI Scored JSON:    $OUTPUT_DIR/integrated_results.json"
echo "  - Interactive HTML:  $OUTPUT_DIR/demo_dashboard.html"
echo "======================================================================"
