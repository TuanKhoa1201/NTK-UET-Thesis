"""
HTML Dashboard Reporter for Hybrid OpenGrep + Local LoRA SAST Framework.
Đồ án Tốt nghiệp NTK / IRIS - Phiên bản An toàn & Bảo mật V2.2.

Bảo vệ XSS & HTML Injection toàn diện:
Toàn bộ dữ liệu mã nguồn, thông điệp cảnh báo, giải trình mô hình AI
đều được mã hóa an toàn qua html.escape() trước khi render ra DOM.
"""

import json
import html
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

class HTMLDashboardReporter:
    def __init__(self, template_title: str = "Báo cáo Thẩm định An toàn Mã nguồn NTK/IRIS (Đồ án Tốt nghiệp)"):
        self.title = template_title

    def generate_html_report(self, findings: List[Dict[str, Any]], target_path: str, output_file: Path) -> Path:
        output_file.parent.mkdir(parents=True, exist_ok=True)

        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get("risk_level") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("risk_level") == "HIGH")
        medium_count = sum(1 for f in findings if f.get("risk_level") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("risk_level") == "LOW")
        fp_count = sum(1 for f in findings if f.get("risk_level") == "BENIGN_OR_FP")

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Thống kê tổng quan
        cards_html = f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_findings}</div>
                <div class="stat-label">Tổng số cảnh báo</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{critical_count}</div>
                <div class="stat-label">Nguy cấp (Critical)</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{high_count}</div>
                <div class="stat-label">Cao (High)</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{medium_count}</div>
                <div class="stat-label">Trung bình (Medium)</div>
            </div>
            <div class="stat-card fp">
                <div class="stat-value">{fp_count}</div>
                <div class="stat-label">Báo động giả đã lọc (FP)</div>
            </div>
        </div>
        """

        rows_html = []
        for idx, f in enumerate(findings, 1):
            rule_id = html.escape(str(f.get("rule_id", "N/A")))
            
            cwe_raw = f.get("metadata", {}).get("cwe", ["N/A"])[0] if f.get("metadata", {}).get("cwe") else "N/A"
            cwe = html.escape(str(cwe_raw))
            
            path = html.escape(str(f.get("path", "")))
            line = int(f.get("line", 0))
            score = float(f.get("risk_score", 0.0))
            level = html.escape(str(f.get("risk_level", "LOW")))
            
            ai_val = f.get("ai_validation", {})
            ai_pred = html.escape(str(ai_val.get("api_role", ai_val.get("predicted_type", "none"))).upper())
            ai_verdict = html.escape(str(ai_val.get("verdict", "UNKNOWN")))
            justification = html.escape(str(ai_val.get("justification", "Chưa có thẩm định.")))
            code_snippet = html.escape(str(f.get("code", "Không có mã nguồn.")))

            level_badge = f'<span class="badge {level.lower()}">{level}</span>'
            verdict_badge = f'<span class="badge verdict-{ai_verdict.lower()}">{ai_verdict} ({ai_pred})</span>'

            row = f"""
            <tr class="finding-row {level.lower()}">
                <td><strong>#{idx}</strong></td>
                <td>
                    <div class="rule-id">{rule_id}</div>
                    <div class="file-path">{path}:{line}</div>
                </td>
                <td><span class="cwe-tag">{cwe}</span></td>
                <td>{verdict_badge}</td>
                <td><div class="risk-score">{score}</div></td>
                <td>{level_badge}</td>
            </tr>
            <tr class="detail-row">
                <td colspan="6">
                    <div class="detail-box">
                        <div class="detail-section">
                            <strong>Nhận định chuyên gia AI (Local LoRA):</strong> {justification}
                        </div>
                        <div class="detail-section code-section">
                            <strong>Trích đoạn mã vi phạm & ngữ cảnh (Escaped Safe):</strong>
                            <pre><code>{code_snippet}</code></pre>
                        </div>
                    </div>
                </td>
            </tr>
            """
            rows_html.append(row)

        escaped_title = html.escape(self.title)
        escaped_target = html.escape(str(target_path))

        full_html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escaped_title} - NTK / IRIS</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --critical-color: #ef4444;
            --high-color: #f97316;
            --medium-color: #eab308;
            --low-color: #3b82f6;
            --fp-color: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            color: #38bdf8;
        }}
        .header .meta {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .stat-card.critical {{ border-top: 4px solid var(--critical-color); }}
        .stat-card.high {{ border-top: 4px solid var(--high-color); }}
        .stat-card.medium {{ border-top: 4px solid var(--medium-color); }}
        .stat-card.fp {{ border-top: 4px solid var(--fp-color); }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 4px;
        }}
        .stat-label {{
            font-size: 13px;
            color: var(--text-muted);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #0b1329;
            color: var(--text-muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .rule-id {{
            font-weight: 600;
            color: #e2e8f0;
            font-size: 14px;
        }}
        .file-path {{
            font-size: 12px;
            color: var(--text-muted);
            font-family: monospace;
        }}
        .cwe-tag {{
            display: inline-block;
            background-color: rgba(56, 189, 248, 0.15);
            color: #38bdf8;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }}
        .risk-score {{
            font-size: 16px;
            font-weight: 700;
            font-family: monospace;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.critical {{ background-color: rgba(239, 68, 68, 0.2); color: var(--critical-color); border: 1px solid var(--critical-color); }}
        .badge.high {{ background-color: rgba(249, 115, 22, 0.2); color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge.medium {{ background-color: rgba(234, 179, 8, 0.2); color: var(--medium-color); border: 1px solid var(--medium-color); }}
        .badge.low {{ background-color: rgba(59, 130, 246, 0.2); color: var(--low-color); border: 1px solid var(--low-color); }}
        .badge.benign_or_fp {{ background-color: rgba(16, 185, 129, 0.2); color: var(--fp-color); border: 1px solid var(--fp-color); }}
        .badge.verdict-likely_vulnerable {{ background-color: rgba(239, 68, 68, 0.2); color: var(--critical-color); }}
        .badge.verdict-potential_taint_entry {{ background-color: rgba(249, 115, 22, 0.2); color: var(--high-color); }}
        .badge.verdict-propagation_detected {{ background-color: rgba(234, 179, 8, 0.2); color: var(--medium-color); }}
        .badge.verdict-suspected_false_positive {{ background-color: rgba(16, 185, 129, 0.2); color: var(--fp-color); }}
        .badge.verdict-needs_review {{ background-color: rgba(148, 163, 184, 0.2); color: var(--text-muted); }}
        .detail-row td {{
            background-color: rgba(15, 23, 42, 0.5);
            padding: 12px 24px;
        }}
        .detail-box {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .detail-section {{
            font-size: 13px;
        }}
        .code-section pre {{
            margin: 4px 0 0 0;
            padding: 12px;
            background-color: #0b1120;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }}
        .code-section code {{
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 12px;
            color: #e2e8f0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{escaped_title}</h1>
        <div class="meta">
            Target: <code>{escaped_target}</code> | Generated: {now_str} | Architecture: OpenGrep + Local QLoRA Stage 3 (100% On-Premise)
        </div>
    </div>

    {cards_html}

    <table>
        <thead>
            <tr>
                <th style="width: 50px;">STT</th>
                <th>Cảnh báo & Vị trí</th>
                <th style="width: 120px;">CWE</th>
                <th style="width: 200px;">Thẩm định AI (Local LoRA)</th>
                <th style="width: 100px;">Điểm rủi ro</th>
                <th style="width: 140px;">Mức ưu tiên</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows_html)}
        </tbody>
    </table>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(full_html)

        return output_file
