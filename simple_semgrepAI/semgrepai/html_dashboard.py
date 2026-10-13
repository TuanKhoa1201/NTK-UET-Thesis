"""
HTML Dashboard Reporter for Hybrid OpenGrep + Local LoRA SAST Framework.
Đồ án Tốt nghiệp NTK / IRIS - Giai đoạn 5.
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

class HTMLDashboardReporter:
    def __init__(self, template_title: str = "Báo cáo Kết quả Quét Mã Nguồn & Thẩm định AI"):
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

        # HTML generation
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
            rule_id = f.get("rule_id", "N/A")
            cwe = f.get("metadata", {}).get("cwe", ["N/A"])[0] if f.get("metadata", {}).get("cwe") else "N/A"
            path = f.get("path", "")
            line = f.get("line", 0)
            score = f.get("risk_score", 0.0)
            level = f.get("risk_level", "LOW")
            
            ai_val = f.get("ai_validation", {})
            ai_pred = ai_val.get("predicted_type", "none").upper()
            ai_verdict = ai_val.get("verdict", "UNKNOWN")
            justification = ai_val.get("justification", "Chưa có thẩm định.")

            code_snippet = f.get("code", "Không có mã nguồn.")

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
                            <strong>Trích đoạn mã vi phạm & ngữ cảnh:</strong>
                            <pre><code>{code_snippet}</code></pre>
                        </div>
                    </div>
                </td>
            </tr>
            """
            rows_html.append(row)

        full_html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title} - NTK / IRIS</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --border-color: #334155;
            --accent-blue: #38bdf8;
            --crit-color: #ef4444;
            --high-color: #f97316;
            --med-color: #eab308;
            --low-color: #3b82f6;
            --fp-color: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .header {{
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            color: var(--accent-blue);
        }}
        .header .meta {{
            color: var(--text-sub);
            font-size: 14px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 4px;
        }}
        .stat-label {{
            font-size: 13px;
            color: var(--text-sub);
        }}
        .stat-card.critical .stat-value {{ color: var(--crit-color); }}
        .stat-card.high .stat-value {{ color: var(--high-color); }}
        .stat-card.medium .stat-value {{ color: var(--med-color); }}
        .stat-card.fp .stat-value {{ color: var(--fp-color); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
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
            background: #1e293b;
            color: var(--text-sub);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--crit-color); }}
        .badge.high {{ background: rgba(249, 115, 22, 0.2); color: var(--high-color); }}
        .badge.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--med-color); }}
        .badge.low {{ background: rgba(59, 130, 246, 0.2); color: var(--low-color); }}
        .badge.benign_or_fp {{ background: rgba(16, 185, 129, 0.2); color: var(--fp-color); }}
        .badge.verdict-true_positive {{ background: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .badge.verdict-false_positive {{ background: rgba(239, 68, 68, 0.15); color: #f87171; }}
        .cwe-tag {{
            background: #334155;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #38bdf8;
            font-family: monospace;
        }}
        .risk-score {{
            font-size: 16px;
            font-weight: bold;
            color: #38bdf8;
        }}
        .rule-id {{
            font-weight: 600;
            font-size: 14px;
            color: var(--text-main);
        }}
        .file-path {{
            font-size: 12px;
            color: var(--text-sub);
            font-family: monospace;
        }}
        .detail-box {{
            padding: 12px;
            background: #0f172a;
            border-radius: 6px;
            margin: 8px 0;
            border-left: 3px solid var(--accent-blue);
        }}
        .detail-section {{
            margin-bottom: 8px;
            font-size: 13px;
        }}
        pre {{
            margin: 4px 0 0 0;
            padding: 10px;
            background: #090d16;
            border-radius: 4px;
            overflow-x: auto;
        }}
        code {{
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 12px;
            color: #e2e8f0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{self.title}</h1>
        <div class="meta">
            <span>Dự án: <strong>{target_path}</strong></span> | 
            <span>Thời điểm quét: <strong>{now_str}</strong></span> | 
            <span>Engine: <strong>OpenGrep v1.25.0 + Qwen2.5-Coder LoRA</strong></span>
        </div>
    </div>

    {cards_html}

    <table>
        <thead>
            <tr>
                <th>STT</th>
                <th>Quy tắc & Tệp vi phạm</th>
                <th>CWE</th>
                <th>Thẩm định AI</th>
                <th>Điểm rủi ro</th>
                <th>Phân loại</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows_html)}
        </tbody>
    </table>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as fp:
            fp.write(full_html)

        return output_file
