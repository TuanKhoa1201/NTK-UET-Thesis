"""
SAST Observable Evidence Risk Prioritization Framework.
Đồ án Tốt nghiệp NTK / IRIS - Phiên bản Chuẩn hóa Khoa học V2.1.

Mô hình chấm điểm và tái ưu tiên (re-ranking) cảnh báo dựa trên các bằng chứng quan sát được:
1. Effective Static Base Severity (S_eff): Mức độ nghiêm trọng tĩnh & CWE intrinsic impact.
2. Rule Precision (P): Độ tin cậy khai báo của rule phân tích tĩnh.
3. Local Semantic Model Evidence (C_sem): Bằng chứng ngữ nghĩa từ mô hình LLM/LoRA cục bộ (Stage 3 API role).
4. Exploitability & Dataflow Reachability (E): Dấu vết luồng truyền taint source -> sink.
5. Conservative Demotion Factor (gamma): Hệ số hạ bậc bảo thủ cho các cảnh báo nghi ngờ báo động giả.

Công thức:
    RawScore = 100 * (w_s * S_eff + w_p * P + w_a * C_sem + w_e * E)
    FinalScore = round(RawScore * gamma, 1)
"""

from typing import Dict, Any, Optional, List
import re
from dataclasses import dataclass, asdict

# Trọng số thành phần (Tổng = 1.0)
WEIGHT_SEVERITY = 0.35
WEIGHT_AI = 0.30
WEIGHT_EXPLOITABILITY = 0.25
WEIGHT_PRECISION = 0.10

# Bảng quy đổi Severity sang thang [0.0, 1.0]
SEVERITY_SCALE = {
    "CRITICAL": 1.0,
    "ERROR": 0.85,
    "HIGH": 0.80,
    "WARNING": 0.55,
    "MEDIUM": 0.55,
    "LOW": 0.25,
    "INFO": 0.10,
    "EXPERIMENT": 0.10,
    "UNKNOWN": 0.50,
}

# Điểm điều chỉnh tác động đặc thù theo CWE (CWE Intrinsic Impact Modifier)
CWE_IMPACT_MODIFIERS = {
    "CWE-78": 0.10,   # OS Command Injection (RCE)
    "CWE-502": 0.10,  # Deserialization of Untrusted Data (RCE)
    "CWE-89": 0.08,   # SQL Injection
    "CWE-611": 0.08,  # XXE
    "CWE-22": 0.05,   # Path Traversal
    "CWE-23": 0.05,   # Relative Path Traversal
    "CWE-79": 0.03,   # Cross-site Scripting (XSS)
    "CWE-918": 0.05,  # SSRF
}

# Bảng quy đổi Rule Precision sang thang [0.0, 1.0]
PRECISION_SCALE = {
    "VERY-HIGH": 1.0,
    "VERY_HIGH": 1.0,
    "HIGH": 0.85,
    "MEDIUM": 0.60,
    "LOW": 0.40,
    "UNKNOWN": 0.50,
}

# Phân loại mức độ rủi ro (Risk Bands)
RISK_BANDS = [
    (85.0, 100.0, "CRITICAL", "Cần xử lý khẩn cấp; rủi ro khai thác trực tiếp rất cao."),
    (70.0, 84.9, "HIGH", "Mức độ ưu tiên cao; lỗ hổng nghiêm trọng đã được kiểm chứng."),
    (40.0, 69.9, "MEDIUM", "Mức độ trung bình; có khả năng gây ảnh hưởng nếu điều kiện khai thác thỏa mãn."),
    (20.0, 39.9, "LOW", "Mức độ rủi ro thấp; cảnh báo tiềm năng hoặc thiếu luồng tấn công rõ ràng."),
    (0.0, 19.9, "BENIGN_OR_FP", "Báo động giả (False Positive) hoặc mã nguồn an toàn; đã bị hạ bậc ưu tiên.")
]

@dataclass
class ScoreBreakdown:
    static_severity_score: float
    cwe_impact_modifier: float
    effective_severity: float
    rule_precision_score: float
    ai_confidence_score: float
    exploitability_score: float
    raw_score: float
    penalty_factor: float
    final_score: float
    risk_level: str
    risk_description: str
    ai_verdict: str

class SASTScoringEngine:
    """
    Thuật toán chấm điểm rủi ro toàn diện cho các cảnh báo SAST.
    Tuân thủ các nguyên lý của MITRE CWSS và CVSS v3.1.
    """

    def __init__(
        self,
        weight_severity: float = WEIGHT_SEVERITY,
        weight_ai: float = WEIGHT_AI,
        weight_exploitability: float = WEIGHT_EXPLOITABILITY,
        weight_precision: float = WEIGHT_PRECISION
    ):
        total = weight_severity + weight_ai + weight_exploitability + weight_precision
        assert abs(total - 1.0) < 1e-4, f"Tổng trọng số phải bằng 1.0, thực tế: {total}"
        self.w_s = weight_severity
        self.w_a = weight_ai
        self.w_e = weight_exploitability
        self.w_p = weight_precision

    @staticmethod
    def extract_cwe_id(finding: Dict[str, Any]) -> Optional[str]:
        """Trích xuất mã CWE chuẩn hóa dạng 'CWE-XXX'."""
        metadata = finding.get("metadata", {})
        cwe_raw = metadata.get("cwe")
        if not cwe_raw:
            # Tìm trong rule_id hoặc message
            text = f"{finding.get('rule_id', '')} {finding.get('message', '')}"
            m = re.search(r"CWE[-_\s]?0*(\d+)", text, re.IGNORECASE)
            return f"CWE-{m.group(1)}" if m else None

        if isinstance(cwe_raw, list) and cwe_raw:
            val = str(cwe_raw[0])
        else:
            val = str(cwe_raw)

        m = re.search(r"CWE[-_\s]?0*(\d+)", val, re.IGNORECASE)
        return f"CWE-{m.group(1)}" if m else None

    def calculate_static_severity(self, finding: Dict[str, Any]) -> tuple[float, float, float]:
        """Tính điểm mức độ nghiêm trọng tĩnh kết hợp CWE modifier."""
        raw_sev = str(finding.get("severity", "UNKNOWN")).upper()
        base_s = SEVERITY_SCALE.get(raw_sev, SEVERITY_SCALE["UNKNOWN"])

        cwe = self.extract_cwe_id(finding)
        cwe_mod = CWE_IMPACT_MODIFIERS.get(cwe, 0.0) if cwe else 0.0

        effective_s = min(1.0, max(0.0, base_s + cwe_mod))
        return base_s, cwe_mod, effective_s

    def calculate_rule_precision(self, finding: Dict[str, Any]) -> float:
        """Tính điểm độ chính xác của Rule."""
        metadata = finding.get("metadata", {})
        raw_prec = str(metadata.get("confidence", "UNKNOWN")).upper()
        return PRECISION_SCALE.get(raw_prec, PRECISION_SCALE["UNKNOWN"])

    def calculate_exploitability(self, finding: Dict[str, Any]) -> float:
        """
        Đánh giá khả năng khai thác dựa trên luồng dữ liệu (Dataflow Reachability).
        """
        dataflow = finding.get("dataflow", [])
        has_source = False
        has_sink = False
        has_intermediate = False

        if isinstance(dataflow, list):
            for step in dataflow:
                if isinstance(step, dict):
                    stype = step.get("type", "").lower()
                    if "source" in stype:
                        has_source = True
                    if "sink" in stype:
                        has_sink = True
                    if "intermediate" in stype or "step" in stype:
                        has_intermediate = True

        # Nếu có đủ cả source và sink và bước trung gian -> Taint trace hoàn chỉnh
        if has_source and has_sink and has_intermediate:
            return 1.0
        elif has_source and has_sink:
            return 0.85
        elif has_source or has_sink:
            return 0.60
        elif len(dataflow) > 0:
            return 0.50
        else:
            # Không có dataflow trace (chỉ là pattern matching)
            return 0.30

    def evaluate_ai_validation(self, finding: Dict[str, Any]) -> tuple[float, float, str]:
        """
        Đánh giá kết quả từ mô hình ngữ nghĩa cục bộ (Decoupled Evidence Model).
        Trả về: (ai_semantic_score, demotion_factor, verdict_status)
        """
        ai_val = finding.get("ai_validation", {})
        if not ai_val:
            # Chưa có AI validation -> Mặc định trung tính, không hạ bậc
            return 0.50, 1.0, "NOT_EVALUATED"

        is_valid = ai_val.get("is_valid")
        verdict = str(ai_val.get("verdict", "")).upper()
        api_role = str(ai_val.get("api_role", ai_val.get("predicted_type", ""))).lower()

        # Ánh xạ theo đặc tả SAST_SCORING_SPEC_FINAL
        if verdict in ["LIKELY_VULNERABLE", "TRUE_POSITIVE", "VULNERABLE", "CONFIRMED"] or api_role == "sink":
            return 0.90, 1.00, "LIKELY_VULNERABLE"
        elif verdict in ["POTENTIAL_TAINT_ENTRY"] or api_role == "source":
            return 0.75, 0.90, "POTENTIAL_TAINT_ENTRY"
        elif verdict in ["PROPAGATION_DETECTED"] or api_role == "taint-propagator":
            return 0.70, 0.90, "PROPAGATION_DETECTED"
        elif verdict in ["SUSPECTED_FALSE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "SAFE"] or api_role == "none":
            # Hạ bậc bảo thủ (Conservative Demotion factor = 0.35, semantic score = 0.20)
            return 0.20, 0.35, "SUSPECTED_FALSE_POSITIVE"
        else:
            # Lỗi phân tích hoặc cần chuyên viên rà soát thủ công
            return 0.50, 0.75, "NEEDS_REVIEW"

    def score_finding(self, finding: Dict[str, Any]) -> ScoreBreakdown:
        """
        Tính điểm rủi ro toàn diện cho một finding.
        """
        base_s, cwe_mod, effective_s = self.calculate_static_severity(finding)
        p_score = self.calculate_rule_precision(finding)
        e_score = self.calculate_exploitability(finding)
        ai_score, penalty, verdict = self.evaluate_ai_validation(finding)

        # Tính điểm thô (RawScore)
        raw_score = 100.0 * (
            self.w_s * effective_s +
            self.w_p * p_score +
            self.w_a * ai_score +
            self.w_e * e_score
        )

        # Áp dụng hệ số phạt
        final_score = round(max(0.0, min(100.0, raw_score * penalty)), 1)

        # Xác định Risk Level
        risk_level = "LOW"
        risk_desc = ""
        for low, high, level, desc in RISK_BANDS:
            if low <= final_score <= high:
                risk_level = level
                risk_desc = desc
                break

        return ScoreBreakdown(
            static_severity_score=round(base_s, 2),
            cwe_impact_modifier=round(cwe_mod, 2),
            effective_severity=round(effective_s, 2),
            rule_precision_score=round(p_score, 2),
            ai_confidence_score=round(ai_score, 2),
            exploitability_score=round(e_score, 2),
            raw_score=round(raw_score, 1),
            penalty_factor=round(penalty, 2),
            final_score=final_score,
            risk_level=risk_level,
            risk_description=risk_desc,
            ai_verdict=verdict
        )

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Chấm điểm và làm giàu thông tin cho toàn bộ danh sách findings,
        đồng thời sắp xếp theo thứ tự ưu tiên giảm dần (Highest Risk first).
        """
        enriched = []
        for finding in findings:
            breakdown = self.score_finding(finding)
            f_copy = dict(finding)
            f_copy["risk_score"] = breakdown.final_score
            f_copy["risk_level"] = breakdown.risk_level
            f_copy["scoring_breakdown"] = asdict(breakdown)
            enriched.append(f_copy)

        # Sắp xếp theo thứ tự ưu tiên giảm dần
        enriched.sort(key=lambda x: x["risk_score"], reverse=True)
        return enriched
