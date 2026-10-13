"""
Unit tests for SASTScoringEngine.
Đồ án Tốt nghiệp NTK / IRIS - Kiểm định Khoa học Giai đoạn 2.
"""

import sys
from pathlib import Path

# Ensure semgrepai is on python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from semgrepai.scoring.sast_scoring_engine import SASTScoringEngine, ScoreBreakdown

def test_score_boundary_conditions():
    """Kiểm tra điều kiện biên: điểm số luôn nằm trong đoạn [0.0, 100.0]."""
    engine = SASTScoringEngine()

    # Kịch bản rủi ro cực đại: Critical + RCE CWE-78 + Full Dataflow + Confirmed True Positive
    max_finding = {
        "rule_id": "rules.rce.command-injection",
        "severity": "CRITICAL",
        "message": "Command injection vulnerability",
        "metadata": {"cwe": ["CWE-78"], "confidence": "VERY-HIGH"},
        "dataflow": [
            {"type": "source", "content": "request.getParameter()"},
            {"type": "intermediate", "content": "cmd"},
            {"type": "sink", "content": "Runtime.getRuntime().exec()"}
        ],
        "ai_validation": {"is_valid": True, "verdict": "TRUE_POSITIVE", "confidence": 0.99}
    }

    max_res = engine.score_finding(max_finding)
    assert 0.0 <= max_res.final_score <= 100.0
    assert max_res.final_score >= 85.0
    assert max_res.risk_level == "CRITICAL"

    # Kịch bản rủi ro cực tiểu / False Positive
    min_finding = {
        "rule_id": "rules.info.debug-message",
        "severity": "LOW",
        "metadata": {"cwe": ["CWE-200"], "confidence": "LOW"},
        "dataflow": [],
        "ai_validation": {"is_valid": False, "verdict": "FALSE_POSITIVE", "confidence": 0.95}
    }

    min_res = engine.score_finding(min_finding)
    assert 0.0 <= min_res.final_score <= 100.0
    assert min_res.final_score < 20.0
    assert min_res.risk_level == "BENIGN_OR_FP"

def test_score_monotonicity_severity():
    """Kiểm tra tính đơn điệu theo mức độ nghiêm trọng: Critical > High > Medium > Low."""
    engine = SASTScoringEngine()
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    scores = []

    for sev in severities:
        finding = {
            "rule_id": "test.rule",
            "severity": sev,
            "metadata": {"confidence": "MEDIUM"},
            "dataflow": [{"type": "sink"}],
            "ai_validation": {"is_valid": True, "verdict": "TRUE_POSITIVE", "confidence": 0.8}
        }
        res = engine.score_finding(finding)
        scores.append(res.final_score)

    # Kiểm tra giảm dần nghiêm ngặt
    for i in range(len(scores) - 1):
        assert scores[i] >= scores[i+1], f"Điểm không thỏa mãn đơn điệu: {scores[i]} < {scores[i+1]}"

def test_false_positive_demotion_power():
    """
    Kiểm tra hiệu lực hạ bậc của AI khi phát hiện False Positive:
    Cùng một lỗi CRITICAL nhưng nếu AI xác nhận là False Positive, điểm phải bị phạt sâu xuống dưới 20.
    """
    engine = SASTScoringEngine()

    base_finding = {
        "rule_id": "rules.sqli.mybatis",
        "severity": "CRITICAL",
        "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
        "dataflow": [
            {"type": "source"}, {"type": "intermediate"}, {"type": "sink"}
        ]
    }

    # Trường hợp 1: True Positive
    tp_finding = dict(base_finding)
    tp_finding["ai_validation"] = {"is_valid": True, "verdict": "TRUE_POSITIVE", "confidence": 0.92}
    tp_score = engine.score_finding(tp_finding).final_score

    # Trường hợp 2: False Positive
    fp_finding = dict(base_finding)
    fp_finding["ai_validation"] = {"is_valid": False, "verdict": "FALSE_POSITIVE", "confidence": 0.95}
    fp_res = engine.score_finding(fp_finding)

    assert tp_score >= 80.0, f"True positive score must be high: {tp_score}"
    assert fp_res.final_score < 20.0, f"False positive score must be demoted < 20, got: {fp_res.final_score}"
    assert fp_res.risk_level == "BENIGN_OR_FP"
    assert fp_res.penalty_factor == 0.15

def test_missing_and_malformed_metadata_resilience():
    """Kiểm tra tính bền bỉ với dữ liệu khuyết thiếu hoặc không chuẩn."""
    engine = SASTScoringEngine()

    bare_finding = {
        "rule_id": "unknown_rule"
    }

    res = engine.score_finding(bare_finding)
    assert 0.0 <= res.final_score <= 100.0
    assert res.ai_verdict == "NOT_EVALUATED"
    assert res.penalty_factor == 1.0

def test_enrich_and_prioritized_ranking():
    """Kiểm tra hàm enrich_findings sắp xếp đúng thứ tự ưu tiên giảm dần."""
    engine = SASTScoringEngine()

    findings = [
        {
            "id": "f_fp",
            "rule_id": "rule.high.xss",
            "severity": "HIGH",
            "ai_validation": {"is_valid": False, "verdict": "FALSE_POSITIVE"}
        },
        {
            "id": "f_tp_crit",
            "rule_id": "rule.crit.sqli",
            "severity": "CRITICAL",
            "metadata": {"cwe": ["CWE-89"]},
            "dataflow": [{"type": "source"}, {"type": "intermediate"}, {"type": "sink"}],
            "ai_validation": {"is_valid": True, "verdict": "TRUE_POSITIVE", "confidence": 0.95}
        },
        {
            "id": "f_medium",
            "rule_id": "rule.med.csrf",
            "severity": "MEDIUM",
            "ai_validation": {"is_valid": True, "verdict": "TRUE_POSITIVE", "confidence": 0.70}
        }
    ]

    enriched = engine.enrich_findings(findings)
    assert enriched[0]["id"] == "f_tp_crit", "Critical TP phải đứng đầu bảng xếp hạng"
    assert enriched[1]["id"] == "f_medium", "Medium TP phải đứng thứ 2"
    assert enriched[2]["id"] == "f_fp", "False Positive phải bị đẩy xuống cuối cùng"
    assert enriched[0]["risk_score"] > enriched[1]["risk_score"] > enriched[2]["risk_score"]

if __name__ == "__main__":
    test_score_boundary_conditions()
    test_score_monotonicity_severity()
    test_false_positive_demotion_power()
    test_missing_and_malformed_metadata_resilience()
    test_enrich_and_prioritized_ranking()
    print("ALL TESTS PASSED SUCCESSFULLY!")
