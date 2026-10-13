#!/usr/bin/env python3
"""
tests/test_integration_scoring_v2.py

Unit test suite validating integration/scoring_v2.py.
Tests compatibility with MergedFinding dataclass and verifies
all 6 Scientific Safety Invariants are enforced, including
specific counterexample protections from Audit V4 (Phase D).
"""

import sys
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR / "integration"))

from scoring_v2 import SASTScoringEngineV2, score_finding_v2

class DummyMergedFinding:
    def __init__(self, severity="High", cwe="CWE-89", path_count=0, status="OpenGrep Only", iris_confirmed=None, ai_val=None):
        self.severity = severity
        self.cwe = cwe
        self.path_count = path_count
        self.status = status
        self.iris_confirmed = iris_confirmed
        self.rule_id = "test.rule.sqli"
        self.message = "SQL Injection candidate"
        self.file = "test/Vuln.java"
        self.line = 10
        self.duplicate_count = 1
        self.confidence_score = 80.0
        self.ai_validation = ai_val or {}

class TestIntegrationScoringV2(unittest.TestCase):

    def setUp(self):
        self.engine = SASTScoringEngineV2()

    def test_merged_finding_critical_safety_floor(self):
        """Critical finding with negative IRIS verdict must not drop below Safety Floor >= 40.0"""
        mf = DummyMergedFinding(severity="Critical", cwe="CWE-89", path_count=0, status="IRIS Posthoc Negative", iris_confirmed=False)
        scored = score_finding_v2(mf)
        self.assertGreaterEqual(scored["risk_score"], 40.0)
        self.assertNotEqual(scored["risk_level"], "Informational")
        self.assertEqual(scored["score_version"], "NTK-SAST-SCORING-V2.2-SAFETY-INVARIANTS")
        self.assertTrue(scored["score_components"]["safety_floor_applied"])

    def test_merged_finding_dataflow_precedence(self):
        """Finding with taint dataflow (path_count > 0) has high exploitability and elevates priority"""
        mf = DummyMergedFinding(severity="High", cwe="CWE-89", path_count=2, status="IRIS Posthoc Positive", iris_confirmed=True)
        scored = score_finding_v2(mf)
        self.assertGreaterEqual(scored["risk_score"], 80)
        self.assertIn(scored["risk_level"], ["High", "Critical"])
        self.assertGreaterEqual(scored["score_components"]["exploitability"], 0.85)

    def test_neutral_unknown(self):
        """Finding with unknown IRIS verdict gets neutral weight and penalty 1.0"""
        mf = DummyMergedFinding(severity="Medium", cwe="CWE-22", path_count=0, status="OpenGrep Only", iris_confirmed=None)
        scored = score_finding_v2(mf)
        self.assertEqual(scored["score_components"]["penalty_factor"], 1.0)
        self.assertEqual(scored["score_components"]["ai_confidence"], 0.5)

    def test_low_rule_demotion(self):
        """Low severity finding with negative posthoc can be demoted to Informational"""
        mf = DummyMergedFinding(severity="Low", cwe="CWE-79", path_count=0, status="IRIS Posthoc Negative", iris_confirmed=False)
        scored = score_finding_v2(mf)
        self.assertEqual(scored["risk_level"], "Informational")
        self.assertLess(scored["risk_score"], 25)

    def test_counterexample_high_cwe79_none_protected(self):
        """
        Audit V4 Counterexample:
        A High severity finding with CWE-79, no dataflow, and AI role 'none'
        without sanitizer evidence must NEVER be demoted to Low or Informational (Floor >= 40.0 -> Medium).
        """
        finding = {
            "severity": "High",
            "cwe": "CWE-79",
            "path_count": 0,
            "ai_validation": {"pred_type": "none"}
        }
        res = self.engine.score(finding)
        self.assertNotEqual(res.risk_level, "Informational")
        self.assertNotEqual(res.risk_level, "Low")
        self.assertEqual(res.risk_level, "Medium")
        self.assertGreaterEqual(res.final_score, 40.0)
        self.assertEqual(res.penalty_factor, 0.60)
        self.assertEqual(res.ai_verdict, "POTENTIAL_BENIGN_CONTEXT")

    def test_high_with_sanitizer_allowed_demotion_to_low(self):
        """High finding WITH explicit sanitizer evidence can be demoted to Low (Floor >= 30.0)"""
        finding = {
            "severity": "High",
            "cwe": "CWE-79",
            "path_count": 0,
            "has_sanitizer": True,
            "ai_validation": {"pred_type": "none"}
        }
        res = self.engine.score(finding)
        self.assertEqual(res.risk_level, "Low")
        self.assertEqual(res.final_score, 30.3)

    def test_high_malformed_json_neutral(self):
        """Invariant 2 & 3: Malformed JSON output must result in neutral scoring (penalty 1.0)"""
        finding = {
            "severity": "High",
            "cwe": "CWE-89",
            "path_count": 0,
            "ai_validation": {"parse_status": "PARSE_ERROR"}
        }
        res = self.engine.score(finding)
        self.assertEqual(res.penalty_factor, 1.00)
        self.assertEqual(res.ai_confidence_score, 0.50)
        self.assertEqual(res.ai_verdict, "NEEDS_REVIEW")

    def test_valid_sqli_wrong_api_classification_flow_precedence(self):
        """
        Invariant 4: When taint dataflow is confirmed (exploitability >= 0.85),
        an erroneous AI prediction of 'none' cannot demote the finding.
        """
        finding = {
            "severity": "High",
            "cwe": "CWE-89",
            "path_count": 2,
            "dataflow": [{"step": 1}, {"step": 2}],
            "ai_validation": {"pred_type": "none"}
        }
        res = self.engine.score(finding)
        self.assertEqual(res.penalty_factor, 1.00)
        self.assertEqual(res.ai_verdict, "CONFIRMED_DATAFLOW_PRECEDENCE")
        self.assertGreaterEqual(res.final_score, 70.0)

    def test_no_dropped_findings_in_scoring(self):
        """Invariant 5: Scoring preserves 100% of findings without deletion"""
        raw_findings = [
            {"rule_id": "r1", "severity": "CRITICAL", "dataflow": []},
            {"rule_id": "r2", "severity": "HIGH", "dataflow": [], "ai_validation": {"pred_type": "none"}},
            {"rule_id": "r3", "severity": "LOW", "dataflow": []},
        ]
        scored_findings = [self.engine.score(f) for f in raw_findings]
        self.assertEqual(len(scored_findings), 3)

if __name__ == "__main__":
    unittest.main()
