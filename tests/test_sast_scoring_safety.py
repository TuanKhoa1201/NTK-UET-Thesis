#!/usr/bin/env python3
"""
test_sast_scoring_safety.py

Unit test suite validating the 6 Scientific Safety Invariants of SAST Scoring Engine V2.2.
Guarantees that Critical/High findings are protected from improper demotion
and that local AI predictions obey conservative security properties.
"""

import sys
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR / "simple_semgrepAI"))

from semgrepai.scoring.sast_scoring_engine import SASTScoringEngine, ScoreBreakdown

class TestSASTScoringSafetyInvariants(unittest.TestCase):

    def setUp(self):
        self.scorer = SASTScoringEngine()

    def test_invariant_1_api_role_none_not_false_positive_alone(self):
        """Invariant 1: API role 'none' alone does not make a finding a False Positive."""
        finding = {
            "rule_id": "test.rule.rce",
            "severity": "CRITICAL",
            "message": "Potential OS command execution",
            "path": "com/example/Exec.java",
            "line": 42,
            "dataflow": [],
            "metadata": {"cwe": ["CWE-78: Command Injection"], "confidence": "HIGH"},
            "ai_validation": {
                "is_valid": None,
                "verdict": "NEEDS_REVIEW",
                "api_role": "none",
                "justification": "AI classified method as none"
            }
        }
        res = self.scorer.score_finding(finding)
        self.assertNotEqual(res.risk_level, "BENIGN_OR_FP")
        self.assertGreaterEqual(res.final_score, 40.0)
        self.assertEqual(res.ai_verdict, "NEEDS_REVIEW")

    def test_invariant_2_missing_dataflow_asymmetry(self):
        """Invariant 2: Missing dataflow is not proof of safety (base exploitability = 0.30)."""
        finding = {
            "rule_id": "test.rule.sqli",
            "severity": "ERROR",
            "dataflow": []
        }
        e_score = self.scorer.calculate_exploitability(finding)
        self.assertEqual(e_score, 0.30)

    def test_invariant_3_neutral_unknowns(self):
        """Invariant 3: Unknown or parse-error model output gets neutral weight and gamma = 1.0."""
        finding = {
            "rule_id": "test.rule.sqli",
            "severity": "ERROR",
            "dataflow": [],
            "ai_validation": {
                "is_valid": None,
                "verdict": "NEEDS_REVIEW",
                "api_role": "unknown",
                "parse_status": "PARSE_ERROR"
            }
        }
        ai_score, penalty, verdict = self.scorer.evaluate_ai_validation(finding)
        self.assertEqual(ai_score, 0.50)
        self.assertEqual(penalty, 1.00)
        self.assertEqual(verdict, "NEEDS_REVIEW")

    def test_invariant_4_flow_precedence(self):
        """Invariant 4: Complete dataflow trace (E >= 0.85) cannot be overridden by AI 'none'."""
        finding = {
            "rule_id": "test.rule.sqli",
            "severity": "ERROR",
            "dataflow": [
                {"type": "source", "file": "Foo.java", "line": 10},
                {"type": "intermediate", "file": "Foo.java", "line": 15},
                {"type": "sink", "file": "Foo.java", "line": 20}
            ],
            "ai_validation": {
                "is_valid": False,
                "verdict": "SUSPECTED_FALSE_POSITIVE",
                "api_role": "none"
            }
        }
        ai_score, penalty, verdict = self.scorer.evaluate_ai_validation(finding)
        self.assertEqual(penalty, 1.00)
        self.assertEqual(verdict, "NEEDS_REVIEW")

    def test_invariant_5_audit_trail_preservation(self):
        """Invariant 5: No finding is ever dropped or deleted during scoring."""
        findings = [
            {"id": "f1", "rule_id": "r1", "severity": "CRITICAL", "dataflow": []},
            {"id": "f2", "rule_id": "r2", "severity": "LOW", "dataflow": [], "ai_validation": {"api_role": "none", "verdict": "SUSPECTED_FALSE_POSITIVE"}},
            {"id": "f3", "rule_id": "r3", "severity": "INFO", "dataflow": []}
        ]
        enriched = self.scorer.enrich_findings(findings)
        self.assertEqual(len(enriched), 3)
        ids = [f["id"] for f in enriched]
        self.assertIn("f1", ids)
        self.assertIn("f2", ids)
        self.assertIn("f3", ids)

    def test_invariant_6_critical_safety_floor(self):
        """Invariant 6: Critical/Error finding with low precision and AI 'none' is capped at Floor >= 40.0."""
        finding = {
            "rule_id": "test.critical.xxe",
            "severity": "ERROR",
            "message": "Critical XXE parser injection",
            "dataflow": [],
            "metadata": {"cwe": [], "confidence": "LOW"},
            "ai_validation": {
                "is_valid": False,
                "verdict": "SUSPECTED_FALSE_POSITIVE",
                "api_role": "none"
            }
        }
        res = self.scorer.score_finding(finding)
        # In old V2.1 scoring, this dropped to 18.7 (BENIGN_OR_FP)
        # In V2.2, calculated score is 39.9, so Safety Floor (40.0) is triggered
        self.assertEqual(res.final_score, 40.0)
        self.assertIn(res.risk_level, ["MEDIUM", "HIGH", "CRITICAL"])
        self.assertNotEqual(res.risk_level, "BENIGN_OR_FP")
        self.assertTrue(res.safety_floor_applied)

    def test_benign_demotion_allowed_for_low_severity(self):
        """Legitimate conservative demotion: Low severity without dataflow and AI 'none' safely demoted."""
        finding = {
            "rule_id": "test.low.info",
            "severity": "LOW",
            "message": "Minor code smell",
            "dataflow": [],
            "metadata": {"confidence": "LOW"},
            "ai_validation": {
                "is_valid": False,
                "verdict": "SUSPECTED_FALSE_POSITIVE",
                "api_role": "none"
            }
        }
        res = self.scorer.score_finding(finding)
        self.assertEqual(res.penalty_factor, 0.35)
        self.assertEqual(res.risk_level, "BENIGN_OR_FP")
        self.assertFalse(res.safety_floor_applied)

if __name__ == "__main__":
    unittest.main()
