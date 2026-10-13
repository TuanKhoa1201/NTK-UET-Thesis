#!/usr/bin/env python3
"""
tests/test_integration_scoring_v2.py

Unit test suite validating integration/scoring_v2.py.
Tests compatibility with MergedFinding dataclass and verifies
all 6 Scientific Safety Invariants are enforced.
"""

import sys
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR / "integration"))

from scoring_v2 import SASTScoringEngineV2, score_finding_v2

class DummyMergedFinding:
    def __init__(self, severity="High", cwe="CWE-89", path_count=0, status="OpenGrep Only", iris_confirmed=None):
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

class TestIntegrationScoringV2(unittest.TestCase):

    def setUp(self):
        self.engine = SASTScoringEngineV2()

    def test_merged_finding_critical_safety_floor(self):
        """Critical finding with negative IRIS verdict must not drop below Safety Floor >= 40.0"""
        mf = DummyMergedFinding(severity="Critical", cwe="CWE-89", path_count=0, status="IRIS Posthoc Negative", iris_confirmed=False)
        scored = score_finding_v2(mf)
        self.assertGreaterEqual(scored["risk_score"], 40)
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

if __name__ == "__main__":
    unittest.main()
