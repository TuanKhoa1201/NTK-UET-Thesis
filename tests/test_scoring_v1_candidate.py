import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integration.scoring_v1 import score_finding


def score(**changes):
    finding = {
        "severity": "High",
        "cwe": "CWE-89",
        "iris_confirmed": None,
        "path_count": 0,
        "opengrep": True,
        "iris": False,
    }
    finding.update(changes)
    return score_finding(finding)


class ScoringCandidateTests(unittest.TestCase):

    def test_output_contract(self):
        result = score()
        self.assertTrue({
            "risk_score", "risk_level", "score_version",
            "score_components", "score_evidence",
            "score_explanation",
        }.issubset(result))

    def test_deterministic(self):
        self.assertEqual(score(), score())

    def test_bounds(self):
        for severity in (
            "Critical", "High", "Medium", "Low", "Unknown"
        ):
            value = score(severity=severity)["risk_score"]
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 100)

    def test_severity_order(self):
        values = [
            score(severity=s)["risk_score"]
            for s in ("Critical", "High", "Medium", "Low")
        ]
        self.assertEqual(values, sorted(values, reverse=True))
        self.assertEqual(len(set(values)), 4)

    def test_positive_evidence(self):
        baseline = score()["risk_score"]
        positive = score(
            iris_confirmed=True, path_count=1
        )["risk_score"]
        self.assertGreater(positive, baseline)

    def test_negative_evidence(self):
        baseline = score()["risk_score"]
        negative = score(
            iris_confirmed=False
        )["risk_score"]
        self.assertLess(negative, baseline)

    def test_path_count_saturation(self):
        a = score(iris_confirmed=True, path_count=1)
        b = score(iris_confirmed=True, path_count=100)
        self.assertEqual(a["risk_score"], b["risk_score"])

    def test_missing_verdict(self):
        a = score(iris=False, iris_confirmed=None)
        b = score(iris=True, iris_confirmed=None)
        self.assertEqual(a["risk_score"], b["risk_score"])

    def test_no_duplicate_reward(self):
        a = score_finding({
            "severity": "High", "cwe": "CWE-89",
            "duplicate_count": 1
        })
        b = score_finding({
            "severity": "High", "cwe": "CWE-89",
            "duplicate_count": 100
        })
        self.assertEqual(a["risk_score"], b["risk_score"])

    def test_critical_possible(self):
        result = score(
            severity="Critical",
            iris_confirmed=True,
            path_count=1
        )
        self.assertEqual(result["risk_level"], "Critical")


if __name__ == "__main__":
    unittest.main(verbosity=2)
