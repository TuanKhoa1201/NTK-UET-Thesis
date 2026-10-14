import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integration"))

from report_generator import Finding, IrisVerdict, FindingMerger, SarifLoader
from scoring_v2 import score_finding_v2

FILE = "src/main/java/demo/SqlInjection.java"


class TestFusionPathCount(unittest.TestCase):

    def og(self):
        return Finding(
            rule_id="og-sqli", message="SQL Injection",
            severity="High", file=FILE, line=27, cwe="CWE-89"
        )

    def ir(self, count):
        return Finding(
            rule_id="iris-sqli", message="SQL Injection",
            severity="High", file=FILE, line=27,
            cwe="CWE-89", path_count=count
        )

    def verdict(self, value, index=0):
        return IrisVerdict(
            file=FILE, line=27, confirmed=value,
            cwe="CWE-89", path_count=1,
            rule_id=f"iris-path-0-{index}",
            locations=[(FILE, 27)]
        )

    def sarif_findings(self, count, duplicates=1):
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": FILE},
                "region": {"startLine": 27}
            }
        }

        flow = {
            "threadFlows": [
                {"locations": [{"location": location}]}
            ]
        }

        result = {
            "ruleId": "iris-sqli",
            "level": "error",
            "message": {"text": "SQL Injection"},
            "locations": [location],
            "codeFlows": [flow for _ in range(count)]
        }

        document = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "IRIS", "rules": []}},
                "results": [result for _ in range(duplicates)]
            }]
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp) / "cwe-089-posthoc-filter" /
                "results.sarif"
            )
            path.parent.mkdir()
            path.write_text(json.dumps(document), encoding="utf-8")
            return SarifLoader.load(path, "IRIS")

    def test_loader_counts_two_codeflows(self):
        findings = self.sarif_findings(2)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path_count, 2)

    def test_empty_posthoc_flows_not_a_finding(self):
        self.assertEqual(self.sarif_findings(0), [])

    def test_duplicate_sarif_does_not_double_count(self):
        findings = self.sarif_findings(2, duplicates=2)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].raw_count, 2)
        self.assertEqual(findings[0].path_count, 2)

    def test_two_positive_paths_one_finding(self):
        merged = FindingMerger().merge(
            [self.og()],
            [self.ir(2)],
            [self.verdict(True, 0), self.verdict(True, 1)]
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].path_count, 2)
        self.assertIs(merged[0].iris_confirmed, True)

        score = score_finding_v2(merged[0])
        self.assertEqual(
            score["score_components"]["exploitability"], 0.90
        )

    def test_mixed_verdict_only_positive_survives(self):
        merged = FindingMerger().merge(
            [self.og()],
            [self.ir(1)],
            [self.verdict(False, 0), self.verdict(True, 1)]
        )
        self.assertEqual(len(merged), 1)
        self.assertIs(merged[0].iris_confirmed, True)
        self.assertEqual(merged[0].path_count, 1)

    def test_negative_without_survivor_has_no_active_flow(self):
        merged = FindingMerger().merge(
            [self.og()], [], [self.verdict(False)]
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].status, "IRIS Posthoc Negative")
        self.assertEqual(merged[0].path_count, 0)

    def test_iris_only_preserves_paths(self):
        merged = FindingMerger().merge(
            [], [self.ir(2)], [self.verdict(True)]
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].path_count, 2)
        self.assertIs(merged[0].iris_confirmed, True)

    def test_opengrep_only_unchanged(self):
        merged = FindingMerger().merge([self.og()], [], [])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].status, "OpenGrep Only")
        self.assertEqual(merged[0].path_count, 0)


if __name__ == "__main__":
    unittest.main()
