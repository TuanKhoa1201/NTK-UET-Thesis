"""
parser.py

Normalize OpenGrep SARIF results into a simplified JSON
used by Dispatcher and IRIS.
"""

import json
import re
from pathlib import Path
from collections import Counter

from logger import Logger

logger = Logger()


# ==========================================================
# Helpers
# ==========================================================

def normalize_cwe(tags):

    if not tags:
        return []

    if isinstance(tags, str):
        tags = [tags]

    result = []

    for tag in tags:
        m = re.search(r"CWE-\d+", tag)

        if m:
            cwe = m.group()

            if cwe not in result:
                result.append(cwe)

    return result


# ==========================================================
# Parse SARIF
# ==========================================================

def parse_sarif(sarif_file):

    with open(sarif_file, "r", encoding="utf-8") as f:
        sarif = json.load(f)

    findings = []

    runs = sarif.get("runs", [])

    if not runs:
        return findings

    run = runs[0]

    rules = {}

    for rule in run.get("tool", {}).get("driver", {}).get("rules", []):

        rules[rule["id"]] = rule

    for result in run.get("results", []):

        rule_id = result.get("ruleId")

        rule = rules.get(rule_id, {})

        properties = rule.get("properties", {})

        tags = properties.get("tags", [])

        cwe = normalize_cwe(tags)

        location = result.get("locations", [{}])[0]

        physical = location.get("physicalLocation", {})

        artifact = physical.get("artifactLocation", {})

        region = physical.get("region", {})

        findings.append({

            "rule_id": rule_id,

            "path": artifact.get("uri", ""),

            "line": region.get("startLine", 1),

            "severity": result.get("level", "warning"),

            "message": result.get("message", {}).get("text", ""),

            "cwe": cwe,

            "tags": tags

        })

    return findings


# ==========================================================
# Pipeline API
# ==========================================================

def normalize_sarif(cfg):

    integration_dir = Path(__file__).resolve().parent

    input_file = (
        integration_dir / cfg.opengrep["output"]
    ).resolve()

    output_file = (
        integration_dir / cfg.paths["normalized_findings"]
    ).resolve()

    logger.start("Normalize SARIF")

    if not Path(input_file).exists():

        raise FileNotFoundError(input_file)

    findings = parse_sarif(input_file)

    Path(output_file).parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(output_file, "w", encoding="utf-8") as f:

        json.dump(
            findings,
            f,
            indent=2,
            ensure_ascii=False,
        )

    counter = Counter()

    for finding in findings:

        for cwe in finding["cwe"]:

            counter[cwe] += 1

    logger.info(f"Findings : {len(findings)}")

    for cwe, count in counter.items():

        logger.info(f"{cwe} : {count}")

    logger.file(output_file)

    logger.finish("Normalize SARIF")

    return findings


# ==========================================================
# Standalone test
# ==========================================================

if __name__ == "__main__":

    from config import Config

    cfg = Config()

    normalize_sarif(cfg)
