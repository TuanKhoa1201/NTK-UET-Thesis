"""
dispatcher.py

Create IRIS jobs from normalized OpenGrep findings.
"""

import json
from pathlib import Path

from logger import Logger

logger = Logger()

# ==========================================================
# Supported IRIS queries
# ==========================================================

SUPPORTED_CWE = {
    "CWE-22": "cwe-022wLLM",
    "CWE-23": "cwe-022wLLM",
    "CWE-78": "cwe-078wLLM",
    "CWE-79": "cwe-079wLLM",
    "CWE-89": "cwe-089wLLM",
}

# ==========================================================
# Helpers
# ==========================================================

def load_findings(file_path: str) -> list:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_jobs(
    findings: list,
    configured_queries=None,
    mode: str = "detected",
) -> list:
    """
    Build one IRIS job for each unique IRIS query.

    Modes:
        detected
            Preserve the original behavior: create jobs only from
            CWE values found by OpenGrep and normalized by parser.py.

        configured
            Create jobs only from cfg.iris["queries"].

        hybrid
            Union of OpenGrep-detected queries and configured queries.

    Configured queries do not create or modify OpenGrep findings.
    They only control which IRIS/CodeQL analyses are executed.
    """

    valid_modes = {"detected", "configured", "hybrid"}

    if mode not in valid_modes:
        raise ValueError(
            f"Unsupported iris.dispatch_mode: {mode!r}. "
            f"Expected one of: {sorted(valid_modes)}"
        )

    if configured_queries is None:
        configured_queries = []

    if not isinstance(configured_queries, list):
        raise TypeError("iris.queries must be a list")

    query_map = {}

    # ---------------------------------------------------------
    # OpenGrep-detected routing (original behavior)
    # ---------------------------------------------------------
    if mode in {"detected", "hybrid"}:

        for finding in findings:

            for cwe in finding.get("cwe", []):

                query = SUPPORTED_CWE.get(cwe)

                if query is None:
                    continue

                query_map.setdefault(query, set()).add(cwe)

    # ---------------------------------------------------------
    # Explicitly configured IRIS analyses
    # ---------------------------------------------------------
    if mode in {"configured", "hybrid"}:

        supported_queries = set(SUPPORTED_CWE.values())

        for query in configured_queries:

            if query not in supported_queries:
                raise ValueError(
                    f"Unsupported configured IRIS query: {query!r}"
                )

            covered_cwes = {
                cwe
                for cwe, mapped_query in SUPPORTED_CWE.items()
                if mapped_query == query
            }

            query_map.setdefault(query, set()).update(covered_cwes)

    jobs = []

    for query in sorted(query_map.keys()):

        jobs.append(
            {
                "query": query,
                "cwes": sorted(query_map[query]),
            }
        )

    return jobs


def save_jobs(jobs: list, output_file: str):

    Path(output_file).parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            jobs,
            f,
            indent=2,
            ensure_ascii=False,
        )


# ==========================================================
# Pipeline API
# ==========================================================

def create_jobs(cfg):

    integration_dir = Path(__file__).resolve().parent

    input_file = (
        integration_dir / cfg.paths["normalized_findings"]
    ).resolve()

    output_file = (
        integration_dir / cfg.paths["iris_jobs"]
    ).resolve()

    logger.start("Create IRIS Jobs")

    if not Path(input_file).exists():
        raise FileNotFoundError(input_file)

    findings = load_findings(input_file)

    dispatch_mode = cfg.iris.get("dispatch_mode", "detected")
    configured_queries = cfg.iris.get("queries", [])

    jobs = build_jobs(
        findings,
        configured_queries=configured_queries,
        mode=dispatch_mode,
    )

    save_jobs(jobs, output_file)

    logger.info(f"Total findings : {len(findings)}")
    logger.info(f"Dispatch mode  : {dispatch_mode}")
    logger.info(f"IRIS jobs      : {len(jobs)}")

    for job in jobs:

        logger.info(
            f"{', '.join(job['cwes'])} -> {job['query']}"
        )

    logger.file(output_file)

    logger.finish("Create IRIS Jobs")

    return jobs


# ==========================================================
# Standalone test
# ==========================================================

if __name__ == "__main__":

    from config import Config

    cfg = Config()

    create_jobs(cfg)
