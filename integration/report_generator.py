#!/usr/bin/env python3
"""
report_generator.py
====================

Professional SAST reporting engine for the OpenGrep -> parser.py ->
dispatcher.py -> runner.py -> IRIS pipeline.

This module merges OpenGrep SARIF findings with IRIS (CodeQL + LLM
triage) SARIF findings and IRIS's ``results.json`` confirmation/dataflow
data into a single, presentation-ready security report emitted as JSON,
CSV, SARIF 2.1.0 and a self-contained interactive HTML dashboard.

Public API
----------
    generate_report(cfg) -> dict
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html as html_lib
import json
import logging
import math
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("report_generator")

if not logging.getLogger().handlers:  # pragma: no cover - environment dependent
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

REPORT_GENERATOR_VERSION = "2.0.0"

__all__ = ["generate_report"]

# ---------------------------------------------------------------------------
# Constants / lookup tables
# ---------------------------------------------------------------------------

SEVERITY_ORDER: list[str] = ["Critical", "High", "Medium", "Low"]

SEVERITY_SCORES: dict[str, int] = {
    "Critical": 95,
    "High": 80,
    "Medium": 55,
    "Low": 25,
}
DEFAULT_SEVERITY_SCORE = 50

_CWE_PATTERN = re.compile(r"cwe-?(\d+)", re.IGNORECASE)

CWE_NAMES: dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

CWE_IMPORTANCE_WEIGHTS: dict[str, int] = {
    "CWE-89": 20, "CWE-78": 20, "CWE-94": 20, "CWE-502": 20, "CWE-798": 20,
    "CWE-327": 18, "CWE-611": 18, "CWE-295": 16, "CWE-918": 14,
    "CWE-416": 14, "CWE-787": 14, "CWE-79": 12, "CWE-22": 12, "CWE-306": 12,
    "CWE-352": 10, "CWE-434": 10, "CWE-862": 10, "CWE-863": 10,
    "CWE-476": 8, "CWE-190": 8, "CWE-125": 8, "CWE-522": 8,
    "CWE-200": 6, "CWE-732": 6, "CWE-330": 6, "CWE-311": 6, "CWE-601": 6,
    "CWE-20": 4,
}

CWE_REMEDIATION_TIPS: dict[str, str] = {
    "CWE-89": "Use parameterized queries or an ORM; never concatenate user input into SQL.",
    "CWE-78": "Avoid invoking a shell with user input; prefer safe APIs or strict allow-lists.",
    "CWE-79": "Encode output contextually and adopt a Content-Security-Policy.",
    "CWE-22": "Canonicalize and validate file paths against an allow-listed base directory.",
    "CWE-502": "Avoid deserializing untrusted data; prefer safe formats (JSON) with schema validation.",
    "CWE-798": "Move credentials to a secrets manager or environment variables; rotate exposed secrets.",
    "CWE-327": "Replace weak algorithms (MD5/SHA1/DES/RC4) with vetted modern primitives (AES-GCM, SHA-256+).",
    "CWE-295": "Enforce certificate validation; never disable TLS verification in production code.",
    "CWE-611": "Disable external entity resolution in XML parsers.",
    "CWE-352": "Use anti-CSRF tokens and SameSite cookies for state-changing requests.",
    "CWE-434": "Validate file type/content and store uploads outside the web root.",
    "CWE-918": "Validate and allow-list outbound request destinations; block internal address ranges.",
    "CWE-306": "Require authentication on all state-changing or sensitive endpoints.",
    "CWE-862": "Add explicit authorization checks before granting access to resources.",
    "CWE-863": "Re-review authorization logic for edge cases and privilege boundaries.",
    "CWE-200": "Remove sensitive data from logs, error messages, and API responses.",
    "CWE-732": "Apply least-privilege permissions to files and critical resources.",
    "CWE-522": "Store credentials hashed/encrypted, never in plaintext or client-accessible storage.",
    "CWE-330": "Use a cryptographically secure random generator (e.g. `secrets`) instead of `random`.",
    "CWE-311": "Encrypt sensitive data in transit and at rest.",
    "CWE-416": "Audit object lifetimes; avoid using freed memory or references.",
    "CWE-787": "Add bounds checking before writes; use memory-safe abstractions.",
    "CWE-125": "Add bounds checking before reads; validate buffer sizes.",
    "CWE-20": "Centralize and strengthen input validation at trust boundaries.",
    "CWE-94": "Never evaluate or exec() untrusted input; use safe parsers instead.",
    "CWE-601": "Validate redirect targets against an allow-list of trusted destinations.",
    "CWE-190": "Validate numeric ranges and use overflow-checked arithmetic.",
    "CWE-476": "Add null/None checks before dereferencing potentially-empty values.",
}

STATUS_ORDER: list[str] = [
    "IRIS Posthoc Positive",
    "OpenGrep + IRIS Match",
    "IRIS Only",
    "OpenGrep Only",
    "IRIS Posthoc Negative",
    "Unknown",
]

# ---------------------------------------------------------------------------
# Small generic utilities
# ---------------------------------------------------------------------------

def _get_value(source: Any, *keys: str, default: Any = None) -> Any:
    if source is None:
        return default
    for key in keys:
        try:
            if hasattr(source, key):
                val = getattr(source, key)
                if val is not None:
                    return val
        except Exception:
            pass
        try:
            if isinstance(source, Mapping) and key in source:
                val = source[key]
                if val is not None:
                    return val
        except Exception:
            pass
        try:
            val = source[key]  # type: ignore[index]
            if val is not None:
                return val
        except Exception:
            pass
    return default

def _first_present(d: Any, *keys: str) -> Any:
    if not isinstance(d, dict):
        return None
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    try:
        lower_map = {str(k).lower(): v for k, v in d.items()}
    except Exception:
        return None
    for k in keys:
        v = lower_map.get(k.lower())
        if v is not None:
            return v
    return None

def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)

def normalize_path(raw_path: str) -> str:
    if not raw_path:
        return "unknown"
    cleaned = str(raw_path).replace("\\", "/").strip()
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    return cleaned or "unknown"

def normalize_severity(level: str, security_severity: Optional[float]) -> str:
    if security_severity is not None:
        try:
            sec = float(security_severity)
            if sec >= 9.0:
                return "Critical"
            if sec >= 7.0:
                return "High"
            if sec >= 4.0:
                return "Medium"
            return "Low"
        except (TypeError, ValueError):
            pass

    level_norm = str(level or "").strip().capitalize()
    if level_norm in SEVERITY_SCORES:
        return level_norm

    mapping = {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}
    return mapping.get(str(level or "").strip().lower(), "Medium")

def _extract_security_severity(obj: dict) -> Optional[float]:
    if not isinstance(obj, dict):
        return None
    props = obj.get("properties", {})
    if not isinstance(props, dict):
        return None
    raw = props.get("security-severity")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None

def _extract_cwe(rule_def: dict, result: dict) -> Optional[str]:
    candidates: list[str] = []
    for obj in (result, rule_def):
        if not isinstance(obj, dict):
            continue
        props = obj.get("properties", {})
        if not isinstance(props, dict):
            continue
        tags = props.get("tags", [])
        if isinstance(tags, list):
            candidates.extend(str(t) for t in tags)
        cwe_prop = props.get("cwe")
        if cwe_prop:
            if isinstance(cwe_prop, list):
                candidates.extend(str(c) for c in cwe_prop)
            else:
                candidates.append(str(cwe_prop))
    for c in candidates:
        m = _CWE_PATTERN.search(c)
        if m:
            return f"CWE-{int(m.group(1))}"
    return None

def _extract_cwe_from_value(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    m = _CWE_PATTERN.search(str(raw))
    if m:
        return f"CWE-{int(m.group(1))}"
    return None

def _more_severe(a: str, b: str) -> str:
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return a if order.get(a, len(order)) <= order.get(b, len(order)) else b

def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default

def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    message: str
    severity: str
    file: str
    line: int
    end_line: int = 0
    cwe: Optional[str] = None
    rule_name: Optional[str] = None
    tool: str = ""
    raw_count: int = 1

@dataclass
class IrisVerdict:
    file: str
    line: int
    confirmed: Optional[bool] = None
    confidence: Optional[float] = None
    cwe: Optional[str] = None
    path_count: int = 0
    reasoning: Optional[str] = None
    rule_id: Optional[str] = None
    # Every (file, line) location along the IRIS dataflow path (source,
    # intermediate steps, sink). `file`/`line` above is normally the sink
    # (last step), but OpenGrep may flag the same vulnerability at any
    # point on the path, so matching is attempted against all of them.
    locations: list = field(default_factory=list)

@dataclass
class MergedFinding:
    fingerprint: str
    rule_id: str
    opengrep_rule_id: Optional[str]
    iris_rule_id: Optional[str]
    file: str
    line: int
    end_line: int
    severity: str
    message: str
    cwe: Optional[str]
    opengrep: bool
    iris: bool
    iris_confirmed: Optional[bool]
    status: str
    source: str
    confidence_score: Optional[float]
    confidence_label: str
    path_count: int
    duplicate_count: int
    reasoning: Optional[str]
    risk_score: int
    risk_level: str
    snippet: Optional[dict] = field(default=None, compare=False)

    def finalize(self) -> None:
        if self.iris_confirmed is True:
            self.status = "IRIS Posthoc Positive"
        elif self.iris_confirmed is False:
            self.status = "IRIS Posthoc Negative"
        elif self.opengrep and self.iris:
            self.status = "OpenGrep + IRIS Match"
        elif self.opengrep:
            self.status = "OpenGrep Only"
        elif self.iris:
            self.status = "IRIS Only"
        else:
            self.status = "Unknown"

        if self.opengrep and self.iris:
            self.source = "OpenGrep + IRIS"
        elif self.opengrep:
            self.source = "OpenGrep"
        elif self.iris:
            self.source = "IRIS"
        else:
            self.source = "Unknown"

        if self.confidence_score is not None:
            if self.confidence_score >= 90:
                self.confidence_label = "Very High"
            elif self.confidence_score >= 70:
                self.confidence_label = "High"
            elif self.confidence_score >= 40:
                self.confidence_label = "Medium"
            else:
                self.confidence_label = "Low"
        else:
            fallback = {
                "IRIS Posthoc Positive": "Very High",
                "IRIS Posthoc Negative": "Low",
                "OpenGrep + IRIS Match": "High",
                "OpenGrep Only": "Medium",
                "IRIS Only": "Medium",
                "Unknown": "Low",
            }
            self.confidence_label = fallback.get(self.status, "Medium")

@dataclass
class IrisArtifacts:
    directories: list[Path] = field(default_factory=list)
    results_json_files: list[Path] = field(default_factory=list)
    results_sarif_files: list[Path] = field(default_factory=list)
    stats_json_files: list[Path] = field(default_factory=list)

    @property
    def has_any(self) -> bool:
        return bool(self.results_json_files or self.results_sarif_files or self.stats_json_files)

# ---------------------------------------------------------------------------
# Configuration resolution
# ---------------------------------------------------------------------------

class ConfigResolver:
    def __init__(self, cfg: Any) -> None:
        self.warnings: list[str] = []

        report_cfg = _get_value(cfg, "report")
        paths_cfg = _get_value(cfg, "paths")
        opengrep_cfg = _get_value(cfg, "opengrep")
        iris_cfg = _get_value(cfg, "iris")
        project_cfg = _get_value(cfg, "project")

        self.integration_dir = Path(__file__).resolve().parent
        self.project_root = self.integration_dir.parent

        self.report_output_dir: Path = self._resolve_path(
            _get_value(report_cfg, "output_dir", "output", "reports_dir", "dir", default="reports"),
            self.project_root,
        )

        self.normalized_findings_path: Optional[Path] = self._resolve_optional_path(
            _get_value(paths_cfg, "normalized_findings", "normalized_findings_path"),
            self.integration_dir,
        )
        self.iris_jobs_path: Optional[Path] = self._resolve_optional_path(
            _get_value(paths_cfg, "iris_jobs", "iris_jobs_path"),
            self.integration_dir,
        )
        self.opengrep_sarif_path: Optional[Path] = self._resolve_optional_path(
            _get_value(opengrep_cfg, "output", "output_path", "sarif", "sarif_path", "result", "results"),
            self.integration_dir,
        )
        self.source_root: Optional[Path] = self._resolve_optional_path(
            _get_value(paths_cfg, "source_root", "project_root", "repo_root", "source_dir", "target"),
            self.project_root,
        )

        self.project_name: str = self._resolve_project_name(
            project_cfg,
            _get_value(report_cfg, "project_name", "project", default=None),
        )
        self.project_slug: str = self._resolve_project_slug(
            project_cfg,
            self.project_name,
        )

        iris_base_dir = self._resolve_path(
            _get_value(iris_cfg, "output_dir", "output_base", "output", "results_dir", "base_dir", default="output"),
            self.project_root,
        )
        self.run_id: Optional[str] = _get_value(iris_cfg, "run_id", "run", "id", default=None)
        if not self.run_id:
            self.run_id = _get_value(report_cfg, "run_id", default=None)

        self.analyzer_version: str = str(
            _get_value(iris_cfg, "version", default=None)
            or _get_value(report_cfg, "analyzer_version", "version", default=None)
            or _get_value(cfg, "version", "analyzer_version", default=REPORT_GENERATOR_VERSION)
        )

        locator = IrisOutputLocator(iris_base_dir, self.project_slug, self.run_id)
        self.iris_artifacts: IrisArtifacts = locator.locate()

        if self.opengrep_sarif_path is None:
            self._warn("cfg.opengrep['output'] could not be resolved to a path; will fall back to normalized findings if available.")
        elif not self.opengrep_sarif_path.is_file():
            self._warn(f"OpenGrep SARIF path does not exist: {self.opengrep_sarif_path}")

        if not self.iris_artifacts.has_any:
            self._warn("No IRIS output artifacts were located; report will be OpenGrep-only.")

    def _warn(self, message: str) -> None:
        self.warnings.append(message)
        logger.warning(message)

    def _resolve_project_name(self, project_cfg: Any, fallback: Any = None) -> str:
        if isinstance(project_cfg, str) and project_cfg.strip():
            return project_cfg.strip()
        name = _get_value(project_cfg, "name", "project_name", "id", "slug", default=None)
        if name:
            return str(name)
        if fallback:
            return str(fallback)
        if project_cfg is not None and not (isinstance(project_cfg, Mapping) and not project_cfg):
            try:
                text = str(project_cfg).strip()
                if text and not text.startswith("<"):
                    return text
            except Exception:
                pass
        if self.opengrep_sarif_path is not None:
            self._warn("cfg.project not resolved; deriving project name from OpenGrep output filename.")
            return self.opengrep_sarif_path.stem
        self._warn("Could not determine project name from cfg.project; using 'unknown-project'.")
        return "unknown-project"

    @staticmethod
    def _resolve_project_slug(project_cfg: Any, fallback: str) -> str:
        source = _get_value(
            project_cfg,
            "source",
            "path",
            "root",
            default=None,
        )

        if source:
            try:
                name = Path(str(source)).expanduser().name
                if name:
                    return name
            except Exception:
                pass

        return re.sub(
            r"[^A-Za-z0-9_.\\-]",
            "_",
            str(fallback),
        )

    @staticmethod
    def _resolve_path(value: Any, base_dir: Optional[Path] = None) -> Path:
        try:
            path = Path(str(value)).expanduser()

            if not path.is_absolute() and base_dir is not None:
                path = base_dir / path

            return path.resolve()
        except Exception:
            fallback = Path("reports")
            if base_dir is not None:
                fallback = base_dir / fallback
            return fallback.resolve()

    @staticmethod
    def _resolve_optional_path(
        value: Any,
        base_dir: Optional[Path] = None,
    ) -> Optional[Path]:
        if not value:
            return None

        try:
            path = Path(str(value)).expanduser()

            if not path.is_absolute() and base_dir is not None:
                path = base_dir / path

            return path.resolve()
        except Exception:
            return None


class IrisOutputLocator:
    # results.json  -> confirmation / dataflow verdicts (IrisResultsLoader)
    # results.sarif -> IRIS SARIF findings (SarifLoader)
    # stats.json    -> aggregate run statistics (IrisStatsLoader)
    RESULT_FILENAMES = ("results.json", "iris_results.json", "results_final.json")
    SARIF_FILENAMES = ("results.sarif", "iris.sarif", "results.sarif.json", "iris_results.sarif", "results_pp.sarif")
    STATS_FILENAMES = ("stats.json", "statistics.json", "iris_stats.json")
    MAX_RECURSIVE_SCAN = 5000

    def __init__(self, base_dir: Path, project: str, run_id: Optional[str]) -> None:
        self.base_dir = base_dir
        self.project = project
        self.run_id = run_id

    def locate(self) -> IrisArtifacts:
        candidates = self._candidate_directories()
        logger.info("IRIS base_dir = %s", self.base_dir)

        for c in candidates:
            logger.info("Candidate: %s exists=%s", c, c.exists() if c else False)

        best_artifacts: Optional[IrisArtifacts] = None
        for root in candidates:
            logger.info("Scanning candidate: %s", root)
            try:
                if not root or not root.is_dir():
                    continue
                cwe_dirs = self._find_cwe_dirs(root)
                if not cwe_dirs:
                    continue
                artifacts = self._collect_from_directories(cwe_dirs)
                if artifacts.has_any:
                    logger.info(
                        "Located IRIS artifacts in %d 'cwe-*' director%s under %s "
                        "(results.json=%d, results.sarif=%d, stats.json=%d)",
                        len(artifacts.directories),
                        "y" if len(artifacts.directories) == 1 else "ies",
                        root,
                        len(artifacts.results_json_files),
                        len(artifacts.results_sarif_files),
                        len(artifacts.stats_json_files),
                    )
                    # A more specific candidate (e.g. base/project/run_id) that yields
                    # artifacts is preferred, but keep scanning broader fallbacks only
                    # if nothing was found yet.
                    return artifacts
            except Exception:
                logger.debug("Error while probing candidate IRIS root %s", root, exc_info=True)

        return best_artifacts if best_artifacts is not None else IrisArtifacts()

    @classmethod
    def _find_cwe_dirs(cls, root: Path) -> list[Path]:
        """Recursively discover every directory whose name starts with 'cwe-'.

        IRIS runs typically emit several sibling directories per CWE
        (e.g. ``cwe-089wLLM``, ``cwe-089wLLM-final``,
        ``cwe-089wLLM-posthoc-filter``), each of which may hold a different
        subset of ``results.json`` / ``results.sarif`` / ``stats.json``. All
        of them are discovered here; ``_collect_from_directories`` decides
        what each one actually contributes.
        """
        found: list[Path] = []
        try:
            if root.is_dir() and root.name.lower().startswith("cwe-"):
                found.append(root)
        except OSError:
            pass

        scanned = 0
        try:
            for path in root.rglob("cwe-*"):
                scanned += 1
                if scanned > cls.MAX_RECURSIVE_SCAN:
                    logger.warning("IRIS directory scan truncated after %d entries under %s", cls.MAX_RECURSIVE_SCAN, root)
                    break
                try:
                    if path.is_dir():
                        found.append(path)
                except OSError:
                    continue
        except OSError:
            pass

        seen: set[str] = set()
        unique: list[Path] = []
        for p in found:
            key = str(p)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    @classmethod
    def _collect_from_directories(cls, directories: list[Path]) -> IrisArtifacts:
        used_dirs: list[Path] = []
        results_json_files: list[Path] = []
        sarif_files: list[Path] = []
        stats_files: list[Path] = []

        for directory in sorted(directories, key=str):
            try:
                if not directory.is_dir():
                    continue
            except OSError:
                continue

            results_json = cls._find_first(directory, cls.RESULT_FILENAMES)
            sarif = cls._find_first(directory, cls.SARIF_FILENAMES)
            stats = cls._find_first(directory, cls.STATS_FILENAMES)

            if not (results_json or sarif or stats):
                continue

            used_dirs.append(directory)
            if results_json:
                results_json_files.append(results_json)
                logger.info("Discovered IRIS results.json: %s", results_json)
            if sarif:
                sarif_files.append(sarif)
                logger.info("Discovered IRIS results.sarif: %s", sarif)
            if stats:
                stats_files.append(stats)
                logger.info("Discovered IRIS stats.json: %s", stats)

        return IrisArtifacts(
            directories=used_dirs,
            results_json_files=results_json_files,
            results_sarif_files=sarif_files,
            stats_json_files=stats_files,
        )

    def _candidate_directories(self) -> list[Optional[Path]]:
        """Build an ordered list of plausible IRIS output roots to scan.

        The documented layout is ``<base>/<project>/<run_id>/cwe-xx/...``,
        but in practice ``run_id`` frequently already encodes the
        project-specific subpath on its own (e.g.
        ``webgoat_sql_CVE-2026-0006_1.0/opengrep_CWE89``), so ``<base>/<run_id>``
        needs to be tried directly as well. All candidates are tried in
        order and the first one that actually yields IRIS artifacts wins.
        """
        candidates: list[Optional[Path]] = []
        base = self.base_dir
        if base is None:
            return candidates

        sanitized_project = self._sanitize(self.project)

        if self.run_id:
            # Configured run: remain scoped to this project/run only.
            candidates.append(base / sanitized_project / str(self.run_id))
            candidates.append(base / str(self.run_id))
        else:
            # Without a run id, project-scoped discovery is still safe.
            candidates.append(base / sanitized_project)

            # Whole-base discovery is allowed only when the project itself
            # could not be resolved.
            if sanitized_project == "unknown-project":
                candidates.append(base)

        seen: set[str] = set()
        unique: list[Optional[Path]] = []
        for c in candidates:
            if c is None:
                continue
            key = str(c)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    @staticmethod
    def _sanitize(name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.\-]", "_", str(name))

    @staticmethod
    def _find_first(directory: Path, names: tuple[str, ...]) -> Optional[Path]:
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        return None


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

class SarifLoader:
    @staticmethod
    def load(path: Path, tool_name: str) -> list[Finding]:
        logger.info("Loading %s SARIF from %s ...", tool_name, path)
        try:
            sarif = _load_json(path)
        except Exception:
            return []

        dedup: dict[tuple[str, str, int, str], Finding] = {}

        runs = sarif.get("runs", []) if isinstance(sarif, dict) else []
        for run in runs:
            if not isinstance(run, dict):
                continue
            driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
            rules_by_id = {
                r.get("id"): r for r in driver.get("rules", []) if isinstance(r, dict) and r.get("id")
            }

            for result in run.get("results", []):
                if not isinstance(result, dict):
                    continue

                # IRIS_POSTHOC_EMPTY_FLOW_FILTER
                #
                # Stage 8 preserves the SARIF result container while
                # removing codeFlows rejected by posthoc filtering.
                # For effective IRIS posthoc SARIF, a result with an
                # explicitly empty codeFlows list is therefore not a
                # surviving finding.
                #
                # Scope this only to IRIS *-posthoc-filter artifacts so
                # OpenGrep SARIF and raw/pre-posthoc IRIS SARIF semantics
                # remain unchanged.
                if (
                    str(tool_name).strip().lower() == "iris"
                    and path.parent.name.lower().endswith(
                        "-posthoc-filter"
                    )
                    and "codeFlows" in result
                    and not (result.get("codeFlows") or [])
                ):
                    continue

                try:
                    finding = SarifLoader._parse_result(result, rules_by_id)
                except Exception:
                    logger.debug("Skipping unparsable %s SARIF result: %r", tool_name, result, exc_info=True)
                    continue
                if finding is None:
                    continue
                finding.tool = tool_name
                key = (finding.rule_id, finding.file, finding.line, finding.message)
                if key in dedup:
                    dedup[key].raw_count += 1
                    dedup[key].end_line = max(dedup[key].end_line, finding.end_line)
                else:
                    dedup[key] = finding

        findings = list(dedup.values())
        logger.info(
            "Loaded %d unique findings (%d raw) from %s SARIF",
            len(findings), sum(f.raw_count for f in findings), tool_name,
        )
        return findings

    @staticmethod
    def _parse_result(result: dict, rules_by_id: dict) -> Optional[Finding]:
        rule_id = str(result.get("ruleId") or "unknown-rule")
        level = result.get("level", "warning")

        message_obj = result.get("message", {})
        if isinstance(message_obj, dict):
            message = str(message_obj.get("text", "") or "")
        else:
            message = str(message_obj or "")

        locations = result.get("locations") or []
        if not locations or not isinstance(locations, list):
            return None

        physical = locations[0].get("physicalLocation", {}) if isinstance(locations[0], dict) else {}
        artifact = physical.get("artifactLocation", {}).get("uri", "unknown")
        region = physical.get("region", {}) if isinstance(physical.get("region"), dict) else {}
        line = _safe_int(region.get("startLine"), 0)
        end_line = _safe_int(region.get("endLine"), line) or line

        rule_def = rules_by_id.get(rule_id, {}) if isinstance(rules_by_id.get(rule_id, {}), dict) else {}

        security_severity = _extract_security_severity(result) or _extract_security_severity(rule_def)
        severity = normalize_severity(level, security_severity)
        cwe = _extract_cwe(rule_def, result)

        rule_name = None
        short_desc = rule_def.get("shortDescription") if isinstance(rule_def, dict) else None
        if isinstance(short_desc, dict):
            rule_name = short_desc.get("text")
        if not rule_name:
            rule_name = rule_def.get("name") if isinstance(rule_def, dict) else None

        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            file=normalize_path(artifact),
            line=line,
            end_line=end_line,
            cwe=cwe,
            rule_name=str(rule_name) if rule_name else None,
        )

class NormalizedFindingsLoader:
    @staticmethod
    def load(path: Path) -> list[Finding]:
        logger.info("Loading normalized findings from %s ...", path)
        data = _load_json(path)
        items: list[dict] = []
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            for candidate_key in ("findings", "results", "items", "normalized_findings"):
                val = data.get(candidate_key)
                if isinstance(val, list):
                    items = [x for x in val if isinstance(x, dict)]
                    break

        dedup: dict[tuple[str, str, int, str], Finding] = {}
        for item in items:
            finding = NormalizedFindingsLoader._parse_item(item)
            if finding is None:
                continue
            dedup_key = (finding.rule_id, finding.file, finding.line, finding.message)
            if dedup_key in dedup:
                dedup[dedup_key].raw_count += 1
            else:
                dedup[dedup_key] = finding
        return list(dedup.values())

    @staticmethod
    def _parse_item(item: dict) -> Optional[Finding]:
        file_raw = _first_present(item, "file", "path", "filename", "file_path")
        if not file_raw:
            return None
        rule_id = str(_first_present(item, "rule_id", "ruleId", "rule", "check_id") or "unknown-rule")
        line = _safe_int(_first_present(item, "line", "start_line", "lineno", "line_number"), 0)
        end_line = _safe_int(_first_present(item, "end_line", "endLine"), line) or line
        message = str(_first_present(item, "message", "description", "msg") or "")
        sev_raw = _first_present(item, "severity", "level")
        sec_sev = _safe_float(_first_present(item, "security_severity", "cvss", "score"))
        severity = normalize_severity(str(sev_raw or "warning"), sec_sev)
        cwe = _extract_cwe_from_value(_first_present(item, "cwe", "cwe_id"))

        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            file=normalize_path(str(file_raw)),
            line=line,
            end_line=end_line,
            cwe=cwe,
            rule_name=None,
            tool="OpenGrep",
        )

class IrisResultsLoader:
    """Parses IRIS ``results.json`` files into :class:`IrisVerdict` objects.

    ``results.json`` holds IRIS's confirmation / dataflow verdict data (as
    opposed to ``results.sarif``, which holds the raw findings, and
    ``stats.json``, which holds aggregate run statistics). The exact shape
    of this file varies across IRIS versions/pipelines, so this loader
    tolerates a range of common key names for the location, verdict,
    confidence, CWE, path-count and reasoning fields. Files that turn out
    to hold only aggregate statistics (no per-finding verdict list) are
    skipped gracefully, yielding no verdicts rather than raising.
    """

    LIST_KEYS = (
        "results", "findings", "verdicts", "confirmed_results",
        "labelled_results", "labeled_results", "items", "paths",
        "path_results", "final_results", "data",
    )

    FILE_KEYS = ("file", "path", "filename", "file_path", "source_file", "sink_file", "relative_path")
    LINE_KEYS = ("line", "start_line", "lineno", "line_number", "sink_line", "source_line")
    CONFIRMED_KEYS = ("confirmed", "is_confirmed", "is_true_positive", "true_positive", "tp", "verdict", "label", "classification")
    CONFIDENCE_KEYS = ("confidence", "confidence_score", "score", "certainty", "probability")
    CWE_KEYS = ("cwe", "cwe_id", "cweId")
    PATH_COUNT_KEYS = ("path_count", "num_paths", "paths_count", "n_paths")
    REASONING_KEYS = ("reasoning", "explanation", "justification", "rationale", "analysis")
    RULE_ID_KEYS = ("rule_id", "ruleId", "rule", "check_id", "query_id")

    TRUE_TOKENS = {"true", "confirmed", "true positive", "true_positive", "tp", "yes", "valid", "vulnerable"}
    FALSE_TOKENS = {"false", "rejected", "false positive", "false_positive", "fp", "no", "invalid", "not vulnerable", "benign"}

    @classmethod
    def load(cls, path: Path) -> list[IrisVerdict]:
        logger.info("Loading IRIS results.json from %s ...", path)
        try:
            data = _load_json(path)
        except Exception:
            logger.debug("Could not parse IRIS results.json at %s", path, exc_info=True)
            return []

        if cls._is_path_entry_format(data):
            verdicts = cls._parse_path_entries(data)
            cls._apply_cwe_from_path(path, verdicts)
            logger.info("Loaded %d IRIS verdict(s) from %s", len(verdicts), path)
            return verdicts

        items = cls._extract_items(data)
        if not items:
            logger.info(
                "No per-finding verdicts found in %s (likely a statistics-only file); skipping.",
                path,
            )
            return []

        verdicts = []
        for item in items:
            v = cls._parse_item(item)
            if v is not None:
                verdicts.append(v)

        cls._apply_cwe_from_path(path, verdicts)
        logger.info("Loaded %d IRIS verdict(s) from %s", len(verdicts), path)
        return verdicts

    # -- IRIS "posthoc-filter" dataflow-path format -------------------------
    # [
    #   {"result_id": 0, "code_flow_id": 0,
    #    "entry": {"path": [{"file_url": ..., "start_line": ..., ...}, ...],
    #              "ignored_by_filter": true, "result": false}},
    #   {"result_id": 1, "code_flow_id": 0,
    #    "entry": {"path": [...],
    #              "result": {"explanation": "...", "source_is_false_positive": false,
    #                         "sink_is_false_positive": true, "is_vulnerable": false}}},
    #   ...
    # ]
    @staticmethod
    def _is_path_entry_format(data: Any) -> bool:
        if not isinstance(data, list) or not data:
            return False
        return any(isinstance(item, dict) and isinstance(item.get("entry"), dict) for item in data)

    @classmethod
    def _parse_path_entries(cls, data: list) -> list["IrisVerdict"]:
        verdicts: list[IrisVerdict] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            entry = item.get("entry")
            if not isinstance(entry, dict):
                continue
            v = cls._parse_single_path_entry(item, entry)
            if v is not None:
                verdicts.append(v)
        return verdicts

    @classmethod
    def _parse_single_path_entry(cls, item: dict, entry: dict) -> Optional["IrisVerdict"]:
        raw_path = entry.get("path")
        locations: list[tuple[str, int]] = []
        if isinstance(raw_path, list):
            for step in raw_path:
                if not isinstance(step, dict):
                    continue
                file_url = step.get("file_url") or step.get("file") or step.get("uri")
                line_raw = _first_present(step, "start_line", "line", "startLine")
                if not file_url or line_raw is None:
                    continue
                locations.append((normalize_path(str(file_url)), _safe_int(line_raw, 0)))

        if not locations:
            return None

        # De-duplicate while preserving path order (source -> ... -> sink).
        seen: set = set()
        unique_locations: list[tuple[str, int]] = []
        for loc in locations:
            if loc not in seen:
                seen.add(loc)
                unique_locations.append(loc)

        sink_file, sink_line = unique_locations[-1]

        result = entry.get("result")
        ignored_by_filter = bool(entry.get("ignored_by_filter", False))
        reasoning_parts: list[str] = []
        confirmed: Optional[bool]

        if isinstance(result, dict):
            is_vulnerable = result.get("is_vulnerable")
            confirmed = bool(is_vulnerable) if is_vulnerable is not None else None
            explanation = result.get("explanation")
            if explanation:
                reasoning_parts.append(str(explanation))
            if result.get("source_is_false_positive"):
                reasoning_parts.append("IRIS flagged the source as a false positive")
            if result.get("sink_is_false_positive"):
                reasoning_parts.append("IRIS flagged the sink as a false positive")
        elif isinstance(result, bool):
            # A plain boolean here means this path never reached LLM triage
            # (filtered out earlier in the pipeline), not a confirmed verdict.
            confirmed = False if ignored_by_filter else result
            if ignored_by_filter:
                reasoning_parts.append("Path filtered out before LLM triage (ignored_by_filter)")
        else:
            confirmed = None

        code_flow_id = item.get("code_flow_id")
        result_id = item.get("result_id")
        rule_id = f"iris-path-{result_id}-{code_flow_id}" if result_id is not None else None

        verdict = IrisVerdict(
            file=sink_file,
            line=sink_line,
            confirmed=confirmed,
            confidence=None,
            cwe=None,
            path_count=1,
            reasoning="; ".join(reasoning_parts) if reasoning_parts else None,
            rule_id=rule_id,
        )
        verdict.locations = unique_locations
        return verdict

    @staticmethod
    def _apply_cwe_from_path(results_path: Path, verdicts: list["IrisVerdict"]) -> None:
        """IRIS emits one results.json per CWE query (e.g. a ``cwe-089...``
        directory), so infer the CWE from the containing directory name and
        backfill it onto any verdict that didn't carry its own."""
        inferred: Optional[str] = None
        for part in results_path.parts:
            m = _CWE_PATTERN.search(part)
            if m:
                inferred = f"CWE-{int(m.group(1))}"
                break
        if not inferred:
            return
        for v in verdicts:
            if not v.cwe:
                v.cwe = inferred

    @classmethod
    def _extract_items(cls, data: Any) -> list[dict]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if not isinstance(data, dict):
            return []

        for key in cls.LIST_KEYS:
            val = data.get(key)
            if isinstance(val, list) and val:
                items = [x for x in val if isinstance(x, dict)]
                if items:
                    return items

        # Some IRIS variants nest per-finding lists under CWE-shaped keys,
        # e.g. {"CWE-089": [...], "CWE-022": [...]}
        nested_items: list[dict] = []
        for key, val in data.items():
            if isinstance(val, list) and _CWE_PATTERN.search(str(key)):
                nested_items.extend(x for x in val if isinstance(x, dict))
        return nested_items

    @classmethod
    def _parse_item(cls, item: dict) -> Optional[IrisVerdict]:
        file_raw = _first_present(item, *cls.FILE_KEYS)
        line_raw = _first_present(item, *cls.LINE_KEYS)

        if file_raw is None or line_raw is None:
            # Some formats nest the actual code location under a "sink"
            # (or occasionally "source") object rather than at the top level.
            for nested_key in ("sink", "source", "location"):
                nested = item.get(nested_key)
                if isinstance(nested, dict):
                    if file_raw is None:
                        file_raw = _first_present(nested, *cls.FILE_KEYS)
                    if line_raw is None:
                        line_raw = _first_present(nested, *cls.LINE_KEYS)
                if file_raw is not None and line_raw is not None:
                    break

        if not file_raw:
            return None

        line = _safe_int(line_raw, 0)

        confirmed = cls._parse_confirmed(_first_present(item, *cls.CONFIRMED_KEYS))
        confidence = cls._parse_confidence(_first_present(item, *cls.CONFIDENCE_KEYS))
        cwe = _extract_cwe_from_value(_first_present(item, *cls.CWE_KEYS))
        path_count = _safe_int(_first_present(item, *cls.PATH_COUNT_KEYS), 0)
        reasoning = _first_present(item, *cls.REASONING_KEYS)
        rule_id = _first_present(item, *cls.RULE_ID_KEYS)

        return IrisVerdict(
            file=normalize_path(str(file_raw)),
            line=line,
            confirmed=confirmed,
            confidence=confidence,
            cwe=cwe,
            path_count=path_count,
            reasoning=str(reasoning) if reasoning else None,
            rule_id=str(rule_id) if rule_id else None,
        )

    @classmethod
    def _parse_confirmed(cls, raw: Any) -> Optional[bool]:
        if raw is None:
            return None
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, (int, float)):
            return bool(raw)
        text = str(raw).strip().lower()
        if text in cls.TRUE_TOKENS:
            return True
        if text in cls.FALSE_TOKENS:
            return False
        return None

    @staticmethod
    def _parse_confidence(raw: Any) -> Optional[float]:
        value = _safe_float(raw)
        if value is None:
            return None
        # Normalize a 0-1 fractional confidence up to a 0-100 scale.
        if 0.0 <= value <= 1.0:
            value *= 100.0
        return max(0.0, min(100.0, value))

class IrisStatsLoader:
    @staticmethod
    def load(path: Optional[Path]) -> dict[str, int]:
        empty = {"sources": 0, "sinks": 0, "taint_propagators": 0, "paths": 0, "raw_results": 0}
        if path is None:
            return empty
        try:
            data = _load_json(path)
        except Exception:
            return empty

        stats_block = data.get("statistics", data) if isinstance(data, dict) else {}
        vanilla_block = data.get("vanilla_result", {}) if isinstance(data, dict) else {}
        if not isinstance(stats_block, dict):
            stats_block = {}
        if not isinstance(vanilla_block, dict):
            vanilla_block = {}

        return {
            "sources": _safe_int(_first_present(stats_block, "num_labelled_sources", "sources"), 0),
            "sinks": _safe_int(_first_present(stats_block, "num_labelled_sinks", "sinks"), 0),
            "taint_propagators": _safe_int(_first_present(stats_block, "num_labelled_taint_propagators", "taint_propagators", "taint"), 0),
            "paths": _safe_int(_first_present(vanilla_block, "num_paths", "paths") or _first_present(stats_block, "num_paths", "paths"), 0),
            "raw_results": _safe_int(_first_present(vanilla_block, "num_results", "raw_results"), 0),
        }

# ---------------------------------------------------------------------------
# Matching / merging
# ---------------------------------------------------------------------------

def _path_segments(path: str) -> list[str]:
    return [seg for seg in str(path).strip("/").split("/") if seg]


def _path_match_tier(a: str, b: str) -> Optional[int]:
    """Compare two normalized file paths that may be rooted differently
    (absolute vs. relative, different scan-root prefixes, etc.).

    Returns a match "tier" (lower = stronger) or ``None`` if they don't
    plausibly refer to the same file:
      0 - identical (case-insensitive) normalized path
      1 - one path's directory components are a trailing subsequence of
          the other's (e.g. ``src/main/java/Foo.java`` vs.
          ``webgoat/src/main/java/Foo.java``)
      2 - same filename only (last path segment) -- weakest signal, used
          only as a last resort when nothing scores tier 0/1.
    """
    if not a or not b:
        return None
    a_norm, b_norm = a.strip().lower(), b.strip().lower()
    if a_norm == b_norm:
        return 0

    a_parts, b_parts = _path_segments(a_norm), _path_segments(b_norm)
    if not a_parts or not b_parts:
        return None

    shorter, longer = (a_parts, b_parts) if len(a_parts) <= len(b_parts) else (b_parts, a_parts)
    if longer[-len(shorter):] == shorter:
        return 1

    if a_parts[-1] == b_parts[-1]:
        return 2

    return None


class FindingMerger:
    LINE_TOLERANCE = 2
    # Path-match tiers considered "safe enough" on the first pass; tier 2
    # (filename-only) is only tried as a fallback if nothing scores 0/1,
    # to avoid mismatching same-named files that live in different packages.
    _SAFE_TIER = 1
    _FALLBACK_TIER = 2

    def merge(self, opengrep_findings: list[Finding], iris_sarif_findings: list[Finding], iris_verdicts: list[IrisVerdict]) -> list[MergedFinding]:
        """Merge OpenGrep and IRIS findings as a location-aware union.

        OpenGrep and IRIS findings that refer to the same location are
        merged into one finding. IRIS SARIF findings that do not match any
        OpenGrep finding are retained as IRIS-only findings.

        IRIS posthoc verdicts enrich matching findings but are not counted
        as independent findings by themselves; the SARIF result remains
        the finding identity.

        Matching uses every location on an IRIS verdict's dataflow path
        with suffix-aware path matching and a small line tolerance.
        """
        # Flatten IRIS SARIF findings into (file, line, obj) candidates.
        ir_candidates: list[tuple[str, int, Finding]] = [(f.file, f.line, f) for f in iris_sarif_findings]

        # Flatten IRIS verdicts into (file, line, obj) candidates, one entry
        # per distinct location on the verdict's dataflow path (source,
        # intermediate steps, sink) -- not just its primary sink location.
        verdict_candidates: list[tuple[str, int, IrisVerdict]] = []
        for v in iris_verdicts:
            locs = list(dict.fromkeys(v.locations)) if v.locations else [(v.file, v.line)]
            for loc_file, loc_line in locs:
                verdict_candidates.append((loc_file, loc_line, v))

        used_ir_ids: set[int] = set()
        used_verdict_ids: set[int] = set()

        def _take_best(
            candidates: list[tuple[str, int, Any]],
            used_ids: set[int],
            target_file: str,
            target_line: int,
            max_tier: int,
        ) -> Optional[Any]:
            best_obj: Optional[Any] = None
            best_key: Optional[tuple[int, int]] = None
            for cfile, cline, obj in candidates:
                if id(obj) in used_ids:
                    continue
                tier = _path_match_tier(target_file, cfile)
                if tier is None or tier > max_tier:
                    continue
                dist = abs(target_line - cline)
                if dist > self.LINE_TOLERANCE:
                    continue
                key = (tier, dist)
                if best_key is None or key < best_key:
                    best_key = key
                    best_obj = obj
            return best_obj

        def _take(candidates: list[tuple[str, int, Any]], used_ids: set[int], target_file: str, target_line: int) -> Optional[Any]:
            # First pass: safe tiers (exact path or directory-suffix match).
            obj = _take_best(candidates, used_ids, target_file, target_line, self._SAFE_TIER)
            if obj is None:
                # Fallback: filename-only match, only if nothing safer was found.
                obj = _take_best(candidates, used_ids, target_file, target_line, self._FALLBACK_TIER)
            if obj is not None:
                used_ids.add(id(obj))
            return obj

        def _take_verdict(
            used_ids: set[int],
            target_file: str,
            target_line: int,
            require_confirmed: bool,
        ) -> Optional[IrisVerdict]:
            # EFFECTIVE_IRIS_POSITIVE_VERDICT_ONLY
            #
            # Effective posthoc IRIS SARIF contains only findings that
            # still have at least one surviving codeFlow. A negative
            # verdict from another flow at the same location must not
            # turn that surviving finding into a False Positive.
            #
            # Negative verdicts remain eligible for OpenGrep-only
            # findings, where they are useful posthoc enrichment.
            candidates = verdict_candidates

            if require_confirmed:
                candidates = [
                    item
                    for item in verdict_candidates
                    if item[2].confirmed is True
                ]

            return _take(
                candidates,
                used_ids,
                target_file,
                target_line,
            )

        merged: list[MergedFinding] = []
        for og in opengrep_findings:
            ir = _take(ir_candidates, used_ir_ids, og.file, og.line)
            verdict = _take_verdict(
                used_verdict_ids,
                og.file,
                og.line,
                require_confirmed=(ir is not None),
            )
            merged.append(
                self._build_merged(
                    og.file,
                    og.line,
                    og,
                    ir,
                    verdict,
                )
            )

        # ---------------------------------------------------------
        # Preserve unmatched IRIS SARIF findings as first-class
        # findings. This is required for hybrid/configured dispatch:
        # OpenGrep may seed-miss a CWE while IRIS independently
        # produces a valid CodeQL/posthoc finding.
        # ---------------------------------------------------------
        unmatched_ir = [
            f
            for f in iris_sarif_findings
            if id(f) not in used_ir_ids
        ]

        added_iris_only = 0

        for ir in unmatched_ir:
            verdict = _take_verdict(
                used_verdict_ids,
                ir.file,
                ir.line,
                require_confirmed=True,
            )

            merged.append(
                self._build_merged(
                    ir.file,
                    ir.line,
                    None,
                    ir,
                    verdict,
                )
            )

            used_ir_ids.add(id(ir))
            added_iris_only += 1

        if added_iris_only:
            logger.info(
                "%d IRIS SARIF finding(s) did not match OpenGrep; "
                "added as IRIS-only findings.",
                added_iris_only,
            )

        # Verdicts are enrichment data for SARIF findings/dataflow
        # paths, not independent finding identities. Keep unmatched
        # verdicts observable without inflating the finding count.
        unmatched_verdicts = [
            v
            for v in iris_verdicts
            if id(v) not in used_verdict_ids
        ]

        if unmatched_verdicts:
            sample = ", ".join(
                f"{v.file}:{v.line}"
                for v in unmatched_verdicts[:5]
            )

            logger.info(
                "%d IRIS verdict(s) did not match any OpenGrep or "
                "IRIS SARIF finding; not added as independent "
                "findings. Examples: %s",
                len(unmatched_verdicts),
                sample,
            )

        merged.sort(key=lambda m: (-m.risk_score if m.risk_score else 0, m.file, m.line))
        return merged

    @staticmethod
    def _build_merged(file: str, line: int, og: Optional[Finding], ir: Optional[Finding], verdict: Optional[IrisVerdict]) -> MergedFinding:
        has_og = og is not None
        has_ir = ir is not None

        if has_og and has_ir:
            assert og is not None and ir is not None
            rule_id = og.rule_id if og.rule_id == ir.rule_id else f"{og.rule_id} | {ir.rule_id}"
            message = og.message or ir.message
            severity = _more_severe(og.severity, ir.severity)
            end_line = max(og.end_line or line, ir.end_line or line)
        elif has_og:
            assert og is not None
            rule_id, message, severity, end_line = og.rule_id, og.message, og.severity, (og.end_line or line)
        elif has_ir:
            assert ir is not None
            rule_id, message, severity, end_line = ir.rule_id, ir.message, ir.severity, (ir.end_line or line)
        else:
            rule_id = (verdict.rule_id if verdict and verdict.rule_id else "iris-verdict")
            message = (verdict.reasoning if verdict and verdict.reasoning else "") or ""
            severity = "Medium"
            end_line = line

        cwe = (og.cwe if og else None) or (ir.cwe if ir else None) or (verdict.cwe if verdict else None)

        duplicate_count = max(
            og.raw_count if og else 0,
            ir.raw_count if ir else 0,
            1,
        )

        fingerprint = hashlib.sha1(f"{rule_id}:{file}:{line}".encode("utf-8")).hexdigest()[:16]

        mf = MergedFinding(
            fingerprint=fingerprint,
            rule_id=rule_id,
            opengrep_rule_id=og.rule_id if og else None,
            iris_rule_id=(ir.rule_id if ir else (verdict.rule_id if verdict else None)),
            file=file,
            line=line,
            end_line=end_line,
            severity=severity,
            message=message,
            cwe=cwe,
            opengrep=has_og,
            iris=has_ir or (verdict is not None),
            iris_confirmed=verdict.confirmed if verdict else None,
            status="",
            source="",
            confidence_score=verdict.confidence if verdict else None,
            confidence_label="",
            path_count=verdict.path_count if verdict else 0,
            duplicate_count=duplicate_count,
            reasoning=verdict.reasoning if verdict else None,
            risk_score=0,
            risk_level="",
        )
        mf.finalize()
        return mf


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class RiskScorer:
    def __init__(self, cwe_weights: Optional[dict[str, int]] = None) -> None:
        self._cwe_weights = cwe_weights if cwe_weights is not None else CWE_IMPORTANCE_WEIGHTS

    def score(self, mf: MergedFinding) -> None:
        value = float(SEVERITY_SCORES.get(mf.severity, DEFAULT_SEVERITY_SCORE))

        if mf.status == "IRIS Posthoc Positive":
            value += 14.0
        elif mf.status == "IRIS Posthoc Negative":
            value -= 40.0
        elif mf.status == "OpenGrep + IRIS Match":
            value += 8.0
        elif mf.status == "OpenGrep Only":
            value -= 6.0
        elif mf.status == "IRIS Only":
            value += 3.0

        if mf.confidence_score is not None:
            value += (mf.confidence_score - 50.0) / 50.0 * 8.0

        if mf.path_count > 0:
            value += min(math.log2(mf.path_count + 1) * 3.0, 10.0)

        if mf.duplicate_count > 1:
            value += min((mf.duplicate_count - 1) * 1.5, 6.0)

        value += float(self._cwe_weights.get(mf.cwe, 0)) if mf.cwe else 0.0

        value = max(0.0, min(100.0, value))
        mf.risk_score = int(round(value))
        mf.risk_level = self._risk_level(mf.risk_score, mf.status == "IRIS Posthoc Negative")

    @staticmethod
    def _risk_level(score: int, is_false_positive: bool) -> str:
        if is_false_positive:
            return "Informational"
        if score >= 85:
            return "Critical"
        if score >= 65:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

# ---------------------------------------------------------------------------
# Executive summary / statistics
# ---------------------------------------------------------------------------

class StatisticsEngine:
    TOP_N = 5
    HIGH_FALSE_POSITIVE_RATE = 30.0

    def build(self, merged: list[MergedFinding], opengrep_raw_count: int, iris_raw_count: int, iris_stats: dict[str, int]) -> dict[str, Any]:
        total = len(merged)
        confirmed = sum(1 for m in merged if m.status == "IRIS Posthoc Positive")
        likely_tp = sum(1 for m in merged if m.status == "OpenGrep + IRIS Match")
        possible_fp = sum(1 for m in merged if m.status == "OpenGrep Only")
        false_positive = sum(1 for m in merged if m.status == "IRIS Posthoc Negative")
        iris_only = sum(1 for m in merged if m.status == "IRIS Only")

        confirmed_total = confirmed + likely_tp
        confirmation_rate = round((confirmed_total / total) * 100, 1) if total else 0.0
        false_positive_rate = round((false_positive / total) * 100, 1) if total else 0.0

        severity_distribution = {level: 0 for level in SEVERITY_ORDER}
        for m in merged:
            severity_distribution[m.severity] = severity_distribution.get(m.severity, 0) + 1

        status_distribution: dict[str, int] = {s: 0 for s in STATUS_ORDER}
        for m in merged:
            status_distribution[m.status] = status_distribution.get(m.status, 0) + 1
        status_distribution = {k: v for k, v in status_distribution.items() if v > 0} or status_distribution

        confidence_distribution: dict[str, int] = defaultdict(int)
        for m in merged:
            confidence_distribution[m.confidence_label] += 1

        file_counter: Counter[str] = Counter(m.file for m in merged)
        top_files = [{"file": f, "count": c} for f, c in file_counter.most_common(self.TOP_N)]

        cwe_counter: Counter[str] = Counter(m.cwe for m in merged if m.cwe)
        top_cwes = [{"cwe": cwe, "count": c, "name": CWE_NAMES.get(cwe, "Unclassified")} for cwe, c in cwe_counter.most_common(self.TOP_N)]

        avg_risk = round(sum(m.risk_score for m in merged) / total, 1) if total else 0.0
        recommendations = self._recommendations(severity_distribution, top_cwes, false_positive_rate, total)

        return {
            "total_findings": total,
            "opengrep_raw_findings": opengrep_raw_count,
            "iris_raw_findings": iris_raw_count,
            "iris_posthoc_positive_findings": confirmed,
            "cross_tool_match_findings": likely_tp,
            "opengrep_only_findings": possible_fp,
            "iris_posthoc_negative_findings": false_positive,
            "iris_only_findings": iris_only,
            "review_positive_rate_percent": confirmation_rate,
            "iris_posthoc_negative_rate_percent": false_positive_rate,
            "average_risk_score": avg_risk,
            "severity_distribution": severity_distribution,
            "status_distribution": status_distribution,
            "confidence_distribution": dict(confidence_distribution),
            "top_vulnerable_files": top_files,
            "top_cwes": top_cwes,
            "iris_sources": iris_stats.get("sources", 0),
            "iris_sinks": iris_stats.get("sinks", 0),
            "iris_taint_propagators": iris_stats.get("taint_propagators", 0),
            "iris_paths": iris_stats.get("paths", 0),
            "iris_raw_results": iris_stats.get("raw_results", 0),
            "recommendations": recommendations,
        }

    @classmethod
    def _recommendations(cls, severity_distribution: dict[str, int], top_cwes: list[dict[str, Any]], false_positive_rate: float, total: int) -> list[str]:
        recs: list[str] = []
        critical = severity_distribution.get("Critical", 0)
        high = severity_distribution.get("High", 0)

        if critical:
            recs.append(f"Prioritize remediation of {critical} Critical-severity finding(s) before the next release.")
        if high:
            recs.append(f"Schedule {high} High-severity finding(s) for the current sprint.")

        for entry in top_cwes[:3]:
            tip = CWE_REMEDIATION_TIPS.get(entry["cwe"])
            if tip:
                recs.append(f"{entry['cwe']} ({entry['name']}) appears {entry['count']}x: {tip}")

        if false_positive_rate >= cls.HIGH_FALSE_POSITIVE_RATE:
            recs.append(f"IRIS posthoc-negative share is {false_positive_rate}%; review rule/model disagreement and supporting evidence before changing detector thresholds.")

        if total == 0:
            recs.append("No findings were produced by this run; verify the pipeline configuration if this is unexpected.")
        if not recs:
            recs.append("No high-priority issues detected; maintain current secure coding practices.")

        return recs

# ---------------------------------------------------------------------------
# Source snippet extraction
# ---------------------------------------------------------------------------

class SourceSnippetProvider:
    def __init__(self, source_root: Optional[Path], context_lines: int = 4) -> None:
        self._source_root = source_root
        self._context = context_lines
        self._cache: dict[Path, Optional[list[str]]] = {}

    def get_snippet(self, relative_file: str, line: int) -> Optional[dict[str, Any]]:
        if not relative_file or relative_file == "unknown" or line <= 0:
            return None
        for candidate in self._candidate_paths(relative_file):
            lines = self._read_lines(candidate)
            if lines is None:
                continue
            if line > len(lines):
                continue
            start = max(1, line - self._context)
            end = min(len(lines), line + self._context)
            snippet_lines = [{"number": n, "text": lines[n - 1].rstrip("\n").rstrip("\r"), "is_target": n == line} for n in range(start, end + 1)]
            return {"file": relative_file, "target_line": line, "lines": snippet_lines}
        return None

    def _candidate_paths(self, relative_file: str) -> list[Path]:
        rel = Path(relative_file)
        candidates: list[Path] = []
        if self._source_root:
            candidates.append(self._source_root / rel)
        try:
            candidates.append(Path.cwd() / rel)
        except Exception:
            pass
        candidates.append(rel)
        return candidates

    def _read_lines(self, path: Path) -> Optional[list[str]]:
        if path in self._cache:
            return self._cache[path]
        try:
            if not path.is_file():
                self._cache[path] = None
                return None
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines(keepends=True)
            self._cache[path] = lines
            return lines
        except Exception:
            self._cache[path] = None
            return None

# ---------------------------------------------------------------------------
# Exporters: JSON / CSV / SARIF
# ---------------------------------------------------------------------------

class JsonExporter:
    @staticmethod
    def write(path: Path, metadata: dict[str, Any], summary: dict[str, Any], merged: list[MergedFinding]) -> None:
        payload = {"metadata": metadata, "executive_summary": summary, "findings": [asdict(m) for m in merged]}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

class CsvExporter:
    COLUMNS = ["risk_score", "risk_level", "status", "confidence_label", "confidence_score", "severity", "source", "cwe", "rule_id", "opengrep_rule_id", "iris_rule_id", "file", "line", "end_line", "duplicate_count", "path_count", "message"]

    @staticmethod
    def write(path: Path, merged: list[MergedFinding]) -> None:
        with path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=CsvExporter.COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for m in merged:
                writer.writerow({col: asdict(m).get(col, "") for col in CsvExporter.COLUMNS})

class SarifExporter:
    LEVEL_BY_SEVERITY = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}

    @staticmethod
    def write(path: Path, merged: list[MergedFinding], metadata: dict[str, Any]) -> None:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for m in merged:
            rid = m.rule_id or "unknown-rule"
            if rid not in rules:
                rules[rid] = {"id": rid, "name": rid, "shortDescription": {"text": (m.message or rid)[:200]}, "properties": {"tags": [m.cwe] if m.cwe else []}}
            results.append({
                "ruleId": rid,
                "level": SarifExporter.LEVEL_BY_SEVERITY.get(m.severity, "warning"),
                "message": {"text": m.message or rid},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": m.file}, "region": {"startLine": max(1, m.line), "endLine": max(1, m.end_line or m.line)}}}],
                "partialFingerprints": {"mergedFingerprint/v1": m.fingerprint},
                "properties": {"riskScore": m.risk_score, "riskLevel": m.risk_level, "status": m.status, "confidence": m.confidence_label, "source": m.source, "cwe": m.cwe, "duplicateCount": m.duplicate_count, "pathCount": m.path_count, "security-severity": str(round(SEVERITY_SCORES.get(m.severity, DEFAULT_SEVERITY_SCORE) / 10, 1))},
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "report_generator-merged", "informationUri": "https://github.com", "version": str(metadata.get("analyzer_version", REPORT_GENERATOR_VERSION)), "rules": list(rules.values())}}, "results": results}],
        }
        path.write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")


class HtmlExporter:
    """Renders a self-contained, responsive HTML report.

    Per requirements, this reads its data directly from an already-written
    ``report.json`` (rather than being handed the in-memory objects), so it
    stays decoupled from whatever produced that JSON. This class only
    controls presentation -- it does not alter or recompute any figures
    found in ``report.json``.
    """

    # status -> (badge background, badge/accent text color)
    STATUS_STYLES: dict[str, tuple[str, str]] = {
        "IRIS Posthoc Positive": ("#e6f4ea", "#1e7e34"),               # green
        "IRIS Posthoc Negative": ("#fdecea", "#c62828"),          # red
        "OpenGrep + IRIS Match": ("#fff8e1", "#b8860b"),    # amber
        "OpenGrep Only": ("#eceff1", "#607d8b"), # blue-gray
        "IRIS Only": ("#e3f2fd", "#1565c0"),                # blue (kept for older data)
        "Unknown": ("#eceff1", "#78909c"),
    }
    DEFAULT_STATUS_STYLE = ("#eceff1", "#78909c")

    # severity / risk-level -> solid accent color, shared by badges and charts
    SEVERITY_COLORS: dict[str, str] = {
        "Critical": "#b71c1c",
        "High": "#e53935",
        "Medium": "#fb8c00",
        "Low": "#43a047",
    }
    RISK_LEVEL_COLORS: dict[str, str] = {
        "Critical": "#b71c1c",
        "High": "#e53935",
        "Medium": "#fb8c00",
        "Low": "#43a047",
        "Informational": "#78909c",
    }
    DEFAULT_ACCENT = "#78909c"

    SEVERITY_ORDER_FOR_DISPLAY = SEVERITY_ORDER
    SHORT_PATH_SEGMENTS = 2  # how many trailing path components to show (full path stays in the tooltip)

    @staticmethod
    def write(json_path: Path, html_path: Path) -> None:
        data = _load_json(json_path)
        metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
        summary = data.get("executive_summary", {}) if isinstance(data, dict) else {}
        findings = data.get("findings", []) if isinstance(data, dict) else []
        if not isinstance(findings, list):
            findings = []

        html_doc = HtmlExporter._render(metadata, summary, findings)
        html_path.write_text(html_doc, encoding="utf-8")

    # -- small helpers ---------------------------------------------------

    @classmethod
    def _shorten_path(cls, path: str) -> str:
        parts = [p for p in str(path).replace("\\", "/").split("/") if p]
        if len(parts) <= cls.SHORT_PATH_SEGMENTS:
            return "/".join(parts) or str(path)
        return ".../" + "/".join(parts[-cls.SHORT_PATH_SEGMENTS:])

    @classmethod
    def _slug(cls, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", str(value).strip().lower()).strip("-") or "unknown"

    # -- rendering -------------------------------------------------------

    @classmethod
    def _render(cls, metadata: dict[str, Any], summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        esc = html_lib.escape
        project = esc(str(metadata.get("project_name", "N/A")))
        run_id = esc(str(metadata.get("run_id") or "N/A"))
        generated_at = esc(str(metadata.get("timestamp", "N/A")))
        analyzer_version = esc(str(metadata.get("analyzer_version", "N/A")))

        total = summary.get("total_findings", len(findings))
        confirmed = summary.get("iris_posthoc_positive_findings", 0)
        likely_tp = summary.get("cross_tool_match_findings", 0)
        false_positive = summary.get("iris_posthoc_negative_findings", 0)
        confirmation_rate = summary.get("review_positive_rate_percent", 0)
        severity_distribution = summary.get("severity_distribution", {}) or {}
        status_distribution = summary.get("status_distribution", {}) or {}

        cards_html = cls._render_summary_cards(total, confirmed, likely_tp, false_positive, confirmation_rate)
        severity_chart_html = cls._render_severity_chart(severity_distribution)
        status_chart_html = cls._render_status_donut(status_distribution)
        rows_html = "\n".join(cls._render_finding_row(f) for f in findings) or (
            '<tr><td colspan="8" class="empty-state">No findings.</td></tr>'
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report - {project}</title>
<style>
{cls._css()}
</style>
</head>
<body>
  <header class="page-header">
    <div class="header-inner">
      <div class="header-title">
        <h1>Security Findings Report</h1>
        <p class="subtitle">{project}</p>
      </div>
      <div class="meta">
        <div class="meta-item"><span class="meta-label">Run ID</span><span class="meta-value">{run_id}</span></div>
        <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{generated_at}</span></div>
        <div class="meta-item"><span class="meta-label">Analyzer</span><span class="meta-value">v{analyzer_version}</span></div>
      </div>
    </div>
  </header>

  <main>
    <section class="summary">
      <h2>Executive Summary</h2>
      <div class="cards">
        {cards_html}
      </div>

      <div class="charts-grid">
        <div class="chart-panel">
          <h3>Severity Distribution</h3>
          {severity_chart_html}
        </div>
        <div class="chart-panel">
          <h3>Finding Status</h3>
          {status_chart_html}
        </div>
      </div>
    </section>

    <section class="findings">
      <h2>Findings <span class="count-pill">{total}</span></h2>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Line</th>
              <th>Rule</th>
              <th>CWE</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Risk Level</th>
              <th>Reasoning</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <footer>
    <p>Generated by report_generator.py v{analyzer_version}</p>
  </footer>
</body>
</html>
"""

    @staticmethod
    def _render_summary_cards(total: Any, confirmed: Any, likely_tp: Any, false_positive: Any, confirmation_rate: Any) -> str:
        cards = [
            ("Total Findings", total, "neutral", "\U0001F4CB"),
            ("IRIS Posthoc Positive", confirmed, "confirmed", "\u2705"),
            ("OpenGrep + IRIS Match", likely_tp, "likely-tp", "\u26A0\uFE0F"),
            ("IRIS Posthoc Negative", false_positive, "false-positive", "\u274C"),
            ("Review-Positive Rate", f"{confirmation_rate}%", "neutral", "\U0001F4C8"),
        ]
        parts = []
        for label, value, css_class, icon in cards:
            parts.append(
                f'<div class="card card-{css_class}">'
                f'<div class="card-icon">{icon}</div>'
                f'<div class="card-body">'
                f'<div class="card-value">{html_lib.escape(str(value))}</div>'
                f'<div class="card-label">{html_lib.escape(label)}</div>'
                f'</div>'
                f'</div>'
            )
        return "\n".join(parts)

    @classmethod
    def _render_severity_chart(cls, severity_distribution: dict[str, Any]) -> str:
        ordered = list(cls.SEVERITY_ORDER_FOR_DISPLAY)
        for key in severity_distribution:
            if key not in ordered:
                ordered.append(key)

        counts = {level: _safe_int(severity_distribution.get(level, 0), 0) for level in ordered}
        max_count = max(counts.values() or [0]) or 1

        bars = []
        legend = []
        for level in ordered:
            count = counts[level]
            pct = round((count / max_count) * 100) if max_count else 0
            color = cls.SEVERITY_COLORS.get(level, cls.DEFAULT_ACCENT)
            bars.append(
                '<div class="bar-col">'
                f'<div class="bar-count">{count}</div>'
                f'<div class="bar-track"><div class="bar-fill" style="height:{pct}%;background:{color}"></div></div>'
                f'<div class="bar-label">{html_lib.escape(str(level))}</div>'
                '</div>'
            )
            legend.append(
                f'<span class="legend-item"><span class="legend-swatch" style="background:{color}"></span>'
                f'{html_lib.escape(str(level))} ({count})</span>'
            )

        return (
            '<div class="bar-chart">' + "".join(bars) + '</div>'
            '<div class="legend">' + "".join(legend) + '</div>'
        )

    @classmethod
    def _render_status_donut(cls, status_distribution: dict[str, Any]) -> str:
        total = sum(_safe_int(v, 0) for v in status_distribution.values())
        if total <= 0:
            return '<div class="empty-state">No status data.</div>'

        cumulative = 0.0
        stops = []
        legend = []
        for status, raw_count in status_distribution.items():
            count = _safe_int(raw_count, 0)
            if count <= 0:
                continue
            _, color = cls.STATUS_STYLES.get(status, cls.DEFAULT_STATUS_STYLE)
            start = cumulative / total * 100
            cumulative += count
            end = cumulative / total * 100
            stops.append(f"{color} {start:.3f}% {end:.3f}%")
            pct_label = round(count / total * 100)
            legend.append(
                f'<span class="legend-item"><span class="legend-swatch" style="background:{color}"></span>'
                f'{html_lib.escape(str(status))} ({count}, {pct_label}%)</span>'
            )

        gradient = ", ".join(stops)
        return (
            f'<div class="donut" style="background:conic-gradient({gradient})">'
            f'<div class="donut-hole"><span class="donut-total">{total}</span><span class="donut-caption">total</span></div>'
            '</div>'
            '<div class="legend">' + "".join(legend) + '</div>'
        )

    @classmethod
    def _render_finding_row(cls, f: dict[str, Any]) -> str:
        esc = html_lib.escape
        status = str(f.get("status", "Unknown") or "Unknown")
        bg, fg = cls.STATUS_STYLES.get(status, cls.DEFAULT_STATUS_STYLE)
        status_style = f'background:{bg};color:{fg};'

        full_path = str(f.get("file", "unknown"))
        short_path = cls._shorten_path(full_path)
        line = esc(str(f.get("line", "")))
        rule = esc(str(f.get("rule_id", "") or ""))
        cwe = esc(str(f.get("cwe") or "-"))

        severity = str(f.get("severity", "Medium") or "Medium")
        severity_color = cls.SEVERITY_COLORS.get(severity, cls.DEFAULT_ACCENT)

        risk_level = str(f.get("risk_level", "") or "-")
        risk_color = cls.RISK_LEVEL_COLORS.get(risk_level, cls.DEFAULT_ACCENT)

        reasoning = f.get("reasoning") or f.get("message") or ""
        reasoning = esc(str(reasoning))

        return (
            "<tr>"
            f'<td class="col-file" data-label="File"><span class="file-short" title="{esc(full_path)}">{esc(short_path)}</span></td>'
            f'<td class="col-line" data-label="Line">{line}</td>'
            f'<td class="col-rule" data-label="Rule">{rule}</td>'
            f'<td class="col-cwe" data-label="CWE">{cwe}</td>'
            f'<td class="col-severity" data-label="Severity"><span class="badge" style="background:{severity_color}1a;color:{severity_color}">{esc(severity)}</span></td>'
            f'<td class="col-status" data-label="Status"><span class="badge" style="{status_style}">{esc(status)}</span></td>'
            f'<td class="col-risk" data-label="Risk Level"><span class="badge" style="background:{risk_color}1a;color:{risk_color}">{esc(risk_level)}</span></td>'
            f'<td class="col-reasoning" data-label="Reasoning">{reasoning}</td>'
            "</tr>"
        )

    @staticmethod
    def _css() -> str:
        return """
:root {
  --bg: #f3f4f7;
  --panel-bg: #ffffff;
  --border: #e4e6ea;
  --text: #1a1d21;
  --muted: #6b7280;
  --accent: #4f46e5;
  --accent-soft: #eef0fe;
  --radius: 12px;
  --shadow: 0 1px 3px rgba(16, 24, 40, 0.06), 0 1px 2px rgba(16, 24, 40, 0.04);
}
* { box-sizing: border-box; }
html { -webkit-font-smoothing: antialiased; }
body {
  margin: 0;
  font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.45;
}

.page-header {
  background: linear-gradient(135deg, #1e2049 0%, #4f46e5 100%);
  color: #fff;
  padding: 2rem;
}
.header-inner {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1.25rem;
}
.header-title h1 { margin: 0; font-size: 1.6rem; font-weight: 700; letter-spacing: -0.01em; }
.header-title .subtitle { margin: 0.2rem 0 0 0; color: rgba(255,255,255,0.8); font-size: 0.95rem; }
.meta { display: flex; flex-wrap: wrap; gap: 1.5rem; }
.meta-item { display: flex; flex-direction: column; }
.meta-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: rgba(255,255,255,0.65); }
.meta-value { font-size: 0.95rem; font-weight: 600; }

main { padding: 1.75rem 2rem 2.5rem; max-width: 1400px; margin: 0 auto; }
section.summary, section.findings {
  background: var(--panel-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1.5rem 1.75rem;
  margin-bottom: 1.75rem;
}
h2 { margin: 0 0 1.1rem 0; font-size: 1.15rem; font-weight: 700; display: flex; align-items: center; gap: 0.6rem; }
h3 { font-size: 0.95rem; font-weight: 700; color: var(--text); margin: 0 0 0.9rem 0; }
.count-pill {
  background: var(--accent-soft); color: var(--accent);
  font-size: 0.8rem; font-weight: 700;
  padding: 0.15rem 0.6rem; border-radius: 999px;
}

/* Executive summary cards */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 1rem;
  margin-bottom: 1.75rem;
}
.card {
  display: flex;
  align-items: center;
  gap: 0.85rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.1rem 1.2rem;
  background: #fbfbfc;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.card:hover { transform: translateY(-2px); box-shadow: var(--shadow); }
.card-icon { font-size: 1.5rem; line-height: 1; flex-shrink: 0; }
.card-value { font-size: 1.7rem; font-weight: 800; letter-spacing: -0.02em; }
.card-label { font-size: 0.8rem; color: var(--muted); margin-top: 0.15rem; font-weight: 600; }
.card-confirmed .card-value { color: #1e7e34; }
.card-likely-tp .card-value { color: #b8860b; }
.card-false-positive .card-value { color: #c62828; }
.card-neutral .card-value { color: var(--accent); }

/* Charts */
.charts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
}
.chart-panel {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem;
  background: #fbfbfc;
}

.bar-chart {
  display: flex;
  align-items: flex-end;
  justify-content: space-around;
  gap: 0.75rem;
  height: 140px;
  margin-bottom: 0.75rem;
}
.bar-col { display: flex; flex-direction: column; align-items: center; flex: 1; height: 100%; }
.bar-count { font-size: 0.8rem; font-weight: 700; color: var(--text); margin-bottom: 0.25rem; }
.bar-track { flex: 1; width: 28px; display: flex; align-items: flex-end; background: #eef0f3; border-radius: 6px; overflow: hidden; }
.bar-fill { width: 100%; border-radius: 6px 6px 0 0; transition: height 0.2s ease; }
.bar-label { font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem; font-weight: 600; text-align: center; }

.donut {
  width: 160px; height: 160px;
  border-radius: 50%;
  margin: 0 auto 1rem;
  display: flex; align-items: center; justify-content: center;
  position: relative;
}
.donut-hole {
  width: 96px; height: 96px;
  background: var(--panel-bg);
  border-radius: 50%;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  box-shadow: inset 0 0 0 1px var(--border);
}
.donut-total { font-size: 1.4rem; font-weight: 800; }
.donut-caption { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }

.legend { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; justify-content: center; font-size: 0.8rem; color: var(--muted); }
.legend-item { display: inline-flex; align-items: center; gap: 0.4rem; font-weight: 600; }
.legend-swatch { width: 10px; height: 10px; border-radius: 3px; display: inline-block; flex-shrink: 0; }

/* Findings table */
.table-wrapper {
  overflow: auto;
  max-height: 75vh;
  border: 1px solid var(--border);
  border-radius: 10px;
}
table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.88rem; }
thead th {
  position: sticky; top: 0; z-index: 2;
  text-align: left;
  padding: 0.7rem 0.9rem;
  background: #f7f8fa;
  color: var(--text);
  font-weight: 700;
  border-bottom: 2px solid var(--border);
  white-space: nowrap;
}
tbody td {
  padding: 0.65rem 0.9rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tbody tr:nth-child(even) { background: #fafbfc; }
tbody tr:hover { background: var(--accent-soft); }
.col-file { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }
.file-short { cursor: help; border-bottom: 1px dotted var(--muted); }
.col-reasoning { color: var(--muted); max-width: 420px; }
.empty-state { text-align: center; color: var(--muted); padding: 1.5rem; }

.badge {
  display: inline-block;
  padding: 0.2rem 0.65rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 700;
  white-space: nowrap;
}

footer { text-align: center; color: var(--muted); font-size: 0.8rem; padding: 1.75rem; }

@media (max-width: 720px) {
  main { padding: 1rem; }
  .page-header { padding: 1.25rem 1rem; }
  .header-inner { flex-direction: column; align-items: flex-start; }
  section.summary, section.findings { padding: 1.1rem; }
  .table-wrapper { max-height: none; }
  thead { display: none; }
  table, tbody, tr, td { display: block; width: 100%; }
  tbody tr {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 0.75rem;
    padding: 0.6rem 0.85rem;
  }
  tbody tr:nth-child(even) { background: var(--panel-bg); }
  tbody td {
    border-bottom: none;
    padding: 0.3rem 0;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
  }
  tbody td::before {
    content: attr(data-label);
    font-weight: 700;
    color: var(--muted);
    flex-shrink: 0;
  }
  .col-reasoning { max-width: none; text-align: right; }
}
"""


def generate_report(cfg: Any) -> dict:
    """Entry point called by the pipeline (and by ``main()`` below).

    Never raises: any failure is logged and reflected in the returned
    dict's ``success``/``error`` keys instead of propagating.
    """
    try:
        return _generate_report_impl(cfg)
    except Exception as exc:  # noqa: BLE001 - intentional top-level guard
        logger.critical("report_generator failed unexpectedly: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc), "outputs": {}, "total_findings": 0}


def _generate_report_impl(cfg: Any) -> dict:
    resolver = ConfigResolver(cfg)
    logger.info("Starting report generation for %s", resolver.project_name)

    opengrep_findings: list[Finding] = []
    if resolver.opengrep_sarif_path and resolver.opengrep_sarif_path.is_file():
        opengrep_findings = SarifLoader.load(resolver.opengrep_sarif_path, "OpenGrep")
    elif resolver.normalized_findings_path and resolver.normalized_findings_path.is_file():
        opengrep_findings = NormalizedFindingsLoader.load(resolver.normalized_findings_path)

    if resolver.iris_artifacts.has_any:
        logger.info(
            "IRIS artifacts discovered: %d results.json, %d results.sarif, %d stats.json across %d director%s",
            len(resolver.iris_artifacts.results_json_files),
            len(resolver.iris_artifacts.results_sarif_files),
            len(resolver.iris_artifacts.stats_json_files),
            len(resolver.iris_artifacts.directories),
            "y" if len(resolver.iris_artifacts.directories) == 1 else "ies",
        )
        for p in resolver.iris_artifacts.results_json_files:
            logger.info("  results.json: %s", p)
        for p in resolver.iris_artifacts.results_sarif_files:
            logger.info("  results.sarif: %s", p)
        for p in resolver.iris_artifacts.stats_json_files:
            logger.info("  stats.json: %s", p)

    # Prefer the terminal posthoc SARIF for each CWE family.
    # The base cwe-* results.sarif and the sibling
    # cwe-*-posthoc-filter/results.sarif represent different stages
    # of the same analysis and must not both count as raw findings.
    all_iris_sarif_files = resolver.iris_artifacts.results_sarif_files

    posthoc_by_family: dict[str, Path] = {}
    for sarif_path in all_iris_sarif_files:
        dirname = sarif_path.parent.name
        suffix = "-posthoc-filter"

        if dirname.endswith(suffix):
            family = dirname[:-len(suffix)]
            posthoc_by_family[family] = sarif_path

    effective_iris_sarif_files: list[Path] = []

    for sarif_path in all_iris_sarif_files:
        dirname = sarif_path.parent.name

        if dirname.endswith("-posthoc-filter"):
            effective_iris_sarif_files.append(sarif_path)
            continue

        if dirname in posthoc_by_family:
            continue

        effective_iris_sarif_files.append(sarif_path)

    logger.info(
        "Effective IRIS SARIF inputs: %d of %d discovered",
        len(effective_iris_sarif_files),
        len(all_iris_sarif_files),
    )

    iris_sarif_findings: list[Finding] = []
    for p in effective_iris_sarif_files:
        iris_sarif_findings.extend(SarifLoader.load(p, "IRIS"))

    iris_verdicts: list[IrisVerdict] = []
    for p in resolver.iris_artifacts.results_json_files:
        iris_verdicts.extend(IrisResultsLoader.load(p))

    # Stage 9 final/results.json is the authoritative aggregate
    # statistics file for a single-query run. It contains both the
    # Stage 1-4 labelling totals and vanilla_result path/result counts.
    final_stats_files = [
        p
        for p in resolver.iris_artifacts.results_json_files
        if p.parent.name.endswith("-final")
    ]

    iris_stats_dict = {}

    if len(final_stats_files) == 1:
        logger.info(
            "Using Stage 9 final statistics from %s",
            final_stats_files[0],
        )
        iris_stats_dict = IrisStatsLoader.load(final_stats_files[0])
    else:
        if len(final_stats_files) > 1:
            logger.warning(
                "Multiple Stage 9 final statistics files found (%d); "
                "falling back to dedicated stats.json artifacts.",
                len(final_stats_files),
            )

        for p in resolver.iris_artifacts.stats_json_files:
            iris_stats_dict.update(IrisStatsLoader.load(p))

    merger = FindingMerger()
    merged = merger.merge(opengrep_findings, iris_sarif_findings, iris_verdicts)

    scorer = RiskScorer()
    for m in merged:
        scorer.score(m)

    try:
        resolver.report_output_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        logger.exception(
            "Could not create report output directory %s; falling back to CWD.",
            resolver.report_output_dir,
        )
        resolver.report_output_dir = Path.cwd() / "reports"
        resolver.report_output_dir.mkdir(parents=True, exist_ok=True)

    json_path = resolver.report_output_dir / "report.json"
    csv_path = resolver.report_output_dir / "report.csv"
    sarif_path = resolver.report_output_dir / "report.sarif"

    stats_engine = StatisticsEngine()
    summary = stats_engine.build(merged, len(opengrep_findings), len(iris_sarif_findings), iris_stats_dict)

    metadata = {
        "project_name": resolver.project_name,
        "run_id": resolver.run_id,
        "analyzer_version": resolver.analyzer_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    runtime_cfg = _get_value(cfg, "runtime")
    want_json = bool(_get_value(runtime_cfg, "generate_json", default=True))
    want_csv = bool(_get_value(runtime_cfg, "generate_csv", default=True))
    want_html = bool(_get_value(runtime_cfg, "generate_html", default=True))

    outputs: dict[str, str] = {}

    # JSON is always physically written: it's the data source HtmlExporter
    # reads from, so it must exist on disk whenever an HTML report is
    # requested, even if runtime.generate_json itself is turned off.
    JsonExporter.write(json_path, metadata, summary, merged)
    if want_json:
        outputs["json"] = str(json_path)
        logger.info("JSON report written.")

    if want_csv:
        CsvExporter.write(csv_path, merged)
        outputs["csv"] = str(csv_path)
        logger.info("CSV report written.")

    # SARIF is always emitted: it has no dedicated runtime.generate_* flag
    # and downstream tooling (code-scanning upload, etc.) generally expects it.
    SarifExporter.write(sarif_path, merged, metadata)
    outputs["sarif"] = str(sarif_path)
    logger.info("SARIF report written.")

    if want_html:
        html_path = resolver.report_output_dir / "report.html"
        try:
            HtmlExporter.write(json_path, html_path)
            outputs["html"] = str(html_path)
            logger.info("HTML report written.")
        except Exception:
            logger.exception("Failed to generate HTML report from %s; skipping.", json_path)

    if not want_json:
        try:
            json_path.unlink(missing_ok=True)
        except Exception:
            logger.debug("Could not remove internal-only report.json at %s", json_path, exc_info=True)

    logger.info(
        "Report generation complete: %d findings (%d IRIS posthoc-positive) -> %s",
        len(merged),
        summary.get("iris_posthoc_positive_findings", 0),
        resolver.report_output_dir,
    )

    return {
        "success": True,
        "summary": summary,
        "metadata": metadata,
        "output_dir": str(resolver.report_output_dir),
        "outputs": outputs,
        "warnings": resolver.warnings,
    }


# ---------------------------------------------------------------------------
# Standalone CLI (optional -- for manual testing/debugging; the surrounding
# pipeline normally calls generate_report(cfg) directly and never goes
# through here).
# ---------------------------------------------------------------------------

def _cfg_section(base: dict[str, Any], name: str) -> dict[str, Any]:
    section = base.get(name)
    copied = dict(section) if isinstance(section, Mapping) else {}
    base[name] = copied
    return copied


def _set_if_value(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value


def _load_cli_config(config_file: Optional[str]) -> dict[str, Any]:
    """Load ``config.yaml`` (or whatever --config points at) into a dict.

    Tries the pipeline's own ``config.Config`` wrapper first (if it is
    importable from the current working directory / PYTHONPATH), so this
    stays consistent with however parser.py/dispatcher.py/runner.py load
    configuration. Falls back to a plain PyYAML load, since report_generator.py
    otherwise has no hard dependency on that wrapper existing.
    """
    if not config_file:
        return {}

    config_path = Path(config_file).expanduser()
    if not config_path.is_file():
        logger.warning("Config file %s not found; continuing with CLI args/defaults only.", config_path)
        return {}

    try:
        from config import Config  # type: ignore  # local pipeline config wrapper, if present

        loaded = Config(str(config_path))
        raw = getattr(loaded, "cfg", None)
        if isinstance(raw, Mapping):
            logger.info("Loaded report configuration from %s", config_path)
            return dict(raw)
    except Exception:
        logger.debug("No usable local 'config' module; falling back to plain YAML load.", exc_info=True)

    try:
        import yaml  # PyYAML
    except ImportError:
        logger.error("PyYAML is not installed; cannot parse %s. Install it with `pip install pyyaml`.", config_path)
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, Mapping):
            logger.info("Loaded report configuration from %s", config_path)
            return dict(data)
        logger.warning("Config file %s did not contain a YAML mapping; ignoring.", config_path)
    except Exception:
        logger.exception("Could not parse config file %s; continuing with CLI/default discovery.", config_path)
    return {}


def _discover_existing_file(candidates: list[Path]) -> Optional[str]:
    for candidate in candidates:
        try:
            path = candidate.expanduser()
            if path.is_file():
                return str(path)
        except OSError:
            continue
    return None


def _discover_named_file(names: tuple[str, ...]) -> Optional[str]:
    roots = (Path.cwd(), Path("output"), Path("reports"), Path("results"), Path("temp"))
    discovered = _discover_existing_file([root / name for root in roots for name in names])
    if discovered:
        return discovered

    scanned = 0
    try:
        for path in Path.cwd().rglob("*"):
            scanned += 1
            if scanned > 5000:
                break
            if path.is_file() and path.name in names:
                return str(path)
    except OSError:
        return None
    return None


def _build_cfg_from_args(args: argparse.Namespace) -> SimpleNamespace:
    base = _load_cli_config(args.config)

    report_cfg = _cfg_section(base, "report")
    paths_cfg = _cfg_section(base, "paths")
    opengrep_cfg = _cfg_section(base, "opengrep")
    iris_cfg = _cfg_section(base, "iris")
    runtime_cfg = _cfg_section(base, "runtime")

    _set_if_value(report_cfg, "output_dir", args.output)
    _set_if_value(paths_cfg, "normalized_findings", args.normalized_findings)
    _set_if_value(paths_cfg, "iris_jobs", args.iris_jobs)
    _set_if_value(paths_cfg, "source_root", args.source_root)
    _set_if_value(opengrep_cfg, "output", args.opengrep)
    _set_if_value(iris_cfg, "output_dir", args.iris_output)
    _set_if_value(iris_cfg, "run_id", args.run_id)
    _set_if_value(iris_cfg, "version", args.analyzer_version)
    if args.project is not None:
        base["project"] = args.project

    if _get_value(opengrep_cfg, "output", "output_path", "sarif", "sarif_path") is None:
        discovered = _discover_named_file(("opengrep.sarif", "report.sarif", "opengrep_report.sarif"))
        if discovered:
            logger.info("Discovered OpenGrep SARIF at %s", discovered)
            opengrep_cfg["output"] = discovered

    if _get_value(paths_cfg, "normalized_findings", "normalized_findings_path") is None:
        discovered = _discover_named_file(("normalized_findings.json", "findings.normalized.json"))
        if discovered:
            logger.info("Discovered normalized findings at %s", discovered)
            paths_cfg["normalized_findings"] = discovered

    return SimpleNamespace(
        report=report_cfg,
        paths=paths_cfg,
        opengrep=opengrep_cfg,
        iris=iris_cfg,
        runtime=runtime_cfg,
        project=base.get("project"),
        version=base.get("version") or base.get("analyzer_version"),
    )


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Standalone runner for report_generator.py (the pipeline normally "
                     "calls generate_report(cfg) directly; this is for manual runs/debugging)."
    )
    parser.add_argument("--config", default="config.yaml", help="Pipeline config file to load when present (default: config.yaml).")
    parser.add_argument("--opengrep", default=None, help="Path to the OpenGrep SARIF file.")
    parser.add_argument("--iris-output", default=None, help="Base IRIS output directory (default: config value, then output/).")
    parser.add_argument("--run-id", default=None, help="IRIS run identifier, if known.")
    parser.add_argument("--normalized-findings", default=None, help="Path to parser.py's normalized_findings.json.")
    parser.add_argument("--iris-jobs", default=None, help="Path to dispatcher.py's iris_jobs.json.")
    parser.add_argument("--source-root", default=None, help="Root directory of the scanned source tree (for code snippets).")
    parser.add_argument("--output", default=None, help="Output directory (default: config value, then reports/).")
    parser.add_argument("--project", default=None, help="Project name.")
    parser.add_argument("--analyzer-version", default=None, help="Analyzer/tool version string.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    cfg = _build_cfg_from_args(args)
    result = generate_report(cfg)

    if result.get("success"):
        print()
        print("Report generated in:", result.get("output_dir"))
        for kind, filename in result.get("outputs", {}).items():
            print(f"  {kind.upper():6s}: {filename}")
        if result.get("warnings"):
            print("\nWarnings:")
            for w in result["warnings"]:
                print("  -", w)
        return 0

    print("Report generation failed:", result.get("error"), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
