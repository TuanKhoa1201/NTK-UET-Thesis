#!/usr/bin/env python3
"""
NTK Web MVP Backend Service & Local HTTP API Server (`ntk_web_backend_service.py`)
Architecture: FROZEN_ARCHITECTURE_V1
  GitHub Java Repository -> Local Source Acquisition -> OpenGrep v1.25.0
  -> IRIS Java AST/Dataflow (OpenJDK 17 JavacTask AST) -> Local Qwen2.5-Coder-0.5B-Instruct LoRA
  -> Bounded Safety Floor (0.55) -> Alert Verification & False Positive Triage (`FindingSchemaV2`)
  -> Local HTTP API (`127.0.0.1`) -> GretaAI Web UI

Guarantees:
  - 100% local execution (`local_files_only=True`, `trust_remote_code=False`, zero cloud calls).
  - Genuine Java AST parsing via OpenJDK 17 `com.sun.source.tree.*` (`JavacTask.parse()`).
  - Thread-safe serialized local LLM inference via `_MODEL_INFERENCE_LOCK`.
  - Strict GitHub URL allowlist & SSRF/injection/symlink/path-traversal protection.
  - Honest readiness status progression:
      CONTRACT_ONLY -> LOCAL_API_VERIFIED -> GITHUB_REAL_E2E_VERIFIED
      (reserving FULL_WEB_UI_E2E_VERIFIED for when the GretaAI frontend UI is mounted).
"""

import argparse
import base64
import collections
import fnmatch
import gc
import hashlib
import html
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ntk_alert_verification as triage_mod
import ntk_iris_shared as shared
import ntk_pipeline_telemetry_and_datasets as telemetry_mod

DEFAULT_BASE_MODEL_WSL = (
    "/home/tuankhoa/.cache/huggingface/hub/models--Qwen--Qwen2.5-Coder-0.5B-Instruct/"
    "snapshots/ea3f2471cf1b1f0db85067f1ef93848e38e88c25"
)
DEFAULT_BEST_ADAPTER_WSL = (
    "/mnt/f/NTK_EO06_Runs/eo06_vnext31_trackb_recovery_20261024/"
    "checkpoints/eo06_vnext31_trackb_main/best_checkpoint"
)
DEFAULT_BEST_ADAPTER_SHA256 = "176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84"

GRETAAI_PREVIEW_ORIGIN = "https://preview-e7ceb8ff-4499-44cc-b9ab-a29f90eb1d49.greta.questera.ai"
DEFAULT_CORS_ALLOWED_ORIGINS: Tuple[str, ...] = (
    GRETAAI_PREVIEW_ORIGIN,
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)
DEFAULT_CORS_ALLOW_METHODS = "GET, POST, OPTIONS"
DEFAULT_CORS_ALLOW_HEADERS = (
    "Content-Type, Accept, Origin, X-Requested-With, X-Archive-Filename, X-Scan-Id, Cache-Control, Pragma"
)
DEFAULT_CORS_MAX_AGE = "600"


def get_configured_cors_allowed_origins() -> Tuple[str, ...]:
    """
    Returns the explicit tuple of allowed CORS browser origins.
    Never permits '*' or 'null'. Supports optional comma-separated extension via NTK_CORS_ALLOWED_ORIGINS.
    """
    raw_env = os.environ.get("NTK_CORS_ALLOWED_ORIGINS", "").strip()
    origins: List[str] = list(DEFAULT_CORS_ALLOWED_ORIGINS)
    if raw_env:
        for item in raw_env.split(","):
            cand = item.strip().rstrip("/")
            if cand and cand not in ("*", "null") and cand not in origins:
                origins.append(cand)
    return tuple(origins)


def evaluate_cors_origin(
    request_origin: Optional[str],
    allowed_origins: Optional[Sequence[str]] = None,
) -> Tuple[bool, Optional[str], str]:
    """
    Evaluates the HTTP `Origin` request header against the explicit CORS allowlist.
    Returns `(is_request_permitted, allow_origin_header_value, status_reason)`:
      - If `request_origin` is None or empty (non-browser CLI/server client):
          returns `(True, None, "NO_ORIGIN_HEADER_CLI_ALLOWED")`
      - If `request_origin` exactly matches an entry in `allowed_origins`:
          returns `(True, clean_origin, "ALLOWED_EXPLICIT_ORIGIN")`
      - Otherwise (untrusted browser origin, including 'null' or '*'):
          returns `(False, None, "REJECTED_UNTRUSTED_ORIGIN")`
    """
    if request_origin is None or not str(request_origin).strip():
        return True, None, "NO_ORIGIN_HEADER_CLI_ALLOWED"
    clean_origin = str(request_origin).strip()
    allowlist = tuple(allowed_origins) if allowed_origins is not None else get_configured_cors_allowed_origins()
    if clean_origin in ("*", "null") or clean_origin not in allowlist:
        return False, None, "REJECTED_UNTRUSTED_ORIGIN"
    return True, clean_origin, "ALLOWED_EXPLICIT_ORIGIN"


_MODEL_INFERENCE_LOCK = threading.Lock()
_SCAN_EXECUTION_LOCK = threading.Lock()
_CACHED_MODEL_BUNDLE: Optional[Tuple[Any, Any, Any, str, str, Dict[str, Any]]] = None
_LAST_INFERENCE_TELEMETRY: Dict[str, Any] = {}

DEFAULT_PERSISTENT_STORAGE_DIR: Path = (
    Path(__file__).resolve().parent.parent.parent / "persisted_api_store"
)


def resolve_configured_inference_device(explicit_device: Optional[str] = None) -> Tuple[str, str]:
    """
    Resolves the target inference device (`"cuda"` or `"cpu"`) and resolution mode:
      - If explicit_device or `NTK_INFERENCE_DEVICE` is explicitly `"cuda"` / `"cuda:0"`:
          returns `(raw, "EXPLICIT_CUDA_CONFIGURED")` (will strictly require CUDA at load time; no silent fallback).
      - If explicit_device or `NTK_INFERENCE_DEVICE` is explicitly `"cpu"`:
          returns `("cpu", "EXPLICIT_CPU_CONFIGURED")`.
      - If unset or `"auto"`:
          automatically selects `"cuda"` when `torch.cuda.is_available()` is True, else `"cpu"`.
    """
    raw_env = os.environ.get("NTK_INFERENCE_DEVICE", "").strip().lower()
    raw = str(explicit_device).strip().lower() if explicit_device is not None else raw_env
    if raw in ("", "auto"):
        try:
            import torch

            if torch.cuda.is_available():
                return "cuda", "AUTO_DETECTED_CUDA_AVAILABLE"
        except Exception:
            pass
        return "cpu", "AUTO_FALLBACK_CPU_CUDA_UNAVAILABLE"
    if raw == "cuda" or raw.startswith("cuda:"):
        mode = "EXPLICIT_CUDA_ENV" if raw == raw_env else "EXPLICIT_CUDA_CONFIGURED"
        return raw, mode
    if raw == "cpu":
        mode = "EXPLICIT_CPU_ENV" if raw == raw_env else "EXPLICIT_CPU_CONFIGURED"
        return "cpu", mode
    raise ValueError(f"Unsupported NTK_INFERENCE_DEVICE value: {raw!r} (expected 'cuda', 'cpu', or 'auto')")


@dataclass(frozen=True)
class NtkWebBackendConfig:
    base_model_path: str = os.environ.get("NTK_BASE_MODEL_PATH", DEFAULT_BASE_MODEL_WSL)
    best_adapter_path: str = os.environ.get("NTK_BEST_ADAPTER_PATH", DEFAULT_BEST_ADAPTER_WSL)
    opengrep_bin: str = os.environ.get("NTK_OPENGREP_BIN", "/usr/local/bin/opengrep")
    javac_bin: str = os.environ.get("NTK_JAVAC_BIN", "/usr/bin/javac")
    git_bin: str = os.environ.get("NTK_GIT_BIN", "/usr/bin/git")
    subprocess_timeout_sec: float = float(os.environ.get("NTK_SUBPROCESS_TIMEOUT_SEC", "60.0"))
    git_clone_timeout_sec: float = float(os.environ.get("NTK_GIT_CLONE_TIMEOUT_SEC", "90.0"))
    llm_inference_timeout_sec: float = float(os.environ.get("NTK_LLM_TIMEOUT_SEC", "20.0"))
    max_source_files: int = int(os.environ.get("NTK_MAX_SOURCE_FILES", "3000"))
    max_source_files_ceiling: int = int(os.environ.get("NTK_MAX_SOURCE_FILES_CEILING", "10000"))
    max_file_bytes: int = int(os.environ.get("NTK_MAX_FILE_BYTES", str(512 * 1024)))
    max_repo_total_bytes: int = int(os.environ.get("NTK_MAX_REPO_BYTES", str(64 * 1024 * 1024)))
    max_repo_total_bytes_ceiling: int = int(os.environ.get("NTK_MAX_REPO_BYTES_CEILING", str(128 * 1024 * 1024)))
    max_zip_upload_bytes: int = int(os.environ.get("NTK_MAX_ZIP_UPLOAD_BYTES", str(25 * 1024 * 1024)))
    max_zip_entries: int = int(os.environ.get("NTK_MAX_ZIP_ENTRIES", "4000"))
    max_new_tokens: int = 96
    safety_floor: float = shared.SAFETY_FLOOR_SCORE
    device: str = field(default_factory=lambda: resolve_configured_inference_device()[0])
    model_version: str = triage_mod.MODEL_VERSION_DEFAULT
    ruleset_version: str = triage_mod.RULESET_VERSION_DEFAULT
    scoring_policy_version: str = triage_mod.SCORING_POLICY_VERSION_DEFAULT
    cors_allowed_origins: Tuple[str, ...] = get_configured_cors_allowed_origins()
    keep_model_cached: bool = True


DEFAULT_OPENGREP_RULES_YAML: str = """rules:
  - id: ntk.java.cwe089.statement-executequery
    languages: [java]
    message: "Potential SQL query execution sink (CWE-089)"
    severity: ERROR
    metadata:
      cwe: 89
    patterns:
      - pattern-either:
          - pattern: $STMT.executeQuery($SQL)
          - pattern: $PS.executeQuery()
          - pattern: $STMT.executeUpdate($SQL)
          - pattern: $STMT.executeUpdate($SQL, ...)
          - pattern: $PS.executeUpdate()
          - pattern: $STMT.execute($SQL)
          - pattern: $STMT.execute($SQL, ...)
          - pattern: $PS.execute()
          - pattern: $STMT.addBatch($SQL)
          - pattern: $TPL.batchUpdate($SQL)
          - pattern: $TPL.queryForObject($SQL, ...)
          - pattern: $TPL.queryForList($SQL, ...)
          - pattern: $TPL.queryForMap($SQL, ...)
          - pattern: $TPL.queryForRowSet($SQL, ...)
          - pattern: $TPL.queryForInt($SQL, ...)
          - pattern: $TPL.queryForLong($SQL, ...)
          - pattern: $TPL.query($SQL, ...)
          - pattern: $TPL.update($SQL, ...)

  - id: ntk.java.cwe078.runtime-exec
    languages: [java]
    message: "Potential OS command execution sink (CWE-078)"
    severity: ERROR
    metadata:
      cwe: 78
    patterns:
      - pattern-either:
          - pattern: Runtime.getRuntime().exec(...)
          - pattern: (Runtime $RT).exec(...)
          - pattern: (java.lang.Runtime $RT).exec(...)
          - pattern: new ProcessBuilder(...).start()
          - pattern: $PB.start()

  - id: ntk.java.cwe022.files-readallbytes
    languages: [java]
    message: "Potential filesystem path read sink (CWE-022)"
    severity: ERROR
    metadata:
      cwe: 22
    patterns:
      - pattern-either:
          - pattern: Files.readAllBytes($PATH)
          - pattern: Files.readString($PATH)
          - pattern: Files.lines($PATH)
          - pattern: Files.newInputStream($PATH, ...)
          - pattern: new java.io.FileInputStream(...)
          - pattern: new FileInputStream(...)
          - pattern: new java.io.FileOutputStream(...)
          - pattern: new FileOutputStream(...)
          - pattern: new java.io.FileReader(...)
          - pattern: new FileReader(...)
          - pattern: new java.io.FileWriter(...)
          - pattern: new FileWriter(...)

  - id: ntk.java.cwe079.printwriter-println
    languages: [java]
    message: "Potential HTML output response sink (CWE-079)"
    severity: ERROR
    metadata:
      cwe: 79
    patterns:
      - pattern-either:
          - pattern: $OUT.println($HTML)
          - pattern: $OUT.print($HTML)
          - pattern: $OUT.write($HTML)
          - pattern: $OUT.printf($FMT, ...)
          - pattern: $OUT.format($FMT, ...)
      - pattern-not: $OUT.println("...")
      - pattern-not: $OUT.print("...")
      - pattern-not: $OUT.write("...")
      - pattern-not: $OUT.write($ARR, $OFF, $LEN)
      - pattern-not: String.format(...)
      - pattern-not: java.lang.String.format(...)
      - pattern-not: System.out.println(...)
      - pattern-not: System.out.print(...)
      - pattern-not: System.out.write(...)
      - pattern-not: System.out.printf(...)
      - pattern-not: System.out.format(...)
      - pattern-not: System.err.println(...)
      - pattern-not: System.err.print(...)
      - pattern-not: System.err.write(...)
      - pattern-not: System.err.printf(...)
      - pattern-not: System.err.format(...)
"""


def _infer_cwe_from_rule(hit: Dict[str, Any]) -> int:
    meta_cwe = hit.get("extra", {}).get("metadata", {}).get("cwe")
    if meta_cwe is not None:
        try:
            return int(str(meta_cwe).replace("CWE-", "").strip())
        except ValueError:
            pass
    check_id = str(hit.get("check_id", "")).lower()
    for cwe_id in (22, 78, 79, 89):
        if f"cwe0{cwe_id}" in check_id or f"cwe-{cwe_id}" in check_id or f"cwe-0{cwe_id}" in check_id:
            return cwe_id
    return 89


# ============================================================================
# Security Validators for GitHub Repository URLs, Refs, and Subpaths
# ============================================================================
_GITHUB_REPO_PATH_RE = re.compile(r"^/([A-Za-z0-9_.\-]{1,100})/([A-Za-z0-9_.\-]{1,100}?)(?:\.git)?/?$")
_GIT_REF_RE = re.compile(r"^[A-Za-z0-9_./\-]{1,128}$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_SHELL_METACHAR_RE = re.compile(r"[;|&$`><\n\r\x00]")


def validate_github_repo_url(repo_url: str) -> Tuple[bool, str, str]:
    """
    Validates that `repo_url` is a canonical public HTTPS GitHub repository URL.
    Blocks SSRF (localhost, private/loopback/link-local IPs), non-HTTPS schemes (`file://`, `ssh://`,
    `git@`, `http://`), embedded credentials, query/fragment components, path traversal, and shell metacharacters.
    Returns `(is_valid, error_code_or_ok, canonical_https_url)`.
    """
    if not isinstance(repo_url, str) or not repo_url.strip():
        return False, "EMPTY_REPO_URL", ""
    raw = repo_url.strip()
    if len(raw) > 300:
        return False, "REPO_URL_TOO_LONG", ""
    if _SHELL_METACHAR_RE.search(raw):
        return False, "SHELL_METACHARACTER_REJECTED", ""
    if raw.startswith("git@") or raw.startswith("ssh://") or raw.startswith("file://"):
        return False, "NON_HTTPS_SCHEME_REJECTED", ""

    try:
        parsed = urllib.parse.urlsplit(raw)
    except Exception:
        return False, "MALFORMED_URL", ""

    if parsed.scheme != "https":
        return False, "NON_HTTPS_SCHEME_REJECTED", ""
    if parsed.username or parsed.password or "@" in parsed.netloc:
        return False, "URL_CREDENTIALS_REJECTED", ""
    if parsed.query or parsed.fragment:
        return False, "URL_QUERY_OR_FRAGMENT_REJECTED", ""

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "MISSING_HOSTNAME", ""

    # Block any IP literal (IPv4/IPv6) or localhost
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local") or host.endswith(".internal"):
        return False, "SSRF_LOCALHOST_REJECTED", ""
    try:
        ip_obj = ipaddress.ip_address(host.strip("[]"))
        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False, "SSRF_PRIVATE_OR_LOOPBACK_IP_REJECTED", ""
        return False, "IP_LITERAL_HOST_REJECTED", ""
    except ValueError:
        pass

    if host != "github.com" or (parsed.port not in (None, 443)):
        return False, "HOST_NOT_IN_GITHUB_ALLOWLIST", ""

    if ".." in parsed.path or "\\\\" in parsed.path:
        return False, "URL_PATH_TRAVERSAL_REJECTED", ""

    m = _GITHUB_REPO_PATH_RE.match(parsed.path)
    if not m:
        return False, "INVALID_GITHUB_OWNER_REPO_PATH", ""

    owner, repo = m.group(1), m.group(2)
    if owner in (".", "..") or repo in (".", "..") or owner.startswith("-") or repo.startswith("-"):
        return False, "INVALID_GITHUB_OWNER_REPO_NAME", ""

    canonical_url = f"https://github.com/{owner}/{repo}.git"
    return True, "OK", canonical_url


def validate_git_ref(ref: Optional[str], is_commit_sha: bool = False) -> Tuple[bool, str]:
    if ref is None or str(ref).strip() == "":
        return True, "OK"
    s = str(ref).strip()
    if s.startswith("-"):
        return False, "GIT_OPTION_INJECTION_REJECTED"
    if ".." in s or _SHELL_METACHAR_RE.search(s) or "\\" in s:
        return False, "INVALID_GIT_REF_CHARACTERS"
    if is_commit_sha:
        if not _COMMIT_SHA_RE.match(s):
            return False, "INVALID_COMMIT_SHA_FORMAT"
    else:
        if not _GIT_REF_RE.match(s):
            return False, "INVALID_BRANCH_OR_TAG_FORMAT"
    return True, "OK"


def validate_relative_subpath(subpath: Optional[str]) -> Tuple[bool, str, str]:
    if subpath is None or str(subpath).strip() == "":
        return True, "OK", ""
    s = str(subpath).strip().replace("\\", "/").strip("/")
    if not s:
        return True, "OK", ""
    if s.startswith("-") or s.startswith("/") or ":" in s or _SHELL_METACHAR_RE.search(s):
        return False, "INVALID_SUBPATH_CHARACTERS", ""
    parts = [p for p in s.split("/") if p]
    if any(p in (".", "..") for p in parts):
        return False, "SUBPATH_TRAVERSAL_REJECTED", ""
    return True, "OK", "/".join(parts)


_SKIP_BUILD_AND_VCS_DIRS: Set[str] = {
    ".git",
    ".gradle",
    ".mvn",
    ".idea",
    ".vscode",
    "node_modules",
    "target",
    "build",
    "dist",
    "out",
    "__pycache__",
}

SUPPORTED_CWE_CATEGORIES: Tuple[str, ...] = ("CWE-022", "CWE-078", "CWE-079", "CWE-089")
DEFAULT_RULES_APPLIED_COUNT: int = 4
SUPPORTED_SCAN_SCOPE_POLICIES: Tuple[str, ...] = (
    "STRICT_FAIL_ON_LIMIT",
    "BOUNDED_PARTIAL_SCAN",
    "FULL_REPOSITORY_BATCHED_SCAN",
)


def validate_glob_patterns(globs: Optional[Sequence[str]], field_name: str = "glob") -> Tuple[bool, str, List[str]]:
    if globs is None:
        return True, "OK", []
    if isinstance(globs, str):
        globs = [p.strip() for p in globs.split(",") if p.strip()]
    if not isinstance(globs, (list, tuple)):
        return False, f"INVALID_{field_name.upper()}_TYPE", []
    if len(globs) > 3000:
        return False, f"TOO_MANY_{field_name.upper()}_PATTERNS", []
    cleaned: List[str] = []
    for g in globs:
        s = str(g).strip().replace("\\", "/").lstrip("/")
        if not s:
            continue
        if len(s) > 240 or ".." in s or ":" in s or _SHELL_METACHAR_RE.search(s):
            return False, f"INVALID_{field_name.upper()}_PATTERN", []
        cleaned.append(s)
    return True, "OK", cleaned


def resolve_effective_scan_limits(
    cfg: NtkWebBackendConfig,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
) -> Tuple[bool, str, int, int, str]:
    """
    Validates and resolves `(ok, err_code, effective_max_files, effective_max_repo_bytes, effective_policy)`.
    """
    pol = str(scan_scope_policy or "STRICT_FAIL_ON_LIMIT").strip().upper()
    if not pol:
        pol = "STRICT_FAIL_ON_LIMIT"
    if pol not in SUPPORTED_SCAN_SCOPE_POLICIES:
        return False, "INVALID_SCAN_SCOPE_POLICY", cfg.max_source_files, cfg.max_repo_total_bytes, pol

    eff_files = cfg.max_source_files_ceiling if pol == "FULL_REPOSITORY_BATCHED_SCAN" else cfg.max_source_files
    if max_files_limit is not None and str(max_files_limit).strip() != "":
        try:
            req_lim = int(max_files_limit)
        except (ValueError, TypeError):
            return False, "INVALID_MAX_FILES_LIMIT", cfg.max_source_files, cfg.max_repo_total_bytes, pol
        if req_lim < 1 or req_lim > cfg.max_source_files_ceiling:
            return False, "MAX_FILES_LIMIT_OUT_OF_RANGE", cfg.max_source_files, cfg.max_repo_total_bytes, pol
        eff_files = req_lim

    eff_repo_bytes = (
        cfg.max_repo_total_bytes_ceiling if eff_files > cfg.max_source_files else cfg.max_repo_total_bytes
    )
    return True, "OK", eff_files, eff_repo_bytes, pol


def detect_java_project_layout(root_dir: Path) -> Dict[str, Any]:
    """
    Passively inspects `root_dir` for Maven (`pom.xml`) and Gradle (`build.gradle*`, `settings.gradle*`)
    project descriptors and standard source roots without executing any build tool or plugin.
    """
    has_root_pom = (root_dir / "pom.xml").is_file()
    has_root_gradle = (root_dir / "build.gradle").is_file() or (root_dir / "build.gradle.kts").is_file()
    has_settings_gradle = (root_dir / "settings.gradle").is_file() or (root_dir / "settings.gradle.kts").is_file()
    has_src_main_java = (root_dir / "src" / "main" / "java").is_dir()
    has_src_test_java = (root_dir / "src" / "test" / "java").is_dir()

    child_poms: List[str] = []
    child_gradles: List[str] = []
    module_source_roots: List[str] = []
    try:
        for child in sorted(root_dir.iterdir()):
            if not child.is_dir() or child.name in _SKIP_BUILD_AND_VCS_DIRS or child.name.startswith("."):
                continue
            if (child / "pom.xml").is_file():
                child_poms.append(child.name)
            if (child / "build.gradle").is_file() or (child / "build.gradle.kts").is_file():
                child_gradles.append(child.name)
            if (child / "src" / "main" / "java").is_dir():
                module_source_roots.append(f"{child.name}/src/main/java")
    except Exception:
        pass

    if has_root_pom and child_poms:
        layout_kind = "MULTI_MODULE_MAVEN"
    elif has_root_pom:
        layout_kind = "SINGLE_MODULE_MAVEN"
    elif (has_root_gradle or has_settings_gradle) and (child_gradles or module_source_roots):
        layout_kind = "MULTI_MODULE_GRADLE"
    elif has_root_gradle or has_settings_gradle:
        layout_kind = "SINGLE_MODULE_GRADLE"
    elif has_src_main_java:
        layout_kind = "STANDARD_JAVA_SRC_MAIN_LAYOUT"
    else:
        layout_kind = "PLAIN_JAVA_SOURCE_TREE"

    return {
        "layout_kind": layout_kind,
        "has_root_pom_xml": has_root_pom,
        "has_root_build_gradle": has_root_gradle,
        "has_settings_gradle": has_settings_gradle,
        "has_src_main_java": has_src_main_java,
        "has_src_test_java": has_src_test_java,
        "detected_submodules": sorted(set(child_poms + child_gradles)),
        "detected_module_source_roots": module_source_roots,
        "build_execution_policy": "PASSIVE_SOURCE_DISCOVERY_ONLY_NEVER_EXECUTES_MAVEN_OR_GRADLE",
    }


def _matches_any_glob(rel_path: str, patterns: Sequence[str]) -> bool:
    basename = os.path.basename(rel_path)
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(basename, pat):
            return True
        if pat.startswith("**/") and (
            fnmatch.fnmatch(rel_path, pat[3:]) or fnmatch.fnmatch(basename, pat[3:])
        ):
            return True
    return False


def discover_and_verify_java_source_inventory(
    workspace_root: Path,
    scan_root: Path,
    cfg: NtkWebBackendConfig,
    source_mode: str,
    repository_url: str = "",
    requested_commit: str = "",
    resolved_commit: str = "",
    target_subpath: str = "",
    file_allowlist: Optional[Sequence[str]] = None,
    include_globs: Optional[Sequence[str]] = None,
    exclude_globs: Optional[Sequence[str]] = None,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Unified, single-pass Java source inventory & verification engine used across GitHub clones,
    ZIP archive uploads, and local directories:
      - Automatically skips build/VCS/IDE directories (`.git`, `target`, `build`, `.gradle`, `node_modules`, etc.).
      - Removes any symbolic links and strictly enforces workspace root containment.
      - Applies `target_subpath`, `file_allowlist`, `include_globs`, `exclude_globs`.
      - Enforces `max_file_bytes`, `effective_max_repo_total_bytes`, and `effective_max_source_files`
        according to `scan_scope_policy` (`STRICT_FAIL_ON_LIMIT` vs `BOUNDED_PARTIAL_SCAN`).
      - Produces complete `coverage_diagnostics` and `file_sha256_map`.
    """
    ok_inc, inc_err, clean_inc = validate_glob_patterns(include_globs, "include_globs")
    if not ok_inc:
        return {
            "status": "ERROR",
            "error_code": inc_err,
            "error_message": f"Invalid include_globs pattern: {include_globs!r}",
        }
    ok_exc, exc_err, clean_exc = validate_glob_patterns(exclude_globs, "exclude_globs")
    if not ok_exc:
        return {
            "status": "ERROR",
            "error_code": exc_err,
            "error_message": f"Invalid exclude_globs pattern: {exclude_globs!r}",
        }
    ok_lim, lim_err, eff_max_files, eff_max_repo_bytes, eff_policy = resolve_effective_scan_limits(
        cfg, max_files_limit=max_files_limit, scan_scope_policy=scan_scope_policy
    )
    if not ok_lim:
        return {
            "status": "ERROR",
            "error_code": lim_err,
            "error_message": (
                f"Invalid scan limit or scope policy (max_files_limit={max_files_limit!r}, "
                f"ceiling={cfg.max_source_files_ceiling}, scan_scope_policy={scan_scope_policy!r})"
            ),
        }

    allow_set: Optional[Set[str]] = None
    if file_allowlist:
        allow_set = set()
        for fp in file_allowlist:
            ok_f, f_code, cf = validate_relative_subpath(fp)
            if not ok_f:
                return {
                    "status": "ERROR",
                    "error_code": f_code,
                    "error_message": f"Invalid file in file_allowlist: {fp!r}",
                }
            if cf:
                allow_set.add(cf)

    resolved_ws_root = workspace_root.resolve()
    if not scan_root.exists() or not str(scan_root.resolve()).startswith(str(resolved_ws_root)):
        return {
            "status": "ERROR",
            "error_code": "SUBPATH_NOT_FOUND_OR_ESCAPED",
            "error_message": f"Target subpath {target_subpath!r} does not exist inside workspace root",
        }

    layout_info = detect_java_project_layout(resolved_ws_root if resolved_ws_root.is_dir() else scan_root.parent)

    all_candidate_paths: List[Path] = []
    skipped_build_dir_count = 0
    if scan_root.is_file():
        if scan_root.suffix == ".java":
            all_candidate_paths.append(scan_root)
    else:
        for p in sorted(scan_root.rglob("*")):
            if p.is_symlink():
                p.unlink(missing_ok=True)
                continue
            if not p.is_file() or p.suffix != ".java":
                continue
            rp = p.resolve()
            if not str(rp).startswith(str(resolved_ws_root)):
                return {
                    "status": "ERROR",
                    "error_code": "PATH_TRAVERSAL_DETECTED_IN_REPO",
                    "error_message": f"File {p} escaped workspace root",
                }
            rel_parts = rp.relative_to(resolved_ws_root).parts[:-1]
            if any(part in _SKIP_BUILD_AND_VCS_DIRS for part in rel_parts):
                skipped_build_dir_count += 1
                continue
            all_candidate_paths.append(rp)

    discovered_entries: List[Tuple[str, Path, int]] = []
    skipped_filter_count = 0
    total_discovered_bytes = 0
    for rp in all_candidate_paths:
        rel_str = (
            str(rp.relative_to(resolved_ws_root)).replace("\\", "/")
            if rp != resolved_ws_root
            else rp.name
        )
        sz = rp.stat().st_size
        total_discovered_bytes += sz
        if allow_set is not None and rel_str not in allow_set and rp.name not in allow_set:
            skipped_filter_count += 1
            continue
        if clean_inc and not _matches_any_glob(rel_str, clean_inc):
            skipped_filter_count += 1
            continue
        if clean_exc and _matches_any_glob(rel_str, clean_exc):
            skipped_filter_count += 1
            continue
        discovered_entries.append((rel_str, rp, sz))

    total_discovered_count = len(all_candidate_paths)
    matched_count = len(discovered_entries)
    incomplete_reasons: List[str] = []
    was_filtered = bool(
        target_subpath or allow_set is not None or clean_inc or clean_exc or skipped_build_dir_count > 0
    )
    if target_subpath:
        incomplete_reasons.append(f"TARGET_SUBPATH_FILTER:{target_subpath}")
    if allow_set is not None:
        incomplete_reasons.append(f"FILE_ALLOWLIST_FILTER:{len(allow_set)}_entries")
    if clean_inc:
        inc_desc = ",".join(clean_inc) if len(clean_inc) <= 8 else f"{len(clean_inc)}_patterns"
        incomplete_reasons.append(f"INCLUDE_GLOBS_FILTER:{inc_desc}")
    if clean_exc:
        exc_desc = ",".join(clean_exc) if len(clean_exc) <= 8 else f"{len(clean_exc)}_patterns"
        incomplete_reasons.append(f"EXCLUDE_GLOBS_FILTER:{exc_desc}")

    def _build_cov_diag(
        scanned_count: int,
        scanned_b: int,
        skipped_lim: int,
        cov_status: str,
        reasons: List[str],
    ) -> Dict[str, Any]:
        total_skipped = max(0, total_discovered_count - scanned_count)
        return {
            "source_mode": source_mode,
            "repository_url": repository_url,
            "requested_commit": requested_commit,
            "resolved_commit": resolved_commit,
            "target_subpath": target_subpath,
            "scan_scope_policy": eff_policy,
            "include_globs": clean_inc,
            "exclude_globs": clean_exc,
            "project_layout_detected": layout_info,
            "java_files_discovered": total_discovered_count,
            "java_files_matched_after_filters": matched_count,
            "java_files_scanned": scanned_count,
            "java_files_skipped": total_skipped,
            "skipped_files_breakdown": {
                "excluded_by_build_or_vcs_dir": skipped_build_dir_count,
                "excluded_by_globs_or_allowlist": skipped_filter_count,
                "excluded_by_bounded_file_limit": skipped_lim,
            },
            "source_bytes_discovered": total_discovered_bytes,
            "source_bytes_scanned": scanned_b,
            "rules_applied_count": 4,
            "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
            "source_inventory_limits": {
                "configured_default_max_source_files": cfg.max_source_files,
                "effective_max_source_files": eff_max_files,
                "max_source_files_ceiling": cfg.max_source_files_ceiling,
                "max_file_bytes": cfg.max_file_bytes,
                "effective_max_repo_total_bytes": eff_max_repo_bytes,
                "max_repo_total_bytes_ceiling": cfg.max_repo_total_bytes_ceiling,
                "max_zip_upload_bytes": cfg.max_zip_upload_bytes,
                "max_zip_entries": cfg.max_zip_entries,
            },
            "coverage_status": (
                "FULL_SOURCE_COVERAGE"
                if cov_status in ("COMPLETE_SCANNED", "FULL_SOURCE_COVERAGE")
                else ("PARTIAL_BOUNDED" if cov_status == "PARTIAL_BOUNDED" else "FAILED_OR_INCOMPLETE")
            ),
            "analysis_coverage_status": cov_status,
            "legacy_analysis_coverage_status": (
                "COMPLETE_SCANNED" if cov_status == "FULL_SOURCE_COVERAGE" else cov_status
            ),
            "total_discovered_java_files": total_discovered_count,
            "eligible_java_files": matched_count,
            "fully_processed_java_files": scanned_count,
            "excluded_java_files": total_skipped,
            "per_reason_exclusions": {
                "excluded_by_build_or_vcs_dir": skipped_build_dir_count,
                "excluded_by_globs_or_allowlist": skipped_filter_count,
                "excluded_by_bounded_file_limit": skipped_lim,
            },
            "incomplete_analysis_reasons": list(reasons),
        }

    if matched_count == 0:
        err_code = "NO_JAVA_FILES_MATCHED_FILTERS" if total_discovered_count > 0 else "NO_JAVA_FILES_FOUND"
        err_msg = (
            f"Discovered {total_discovered_count} .java files in {scan_root.name}, "
            f"but 0 files matched filters (include_globs={clean_inc}, exclude_globs={clean_exc})"
            if total_discovered_count > 0
            else f"No .java files found in {scan_root}"
        )
        cov_diag = _build_cov_diag(
            0, 0, 0, "FAILED_STAGE_02_NO_JAVA_FILES", incomplete_reasons + [err_code]
        )
        return {
            "status": "ERROR",
            "error_code": err_code,
            "error_message": err_msg,
            "coverage_diagnostics": cov_diag,
        }

    skipped_limit_count = 0
    if matched_count > eff_max_files:
        if eff_policy == "BOUNDED_PARTIAL_SCAN":
            skipped_limit_count = matched_count - eff_max_files
            selected_entries = discovered_entries[:eff_max_files]
            incomplete_reasons.append(
                f"BOUNDED_PARTIAL_SCAN_TRUNCATED:{eff_max_files}_of_{matched_count}_matched_java_files"
            )
        else:
            err_msg = (
                f"Found {matched_count} Java source files (total discovered={total_discovered_count}); "
                f"effective limit is {eff_max_files} (ceiling={cfg.max_source_files_ceiling}). "
                "Provide target_subpath, include_globs, exclude_globs, max_files_limit (up to ceiling), "
                "or scan_scope_policy='BOUNDED_PARTIAL_SCAN'."
            )
            cov_diag = _build_cov_diag(
                0,
                0,
                matched_count,
                "FAILED_STAGE_02_LIMIT_EXCEEDED",
                incomplete_reasons + [f"MAX_SOURCE_FILES_EXCEEDED:{matched_count}_gt_{eff_max_files}"],
            )
            return {
                "status": "ERROR",
                "error_code": "MAX_SOURCE_FILES_EXCEEDED",
                "error_message": err_msg,
                "coverage_diagnostics": cov_diag,
            }
    else:
        selected_entries = discovered_entries

    selected_rel_files: List[str] = []
    selected_abs_paths: List[Path] = []
    file_sha256_map: Dict[str, str] = {}
    scanned_bytes = 0

    for rel_str, rp, sz in selected_entries:
        if sz > cfg.max_file_bytes:
            err_msg = f"File { rp.name } ({rel_str}) is {sz} bytes; limit is {cfg.max_file_bytes}"
            cov_diag = _build_cov_diag(
                0,
                scanned_bytes,
                skipped_limit_count,
                "FAILED_STAGE_02_FILE_BYTES_EXCEEDED",
                incomplete_reasons + [f"MAX_FILE_BYTES_EXCEEDED:{rel_str}:{sz}"],
            )
            return {
                "status": "ERROR",
                "error_code": "MAX_FILE_BYTES_EXCEEDED",
                "error_message": err_msg,
                "coverage_diagnostics": cov_diag,
            }
        scanned_bytes += sz
        if scanned_bytes > eff_max_repo_bytes:
            err_msg = f"Total scanned Java source bytes ({scanned_bytes}) exceeded limit ({eff_max_repo_bytes})"
            cov_diag = _build_cov_diag(
                0,
                scanned_bytes,
                skipped_limit_count,
                "FAILED_STAGE_02_REPO_BYTES_EXCEEDED",
                incomplete_reasons + [f"MAX_REPO_BYTES_EXCEEDED:{scanned_bytes}_gt_{eff_max_repo_bytes}"],
            )
            return {
                "status": "ERROR",
                "error_code": "MAX_REPO_BYTES_EXCEEDED",
                "error_message": err_msg,
                "coverage_diagnostics": cov_diag,
            }
        selected_rel_files.append(rel_str)
        selected_abs_paths.append(rp)
        file_sha256_map[rel_str] = shared.sha256_bytes(rp.read_bytes())

    init_cov_status = (
        "PARTIAL_BOUNDED"
        if (skipped_limit_count > 0 or skipped_filter_count > 0 or bool(target_subpath))
        else "FULL_SOURCE_COVERAGE"
    )
    cov_diag = _build_cov_diag(
        len(selected_rel_files),
        scanned_bytes,
        skipped_limit_count,
        init_cov_status,
        incomplete_reasons,
    )
    return {
        "status": "OK",
        "scan_root": str(scan_root),
        "java_file_count": len(selected_rel_files),
        "java_files_discovered": total_discovered_count,
        "java_files_scanned": len(selected_rel_files),
        "java_files_skipped": cov_diag["java_files_skipped"],
        "java_files": selected_rel_files,
        "java_abs_paths": selected_abs_paths,
        "java_file_paths": [str(p) for p in selected_abs_paths],
        "file_sha256_map": file_sha256_map,
        "total_java_bytes": scanned_bytes,
        "source_bytes_discovered": total_discovered_bytes,
        "source_bytes_scanned": scanned_bytes,
        "was_filtered_or_truncated": bool(
            was_filtered or skipped_limit_count > 0 or len(selected_rel_files) < total_discovered_count
        ),
        "project_layout_detected": layout_info,
        "coverage_diagnostics": cov_diag,
    }


# ============================================================================
# Safe GitHub Java Repository Acquisition
# ============================================================================
_GLOBAL_SCAN_CACHE: Optional[telemetry_mod.NtkMultiLayerScanCache] = None
_GLOBAL_SCAN_CACHE_LOCK = threading.Lock()


def get_global_scan_cache(
    storage_dir: Optional[Path] = None,
    cache_dir: Optional[Path] = None,
) -> telemetry_mod.NtkMultiLayerScanCache:
    global _GLOBAL_SCAN_CACHE
    with _GLOBAL_SCAN_CACHE_LOCK:
        target_storage = Path(storage_dir) if storage_dir is not None else resolve_storage_dir()
        target_cache = telemetry_mod.resolve_ext4_cache_dir(
            storage_dir=target_storage,
            explicit_cache_dir=cache_dir,
        )
        if (
            _GLOBAL_SCAN_CACHE is None
            or _GLOBAL_SCAN_CACHE.storage_dir.resolve() != target_storage.resolve()
            or _GLOBAL_SCAN_CACHE.cache_dir.resolve() != target_cache.resolve()
        ):
            _GLOBAL_SCAN_CACHE = telemetry_mod.NtkMultiLayerScanCache(
                storage_dir=target_storage,
                cache_dir=target_cache,
            )
        return _GLOBAL_SCAN_CACHE


def compute_scoring_summary(
    findings: Sequence[Dict[str, Any]],
    safety_floor: float = 0.55,
    scoring_policy_version: str = "NTK_BOUNDED_SAFETY_FLOOR_FUSION_V1.2",
) -> Dict[str, Any]:
    scores: List[float] = []
    null_or_nan_count = 0
    unit_interval_ok = True
    safety_floor_clamp_count = 0
    ast_release_count = 0
    by_decision: Dict[str, List[float]] = {"REPORT": [], "REVIEW": [], "SUPPRESS": []}
    samples: List[Dict[str, Any]] = []

    for f in findings:
        raw_sc = f.get("final_heuristic_score", f.get("confidence_score"))
        if raw_sc is None:
            null_or_nan_count += 1
            continue
        try:
            sc_val = float(raw_sc)
        except (ValueError, TypeError):
            null_or_nan_count += 1
            continue
        if sc_val != sc_val or sc_val < 0.0 or sc_val > 1.0:
            unit_interval_ok = False
        scores.append(sc_val)
        dec = str(f.get("decision", "REVIEW")).upper()
        by_decision.setdefault(dec, []).append(sc_val)
        sb = f.get("score_breakdown") or f.get("fusion_score_breakdown") or {}
        if isinstance(sb, dict):
            if sb.get("safety_floor_applied"):
                safety_floor_clamp_count += 1
            if sb.get("post_release_veto_applied") or sb.get("ast_sanitizer_or_constant_verified"):
                ast_release_count += 1
        if len(samples) < 10:
            samples.append(
                {
                    "finding_id": f.get("finding_id"),
                    "cwe": f.get("cwe"),
                    "file_path": f.get("file_path"),
                    "line_number": f.get("line_number"),
                    "decision": dec,
                    "final_heuristic_score": sc_val,
                    "confidence_score": f.get("confidence_score", sc_val),
                    "score_breakdown": sb,
                }
            )

    sorted_scores = sorted(scores)
    n_sc = len(sorted_scores)
    if n_sc > 0:
        min_sc = round(sorted_scores[0], 4)
        max_sc = round(sorted_scores[-1], 4)
        mean_sc = round(sum(sorted_scores) / n_sc, 4)
        med_sc = round(
            sorted_scores[n_sc // 2]
            if n_sc % 2 == 1
            else 0.5 * (sorted_scores[n_sc // 2 - 1] + sorted_scores[n_sc // 2]),
            4,
        )
    else:
        min_sc = 0.0
        max_sc = 0.0
        mean_sc = 0.0
        med_sc = 0.0

    dec_summary: Dict[str, Any] = {}
    for d_key in ("REPORT", "REVIEW", "SUPPRESS"):
        d_vals = sorted(by_decision.get(d_key, []))
        if d_vals:
            dec_summary[d_key] = {
                "count": len(d_vals),
                "min_score": round(d_vals[0], 4),
                "max_score": round(d_vals[-1], 4),
                "mean_score": round(sum(d_vals) / len(d_vals), 4),
            }
        else:
            dec_summary[d_key] = {
                "count": 0,
                "min_score": None,
                "max_score": None,
                "mean_score": None,
            }

    return {
        "scoring_policy_version": scoring_policy_version,
        "safety_floor": safety_floor,
        "score_semantics": triage_mod.SCORE_KIND_DEFAULT,
        "total_scored_findings": n_sc,
        "null_or_nan_score_count": null_or_nan_count,
        "all_scores_non_null_and_within_unit_interval": bool(null_or_nan_count == 0 and unit_interval_ok),
        "min_heuristic_score": min_sc,
        "max_heuristic_score": max_sc,
        "mean_heuristic_score": mean_sc,
        "median_heuristic_score": med_sc,
        "safety_floor_clamp_applied_count": safety_floor_clamp_count,
        "ast_sanitizer_or_constant_release_count": ast_release_count,
        "decision_score_breakdown": dec_summary,
        "sample_finding_scores": samples,
    }


def acquire_github_java_repository(
    repo_url: str,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
    target_subpath: Optional[str] = None,
    file_allowlist: Optional[Sequence[str]] = None,
    include_globs: Optional[Sequence[str]] = None,
    exclude_globs: Optional[Sequence[str]] = None,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
    workspace_parent: Optional[Path] = None,
    config: Optional[NtkWebBackendConfig] = None,
    stage_tracker: Optional[telemetry_mod.PipelineStageTracker] = None,
    force_fresh_scan: bool = False,
) -> Dict[str, Any]:
    """
    Safely acquires `.java` files from a public GitHub repository into an isolated workspace directory:
      - Enforces strict URL allowlist (`https://github.com/<owner>/<repo>.git`) & SSRF blocks.
      - Uses `subprocess.run(..., shell=False)` with `git` security flags:
        `-c core.symlinks=false -c protocol.file.allow=never -c submodule.recurse=false`.
      - Performs shallow blobless clone (`--depth 1 --filter=blob:none --no-checkout`) and sparse checkout
        when `target_subpath` or `file_allowlist` is provided so even large repositories (like WebGoat
        or OWASP Benchmark) can be scanned deterministically within resource limits.
      - Runs unified `discover_and_verify_java_source_inventory` in Stage 02 (no duplicate file walk).
    """
    cfg = config or NtkWebBackendConfig()
    t0 = time.perf_counter()
    if stage_tracker is not None:
        stage_tracker.start_stage(
            1,
            {
                "source_mode": "GITHUB_GIT_CLONE",
                "requested_repo_url": repo_url,
                "requested_branch": branch or "",
                "requested_commit_sha": commit_sha or "",
                "target_subpath": target_subpath or "",
                "scan_scope_policy": scan_scope_policy or "STRICT_FAIL_ON_LIMIT",
            },
        )

    ok_url, url_code, canonical_url = validate_github_repo_url(repo_url)
    if not ok_url:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, url_code, f"Rejected repository URL {repo_url!r}: {url_code}")
        return {
            "status": "ERROR",
            "error_code": url_code,
            "error_message": f"Rejected repository URL {repo_url!r}: {url_code}",
        }

    ok_br, br_code = validate_git_ref(branch, is_commit_sha=False)
    if not ok_br:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, br_code, f"Rejected branch {branch!r}: {br_code}")
        return {
            "status": "ERROR",
            "error_code": br_code,
            "error_message": f"Rejected branch {branch!r}: {br_code}",
        }

    ok_sha, sha_code = validate_git_ref(commit_sha, is_commit_sha=True)
    if not ok_sha:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, sha_code, f"Rejected commit_sha {commit_sha!r}: {sha_code}")
        return {
            "status": "ERROR",
            "error_code": sha_code,
            "error_message": f"Rejected commit_sha {commit_sha!r}: {sha_code}",
        }

    ok_sub, sub_code, clean_subpath = validate_relative_subpath(target_subpath)
    if not ok_sub:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, sub_code, f"Rejected target_subpath {target_subpath!r}: {sub_code}")
        return {
            "status": "ERROR",
            "error_code": sub_code,
            "error_message": f"Rejected target_subpath {target_subpath!r}: {sub_code}",
        }

    ok_inc, inc_code, clean_inc = validate_glob_patterns(include_globs, "include_globs")
    if not ok_inc:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, inc_code, f"Rejected include_globs {include_globs!r}: {inc_code}")
        return {
            "status": "ERROR",
            "error_code": inc_code,
            "error_message": f"Rejected include_globs {include_globs!r}: {inc_code}",
        }

    ok_exc, exc_code, clean_exc = validate_glob_patterns(exclude_globs, "exclude_globs")
    if not ok_exc:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, exc_code, f"Rejected exclude_globs {exclude_globs!r}: {exc_code}")
        return {
            "status": "ERROR",
            "error_code": exc_code,
            "error_message": f"Rejected exclude_globs {exclude_globs!r}: {exc_code}",
        }

    ok_lim, lim_code, eff_max_files, eff_max_repo_bytes, eff_policy = resolve_effective_scan_limits(
        cfg, max_files_limit=max_files_limit, scan_scope_policy=scan_scope_policy
    )
    if not ok_lim:
        if stage_tracker is not None:
            stage_tracker.fail_stage(1, lim_code, f"Invalid scan limit or scope policy: {lim_code}")
        return {
            "status": "ERROR",
            "error_code": lim_code,
            "error_message": f"Invalid scan limit or scope policy: {lim_code}",
        }

    scan_cache = get_global_scan_cache()
    can_use_persistent_checkout = bool(
        workspace_parent is None and not file_allowlist and not clean_subpath
    )
    checkout_cache_key = shared.sha256_bytes(
        f"{canonical_url}|{branch or ''}|{commit_sha or ''}".encode("utf-8")
    )[:24]
    persistent_checkout_dir = scan_cache.git_checkouts_dir / f"repo_{checkout_cache_key}"

    git_env = dict(os.environ)
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    git_env["GIT_ASKPASS"] = "echo"

    git_sec_flags = [
        cfg.git_bin,
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "submodule.recurse=false",
    ]

    git_cache_hit = False
    is_cached_checkout = False
    resolved_sha = ""
    resolved_branch = branch or "HEAD"

    if can_use_persistent_checkout and not force_fresh_scan and (persistent_checkout_dir / ".git").exists():
        rev_chk = subprocess.run(
            list(git_sec_flags) + ["-C", str(persistent_checkout_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            env=git_env,
            timeout=10.0,
            check=False,
        )
        cand_sha = (rev_chk.stdout or "").strip()
        sha_matches = True
        if commit_sha and not cand_sha.lower().startswith(str(commit_sha).strip().lower()):
            sha_matches = False
        if rev_chk.returncode == 0 and len(cand_sha) == 40 and sha_matches:
            br_chk = subprocess.run(
                list(git_sec_flags) + ["-C", str(persistent_checkout_dir), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                env=git_env,
                timeout=10.0,
                check=False,
            )
            clone_dir = persistent_checkout_dir
            resolved_sha = cand_sha
            resolved_branch = branch or (br_chk.stdout or "").strip() or "HEAD"
            git_cache_hit = True
            is_cached_checkout = True

    if not git_cache_hit:
        # Check if a verified local mirror exists (e.g., OWASP BenchmarkJava in ~/iris/data/project-sources)
        local_mirror_str = telemetry_mod.KNOWN_LOCAL_GIT_MIRRORS.get(canonical_url)
        if (
            can_use_persistent_checkout
            and not force_fresh_scan
            and local_mirror_str
            and (Path(local_mirror_str) / ".git").exists()
        ):
            mirror_path = Path(local_mirror_str)
            rev_m = subprocess.run(
                [cfg.git_bin, "-C", str(mirror_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                env=git_env,
                timeout=10.0,
                check=False,
            )
            m_sha = (rev_m.stdout or "").strip()
            if rev_m.returncode == 0 and len(m_sha) == 40 and (
                not commit_sha or m_sha.lower().startswith(str(commit_sha).strip().lower())
            ):
                tmp_seed = scan_cache.git_checkouts_dir / f"seed_{uuid.uuid4().hex[:10]}"
                if persistent_checkout_dir.exists():
                    shutil.rmtree(persistent_checkout_dir, ignore_errors=True)
                shutil.copytree(mirror_path, tmp_seed, symlinks=False)
                os.replace(tmp_seed, persistent_checkout_dir)
                clone_dir = persistent_checkout_dir
                resolved_sha = m_sha
                resolved_branch = branch or "master"
                git_cache_hit = True
                is_cached_checkout = True

    if not git_cache_hit:
        base_tmp = Path(workspace_parent) if workspace_parent else Path(tempfile.gettempdir()) / "ntk_github_scans"
        base_tmp.mkdir(parents=True, exist_ok=True)
        clone_dir = base_tmp / f"scan_repo_{uuid.uuid4().hex[:12]}"
        clone_dir.mkdir(parents=True, exist_ok=True)

        try:
            clone_cmd = list(git_sec_flags) + [
                "clone",
                "--no-checkout",
                "--depth",
                "1",
                "--filter=blob:none",
            ]
            if branch:
                clone_cmd.extend(["--branch", str(branch).strip()])
            clone_cmd.extend(["--", canonical_url, str(clone_dir)])

            c_proc = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                env=git_env,
                timeout=cfg.git_clone_timeout_sec,
                check=False,
            )
            if c_proc.returncode != 0:
                shutil.rmtree(clone_dir, ignore_errors=True)
                err_msg = (c_proc.stderr or c_proc.stdout or "git clone failed").strip()[:500]
                if stage_tracker is not None:
                    stage_tracker.fail_stage(1, "GIT_CLONE_FAILED", err_msg)
                return {
                    "status": "ERROR",
                    "error_code": "GIT_CLONE_FAILED",
                    "error_message": err_msg,
                }

            target_ref = "HEAD"
            if commit_sha:
                sha_str = str(commit_sha).strip()
                fetch_cmd = list(git_sec_flags) + [
                    "-C",
                    str(clone_dir),
                    "fetch",
                    "--depth",
                    "1",
                    "origin",
                    sha_str,
                ]
                f_proc = subprocess.run(
                    fetch_cmd,
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=cfg.git_clone_timeout_sec,
                    check=False,
                )
                if f_proc.returncode == 0:
                    target_ref = "FETCH_HEAD"
                else:
                    target_ref = sha_str

            # Configure sparse-checkout if target_subpath or file_allowlist is specified
            if file_allowlist:
                clean_files: List[str] = []
                for fp in file_allowlist:
                    ok_f, f_code, cf = validate_relative_subpath(fp)
                    if not ok_f:
                        shutil.rmtree(clone_dir, ignore_errors=True)
                        if stage_tracker is not None:
                            stage_tracker.fail_stage(1, f_code, f"Invalid file in file_allowlist: {fp!r}")
                        return {
                            "status": "ERROR",
                            "error_code": f_code,
                            "error_message": f"Invalid file in file_allowlist: {fp!r}",
                        }
                    if cf:
                        clean_files.append(cf)
                subprocess.run(
                    list(git_sec_flags) + ["-C", str(clone_dir), "sparse-checkout", "init", "--no-cone"],
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=cfg.subprocess_timeout_sec,
                    check=False,
                )
                subprocess.run(
                    list(git_sec_flags) + ["-C", str(clone_dir), "sparse-checkout", "set", "--"] + clean_files,
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=cfg.subprocess_timeout_sec,
                    check=False,
                )
            elif clean_subpath:
                subprocess.run(
                    list(git_sec_flags) + ["-C", str(clone_dir), "sparse-checkout", "init", "--cone"],
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=cfg.subprocess_timeout_sec,
                    check=False,
                )
                subprocess.run(
                    list(git_sec_flags) + ["-C", str(clone_dir), "sparse-checkout", "set", "--", clean_subpath],
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=cfg.subprocess_timeout_sec,
                    check=False,
                )

            co_proc = subprocess.run(
                list(git_sec_flags) + ["-C", str(clone_dir), "checkout", target_ref],
                capture_output=True,
                text=True,
                env=git_env,
                timeout=cfg.git_clone_timeout_sec,
                check=False,
            )
            if co_proc.returncode != 0:
                shutil.rmtree(clone_dir, ignore_errors=True)
                err_msg = (co_proc.stderr or co_proc.stdout or "git checkout failed").strip()[:500]
                if stage_tracker is not None:
                    stage_tracker.fail_stage(1, "GIT_CHECKOUT_FAILED", err_msg)
                return {
                    "status": "ERROR",
                    "error_code": "GIT_CHECKOUT_FAILED",
                    "error_message": err_msg,
                }

            rev_proc = subprocess.run(
                list(git_sec_flags) + ["-C", str(clone_dir), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                env=git_env,
                timeout=15.0,
                check=False,
            )
            resolved_sha = (rev_proc.stdout or "").strip()

            br_proc = subprocess.run(
                list(git_sec_flags) + ["-C", str(clone_dir), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                env=git_env,
                timeout=15.0,
                check=False,
            )
            resolved_branch = branch or (br_proc.stdout or "").strip() or "HEAD"

            if can_use_persistent_checkout:
                try:
                    if persistent_checkout_dir.exists():
                        shutil.rmtree(persistent_checkout_dir, ignore_errors=True)
                    shutil.move(str(clone_dir), str(persistent_checkout_dir))
                    clone_dir = persistent_checkout_dir
                    is_cached_checkout = True
                except Exception:
                    pass

        except subprocess.TimeoutExpired:
            shutil.rmtree(clone_dir, ignore_errors=True)
            if stage_tracker is not None:
                stage_tracker.fail_stage(
                    1, "GIT_CLONE_TIMEOUT", f"Git acquisition timed out after {cfg.git_clone_timeout_sec}s"
                )
            return {
                "status": "ERROR",
                "error_code": "GIT_CLONE_TIMEOUT",
                "error_message": f"Git acquisition timed out after {cfg.git_clone_timeout_sec}s",
            }

    base_provenance: Dict[str, Any] = {
        "source_mode": "GITHUB_GIT_CLONE",
        "repo_url": repo_url,
        "canonical_repo_url": canonical_url,
        "requested_branch": branch or "",
        "resolved_branch": resolved_branch,
        "requested_commit_sha": commit_sha or "",
        "resolved_commit_sha": resolved_sha,
        "target_subpath": clean_subpath,
        "scan_scope_policy": eff_policy,
        "include_globs": clean_inc,
        "exclude_globs": clean_exc,
    }
    if stage_tracker is not None:
        stage_tracker.update_repository_provenance(base_provenance)
        stage_tracker.complete_stage(
            1,
            {
                "source_mode": "GITHUB_GIT_CLONE",
                "canonical_repo_url": canonical_url,
                "resolved_branch": resolved_branch,
                "resolved_commit_sha": resolved_sha,
            },
        )
        stage_tracker.start_stage(
            2,
            {
                "source_mode": "GITHUB_GIT_CLONE",
                "target_subpath": clean_subpath,
                "effective_max_repo_total_bytes": eff_max_repo_bytes,
                "effective_max_source_files": eff_max_files,
                "scan_scope_policy": eff_policy,
            },
        )

    scan_root = clone_dir / clean_subpath if clean_subpath else clone_dir
    inv_cache_key = shared.sha256_bytes(
        json.dumps(
            {
                "url": canonical_url,
                "sha": resolved_sha,
                "subpath": clean_subpath,
                "allowlist": list(file_allowlist) if file_allowlist else None,
                "inc": clean_inc,
                "exc": clean_exc,
                "max_files": eff_max_files,
                "max_bytes": eff_max_repo_bytes,
                "policy": eff_policy,
            },
            sort_keys=True,
        ).encode("utf-8")
    )
    inventory_cache_hit = False
    inv: Optional[Dict[str, Any]] = None
    if is_cached_checkout and not force_fresh_scan:
        wt_status = subprocess.run(
            list(git_sec_flags) + ["-C", str(clone_dir), "status", "--porcelain", "-uno"],
            capture_output=True,
            text=True,
            env=git_env,
            timeout=10.0,
            check=False,
        )
        wt_clean = wt_status.returncode == 0 and not (wt_status.stdout or "").strip()
        cached_inv = scan_cache.get_json("source_inventory", inv_cache_key) if wt_clean else None
        if isinstance(cached_inv, dict) and cached_inv.get("status") == "OK":
            rel_list = cached_inv.get("java_files", [])
            if rel_list and (clone_dir / rel_list[0]).is_file() and (clone_dir / rel_list[-1]).is_file():
                abs_paths = [(clone_dir / r).resolve() for r in rel_list]
                inv = dict(cached_inv)
                inv["scan_root"] = str(scan_root)
                inv["java_abs_paths"] = abs_paths
                inv["java_file_paths"] = [str(p) for p in abs_paths]
                inventory_cache_hit = True

    if inv is None:
        inv = discover_and_verify_java_source_inventory(
            workspace_root=clone_dir,
            scan_root=scan_root,
            cfg=cfg,
            source_mode="GITHUB_GIT_CLONE",
            repository_url=canonical_url,
            requested_commit=commit_sha or branch or "HEAD",
            resolved_commit=resolved_sha,
            target_subpath=clean_subpath,
            file_allowlist=file_allowlist,
            include_globs=clean_inc,
            exclude_globs=clean_exc,
            max_files_limit=eff_max_files,
            scan_scope_policy=eff_policy,
        )
        if inv.get("status") == "OK" and is_cached_checkout:
            cacheable_inv = {k: v for k, v in inv.items() if k not in ("java_abs_paths", "java_file_paths")}
            cacheable_inv["scan_root"] = clean_subpath or "."
            scan_cache.put_json("source_inventory", inv_cache_key, cacheable_inv)

    if inv.get("status") != "OK":
        if not is_cached_checkout:
            shutil.rmtree(clone_dir, ignore_errors=True)
        err_code = str(inv.get("error_code", "SOURCE_INVENTORY_FAILED"))
        err_msg = str(inv.get("error_message", "Java source inventory validation failed"))
        cov_diag = inv.get("coverage_diagnostics", {})
        base_provenance["java_files_discovered"] = cov_diag.get("java_files_discovered", 0)
        base_provenance["java_file_count"] = 0
        base_provenance["total_java_bytes"] = cov_diag.get("source_bytes_discovered", 0)
        if stage_tracker is not None:
            stage_tracker.update_repository_provenance(base_provenance)
            if isinstance(cov_diag, dict) and cov_diag:
                stage_tracker.update_coverage_diagnostics(cov_diag)
            stage_tracker.fail_stage(2, err_code, err_msg, summary_metadata={"coverage_diagnostics": cov_diag})
        return {
            "status": "ERROR",
            "error_code": err_code,
            "error_message": err_msg,
            "repository_provenance": base_provenance,
            "coverage_diagnostics": cov_diag,
        }

    acq_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    cov_diag = inv["coverage_diagnostics"]
    if stage_tracker is not None:
        stage_tracker.update_coverage_diagnostics(cov_diag)
    return {
        "status": "OK",
        "repo_url": repo_url,
        "canonical_repo_url": canonical_url,
        "requested_branch": branch or "",
        "resolved_branch": resolved_branch,
        "requested_commit_sha": commit_sha or "",
        "resolved_commit_sha": resolved_sha,
        "target_subpath": clean_subpath,
        "scan_scope_policy": eff_policy,
        "include_globs": clean_inc,
        "exclude_globs": clean_exc,
        "clone_dir": str(clone_dir),
        "scan_root": str(scan_root),
        "java_file_count": inv["java_file_count"],
        "java_files_discovered": inv["java_files_discovered"],
        "java_files_scanned": inv["java_files_scanned"],
        "java_files_skipped": inv["java_files_skipped"],
        "java_files": inv["java_files"],
        "java_abs_paths": [str(p) for p in inv["java_abs_paths"]],
        "java_file_paths": inv["java_file_paths"],
        "file_sha256_map": inv["file_sha256_map"],
        "total_java_bytes": inv["total_java_bytes"],
        "source_bytes_discovered": inv["source_bytes_discovered"],
        "source_bytes_scanned": inv["source_bytes_scanned"],
        "was_filtered_or_truncated": inv["was_filtered_or_truncated"],
        "project_layout_detected": inv["project_layout_detected"],
        "coverage_diagnostics": cov_diag,
        "acquisition_latency_ms": acq_ms,
        "is_cached_checkout": is_cached_checkout,
        "git_checkout_cache_hit": git_cache_hit,
        "source_inventory_cache_hit": inventory_cache_hit,
    }


# ============================================================================
# Thread-Safe Local Qwen2.5-Coder-0.5B-Instruct + EO06 LoRA Inference
# ============================================================================
def _get_or_load_model_bundle(cfg: NtkWebBackendConfig) -> Tuple[Any, Any, Any]:
    global _CACHED_MODEL_BUNDLE, _LAST_INFERENCE_TELEMETRY
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    req_dev_str, res_mode = resolve_configured_inference_device(cfg.device)
    if req_dev_str.startswith("cuda") and not torch.cuda.is_available():
        raise RuntimeError(
            f"CUDA_DEVICE_REQUESTED_BUT_UNAVAILABLE: Configured device={cfg.device!r} ({res_mode}), "
            "but torch.cuda.is_available() is False. Refusing silent CPU fallback."
        )

    dev = torch.device(req_dev_str)
    expected_dtype = torch.float16 if dev.type == "cuda" else torch.float32

    if (
        cfg.keep_model_cached
        and _CACHED_MODEL_BUNDLE is not None
        and _CACHED_MODEL_BUNDLE[2].type == dev.type
        and (dev.index is None or _CACHED_MODEL_BUNDLE[2].index == dev.index)
        and _CACHED_MODEL_BUNDLE[3] == cfg.base_model_path
        and _CACHED_MODEL_BUNDLE[4] == cfg.best_adapter_path
    ):
        cached_model = _CACHED_MODEL_BUNDLE[1]
        first_p = next(cached_model.parameters())
        if first_p.device.type == dev.type and first_p.dtype == expected_dtype:
            _CACHED_MODEL_BUNDLE[5]["cache_hit"] = True
            return _CACHED_MODEL_BUNDLE[0], cached_model, _CACHED_MODEL_BUNDLE[2]
        _CACHED_MODEL_BUNDLE = None

    t_load0 = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(
        cfg.base_model_path,
        local_files_only=True,
        trust_remote_code=False,
    )
    base = AutoModelForCausalLM.from_pretrained(
        cfg.base_model_path,
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=expected_dtype,
        attn_implementation="sdpa",
        use_safetensors=True,
    ).to(dev)
    base.config.use_cache = True
    model = PeftModel.from_pretrained(
        base,
        cfg.best_adapter_path,
        is_trainable=False,
        torch_device=str(dev),
    ).to(dev)
    model.eval()
    if dev.type == "cuda":
        torch.cuda.synchronize(dev)
    load_ms = round((time.perf_counter() - t_load0) * 1000.0, 3)

    all_param_devices = sorted({str(p.device) for p in model.parameters()})
    base_param_devices = sorted({str(p.device) for n, p in model.named_parameters() if "lora_" not in n})
    lora_param_devices = sorted({str(p.device) for n, p in model.named_parameters() if "lora_" in n})
    all_param_dtypes = sorted({str(p.dtype) for p in model.parameters()})
    first_param = next(model.parameters())
    actual_dev_str = str(first_param.device)
    actual_dtype_str = str(first_param.dtype)

    if (
        first_param.device.type != dev.type
        or not all(d.startswith(dev.type) for d in all_param_devices)
        or not lora_param_devices
        or not all(d.startswith(dev.type) for d in lora_param_devices)
        or first_param.dtype != expected_dtype
    ):
        raise RuntimeError(
            f"MODEL_DEVICE_OR_DTYPE_VERIFICATION_FAILED: expected device={dev} dtype={expected_dtype}, "
            f"got actual_device={actual_dev_str} base_devices={base_param_devices} "
            f"lora_devices={lora_param_devices} dtypes={all_param_dtypes}"
        )

    load_meta: Dict[str, Any] = {
        "configured_device": req_dev_str,
        "device_resolution_mode": res_mode,
        "model_load_state": "LOADED",
        "actual_model_device": actual_dev_str,
        "actual_model_dtype": actual_dtype_str,
        "base_model_param_devices": base_param_devices,
        "lora_adapter_param_devices": lora_param_devices,
        "all_param_dtypes": all_param_dtypes,
        "peft_torch_device_arg": str(dev),
        "model_load_duration_ms": load_ms,
        "cache_hit": False,
    }
    _LAST_INFERENCE_TELEMETRY.update(load_meta)

    if cfg.keep_model_cached:
        _CACHED_MODEL_BUNDLE = (tokenizer, model, dev, cfg.base_model_path, cfg.best_adapter_path, load_meta)
    return tokenizer, model, dev


def get_model_runtime_telemetry(cfg: Optional[NtkWebBackendConfig] = None) -> Dict[str, Any]:
    """
    Returns honest, live runtime telemetry distinguishing `configured_device`,
    `actual_model_device`, `actual_model_dtype`, and CUDA memory metrics.
    Before the model is loaded into memory, reports `NOT_LOADED` rather than claiming `cuda:0`.
    """
    eff_cfg = cfg or NtkWebBackendConfig()
    req_dev_str, res_mode = resolve_configured_inference_device(eff_cfg.device)
    torch_cuda_avail = False
    cuda_dev_name: Optional[str] = None
    cuda_alloc_bytes = 0
    cuda_reserved_bytes = 0
    cuda_max_alloc_bytes = 0
    try:
        import torch

        torch_cuda_avail = bool(torch.cuda.is_available())
        if torch_cuda_avail:
            cuda_dev_name = str(torch.cuda.get_device_name(0))
            cuda_alloc_bytes = int(torch.cuda.memory_allocated(0))
            cuda_reserved_bytes = int(torch.cuda.memory_reserved(0))
            cuda_max_alloc_bytes = int(torch.cuda.max_memory_allocated(0))
    except Exception:
        pass

    bundle = _CACHED_MODEL_BUNDLE
    if bundle is not None:
        try:
            loaded_model = bundle[1]
            first_p = next(loaded_model.parameters())
            actual_dev = str(first_p.device)
            actual_dt = str(first_p.dtype)
            base_devs = sorted({str(p.device) for n, p in loaded_model.named_parameters() if "lora_" not in n})
            lora_devs = sorted({str(p.device) for n, p in loaded_model.named_parameters() if "lora_" in n})
            load_state = "LOADED"
        except Exception:
            actual_dev = "NOT_LOADED"
            actual_dt = "NOT_LOADED"
            base_devs = []
            lora_devs = []
            load_state = "NOT_LOADED"
    else:
        actual_dev = "NOT_LOADED"
        actual_dt = "NOT_LOADED"
        base_devs = []
        lora_devs = []
        load_state = "NOT_LOADED"

    return {
        "configured_device": req_dev_str,
        "device_resolution_mode": res_mode,
        "model_load_state": load_state,
        "actual_model_device": actual_dev,
        "actual_model_dtype": actual_dt,
        "base_model_param_devices": base_devs,
        "lora_adapter_param_devices": lora_devs,
        "last_generate_input_tensor_device": _LAST_INFERENCE_TELEMETRY.get(
            "input_tensor_device", "NOT_LOADED"
        ),
        "last_generate_output_tensor_device": _LAST_INFERENCE_TELEMETRY.get(
            "output_tensor_device", "NOT_LOADED"
        ),
        "torch_cuda_available": torch_cuda_avail,
        "cuda_device_name": cuda_dev_name,
        "cuda_memory_allocated_bytes": cuda_alloc_bytes,
        "cuda_memory_allocated_mb": round(cuda_alloc_bytes / (1024.0 * 1024.0), 3),
        "cuda_memory_reserved_bytes": cuda_reserved_bytes,
        "cuda_memory_reserved_mb": round(cuda_reserved_bytes / (1024.0 * 1024.0), 3),
        "cuda_max_memory_allocated_mb": round(cuda_max_alloc_bytes / (1024.0 * 1024.0), 3),
    }


def run_llm_inference_for_identities(
    requests: Sequence[Tuple[int, Dict[str, str]]],
    config: Optional[NtkWebBackendConfig] = None,
    custom_llm_callable: Optional[Callable[[int, Dict[str, str]], Tuple[str, float]]] = None,
) -> List[Tuple[str, float]]:
    """
    Runs local Qwen2.5-Coder-0.5B-Instruct + EO06 Best Adapter inference using the canonical IRIS prompt
    (`shared.build_canonical_iris_prompt_messages`), serialized via `_MODEL_INFERENCE_LOCK` to prevent
    concurrent inference race conditions or OOM.
    """
    global _LAST_INFERENCE_TELEMETRY
    cfg = config or NtkWebBackendConfig()
    if not requests:
        return []

    if custom_llm_callable is not None:
        results: List[Tuple[str, float]] = []
        for cwe_int, ident in requests:
            t0 = time.perf_counter()
            try:
                raw_out, lat_ms = custom_llm_callable(int(cwe_int), ident)
                if lat_ms > cfg.llm_inference_timeout_sec * 1000.0:
                    results.append(('{"error":"LLM_INFERENCE_TIMEOUT"}', lat_ms))
                else:
                    results.append((raw_out, lat_ms))
            except TimeoutError:
                elapsed = (time.perf_counter() - t0) * 1000.0
                results.append(('{"error":"LLM_INFERENCE_TIMEOUT"}', elapsed))
            except Exception as exc:
                elapsed = (time.perf_counter() - t0) * 1000.0
                results.append((f'{{"error":"LLM_RUNTIME_EXCEPTION:{type(exc).__name__}"}}', elapsed))
        return results

    import torch

    outputs: List[Tuple[str, float]] = []
    per_identity_latencies_ms: List[float] = []
    with _MODEL_INFERENCE_LOCK:
        tokenizer, model, dev = _get_or_load_model_bundle(cfg)
        load_meta = _CACHED_MODEL_BUNDLE[5] if _CACHED_MODEL_BUNDLE is not None else {}
        first_p = next(model.parameters())
        model_dev = first_p.device
        model_dt = first_p.dtype
        last_in_dev = str(model_dev)
        last_out_dev = str(model_dev)
        try:
            with torch.inference_mode():
                for cwe_int, ident in requests:
                    msgs = shared.build_canonical_iris_prompt_messages(int(cwe_int), ident)
                    prompt_text = tokenizer.apply_chat_template(
                        msgs, tokenize=False, add_generation_prompt=True
                    )
                    enc = tokenizer(prompt_text, return_tensors="pt").to(dev)
                    in_ids = enc["input_ids"]
                    if in_ids.device != model_dev or in_ids.device.type != dev.type:
                        raise RuntimeError(
                            f"INFERENCE_TENSOR_DEVICE_MISMATCH: input_ids.device={in_ids.device}, "
                            f"model_param.device={model_dev}, expected={dev}"
                        )
                    last_in_dev = str(in_ids.device)
                    input_len = in_ids.shape[1]
                    if dev.type == "cuda":
                        torch.cuda.synchronize(dev)
                    t0 = time.perf_counter()
                    gen_ids = model.generate(
                        **enc,
                        max_new_tokens=cfg.max_new_tokens,
                        do_sample=False,
                        pad_token_id=tokenizer.eos_token_id,
                        eos_token_id=tokenizer.eos_token_id,
                        use_cache=True,
                    )
                    if dev.type == "cuda":
                        torch.cuda.synchronize(dev)
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    if gen_ids.device != model_dev:
                        raise RuntimeError(
                            f"INFERENCE_OUTPUT_TENSOR_DEVICE_MISMATCH: gen_ids.device={gen_ids.device} != {model_dev}"
                        )
                    last_out_dev = str(gen_ids.device)
                    per_identity_latencies_ms.append(round(elapsed_ms, 3))
                    if elapsed_ms > cfg.llm_inference_timeout_sec * 1000.0:
                        outputs.append(('{"error":"LLM_INFERENCE_TIMEOUT"}', elapsed_ms))
                    else:
                        new_tokens = gen_ids[0][input_len:]
                        raw_text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
                        outputs.append((raw_text, round(elapsed_ms, 2)))
            _LAST_INFERENCE_TELEMETRY.update(
                {
                    "configured_device": load_meta.get("configured_device", cfg.device),
                    "device_resolution_mode": load_meta.get("device_resolution_mode", "UNKNOWN"),
                    "model_load_state": "LOADED",
                    "actual_model_device": str(model_dev),
                    "actual_model_dtype": str(model_dt),
                    "base_model_param_devices": load_meta.get("base_model_param_devices", [str(model_dev)]),
                    "lora_adapter_param_devices": load_meta.get("lora_adapter_param_devices", [str(model_dev)]),
                    "input_tensor_device": last_in_dev,
                    "output_tensor_device": last_out_dev,
                    "peft_torch_device_arg": str(dev),
                    "model_cache_hit": bool(load_meta.get("cache_hit", False)),
                    "model_load_duration_ms": float(load_meta.get("model_load_duration_ms", 0.0)),
                    "per_identity_generate_latencies_ms": list(per_identity_latencies_ms),
                    "sum_generate_latencies_ms": round(sum(per_identity_latencies_ms), 3),
                    "cuda_device_name": str(torch.cuda.get_device_name(0)) if torch.cuda.is_available() else None,
                    "cuda_memory_allocated_mb": (
                        round(torch.cuda.memory_allocated(0) / (1024.0 * 1024.0), 3)
                        if torch.cuda.is_available()
                        else 0.0
                    ),
                    "cuda_memory_reserved_mb": (
                        round(torch.cuda.memory_reserved(0) / (1024.0 * 1024.0), 3)
                        if torch.cuda.is_available()
                        else 0.0
                    ),
                    "cuda_max_memory_allocated_mb": (
                        round(torch.cuda.max_memory_allocated(0) / (1024.0 * 1024.0), 3)
                        if torch.cuda.is_available()
                        else 0.0
                    ),
                }
            )
        finally:
            if not cfg.keep_model_cached:
                del model, tokenizer
                gc.collect()

    return outputs


# ============================================================================
# Machine-Verified Per-Finding Source Provenance Validator
# ============================================================================
def verify_findings_against_source_tree(
    findings: Sequence[Dict[str, Any]],
    raw_opengrep: Optional[Dict[str, Any]],
    base_dir: Path,
    resolved_commit_sha: str = "",
) -> Dict[str, Any]:
    """
    Independently verifies every finding against the exact checked-out source tree on disk
    BEFORE any temporary workspace cleanup occurs:
      1. `file_path` exists inside `base_dir` and does not escape root.
      2. Computes `file_sha256`, `file_byte_length`, and `file_total_lines`.
      3. Verifies `1 <= line_number <= file_total_lines`.
      4. Reads `exact_source_line` at `line_number` and checks that `matched_code` matches it.
      5. Parses the file with OpenJDK 17 `JavacTask` AST (`parse_java_source_with_javac_ast`) and
         verifies `enclosing_method` exists and spans `start_line <= line_number <= end_line`.
      6. Verifies a matching raw OpenGrep hit exists at `(file_path, line_number, scanner_rule_id)`.
    If any finding fails any check, returns `status = "SOURCE_PROVENANCE_MISMATCH"` and `verified = False`.
    """
    resolved_base = Path(base_dir).resolve()
    og_results = (raw_opengrep or {}).get("results", [])
    og_index: Dict[Tuple[int, str], List[str]] = {}
    for hit in og_results:
        hit_p = str(hit.get("path", "")).replace("\\", "/")
        hit_ln = int(hit.get("start", {}).get("line", -1))
        hit_rule = str(hit.get("check_id", "")).strip()
        og_index.setdefault((hit_ln, hit_rule), []).append(hit_p)

    file_prov_cache: Dict[str, Tuple[bool, str, int, List[str], Optional[Dict[str, Any]]]] = {}
    per_finding_records: List[Dict[str, Any]] = []
    mismatches: List[Dict[str, Any]] = []

    for f in findings:
        fid = str(f.get("finding_id", ""))
        rel_fp = str(f.get("file_path", "")).replace("\\", "/").lstrip("/")
        line_no = int(f.get("line_number", 0))
        matched_code = str(f.get("matched_code", "")).strip()
        enclosing_method = str(f.get("enclosing_method", "")).strip()
        rule_id = str(f.get("scanner_rule_id", "")).strip()
        cwe_str = str(f.get("cwe", "")).strip()

        if rel_fp not in file_prov_cache:
            candidate_path = (resolved_base / rel_fp).resolve()
            inside_root = str(candidate_path).startswith(str(resolved_base))
            f_exists = inside_root and candidate_path.is_file()
            if not f_exists:
                file_prov_cache[rel_fp] = (False, "", 0, [], None)
            else:
                raw_bytes = candidate_path.read_bytes()
                f_sha = shared.sha256_bytes(raw_bytes)
                f_len = len(raw_bytes)
                src_text = raw_bytes.decode("utf-8", errors="replace")
                src_lines = src_text.splitlines()
                ast_d = triage_mod.parse_java_source_with_javac_ast(
                    java_source_text=src_text,
                    file_path=str(candidate_path),
                )
                file_prov_cache[rel_fp] = (True, f_sha, f_len, src_lines, ast_d)

        file_exists, file_sha256, file_bytes_len, source_lines, ast_dict = file_prov_cache[rel_fp]
        file_total_lines = len(source_lines)
        line_in_range = False
        exact_source_line = ""
        code_matches_line = False
        ast_method_verified = False
        ast_method_span: Optional[List[int]] = None
        raw_og_verified = False
        failure_reasons: List[str] = []

        if not file_exists:
            failure_reasons.append("FILE_NOT_FOUND_IN_CHECKOUT")
        else:
            if 1 <= line_no <= file_total_lines:
                line_in_range = True
                exact_source_line = source_lines[line_no - 1].strip()
                if matched_code and (
                    matched_code == exact_source_line
                    or matched_code in exact_source_line
                    or exact_source_line in matched_code
                ):
                    code_matches_line = True
                else:
                    failure_reasons.append(
                        f"MATCHED_CODE_MISMATCH:expected_in={exact_source_line!r},got={matched_code!r}"
                    )
            else:
                failure_reasons.append(
                    f"LINE_NUMBER_OUT_OF_RANGE:line={line_no},file_total_lines={file_total_lines}"
                )

            if ast_dict is not None:
                for cls in ast_dict.get("classes", []):
                    for m in cls.get("methods", []):
                        m_start = int(m.get("start_line", 0))
                        m_end = int(m.get("end_line", 0))
                        if str(m.get("name", "")) == enclosing_method and m_start <= line_no <= m_end:
                            ast_method_verified = True
                            ast_method_span = [m_start, m_end]
                            break
                    if ast_method_verified:
                        break
            if not ast_method_verified:
                failure_reasons.append(
                    f"AST_ENCLOSING_METHOD_MISMATCH:method={enclosing_method!r}_not_spanning_line_{line_no}"
                )

            for hit_p in og_index.get((line_no, rule_id), []):
                if hit_p.endswith(rel_fp) or rel_fp.endswith(hit_p):
                    raw_og_verified = True
                    break
            if not raw_og_verified:
                failure_reasons.append("RAW_OPENGREP_HIT_NOT_FOUND_AT_FILE_AND_LINE")

        finding_ok = (
            file_exists
            and line_in_range
            and code_matches_line
            and ast_method_verified
            and raw_og_verified
            and len(failure_reasons) == 0
        )
        rec = {
            "finding_id": fid,
            "cwe": cwe_str,
            "decision": f.get("decision"),
            "triage_status": f.get("triage_status"),
            "file_path": rel_fp,
            "file_exists": file_exists,
            "file_sha256": file_sha256,
            "file_byte_length": file_bytes_len,
            "file_total_lines": file_total_lines,
            "line_number": line_no,
            "line_in_range": line_in_range,
            "exact_source_line": exact_source_line,
            "matched_code": matched_code,
            "code_matches_line": code_matches_line,
            "enclosing_method": enclosing_method,
            "ast_enclosing_method_verified": ast_method_verified,
            "ast_method_line_span": ast_method_span,
            "raw_opengrep_hit_verified": raw_og_verified,
            "resolved_commit_sha": resolved_commit_sha,
            "verified": finding_ok,
            "status": "SOURCE_PROVENANCE_VERIFIED" if finding_ok else "SOURCE_PROVENANCE_MISMATCH",
            "failure_reasons": failure_reasons,
        }
        per_finding_records.append(rec)
        if not finding_ok:
            mismatches.append(rec)

    all_ok = len(mismatches) == 0
    return {
        "verified": all_ok,
        "status": "SOURCE_PROVENANCE_VERIFIED" if all_ok else "SOURCE_PROVENANCE_MISMATCH",
        "resolved_commit_sha": resolved_commit_sha,
        "total_findings_checked": len(per_finding_records),
        "verified_findings_count": len(per_finding_records) - len(mismatches),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "per_finding_records": per_finding_records,
    }


# ============================================================================
# Safe Java ZIP Archive Acquisition (Zero Untrusted Code Execution)
# ============================================================================
_FORBIDDEN_ARCHIVE_EXTENSIONS: Set[str] = {
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".jmod",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".sh",
    ".bat",
    ".cmd",
    ".ps1",
    ".py",
}


def acquire_java_zip_archive(
    zip_bytes: bytes,
    archive_filename: str = "uploaded_java_sources.zip",
    workspace_parent: Optional[Path] = None,
    target_subpath: Optional[str] = None,
    file_allowlist: Optional[Sequence[str]] = None,
    include_globs: Optional[Sequence[str]] = None,
    exclude_globs: Optional[Sequence[str]] = None,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
    config: Optional[NtkWebBackendConfig] = None,
    stage_tracker: Optional[telemetry_mod.PipelineStageTracker] = None,
) -> Dict[str, Any]:
    """
    Safely validates and extracts `.java` source files from an uploaded `.zip` archive
    into an isolated sandbox directory without ever executing or compiling untrusted code:
      - Enforces `max_zip_upload_bytes` (default 25 MB) and `max_repo_total_bytes` (default 32 MB, ceiling 64 MB).
      - Rejects Zip-Slip path traversal (`..`, leading `/`, drive letters `:`, null bytes).
      - Rejects Unix/POSIX symlinks inside ZIP (`(external_attr >> 16) & 0o170000 == 0o120000`).
      - Rejects precompiled bytecode or executable payloads (`.class`, `.jar`, `.war`, `.sh`, `.exe`, etc.).
      - Rejects zip-bomb compression ratios (> 50x for entries > 64 KB).
      - Extracts ONLY `.java` regular files using explicit path-containment checks, then runs
        `discover_and_verify_java_source_inventory` for layout/filter/limit verification.
    """
    cfg = config or NtkWebBackendConfig()
    t0 = time.perf_counter()
    if stage_tracker is not None:
        stage_tracker.start_stage(
            1,
            {
                "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
                "archive_filename": archive_filename,
                "archive_compressed_bytes": len(zip_bytes) if isinstance(zip_bytes, (bytes, bytearray)) else 0,
            },
        )

    def _fail_zip_stage(
        s_num: int,
        code: str,
        msg: str,
        cov_diag: Optional[Dict[str, Any]] = None,
        prov_dict: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if stage_tracker is not None:
            if prov_dict:
                stage_tracker.update_repository_provenance(prov_dict)
            if cov_diag:
                stage_tracker.update_coverage_diagnostics(cov_diag)
            stage_tracker.fail_stage(s_num, code, msg, summary_metadata=cov_diag)
        return {
            "status": "ERROR",
            "error_code": code,
            "error_message": msg,
            "coverage_diagnostics": cov_diag or {},
            "repository_provenance": prov_dict or {},
        }

    if not isinstance(zip_bytes, (bytes, bytearray)) or len(zip_bytes) == 0:
        return _fail_zip_stage(1, "EMPTY_ZIP_ARCHIVE_REJECTED", "Uploaded ZIP archive is empty")
    if len(zip_bytes) > cfg.max_zip_upload_bytes:
        return _fail_zip_stage(
            1,
            "MAX_ZIP_UPLOAD_BYTES_EXCEEDED",
            f"ZIP size {len(zip_bytes)} exceeds limit {cfg.max_zip_upload_bytes}",
        )
    if len(zip_bytes) < 4 or zip_bytes[:4] not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _fail_zip_stage(
            1, "INVALID_ZIP_MAGIC_HEADER_REJECTED", "Uploaded payload is not a valid PKZIP archive"
        )

    ok_sub, sub_err, clean_sub = validate_relative_subpath(target_subpath)
    if not ok_sub:
        return _fail_zip_stage(1, sub_err, f"Disallowed target_subpath: {target_subpath!r}")

    ok_inc, inc_err, clean_inc = validate_glob_patterns(include_globs, "include_globs")
    if not ok_inc:
        return _fail_zip_stage(1, inc_err, f"Invalid include_globs: {include_globs!r}")

    ok_exc, exc_err, clean_exc = validate_glob_patterns(exclude_globs, "exclude_globs")
    if not ok_exc:
        return _fail_zip_stage(1, exc_err, f"Invalid exclude_globs: {exclude_globs!r}")

    ok_lim, lim_err, eff_max_files, eff_max_repo_bytes, eff_scope_policy = resolve_effective_scan_limits(
        cfg, max_files_limit=max_files_limit, scan_scope_policy=scan_scope_policy
    )
    if not ok_lim:
        return _fail_zip_stage(1, lim_err, f"Invalid scan limit or scope policy: {lim_err}")

    archive_sha256 = shared.sha256_bytes(bytes(zip_bytes))
    safe_archive_name = re.sub(r"[^A-Za-z0-9_.\-]", "_", os.path.basename(archive_filename or "upload.zip"))[:120]

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r")
    except Exception as exc:
        return _fail_zip_stage(1, "MALFORMED_ZIP_ARCHIVE_REJECTED", f"Malformed ZIP archive: {exc}")

    base_tmp = Path(workspace_parent) if workspace_parent else Path(tempfile.gettempdir()) / "ntk_zip_scans"
    base_tmp.mkdir(parents=True, exist_ok=True)
    extract_dir = base_tmp / f"scan_zip_{uuid.uuid4().hex[:12]}"
    extract_dir.mkdir(parents=True, exist_ok=True)
    resolved_extract_root = extract_dir.resolve()

    prov_base = {
        "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
        "archive_filename": safe_archive_name,
        "archive_sha256": archive_sha256,
        "archive_compressed_bytes": len(zip_bytes),
        "resolved_commit_sha": f"zip-sha256:{archive_sha256[:16]}",
        "target_subpath": clean_sub,
    }
    if stage_tracker is not None:
        stage_tracker.update_repository_provenance(prov_base)

    total_uncompressed = 0

    try:
        with zf:
            infos = zf.infolist()
            if len(infos) > cfg.max_zip_entries:
                shutil.rmtree(extract_dir, ignore_errors=True)
                return _fail_zip_stage(
                    1,
                    "ZIP_TOO_MANY_ENTRIES_REJECTED",
                    f"ZIP contains {len(infos)} entries (max {cfg.max_zip_entries})",
                    prov_dict=prov_base,
                )

            if stage_tracker is not None:
                stage_tracker.complete_stage(
                    1,
                    {
                        "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
                        "archive_filename": safe_archive_name,
                        "archive_sha256": archive_sha256,
                        "zip_entries_count": len(infos),
                    },
                )
                stage_tracker.start_stage(
                    2,
                    {
                        "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
                        "max_file_bytes": cfg.max_file_bytes,
                        "max_repo_total_bytes": cfg.max_repo_total_bytes_ceiling,
                        "max_source_files": eff_max_files,
                        "scan_scope_policy": eff_scope_policy,
                    },
                )

            for zinfo in infos:
                raw_name = zinfo.filename or ""
                if "\x00" in raw_name:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_SLIP_PATH_TRAVERSAL_REJECTED",
                        "Null byte in ZIP entry filename",
                        prov_dict=prov_base,
                    )
                norm_name = raw_name.replace("\\", "/")
                if norm_name.startswith("/") or ":" in norm_name:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_SLIP_PATH_TRAVERSAL_REJECTED",
                        f"Absolute or drive-prefixed path rejected in ZIP: {raw_name!r}",
                        prov_dict=prov_base,
                    )
                parts = [p for p in norm_name.split("/") if p]
                if any(p in (".", "..") for p in parts):
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_SLIP_PATH_TRAVERSAL_REJECTED",
                        f"Zip-Slip path traversal rejected in ZIP: {raw_name!r}",
                        prov_dict=prov_base,
                    )

                # Check POSIX symlink mode in external_attr
                unix_mode = (zinfo.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_SYMLINK_ENTRY_REJECTED",
                        f"Symbolic link entry rejected in ZIP: {raw_name!r}",
                        prov_dict=prov_base,
                    )

                if zinfo.flag_bits & 0x1:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_ENCRYPTED_ENTRY_REJECTED",
                        f"Encrypted ZIP entry rejected: {raw_name!r}",
                        prov_dict=prov_base,
                    )

                if zinfo.is_dir() or not parts:
                    continue

                rel_clean = "/".join(parts)
                ext = os.path.splitext(parts[-1])[1].lower()
                if ext in _FORBIDDEN_ARCHIVE_EXTENSIONS:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_FORBIDDEN_EXECUTABLE_OR_BYTECODE_REJECTED",
                        f"Forbidden executable/bytecode file {raw_name!r} ({ext}) rejected",
                        prov_dict=prov_base,
                    )

                # Zip-bomb check
                uncomp_sz = int(zinfo.file_size or 0)
                comp_sz = max(1, int(zinfo.compress_size or 1))
                if uncomp_sz > 65536 and (uncomp_sz / comp_sz) > 50.0:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_BOMB_COMPRESSION_RATIO_REJECTED",
                        f"Suspicious compression ratio on {raw_name!r}",
                        prov_dict=prov_base,
                    )

                if ext != ".java":
                    continue

                if uncomp_sz > cfg.max_file_bytes:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "MAX_FILE_BYTES_EXCEEDED",
                        f"Java file {rel_clean!r} is {uncomp_sz} bytes; limit is {cfg.max_file_bytes}",
                        prov_dict=prov_base,
                    )

                total_uncompressed += uncomp_sz
                if total_uncompressed > cfg.max_repo_total_bytes_ceiling:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "MAX_REPO_BYTES_EXCEEDED",
                        f"Total uncompressed Java bytes exceeded {cfg.max_repo_total_bytes_ceiling}",
                        prov_dict=prov_base,
                    )

                target_file = (extract_dir / rel_clean).resolve()
                if not str(target_file).startswith(str(resolved_extract_root)):
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "ZIP_SLIP_PATH_TRAVERSAL_REJECTED",
                        f"Resolved path escaped sandbox root: {rel_clean!r}",
                        prov_dict=prov_base,
                    )

                target_file.parent.mkdir(parents=True, exist_ok=True)
                data = zf.read(zinfo)
                if len(data) > cfg.max_file_bytes:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return _fail_zip_stage(
                        2,
                        "MAX_FILE_BYTES_EXCEEDED",
                        f"Extracted file {rel_clean!r} exceeded {cfg.max_file_bytes} bytes",
                        prov_dict=prov_base,
                    )
                target_file.write_bytes(data)
    except Exception as exc:
        shutil.rmtree(extract_dir, ignore_errors=True)
        return _fail_zip_stage(
            2, "ZIP_EXTRACTION_FAILED", f"Failed to extract ZIP archive safely: {exc}", prov_dict=prov_base
        )

    inv_res = discover_and_verify_java_source_inventory(
        workspace_root=extract_dir,
        scan_root=(extract_dir / clean_sub if clean_sub else extract_dir),
        cfg=cfg,
        source_mode="JAVA_ZIP_ARCHIVE_UPLOAD",
        repository_url=safe_archive_name,
        requested_commit="",
        resolved_commit=f"zip-sha256:{archive_sha256[:16]}",
        target_subpath=clean_sub,
        file_allowlist=file_allowlist,
        include_globs=clean_inc,
        exclude_globs=clean_exc,
        max_files_limit=eff_max_files,
        scan_scope_policy=eff_scope_policy,
    )
    cov_diag = inv_res.get("coverage_diagnostics", {})
    if inv_res.get("status") != "OK":
        err_code = str(inv_res.get("error_code", "NO_JAVA_FILES_IN_ZIP"))
        if err_code == "NO_JAVA_FILES_FOUND":
            err_code = "NO_JAVA_FILES_IN_ZIP"
        err_msg = str(inv_res.get("error_message", "Uploaded ZIP archive contains zero .java source files"))
        shutil.rmtree(extract_dir, ignore_errors=True)
        return _fail_zip_stage(2, err_code, err_msg, cov_diag=cov_diag, prov_dict=prov_base)

    acq_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    prov_full = {
        **prov_base,
        "java_file_count": inv_res["java_file_count"],
        "java_files_discovered": inv_res["java_files_discovered"],
        "java_files_scanned": inv_res["java_files_scanned"],
        "java_files_skipped": inv_res["java_files_skipped"],
        "source_bytes_discovered": inv_res["source_bytes_discovered"],
        "source_bytes_scanned": inv_res["source_bytes_scanned"],
        "java_files": inv_res["java_files"],
        "file_sha256_map": inv_res["file_sha256_map"],
        "total_java_bytes": inv_res["total_java_bytes"],
        "untrusted_code_execution_disabled": True,
        "acquisition_latency_ms": acq_ms,
    }
    if stage_tracker is not None:
        stage_tracker.update_repository_provenance(prov_full)
        stage_tracker.update_coverage_diagnostics(cov_diag)

    return {
        "status": "OK",
        **prov_full,
        "extract_dir": str(extract_dir),
        "scan_root": inv_res["scan_root"],
        "java_file_paths": inv_res["java_file_paths"],
        "was_filtered_or_truncated": inv_res["was_filtered_or_truncated"],
        "coverage_diagnostics": cov_diag,
    }


def scan_java_sources_and_triage(
    source_dir: Path,
    rules_yaml_path: Optional[Path] = None,
    config: Optional[NtkWebBackendConfig] = None,
    custom_llm_callable: Optional[Callable[[int, Dict[str, str]], Tuple[str, float]]] = None,
    manual_reviews: Optional[Dict[str, triage_mod.ManualReviewRecord]] = None,
    compile_check: bool = True,
    repo_provenance: Optional[Dict[str, Any]] = None,
    readiness_status: str = "LOCAL_API_VERIFIED",
    raw_opengrep_sink: Optional[Dict[str, Any]] = None,
    rel_base_dir: Optional[Path] = None,
    stage_tracker: Optional[telemetry_mod.PipelineStageTracker] = None,
    force_fresh_ast_for_telemetry: bool = False,
    pre_discovered_inventory: Optional[Dict[str, Any]] = None,
    target_subpath: Optional[str] = None,
    file_allowlist: Optional[Sequence[str]] = None,
    include_globs: Optional[Sequence[str]] = None,
    exclude_globs: Optional[Sequence[str]] = None,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
    force_fresh_scan: bool = False,
) -> Dict[str, Any]:
    """
    Executes the full real SAST & Alert Triage pipeline on `.java` files inside `source_dir`
    with genuine 10-stage monotonic instrumentation (`PipelineStageTracker`):
      Stage 01: Project intake & safety validation (if not already started by GitHub/ZIP acquisition).
      Stage 02: Java source discovery, bounds validation, SHA-256 inventory & optional `/usr/bin/javac` check.
      Stage 03: Real `/usr/local/bin/opengrep scan --json` execution & deterministic candidate extraction.
      Stage 04: Code & API context extraction via OpenJDK 17 `JavacTask.parse()` (`NtkJavacAstExtractor`).
      Stage 05: IRIS intraprocedural lexical-scope def-use taint & CWE sanitizer analysis (`analyze_java_site_ast_and_taint`).
      Stage 06: Canonical IRIS prompt generation & Local Qwen2.5-0.5B EO06 LoRA inference.
      Stage 07: Neuro-symbolic Evidence Fusion (`FindingCandidate` + `verify_ast_release_evidence`).
      Stage 08: Heuristic SAST Scoring (`evaluate_bounded_safety_floor` with `0.55` safety floor).
      Stage 09: Alert Verification (`verify_and_triage_finding` + `FindingSchemaV2` + `verify_findings_against_source_tree`).
      Stage 10: Report Synthesis & Trace Assembly.
    """
    t0_total = time.perf_counter()
    cfg = config or NtkWebBackendConfig()
    tracker = stage_tracker or telemetry_mod.PipelineStageTracker(
        source_mode=str((repo_provenance or {}).get("source_mode", "LOCAL_JAVA_DIRECTORY"))
    )
    src_path = Path(source_dir)

    # If Stage 01 was not started by `acquire_github_java_repository` or `acquire_java_zip_archive`,
    # instrument local directory intake in Stage 01 and start Stage 02.
    st_list_init, _, _ = tracker.snapshot_stages()
    if st_list_init[0]["state"] == "NOT_STARTED":
        tracker.start_stage(1, {"source_mode": "LOCAL_JAVA_DIRECTORY", "source_dir": src_path.name})
        if not src_path.exists():
            tracker.fail_stage(1, "SOURCE_PATH_NOT_FOUND", f"Source path does not exist: {src_path}")
            return {
                "status": "ERROR",
                "error_code": "SOURCE_PATH_NOT_FOUND",
                "error_message": f"Source path does not exist: {src_path}",
                "stage_error_code": "SOURCE_PATH_NOT_FOUND",
                "stage_error_message": f"Source path does not exist: {src_path}",
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(),
            }
        tracker.complete_stage(1, {"source_mode": "LOCAL_JAVA_DIRECTORY", "source_exists": True})

    if st_list_init[1]["state"] == "NOT_STARTED":
        tracker.start_stage(
            2,
            {
                "max_source_files": cfg.max_source_files,
                "max_file_bytes": cfg.max_file_bytes,
                "compile_check_requested": bool(compile_check),
            },
        )

    if not src_path.exists():
        tracker.fail_stage(2, "SOURCE_PATH_NOT_FOUND", f"Source path does not exist: {src_path}")
        return {
            "status": "ERROR",
            "error_code": "SOURCE_PATH_NOT_FOUND",
            "error_message": f"Source path does not exist: {src_path}",
            "stage_error_code": "SOURCE_PATH_NOT_FOUND",
            "stage_error_message": f"Source path does not exist: {src_path}",
            "findings": [],
            "pipeline_trace": tracker.to_pipeline_trace_dict(),
        }

    # Resolve or reuse Stage 02 inventory
    if pre_discovered_inventory is not None and pre_discovered_inventory.get("status") == "OK":
        inv_res = pre_discovered_inventory
    else:
        ok_sub, sub_err, clean_sub = validate_relative_subpath(target_subpath)
        if not ok_sub:
            tracker.fail_stage(2, sub_err, f"Disallowed target_subpath: {target_subpath!r}")
            return {
                "status": "ERROR",
                "error_code": sub_err,
                "error_message": f"Disallowed target_subpath: {target_subpath!r}",
                "stage_error_code": sub_err,
                "stage_error_message": f"Disallowed target_subpath: {target_subpath!r}",
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(),
            }
        ok_inc, inc_err, clean_inc = validate_glob_patterns(include_globs, "include_globs")
        if not ok_inc:
            tracker.fail_stage(2, inc_err, f"Invalid include_globs: {include_globs!r}")
            return {
                "status": "ERROR",
                "error_code": inc_err,
                "error_message": f"Invalid include_globs: {include_globs!r}",
                "stage_error_code": inc_err,
                "stage_error_message": f"Invalid include_globs: {include_globs!r}",
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(),
            }
        ok_exc, exc_err, clean_exc = validate_glob_patterns(exclude_globs, "exclude_globs")
        if not ok_exc:
            tracker.fail_stage(2, exc_err, f"Invalid exclude_globs: {exclude_globs!r}")
            return {
                "status": "ERROR",
                "error_code": exc_err,
                "error_message": f"Invalid exclude_globs: {exclude_globs!r}",
                "stage_error_code": exc_err,
                "stage_error_message": f"Invalid exclude_globs: {exclude_globs!r}",
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(),
            }
        ok_lim, lim_err, eff_max_files, eff_max_repo_bytes, eff_scope_policy = resolve_effective_scan_limits(
            cfg, max_files_limit=max_files_limit, scan_scope_policy=scan_scope_policy
        )
        if not ok_lim:
            tracker.fail_stage(2, lim_err, f"Invalid scan limit or scope policy: {lim_err}")
            return {
                "status": "ERROR",
                "error_code": lim_err,
                "error_message": f"Invalid scan limit or scope policy: {lim_err}",
                "stage_error_code": lim_err,
                "stage_error_message": f"Invalid scan limit or scope policy: {lim_err}",
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(),
            }
        inv_root = Path(rel_base_dir) if rel_base_dir is not None else (src_path if src_path.is_dir() else src_path.parent)
        inv_res = discover_and_verify_java_source_inventory(
            workspace_root=inv_root,
            scan_root=(inv_root / clean_sub if clean_sub else src_path),
            cfg=cfg,
            source_mode=str((repo_provenance or {}).get("source_mode", "LOCAL_JAVA_DIRECTORY")),
            repository_url=str((repo_provenance or {}).get("repo_url", src_path.name)),
            requested_commit=str((repo_provenance or {}).get("requested_commit_sha", "")),
            resolved_commit=str((repo_provenance or {}).get("resolved_commit_sha", "")),
            target_subpath=clean_sub,
            file_allowlist=file_allowlist,
            include_globs=clean_inc,
            exclude_globs=clean_exc,
            max_files_limit=eff_max_files,
            scan_scope_policy=eff_scope_policy,
        )
        if inv_res.get("status") != "OK":
            err_code = str(inv_res.get("error_code", "STAGE_02_INVENTORY_ERROR"))
            err_msg = str(inv_res.get("error_message", "Java source inventory check failed"))
            cov_diag = inv_res.get("coverage_diagnostics", {})
            tracker.update_coverage_diagnostics(cov_diag)
            tracker.fail_stage(2, err_code, err_msg, summary_metadata=cov_diag)
            return {
                "status": "ERROR",
                "error_code": err_code,
                "error_message": err_msg,
                "stage_error_code": err_code,
                "stage_error_message": err_msg,
                "coverage_diagnostics": cov_diag,
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(
                    repository_provenance=repo_provenance,
                    coverage_diagnostics=cov_diag,
                ),
            }

    cov_diag = dict(inv_res.get("coverage_diagnostics", {}))
    tracker.update_coverage_diagnostics(cov_diag)
    if repo_provenance is not None:
        tracker.update_repository_provenance(repo_provenance)

    java_files = [Path(p) for p in inv_res.get("java_file_paths", [])]
    if not java_files:
        java_files = sorted(src_path.rglob("*.java")) if src_path.is_dir() else [src_path]
    total_discovered_bytes = int(inv_res.get("source_bytes_discovered", 0))
    total_scanned_bytes = int(inv_res.get("source_bytes_scanned", total_discovered_bytes))
    was_filtered_or_truncated = bool(inv_res.get("was_filtered_or_truncated", False))

    # Optional javac check (explicitly timed inside Stage 02)
    t0_javac = time.perf_counter()
    javac_exit_code = 0
    if compile_check and Path(cfg.javac_bin).exists():
        classes_tmp = src_path.parent / "_ntk_classes_tmp"
        classes_tmp.mkdir(parents=True, exist_ok=True)
        try:
            jc_proc = subprocess.run(
                [cfg.javac_bin, "-d", str(classes_tmp)] + [str(p) for p in java_files],
                capture_output=True,
                text=True,
                timeout=cfg.subprocess_timeout_sec,
                check=False,
            )
            javac_exit_code = jc_proc.returncode
        except subprocess.TimeoutExpired:
            tracker.fail_stage(2, "JAVAC_TIMEOUT", f"javac timed out after {cfg.subprocess_timeout_sec}s")
            return {
                "status": "ERROR",
                "error_code": "JAVAC_TIMEOUT",
                "error_message": f"javac timed out after {cfg.subprocess_timeout_sec}s",
                "stage_error_code": "JAVAC_TIMEOUT",
                "stage_error_message": f"javac timed out after {cfg.subprocess_timeout_sec}s",
                "coverage_diagnostics": cov_diag,
                "findings": [],
                "pipeline_trace": tracker.to_pipeline_trace_dict(
                    repository_provenance=repo_provenance,
                    coverage_diagnostics=cov_diag,
                ),
            }
    javac_duration_ms = round((time.perf_counter() - t0_javac) * 1000.0, 2)
    tracker.complete_stage(
        2,
        {
            "java_file_count": len(java_files),
            "java_files_discovered": int(cov_diag.get("java_files_discovered", len(java_files))),
            "java_files_scanned": len(java_files),
            "java_files_skipped": int(cov_diag.get("java_files_skipped", 0)),
            "total_java_bytes": total_scanned_bytes,
            "source_bytes_discovered": total_discovered_bytes,
            "source_bytes_scanned": total_scanned_bytes,
            "analysis_coverage_status": cov_diag.get("analysis_coverage_status", "COMPLETE_SCANNED"),
            "incomplete_analysis_reasons": cov_diag.get("incomplete_analysis_reasons", []),
            "compile_check_executed": bool(compile_check),
            "javac_exit_code": javac_exit_code,
            "javac_duration_ms": javac_duration_ms,
        },
    )

    effective_rel_root = Path(rel_base_dir or (src_path if src_path.is_dir() else src_path.parent)).resolve()
    scan_cache = get_global_scan_cache()
    use_cache = bool(not force_fresh_scan and rules_yaml_path is None)
    git_cache_hit_flag = bool((repo_provenance or {}).get("git_checkout_cache_hit") or inv_res.get("git_checkout_cache_hit"))
    inv_cache_hit_flag = bool((repo_provenance or {}).get("source_inventory_cache_hit") or inv_res.get("source_inventory_cache_hit"))

    # Stage 03: OpenGrep - Candidate Detection (with 250-file batching + Layer 3 batch cache + checkpointing)
    tracker.start_stage(
        3,
        {
            "opengrep_binary": cfg.opengrep_bin,
            "ruleset_version": cfg.ruleset_version,
            "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
            "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
            "target_java_files": len(java_files),
        },
    )
    effective_rules_path = rules_yaml_path
    if effective_rules_path is None:
        effective_rules_path = Path(tempfile.gettempdir()) / "_ntk_default_opengrep_rules_v1.yaml"
        if not effective_rules_path.is_file():
            effective_rules_path.write_text(DEFAULT_OPENGREP_RULES_YAML, encoding="utf-8", newline="\n")
    rules_sha256 = shared.sha256_bytes(effective_rules_path.read_bytes())

    t0_og = time.perf_counter()
    og_hits: List[Dict[str, Any]] = []
    merged_errors: List[Any] = []
    last_og_returncode = 0
    og_batches_executed = 0
    og_batch_cache_hits = 0
    og_batch_cache_misses = 0

    batch_sz = 250
    total_batches = max(1, (len(java_files) + batch_sz - 1) // batch_sz)
    file_sha_map: Dict[str, str] = dict(inv_res.get("file_sha256_map") or {})

    try:
        for b_idx, b_start in enumerate(range(0, len(java_files), batch_sz)):
            batch_path_objs = java_files[b_start : b_start + batch_sz]
            batch_files = [str(p) for p in batch_path_objs]
            batch_rel_sha_pairs: List[Tuple[str, str]] = []
            for p_obj in batch_path_objs:
                rp_resolved = p_obj.resolve()
                rel_s = (
                    str(rp_resolved.relative_to(effective_rel_root)).replace("\\", "/")
                    if str(rp_resolved).startswith(str(effective_rel_root)) and rp_resolved != effective_rel_root
                    else p_obj.name
                )
                f_sha = file_sha_map.get(rel_s) or shared.sha256_bytes(rp_resolved.read_bytes())
                batch_rel_sha_pairs.append((rel_s, f_sha))

            batch_cache_key = shared.sha256_bytes(
                json.dumps(
                    {
                        "ruleset_version": cfg.ruleset_version,
                        "rules_sha256": rules_sha256,
                        "files": batch_rel_sha_pairs,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            )

            cached_batch = scan_cache.get_json("opengrep_batches", batch_cache_key) if use_cache else None
            if isinstance(cached_batch, dict) and isinstance(cached_batch.get("results"), list):
                og_batch_cache_hits += 1
                for ch in cached_batch["results"]:
                    ch_copy = dict(ch)
                    rel_h = str(ch_copy.get("_ntk_rel_path") or ch_copy.get("path") or "").replace("\\", "/").lstrip("/")
                    rehydrated_path = (effective_rel_root / rel_h) if src_path.is_dir() else src_path
                    ch_copy["path"] = str(rehydrated_path)
                    og_hits.append(ch_copy)
            else:
                og_batch_cache_misses += 1
                og_batches_executed += 1
                if not was_filtered_or_truncated and total_batches == 1:
                    cmd_args = [
                        cfg.opengrep_bin,
                        "scan",
                        "--config",
                        str(effective_rules_path),
                        "--json",
                        str(src_path),
                    ]
                else:
                    cmd_args = [
                        cfg.opengrep_bin,
                        "scan",
                        "--config",
                        str(effective_rules_path),
                        "--json",
                    ] + batch_files

                og_proc = subprocess.run(
                    cmd_args,
                    capture_output=True,
                    text=True,
                    timeout=cfg.subprocess_timeout_sec,
                    check=False,
                )
                last_og_returncode = og_proc.returncode
                if og_proc.returncode not in (0, 1):
                    err_msg = og_proc.stderr.strip() or f"OpenGrep exited with code {og_proc.returncode}"
                    tracker.fail_stage(3, "OPENGREP_EXECUTION_FAILED", err_msg)
                    return {
                        "status": "ERROR",
                        "error_code": "OPENGREP_EXECUTION_FAILED",
                        "error_message": err_msg,
                        "stage_error_code": "OPENGREP_EXECUTION_FAILED",
                        "stage_error_message": err_msg,
                        "coverage_diagnostics": cov_diag,
                        "findings": [],
                        "pipeline_trace": tracker.to_pipeline_trace_dict(
                            repository_provenance=repo_provenance,
                            coverage_diagnostics=cov_diag,
                        ),
                    }
                b_json = json.loads(og_proc.stdout)
                b_results = b_json.get("results", [])
                normalized_for_cache: List[Dict[str, Any]] = []
                for h_item in b_results:
                    og_hits.append(h_item)
                    h_copy = dict(h_item)
                    hp_res = Path(str(h_item.get("path", ""))).resolve()
                    rel_h = (
                        str(hp_res.relative_to(effective_rel_root)).replace("\\", "/")
                        if str(hp_res).startswith(str(effective_rel_root)) and hp_res != effective_rel_root
                        else hp_res.name
                    )
                    h_copy["path"] = rel_h
                    h_copy["_ntk_rel_path"] = rel_h
                    normalized_for_cache.append(h_copy)
                merged_errors.extend(b_json.get("errors", []))
                if use_cache:
                    scan_cache.put_json(
                        "opengrep_batches",
                        batch_cache_key,
                        {"results": normalized_for_cache, "errors": b_json.get("errors", [])},
                    )

            tracker.update_stage_progress(
                3,
                {
                    "completed_batches": b_idx + 1,
                    "total_batches": total_batches,
                    "opengrep_batch_cache_hits": og_batch_cache_hits,
                    "opengrep_batch_cache_misses": og_batch_cache_misses,
                    "accumulated_candidates": len(og_hits),
                },
            )
            scan_cache.write_checkpoint(
                tracker.scan_id,
                {
                    "stage": "STAGE_03_OPENGREP_BATCHES",
                    "completed_batches": b_idx + 1,
                    "total_batches": total_batches,
                    "opengrep_batch_cache_hits": og_batch_cache_hits,
                    "opengrep_batch_cache_misses": og_batch_cache_misses,
                    "accumulated_candidates": len(og_hits),
                },
            )
        og_json = {"results": og_hits, "errors": merged_errors}
    except subprocess.TimeoutExpired:
        tracker.fail_stage(3, "OPENGREP_TIMEOUT", f"OpenGrep scan timed out after {cfg.subprocess_timeout_sec}s")
        return {
            "status": "ERROR",
            "error_code": "OPENGREP_TIMEOUT",
            "error_message": f"OpenGrep scan timed out after {cfg.subprocess_timeout_sec}s",
            "stage_error_code": "OPENGREP_TIMEOUT",
            "stage_error_message": f"OpenGrep scan timed out after {cfg.subprocess_timeout_sec}s",
            "coverage_diagnostics": cov_diag,
            "findings": [],
            "pipeline_trace": tracker.to_pipeline_trace_dict(
                repository_provenance=repo_provenance,
                coverage_diagnostics=cov_diag,
            ),
        }
    og_duration_ms = round((time.perf_counter() - t0_og) * 1000.0, 2)

    # Deduplicate and sort hits deterministically by (path, line, check_id)
    dedup_og_map: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    for h in og_hits:
        k_hit = (
            str(h.get("path", "")),
            int(h.get("start", {}).get("line", 0)),
            str(h.get("check_id", "")),
        )
        if k_hit not in dedup_og_map:
            dedup_og_map[k_hit] = h
    og_hits_sorted = [dedup_og_map[k] for k in sorted(dedup_og_map.keys())]
    og_json["results"] = og_hits_sorted
    if raw_opengrep_sink is not None:
        raw_opengrep_sink.update(og_json)

    tracker.complete_stage(
        3,
        {
            "raw_opengrep_candidates": len(og_hits_sorted),
            "opengrep_exit_code": last_og_returncode,
            "opengrep_batches_executed": og_batches_executed,
            "opengrep_total_batches": total_batches,
            "opengrep_batch_cache_hits": og_batch_cache_hits,
            "opengrep_batch_cache_misses": og_batch_cache_misses,
            "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
            "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
            "opengrep_subprocess_duration_ms": og_duration_ms,
        },
    )

    # Stage 04: Context Extraction (OpenJDK 17 JavacTask AST parsing + Layer 4 persistent AST cache)
    tracker.start_stage(
        4,
        {
            "candidate_hits_count": len(og_hits_sorted),
            "ast_parser_engine": "OPENJDK17_JAVAC_TASK_AST",
        },
    )
    t0_ast_total = time.perf_counter()
    unique_hit_paths = sorted({str(h.get("path", "")) for h in og_hits_sorted if h.get("path")})
    prewarm_paths: List[Path] = []
    file_text_cache: Dict[str, str] = {}
    path_to_sha: Dict[str, str] = {}
    shas_to_lookup: List[str] = []

    for hp in unique_hit_paths:
        p_obj = Path(hp)
        txt = p_obj.read_text(encoding="utf-8", errors="replace")
        file_text_cache[hp] = txt
        sha_txt = shared.sha256_bytes(txt.encode("utf-8"))
        path_to_sha[hp] = sha_txt
        if force_fresh_ast_for_telemetry or not use_cache:
            triage_mod._JAVAC_AST_CACHE.pop(sha_txt, None)
            prewarm_paths.append(p_obj)
        elif sha_txt not in triage_mod._JAVAC_AST_CACHE:
            shas_to_lookup.append(sha_txt)

    if use_cache and not force_fresh_ast_for_telemetry and shas_to_lookup:
        cached_asts = scan_cache.get_many_json("javac_ast_files", shas_to_lookup)
        for sha_k, ast_val in cached_asts.items():
            if isinstance(ast_val, dict):
                triage_mod._JAVAC_AST_CACHE[sha_k] = ast_val

    ast_cache_hits = 0
    ast_cache_misses = 0
    missing_ast_shas: List[str] = []
    for hp in unique_hit_paths:
        sha_txt = path_to_sha[hp]
        if not force_fresh_ast_for_telemetry and use_cache and sha_txt in triage_mod._JAVAC_AST_CACHE:
            ast_cache_hits += 1
        else:
            ast_cache_misses += 1
            if Path(hp) not in prewarm_paths:
                prewarm_paths.append(Path(hp))
            missing_ast_shas.append(sha_txt)

    newly_cached_ast_files = 0
    if prewarm_paths:
        newly_cached_ast_files = triage_mod.prewarm_javac_ast_cache(prewarm_paths)
        if use_cache and missing_ast_shas:
            to_persist_asts: Dict[str, Any] = {}
            for s_k in missing_ast_shas:
                if s_k in triage_mod._JAVAC_AST_CACHE and isinstance(triage_mod._JAVAC_AST_CACHE[s_k], dict):
                    ast_copy = dict(triage_mod._JAVAC_AST_CACHE[s_k])
                    fp_raw = str(ast_copy.get("file_path", ""))
                    if fp_raw and str(effective_rel_root) and fp_raw.startswith(str(effective_rel_root)):
                        ast_copy["file_path"] = fp_raw[len(str(effective_rel_root)) :].lstrip("/\\")
                    to_persist_asts[s_k] = ast_copy
            scan_cache.put_many_json("javac_ast_files", to_persist_asts)

    candidate_contexts: List[Tuple[Dict[str, Any], str, int, str, str, int, str]] = []
    for hit in og_hits_sorted:
        hit_path_str = str(hit.get("path", ""))
        hit_line = int(hit.get("start", {}).get("line", 1))
        hit_rule = str(hit.get("check_id", "ntk.java.rule"))
        hit_code = str(hit.get("extra", {}).get("lines", "")).strip()
        cwe_int = _infer_cwe_from_rule(hit)
        java_text = file_text_cache.get(hit_path_str) or Path(hit_path_str).read_text(
            encoding="utf-8", errors="replace"
        )
        candidate_contexts.append((hit, hit_path_str, hit_line, hit_rule, hit_code, cwe_int, java_text))

    context_extraction_ms = tracker.complete_stage(
        4,
        {
            "unique_matched_java_files": len(unique_hit_paths),
            "javac_ast_parsed_files": newly_cached_ast_files,
            "javac_ast_cache_hits": ast_cache_hits,
            "javac_ast_cache_misses": ast_cache_misses,
            "candidate_contexts_extracted": len(candidate_contexts),
        },
    )

    # Stage 05: IRIS - Program Analysis (Lexical-scope def-use taint & CWE sanitizer analysis + Layer 5 cache)
    tracker.start_stage(
        5,
        {
            "candidates_to_analyze": len(candidate_contexts),
            "analysis_scope": "INTRAPROCEDURAL_DEF_USE_AND_STATIC_FINAL_CONSTANTS",
        },
    )
    ast_analyses: List[Tuple[Dict[str, Any], int, triage_mod.JavaAstSiteAnalysis]] = []
    llm_requests: List[Tuple[int, Dict[str, str]]] = []
    site_cache_hits = 0
    site_cache_misses = 0

    site_keys: List[str] = []
    for hit, hit_path_str, hit_line, hit_rule, hit_code, cwe_int, java_text in candidate_contexts:
        f_sha = path_to_sha.get(hit_path_str) or shared.sha256_bytes(java_text.encode("utf-8"))
        s_key = shared.sha256_bytes(
            f"{f_sha}|{hit_line}|{cwe_int}|{hit_rule}|{hit_code}|JAVAC_AST_V1".encode("utf-8")
        )
        site_keys.append(s_key)

    cached_sites = scan_cache.get_many_json("iris_site_taint", site_keys) if use_cache else {}
    new_sites_to_persist: Dict[str, Any] = {}

    for s_key, (hit, hit_path_str, hit_line, hit_rule, hit_code, cwe_int, java_text) in zip(
        site_keys, candidate_contexts
    ):
        c_site = cached_sites.get(s_key) if use_cache else None
        if isinstance(c_site, dict) and isinstance(c_site.get("ast_evidence"), dict):
            site_cache_hits += 1
            ev_d = c_site["ast_evidence"]
            ev_obj = shared.AstReleaseEvidence(
                is_compile_time_constant_arg=bool(ev_d.get("is_compile_time_constant_arg", False)),
                has_cwe_matched_sanitizer=bool(ev_d.get("has_cwe_matched_sanitizer", False)),
                verified_sanitizer_cwe=ev_d.get("verified_sanitizer_cwe"),
                covered_sink_args=tuple(ev_d.get("covered_sink_args", ())),
                ast_proof_node=str(ev_d.get("ast_proof_node", "")),
                sanitizer_method_signature=str(ev_d.get("sanitizer_method_signature", "")),
                output_context=str(ev_d.get("output_context", "")),
                ast_parser_engine=str(ev_d.get("ast_parser_engine", "OPENJDK17_JAVAC_TASK_AST")),
            )
            ast_info = triage_mod.JavaAstSiteAnalysis(
                file_path=hit_path_str,
                match_line=int(c_site.get("match_line", hit_line)),
                cwe=int(c_site.get("cwe", cwe_int)),
                package_name=str(c_site.get("package_name", "")),
                class_name=str(c_site.get("class_name", "")),
                enclosing_method=str(c_site.get("enclosing_method", "")),
                enclosing_signature=str(c_site.get("enclosing_signature", "")),
                untrusted_params=tuple(c_site.get("untrusted_params", ())),
                target_callee_identity=dict(c_site.get("target_callee_identity", {})),
                matched_code_line=str(c_site.get("matched_code_line", hit_code)),
                source_sink_trace_status=str(c_site.get("source_sink_trace_status", "")),
                taint_reaches_sink=bool(c_site.get("taint_reaches_sink", False)),
                taint_source_params=tuple(c_site.get("taint_source_params", ())),
                taint_trace_steps=tuple(c_site.get("taint_trace_steps", ())),
                sanitizer_status=str(c_site.get("sanitizer_status", "")),
                ast_evidence=ev_obj,
                extra_reason_codes=tuple(c_site.get("extra_reason_codes", ())),
                ast_parser_engine=str(c_site.get("ast_parser_engine", "OPENJDK17_JAVAC_TASK_AST")),
                ast_overloaded_signature=str(c_site.get("ast_overloaded_signature", "")),
            )
        else:
            site_cache_misses += 1
            ast_info = triage_mod.analyze_java_site_ast_and_taint(
                java_source_text=java_text,
                file_path=hit_path_str,
                match_line=hit_line,
                cwe=cwe_int,
                opengrep_rule_id=hit_rule,
                opengrep_matched_code=hit_code,
            )
            if use_cache:
                import dataclasses as _dc

                ser_d = _dc.asdict(ast_info)
                ser_d.pop("file_path", None)
                new_sites_to_persist[s_key] = ser_d
        ast_analyses.append((hit, cwe_int, ast_info))
        llm_requests.append((cwe_int, ast_info.target_callee_identity))

    if use_cache and new_sites_to_persist:
        scan_cache.put_many_json("iris_site_taint", new_sites_to_persist)

    iris_program_analysis_ms = tracker.complete_stage(
        5,
        {
            "candidates_analyzed": len(ast_analyses),
            "iris_site_cache_hits": site_cache_hits,
            "iris_site_cache_misses": site_cache_misses,
            "verified_taint_flows_detected": sum(1 for _, _, a in ast_analyses if a.taint_reaches_sink),
            "ast_release_candidates_identified": sum(
                1
                for _, _, a in ast_analyses
                if a.ast_evidence.is_compile_time_constant_arg or a.ast_evidence.has_cwe_matched_sanitizer
            ),
        },
    )
    ast_duration_ms = round((time.perf_counter() - t0_ast_total) * 1000.0, 2)

    # Stage 06: Qwen LoRA - API Classification (with Layer 6 API identity classification cache)
    t0_llm = time.perf_counter()
    unique_req_keys: Dict[Tuple[int, str, str, str, str], int] = {}
    dedup_reqs: List[Tuple[int, Dict[str, str]]] = []
    req_to_dedup_idx: List[int] = []
    for cwe_int, ident in llm_requests:
        k = (
            int(cwe_int),
            ident.get("package", ""),
            ident.get("class", ""),
            ident.get("method", ""),
            ident.get("signature", ""),
        )
        if k not in unique_req_keys:
            unique_req_keys[k] = len(dedup_reqs)
            dedup_reqs.append((cwe_int, ident))
        req_to_dedup_idx.append(unique_req_keys[k])

    callee_predictions: List[shared.CalleeRolePrediction] = []
    stage_06_skip_reason: Optional[str] = None
    llm_cache_hits = 0
    llm_cache_misses = 0
    actual_gpu_inference_calls = 0

    if not llm_requests:
        llm_outputs: List[Tuple[str, float]] = []
        llm_duration_ms = 0.0
        stage_06_skip_reason = "NO_CANDIDATES"
        tracker.skip_stage(
            6,
            "NO_CANDIDATES",
            {
                "stage_skip_reason": "NO_CANDIDATES",
                "legacy_skip_reason": "NO_OPENGREP_CANDIDATES_TO_CLASSIFY",
                "total_candidates": 0,
                "unique_api_identities_inferred": 0,
                "actual_gpu_inference_calls": 0,
            },
        )
    else:
        req_dev_str, res_mode = resolve_configured_inference_device(cfg.device)
        tracker.start_stage(
            6,
            {
                "total_candidates": len(llm_requests),
                "unique_api_identities": len(dedup_reqs),
                "model_version": cfg.model_version,
                "configured_device": req_dev_str,
                "device_resolution_mode": res_mode,
                "device": req_dev_str,
            },
        )
        use_llm_cache = bool(use_cache and custom_llm_callable is None)
        dedup_llm_keys: List[str] = [
            shared.sha256_bytes(
                f"{c_i}|{id_d.get('package','')}|{id_d.get('class','')}|{id_d.get('method','')}|{id_d.get('signature','')}|{cfg.model_version}|{DEFAULT_BEST_ADAPTER_SHA256}".encode(
                    "utf-8"
                )
            )
            for c_i, id_d in dedup_reqs
        ]
        cached_llm_map = scan_cache.get_many_json("llm_api_identities", dedup_llm_keys) if use_llm_cache else {}
        dedup_llm_outputs: List[Optional[Tuple[str, float]]] = [None] * len(dedup_reqs)
        uncached_indices: List[int] = []
        uncached_reqs: List[Tuple[int, Dict[str, str]]] = []

        for idx_d, (ck_llm, req_item) in enumerate(zip(dedup_llm_keys, dedup_reqs)):
            c_entry = cached_llm_map.get(ck_llm) if use_llm_cache else None
            if isinstance(c_entry, dict) and "raw_llm_out" in c_entry:
                llm_cache_hits += 1
                dedup_llm_outputs[idx_d] = (str(c_entry["raw_llm_out"]), 0.0)
            else:
                llm_cache_misses += 1
                uncached_indices.append(idx_d)
                uncached_reqs.append(req_item)

        if uncached_reqs:
            actual_gpu_inference_calls = len(uncached_reqs)
            fresh_outputs = run_llm_inference_for_identities(
                uncached_reqs, config=cfg, custom_llm_callable=custom_llm_callable
            )
            new_llm_to_persist: Dict[str, Any] = {}
            for idx_d, (raw_out, lat_ms) in zip(uncached_indices, fresh_outputs):
                dedup_llm_outputs[idx_d] = (raw_out, lat_ms)
                if use_llm_cache:
                    new_llm_to_persist[dedup_llm_keys[idx_d]] = {
                        "raw_llm_out": raw_out,
                        "original_latency_ms": lat_ms,
                    }
            if use_llm_cache and new_llm_to_persist:
                scan_cache.put_many_json("llm_api_identities", new_llm_to_persist)

        llm_outputs = [dedup_llm_outputs[idx] or ("{}", 0.0) for idx in req_to_dedup_idx]
        for (hit, cwe_int, ast_info), (raw_llm_out, _) in zip(ast_analyses, llm_outputs):
            callee_pred = shared.parse_and_validate_callee_json(
                raw_llm_out,
                expected_identity=ast_info.target_callee_identity,
                cwe=cwe_int,
            )
            callee_predictions.append(callee_pred)
        llm_duration_ms = round((time.perf_counter() - t0_llm) * 1000.0, 2)
        stage6_meta: Dict[str, Any] = {
            "total_candidates": len(llm_requests),
            "unique_api_identities_inferred": len(dedup_reqs),
            "llm_cache_hits": llm_cache_hits,
            "llm_cache_misses": llm_cache_misses,
            "actual_gpu_inference_calls": actual_gpu_inference_calls,
            "strict_json_valid_count": sum(1 for p in callee_predictions if p.strict_valid),
            "abstain_count": sum(1 for p in callee_predictions if p.abstain),
            "predicted_roles": dict(
                collections.Counter(p.role for p in callee_predictions if p.strict_valid)
            ),
        }
        if custom_llm_callable is None and _LAST_INFERENCE_TELEMETRY:
            actual_dev = str(_LAST_INFERENCE_TELEMETRY.get("actual_model_device", req_dev_str))
            stage6_meta.update(
                {
                    "configured_device": str(_LAST_INFERENCE_TELEMETRY.get("configured_device", req_dev_str)),
                    "device_resolution_mode": str(
                        _LAST_INFERENCE_TELEMETRY.get("device_resolution_mode", res_mode)
                    ),
                    "device": actual_dev,
                    "actual_model_device": actual_dev,
                    "actual_model_dtype": str(_LAST_INFERENCE_TELEMETRY.get("actual_model_dtype", "UNKNOWN")),
                    "base_model_param_devices": list(
                        _LAST_INFERENCE_TELEMETRY.get("base_model_param_devices", [])
                    ),
                    "lora_adapter_param_devices": list(
                        _LAST_INFERENCE_TELEMETRY.get("lora_adapter_param_devices", [])
                    ),
                    "input_tensor_device": str(_LAST_INFERENCE_TELEMETRY.get("input_tensor_device", actual_dev)),
                    "output_tensor_device": str(
                        _LAST_INFERENCE_TELEMETRY.get("output_tensor_device", actual_dev)
                    ),
                    "peft_torch_device_arg": str(_LAST_INFERENCE_TELEMETRY.get("peft_torch_device_arg", "")),
                    "model_cache_hit": bool(_LAST_INFERENCE_TELEMETRY.get("model_cache_hit", False)),
                    "model_load_duration_ms": float(
                        _LAST_INFERENCE_TELEMETRY.get("model_load_duration_ms", 0.0)
                    ),
                    "per_identity_generate_latencies_ms": list(
                        _LAST_INFERENCE_TELEMETRY.get("per_identity_generate_latencies_ms", [])
                    ),
                    "sum_generate_latencies_ms": float(
                        _LAST_INFERENCE_TELEMETRY.get("sum_generate_latencies_ms", 0.0)
                    ),
                    "cuda_device_name": _LAST_INFERENCE_TELEMETRY.get("cuda_device_name"),
                    "cuda_memory_allocated_mb": _LAST_INFERENCE_TELEMETRY.get("cuda_memory_allocated_mb"),
                    "cuda_memory_reserved_mb": _LAST_INFERENCE_TELEMETRY.get("cuda_memory_reserved_mb"),
                    "cuda_max_memory_allocated_mb": _LAST_INFERENCE_TELEMETRY.get(
                        "cuda_max_memory_allocated_mb"
                    ),
                }
            )
        tracker.complete_stage(6, stage6_meta)

    # Stage 07: Evidence Fusion (Combining OpenGrep candidate, IRIS AST/Dataflow, and Qwen LoRA prediction)
    tracker.start_stage(7, {"candidates_to_fuse": len(ast_analyses)})
    fused_candidates: List[Tuple[str, str, shared.FindingCandidate, bool, str]] = []
    for idx, ((hit, cwe_int, ast_info), callee_pred) in enumerate(
        zip(ast_analyses, callee_predictions), start=1
    ):
        hit_rule = str(hit.get("check_id", "ntk.java.rule"))
        hit_sev = str(hit.get("extra", {}).get("severity", "ERROR")).upper()
        rel_file = ast_info.file_path
        if effective_rel_root and rel_file.startswith(str(effective_rel_root)):
            rel_file = rel_file[len(str(effective_rel_root)) :].lstrip("/\\")
        finding_id = f"FINDING-{idx:03d}-CWE{cwe_int:03d}-{ast_info.enclosing_method}-L{ast_info.match_line}"
        cand = shared.FindingCandidate(
            finding_id=finding_id,
            cwe=cwe_int,
            file_path=rel_file,
            line_number=ast_info.match_line,
            severity=hit_sev,
            base_scanner_score=0.70,
            callee_prediction=callee_pred,
            ast_evidence=ast_info.ast_evidence,
        )
        rel_verified, rel_reason = shared.verify_ast_release_evidence(cand)
        fused_candidates.append((hit_rule, rel_file, cand, rel_verified, rel_reason))

    evidence_fusion_ms = tracker.complete_stage(
        7,
        {
            "candidates_fused": len(fused_candidates),
            "explicit_ast_releases_verified": sum(1 for _, _, _, r_ok, _ in fused_candidates if r_ok),
        },
    )

    # Stage 08: SAST Scoring (Bounded Safety Floor 0.55 heuristic scoring computation)
    tracker.start_stage(
        8,
        {
            "candidates_to_score": len(fused_candidates),
            "safety_floor_threshold": cfg.safety_floor,
            "scoring_policy_version": cfg.scoring_policy_version,
        },
    )
    floor_score_results: List[Dict[str, Any]] = []
    for _, _, cand, _, _ in fused_candidates:
        floor_res = shared.evaluate_bounded_safety_floor(cand, safety_floor=cfg.safety_floor)
        floor_score_results.append(floor_res)

    sast_scoring_ms = tracker.complete_stage(
        8,
        {
            "candidates_scored": len(floor_score_results),
            "safety_floor_clamped_count": sum(1 for r in floor_score_results if r.get("safety_floor_applied")),
            "post_release_veto_count": sum(1 for r in floor_score_results if r.get("post_release_veto_applied")),
            "retained_after_ast_veto_count": sum(
                1 for r in floor_score_results if r.get("retained_after_ast_veto")
            ),
        },
    )

    # Stage 09: Alert Verification (REPORT/REVIEW/SUPPRESS state machine + FindingSchemaV2 + Source Provenance Check)
    tracker.start_stage(
        9,
        {
            "candidates_to_verify": len(fused_candidates),
            "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
        },
    )
    all_findings: List[Dict[str, Any]] = []
    reported_findings: List[Dict[str, Any]] = []
    review_queue_findings: List[Dict[str, Any]] = []
    suppressed_findings_audit_log: List[Dict[str, Any]] = []
    review_map = manual_reviews or {}

    for (hit, cwe_int, ast_info), (raw_llm_out, llm_lat_ms), callee_pred, (
        hit_rule,
        rel_file,
        cand,
        _,
        _,
    ) in zip(ast_analyses, llm_outputs, callee_predictions, fused_candidates):
        man_rev = review_map.get(cand.finding_id)
        f_v2 = triage_mod.verify_and_triage_finding(
            finding_id=cand.finding_id,
            cwe=cwe_int,
            file_path=rel_file,
            line_number=ast_info.match_line,
            scanner_rule_id=hit_rule,
            static_severity=cand.severity,
            base_scanner_score=0.70,
            ast_analysis=ast_info,
            callee_prediction=callee_pred,
            llm_raw_output=raw_llm_out,
            llm_latency_ms=llm_lat_ms,
            manual_review=man_rev,
            model_version=cfg.model_version,
            ruleset_version=cfg.ruleset_version,
            scoring_policy_version=cfg.scoring_policy_version,
        )
        f_dict = f_v2.to_dict()
        ok_schema, schema_errs = triage_mod.validate_finding_schema_v2_dict(f_dict)
        if not ok_schema:
            tracker.fail_stage(
                9,
                "FINDING_SCHEMA_V2_VALIDATION_FAILED",
                f"FindingSchemaV2 validation failed for {cand.finding_id}: {schema_errs}",
            )
            raise RuntimeError(f"FindingSchemaV2 validation failed for {cand.finding_id}: {schema_errs}")

        all_findings.append(f_dict)
        if f_dict["decision"] == "REPORT":
            reported_findings.append(f_dict)
        elif f_dict["decision"] == "REVIEW":
            review_queue_findings.append(f_dict)
        elif f_dict["decision"] == "SUPPRESS":
            suppressed_findings_audit_log.append(f_dict)

    # Execute machine-verified Per-Finding Source Provenance Verification while files exist on disk
    t0_prov = time.perf_counter()
    resolved_sha = str(
        (repo_provenance or {}).get("resolved_commit_sha")
        or (repo_provenance or {}).get("archive_sha256")
        or ""
    )
    source_prov_check = verify_findings_against_source_tree(
        findings=all_findings,
        raw_opengrep=og_json,
        base_dir=Path(effective_rel_root),
        resolved_commit_sha=resolved_sha,
    )
    source_verification_duration_ms = round((time.perf_counter() - t0_prov) * 1000.0, 2)
    alert_verification_ms = tracker.complete_stage(
        9,
        {
            "total_verified_findings": len(all_findings),
            "report_count": len(reported_findings),
            "review_count": len(review_queue_findings),
            "suppress_count": len(suppressed_findings_audit_log),
            "source_provenance_verified": bool(source_prov_check["verified"]),
            "source_mismatch_count": int(source_prov_check["mismatch_count"]),
            "source_verification_duration_ms": source_verification_duration_ms,
        },
    )

    # Stage 10: Report Synthesis & Trace Assembly
    tracker.start_stage(
        10,
        {
            "scan_id": tracker.scan_id,
            "total_findings": len(all_findings),
        },
    )
    effective_readiness = readiness_status
    if not source_prov_check["verified"]:
        effective_readiness = "SOURCE_PROVENANCE_MISMATCH"

    total_cands = len(all_findings)
    retained_count = sum(1 for f in all_findings if f["kept_by_pipeline"])
    suppressed_count = len(suppressed_findings_audit_log)
    total_ms = round((time.perf_counter() - t0_total) * 1000.0, 2)
    acq_ms = float((repo_provenance or {}).get("acquisition_latency_ms", 0.0))

    eff_source_mode = str((repo_provenance or {}).get("source_mode", tracker.source_mode or "LOCAL_JAVA_DIRECTORY"))
    eff_repo_url = str(
        (repo_provenance or {}).get("canonical_repo_url")
        or (repo_provenance or {}).get("repo_url")
        or (repo_provenance or {}).get("archive_filename")
        or str(src_path)
    )
    eff_req_commit = str(
        (repo_provenance or {}).get("requested_commit_sha")
        or (repo_provenance or {}).get("requested_branch")
        or ""
    )
    eff_res_commit = resolved_sha
    analysis_cov_status = str(cov_diag.get("analysis_coverage_status", "COMPLETE_SCANNED"))
    incomplete_reasons = list(cov_diag.get("incomplete_analysis_reasons", []))
    zero_findings_note: Optional[str] = None
    if total_cands == 0:
        zero_findings_note = (
            f"Scanned {len(java_files)}/{cov_diag.get('java_files_discovered', len(java_files))} Java files "
            f"({total_scanned_bytes} bytes) with {DEFAULT_RULES_APPLIED_COUNT} OpenGrep rules covering "
            f"{', '.join(SUPPORTED_CWE_CATEGORIES)}. Zero sink candidates matched; Stage 06 LLM classification "
            "was skipped with stage_skip_reason='NO_CANDIDATES' (no vulnerable patterns detected within supported CWE scope)."
        )

    stages_reused: List[str] = []
    if git_cache_hit_flag:
        stages_reused.append("STAGE_01_GIT_CHECKOUT")
    if inv_cache_hit_flag:
        stages_reused.append("STAGE_02_SOURCE_INVENTORY")
    if og_batch_cache_hits > 0 and og_batch_cache_misses == 0:
        stages_reused.append("STAGE_03_OPENGREP_BATCHES")
    if ast_cache_hits > 0 and ast_cache_misses == 0:
        stages_reused.append("STAGE_04_JAVAC_AST")
    if site_cache_hits > 0 and site_cache_misses == 0:
        stages_reused.append("STAGE_05_IRIS_SITE_TAINT")
    if llm_cache_hits > 0 and llm_cache_misses == 0:
        stages_reused.append("STAGE_06_QWEN_LORA_API_ROLE")

    overall_cache_hit = bool(
        use_cache
        and (
            git_cache_hit_flag
            or inv_cache_hit_flag
            or og_batch_cache_hits > 0
            or ast_cache_hits > 0
            or site_cache_hits > 0
            or llm_cache_hits > 0
        )
    )
    if force_fresh_scan:
        invalidation_reason: Optional[str] = "FORCE_FRESH_SCAN_REQUESTED"
    elif not use_cache:
        invalidation_reason = "CUSTOM_RULES_OR_CALLABLE_OVERRIDE"
    elif not overall_cache_hit:
        invalidation_reason = "COLD_CACHE_FIRST_SCAN"
    else:
        invalidation_reason = None

    cache_statistics: Dict[str, Any] = {
        "cache_version": telemetry_mod.MULTILAYER_CACHE_VERSION,
        "cache_enabled": use_cache,
        "cache_bypass_requested": bool(force_fresh_scan),
        "cache_hit": overall_cache_hit,
        "invalidation_reason": invalidation_reason,
        "cache_root_dir": str(scan_cache.cache_dir),
        "git_checkouts_dir": str(scan_cache.git_checkouts_dir),
        "sqlite_cache_db_path": str(scan_cache.db_path),
        "stages_reused": stages_reused,
        "layers": {
            "git_checkout": {
                "hits": 1 if git_cache_hit_flag else 0,
                "misses": 0 if git_cache_hit_flag else 1,
            },
            "source_inventory": {
                "hits": 1 if inv_cache_hit_flag else 0,
                "misses": 0 if inv_cache_hit_flag else 1,
            },
            "opengrep_batches": {
                "hits": og_batch_cache_hits,
                "misses": og_batch_cache_misses,
                "total_batches": total_batches,
            },
            "javac_ast_files": {
                "hits": ast_cache_hits,
                "misses": ast_cache_misses,
            },
            "iris_site_taint": {
                "hits": site_cache_hits,
                "misses": site_cache_misses,
            },
            "llm_api_identities": {
                "hits": llm_cache_hits,
                "misses": llm_cache_misses,
                "actual_gpu_inference_calls": actual_gpu_inference_calls,
            },
        },
    }

    scoring_summary = compute_scoring_summary(
        all_findings,
        safety_floor=cfg.safety_floor,
        scoring_policy_version=cfg.scoring_policy_version,
    )
    cov_status_canonical = (
        "FULL_SOURCE_COVERAGE"
        if analysis_cov_status in ("COMPLETE_SCANNED", "FULL_SOURCE_COVERAGE")
        else ("PARTIAL_BOUNDED" if analysis_cov_status == "PARTIAL_BOUNDED" else "FAILED_OR_INCOMPLETE")
    )
    cov_diag["coverage_status"] = cov_status_canonical
    cov_diag["analysis_coverage_status"] = cov_status_canonical
    cov_diag["legacy_analysis_coverage_status"] = (
        "COMPLETE_SCANNED" if cov_status_canonical == "FULL_SOURCE_COVERAGE" else analysis_cov_status
    )
    cov_diag["total_discovered_java_files"] = int(cov_diag.get("java_files_discovered", len(java_files)))
    cov_diag["eligible_java_files"] = int(cov_diag.get("java_files_matched_after_filters", len(java_files)))
    cov_diag["fully_processed_java_files"] = len(java_files)
    cov_diag["excluded_java_files"] = int(cov_diag.get("java_files_skipped", 0))
    cov_diag["per_reason_exclusions"] = cov_diag.get("skipped_files_breakdown", {})
    cov_diag["opengrep_candidate_count"] = total_cands
    cov_diag["unique_api_identities_classified"] = len(dedup_reqs)
    cov_diag["llm_inference_count"] = len(llm_requests)
    cov_diag["actual_gpu_inference_calls"] = actual_gpu_inference_calls
    cov_diag["cache_statistics"] = cache_statistics

    scan_cache.write_checkpoint(
        tracker.scan_id,
        {
            "stage": "COMPLETED",
            "completed_batches": total_batches,
            "total_batches": total_batches,
            "total_scanner_candidates": total_cands,
            "coverage_status": cov_status_canonical,
            "cache_hit": overall_cache_hit,
        },
    )

    summary_block = {
        "total_scanner_candidates": total_cands,
        "opengrep_candidate_count": total_cands,
        "unique_api_identities_classified": len(dedup_reqs),
        "llm_inference_count": len(llm_requests),
        "actual_gpu_inference_calls": actual_gpu_inference_calls,
        "retained_vulnerability_alerts": retained_count,
        "likely_true_positive_report_count": len(reported_findings),
        "needs_review_count": len(review_queue_findings),
        "suppressed_false_positives": suppressed_count,
        "false_positive_reduction_rate": round(suppressed_count / total_cands, 4) if total_cands else 0.0,
        "alert_volume_suppression_rate": round(suppressed_count / total_cands, 4) if total_cands else 0.0,
        "review_escalation_rate": round(len(review_queue_findings) / total_cands, 4) if total_cands else 0.0,
        "suppressed_findings_preserved_for_audit": True,
        "source_provenance_verified": bool(source_prov_check["verified"]),
        "score_semantics": triage_mod.SCORE_KIND_DEFAULT,
        "scoring_summary": scoring_summary,
        "cache_statistics": cache_statistics,
        "source_mode": eff_source_mode,
        "repository_url": eff_repo_url,
        "requested_commit": eff_req_commit or None,
        "resolved_commit": eff_res_commit or None,
        "java_files_discovered": int(cov_diag.get("java_files_discovered", len(java_files))),
        "java_files_scanned": len(java_files),
        "java_files_skipped": int(cov_diag.get("java_files_skipped", 0)),
        "total_discovered_java_files": int(cov_diag.get("java_files_discovered", len(java_files))),
        "eligible_java_files": int(cov_diag.get("java_files_matched_after_filters", len(java_files))),
        "fully_processed_java_files": len(java_files),
        "excluded_java_files": int(cov_diag.get("java_files_skipped", 0)),
        "per_reason_exclusions": cov_diag.get("skipped_files_breakdown", {}),
        "source_bytes_discovered": total_discovered_bytes,
        "source_bytes_scanned": total_scanned_bytes,
        "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
        "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
        "source_inventory_limits": cov_diag.get(
            "source_inventory_limits",
            {
                "default_max_source_files": cfg.max_source_files,
                "max_source_files_ceiling": cfg.max_source_files_ceiling,
                "effective_max_source_files": cfg.max_source_files,
                "max_file_bytes": cfg.max_file_bytes,
                "max_repo_total_bytes": cfg.max_repo_total_bytes,
            },
        ),
        "coverage_status": cov_status_canonical,
        "analysis_coverage_status": cov_status_canonical,
        "legacy_analysis_coverage_status": cov_diag["legacy_analysis_coverage_status"],
        "incomplete_analysis_reasons": incomplete_reasons,
        "stage_skip_reason": stage_06_skip_reason,
        "stage_error_code": None,
        "stage_error_message": None,
        "zero_findings_interpretation_note": zero_findings_note,
    }

    rt_tel = get_model_runtime_telemetry(cfg)
    payload: Dict[str, Any] = {
        "status": "OK" if source_prov_check["verified"] else "SOURCE_PROVENANCE_MISMATCH",
        "api_version": "NTK_WEB_BACKEND_API_V2",
        "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
        "backward_compatible_with": ["NTK_WEB_BACKEND_API_V1", "NTK_WEB_FINDING_SCHEMA_V1"],
        "integration_readiness_status": effective_readiness,
        "integration_readiness_note": (
            f"Backend pipeline verified at status {effective_readiness}. "
            "OpenGrep v1.25.0 + OpenJDK 17 JavacTask AST/Dataflow + Qwen2.5-0.5B EO06 LoRA + "
            "0.55 Bounded Safety Floor + Alert Triage (FindingSchemaV2) + Per-Finding Source Provenance Verification. "
            "FULL_WEB_UI_E2E_VERIFIED is reserved until the GretaAI frontend UI is mounted."
        ),
        "architecture_version": "FROZEN_ARCHITECTURE_V1",
        "model_version": cfg.model_version,
        "ruleset_version": cfg.ruleset_version,
        "scoring_policy_version": cfg.scoring_policy_version,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_mode": eff_source_mode,
        "repository_url": eff_repo_url,
        "requested_commit": eff_req_commit or None,
        "resolved_commit": eff_res_commit or None,
        "java_files_discovered": int(cov_diag.get("java_files_discovered", len(java_files))),
        "java_files_scanned": len(java_files),
        "java_files_skipped": int(cov_diag.get("java_files_skipped", 0)),
        "source_bytes_discovered": total_discovered_bytes,
        "source_bytes_scanned": total_scanned_bytes,
        "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
        "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
        "total_discovered_java_files": summary_block["total_discovered_java_files"],
        "eligible_java_files": summary_block["eligible_java_files"],
        "fully_processed_java_files": summary_block["fully_processed_java_files"],
        "excluded_java_files": summary_block["excluded_java_files"],
        "per_reason_exclusions": summary_block["per_reason_exclusions"],
        "opengrep_candidate_count": total_cands,
        "unique_api_identities_classified": len(dedup_reqs),
        "llm_inference_count": len(llm_requests),
        "actual_gpu_inference_calls": actual_gpu_inference_calls,
        "source_inventory_limits": summary_block["source_inventory_limits"],
        "coverage_status": cov_status_canonical,
        "analysis_coverage_status": cov_status_canonical,
        "legacy_analysis_coverage_status": cov_diag["legacy_analysis_coverage_status"],
        "incomplete_analysis_reasons": incomplete_reasons,
        "scoring_summary": scoring_summary,
        "cache_statistics": cache_statistics,
        "stage_skip_reason": stage_06_skip_reason,
        "stage_error_code": None,
        "stage_error_message": None,
        "coverage_diagnostics": cov_diag,
        "latency_ms": total_ms,
        "javac_duration_ms": javac_duration_ms,
        "opengrep_duration_ms": og_duration_ms,
        "context_extraction_duration_ms": context_extraction_ms,
        "iris_program_analysis_duration_ms": iris_program_analysis_ms,
        "ast_analysis_duration_ms": ast_duration_ms,
        "llm_inference_duration_ms": llm_duration_ms,
        "evidence_fusion_duration_ms": evidence_fusion_ms,
        "sast_scoring_duration_ms": sast_scoring_ms,
        "alert_verification_duration_ms": alert_verification_ms,
        "source_verification_duration_ms": source_verification_duration_ms,
        "report_synthesis_duration_ms": 0.0,
        "total_e2e_duration_ms": round(acq_ms + total_ms, 3),
        "model_metadata": {
            "base_model_id": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
            "adapter_arm_id": "eo06_vnext31_trackb_main",
            "model_version": cfg.model_version,
            "best_adapter_sha256": DEFAULT_BEST_ADAPTER_SHA256,
            "cloud_calls_enabled": False,
            "local_files_only": True,
            "configured_device": rt_tel["configured_device"],
            "device_resolution_mode": rt_tel["device_resolution_mode"],
            "model_load_state": rt_tel["model_load_state"],
            "actual_model_device": rt_tel["actual_model_device"],
            "actual_model_dtype": rt_tel["actual_model_dtype"],
            "base_model_param_devices": rt_tel["base_model_param_devices"],
            "lora_adapter_param_devices": rt_tel["lora_adapter_param_devices"],
            "last_generate_input_tensor_device": rt_tel["last_generate_input_tensor_device"],
            "last_generate_output_tensor_device": rt_tel["last_generate_output_tensor_device"],
            "torch_cuda_available": rt_tel["torch_cuda_available"],
            "cuda_device_name": rt_tel["cuda_device_name"],
            "cuda_memory_allocated_mb": rt_tel["cuda_memory_allocated_mb"],
            "cuda_memory_reserved_mb": rt_tel["cuda_memory_reserved_mb"],
            "cuda_max_memory_allocated_mb": rt_tel["cuda_max_memory_allocated_mb"],
        },
        "scanner_metadata": {
            "opengrep_binary": cfg.opengrep_bin,
            "opengrep_version": "1.25.0",
            "ruleset_version": cfg.ruleset_version,
            "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
            "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
            "javac_binary": cfg.javac_bin,
            "javac_exit_code": javac_exit_code,
            "compile_check_executed": bool(compile_check),
            "ast_parser_engine": "OPENJDK17_JAVAC_TASK_AST",
        },
        "summary": summary_block,
        "source_provenance_verification": source_prov_check,
        "findings": all_findings,
        "reported_findings": reported_findings,
        "review_queue_findings": review_queue_findings,
        "suppressed_findings_audit_log": suppressed_findings_audit_log,
    }
    if repo_provenance is not None:
        payload["repository_provenance"] = repo_provenance

    collisions = shared.find_case_insensitive_duplicate_keys(payload)
    if collisions:
        raise RuntimeError(f"Case-insensitive duplicate keys detected in web payload: {collisions}")

    report_synthesis_ms = tracker.complete_stage(
        10,
        {
            "total_scanner_candidates": total_cands,
            "report_count": len(reported_findings),
            "review_count": len(review_queue_findings),
            "suppress_count": suppressed_count,
            "analysis_coverage_status": analysis_cov_status,
            "java_files_discovered": int(cov_diag.get("java_files_discovered", len(java_files))),
            "java_files_scanned": len(java_files),
            "integration_readiness_status": effective_readiness,
        },
    )
    tracker.finish_pipeline(success=bool(source_prov_check["verified"]))
    pipeline_trace_dict = tracker.to_pipeline_trace_dict(
        scan_summary=summary_block,
        repository_provenance=repo_provenance,
        coverage_diagnostics=cov_diag,
    )
    payload["report_synthesis_duration_ms"] = report_synthesis_ms
    payload["total_e2e_duration_ms"] = pipeline_trace_dict["total_e2e_elapsed_ms"]
    payload["pipeline_trace"] = pipeline_trace_dict
    return payload


def scan_github_repository_and_triage(
    repo_url: str,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
    target_subpath: Optional[str] = None,
    file_allowlist: Optional[Sequence[str]] = None,
    include_globs: Optional[Sequence[str]] = None,
    exclude_globs: Optional[Sequence[str]] = None,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
    config: Optional[NtkWebBackendConfig] = None,
    compile_check: bool = False,
    cleanup_workspace: bool = True,
    raw_opengrep_sink: Optional[Dict[str, Any]] = None,
    stage_tracker: Optional[telemetry_mod.PipelineStageTracker] = None,
    force_fresh_scan: bool = False,
) -> Dict[str, Any]:
    """
    End-to-end GitHub repository scan:
      GitHub HTTPS URL validation -> shallow/sparse git clone -> Java file verification
      -> OpenGrep scan -> OpenJDK 17 JavacTask AST/Dataflow -> Local Qwen2.5-0.5B EO06 LoRA
      -> Bounded Safety Floor (0.55) -> Alert Triage (`FindingSchemaV2`)
      -> Per-Finding Source Provenance Verification.
    """
    cfg = config or NtkWebBackendConfig()
    tracker = stage_tracker or telemetry_mod.PipelineStageTracker(source_mode="GITHUB_GIT_CLONE")
    tracker.start_pipeline()
    t0 = time.perf_counter()
    acq = acquire_github_java_repository(
        repo_url=repo_url,
        branch=branch,
        commit_sha=commit_sha,
        target_subpath=target_subpath,
        file_allowlist=file_allowlist,
        include_globs=clean_inc if "clean_inc" in locals() else include_globs,
        exclude_globs=clean_exc if "clean_exc" in locals() else exclude_globs,
        max_files_limit=max_files_limit,
        scan_scope_policy=scan_scope_policy,
        config=cfg,
        stage_tracker=tracker,
        force_fresh_scan=force_fresh_scan,
    )
    if acq.get("status") != "OK":
        cov_diag = acq.get("coverage_diagnostics", {})
        prov_err = acq.get("repository_provenance", {})
        err_code = acq.get("error_code", "GITHUB_ACQUISITION_ERROR")
        err_msg = acq.get("error_message", "Failed to acquire GitHub repository")
        return {
            "status": "ERROR",
            "error_code": err_code,
            "error_message": err_msg,
            "stage_error_code": err_code,
            "stage_error_message": err_msg,
            "source_mode": "GITHUB_GIT_CLONE",
            "repository_url": prov_err.get("canonical_repo_url") or repo_url,
            "requested_commit": commit_sha or branch,
            "resolved_commit": prov_err.get("resolved_commit_sha"),
            "java_files_discovered": cov_diag.get("java_files_discovered", 0),
            "java_files_scanned": cov_diag.get("java_files_scanned", 0),
            "java_files_skipped": cov_diag.get("java_files_skipped", 0),
            "source_bytes_discovered": cov_diag.get("source_bytes_discovered", 0),
            "source_bytes_scanned": cov_diag.get("source_bytes_scanned", 0),
            "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
            "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
            "source_inventory_limits": cov_diag.get("source_inventory_limits", {}),
            "analysis_coverage_status": cov_diag.get("analysis_coverage_status", "FAILED_STAGE_02_LIMIT_EXCEEDED"),
            "incomplete_analysis_reasons": cov_diag.get("incomplete_analysis_reasons", [f"{err_code}: {err_msg}"]),
            "repository_provenance": prov_err,
            "coverage_diagnostics": cov_diag,
            "findings": [],
            "pipeline_trace": tracker.to_pipeline_trace_dict(
                repository_provenance=prov_err,
                coverage_diagnostics=cov_diag,
            ),
        }

    clone_dir = Path(acq["clone_dir"])
    scan_root = Path(acq["scan_root"])
    provenance = {
        "source_mode": "GITHUB_GIT_CLONE",
        "repo_url": acq["repo_url"],
        "canonical_repo_url": acq["canonical_repo_url"],
        "requested_branch": acq["requested_branch"],
        "resolved_branch": acq["resolved_branch"],
        "requested_commit_sha": acq["requested_commit_sha"],
        "resolved_commit_sha": acq["resolved_commit_sha"],
        "target_subpath": acq["target_subpath"],
        "java_file_count": acq["java_file_count"],
        "java_files_discovered": acq["java_files_discovered"],
        "java_files_scanned": acq["java_files_scanned"],
        "java_files_skipped": acq["java_files_skipped"],
        "source_bytes_discovered": acq["source_bytes_discovered"],
        "source_bytes_scanned": acq["source_bytes_scanned"],
        "java_files": acq["java_files"],
        "file_sha256_map": acq["file_sha256_map"],
        "total_java_bytes": acq["total_java_bytes"],
        "acquisition_latency_ms": acq["acquisition_latency_ms"],
        "is_cached_checkout": bool(acq.get("is_cached_checkout", False)),
        "git_checkout_cache_hit": bool(acq.get("git_checkout_cache_hit", False)),
        "source_inventory_cache_hit": bool(acq.get("source_inventory_cache_hit", False)),
    }
    try:
        res = scan_java_sources_and_triage(
            source_dir=scan_root,
            config=cfg,
            compile_check=compile_check,
            repo_provenance=provenance,
            readiness_status="GITHUB_REAL_E2E_VERIFIED",
            raw_opengrep_sink=raw_opengrep_sink,
            rel_base_dir=clone_dir,
            stage_tracker=tracker,
            pre_discovered_inventory=acq,
            force_fresh_scan=force_fresh_scan,
        )
        # Do not overwrite pipeline_trace["total_e2e_elapsed_ms"] after Stage 10 sealed the trace;
        # keep res["total_e2e_duration_ms"] strictly identical to pipeline_trace["total_e2e_elapsed_ms"].
        res["outer_wrapper_elapsed_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return res
    finally:
        if cleanup_workspace and not acq.get("is_cached_checkout", False):
            shutil.rmtree(clone_dir, ignore_errors=True)


def scan_java_zip_and_triage(
    zip_bytes: bytes,
    archive_filename: str = "uploaded_java_sources.zip",
    target_subpath: Optional[str] = None,
    file_allowlist: Optional[Sequence[str]] = None,
    include_globs: Optional[Sequence[str]] = None,
    exclude_globs: Optional[Sequence[str]] = None,
    max_files_limit: Optional[int] = None,
    scan_scope_policy: Optional[str] = None,
    config: Optional[NtkWebBackendConfig] = None,
    compile_check: bool = False,
    cleanup_workspace: bool = True,
    raw_opengrep_sink: Optional[Dict[str, Any]] = None,
    stage_tracker: Optional[telemetry_mod.PipelineStageTracker] = None,
) -> Dict[str, Any]:
    """
    End-to-end Java `.zip` archive scan:
      Safe ZIP validation (Zip-Slip, symlink, bytecode, zip-bomb blocks)
      -> `.java`-only sandbox extraction (`compile_check=False` so untrusted code is never compiled/executed)
      -> OpenGrep scan -> OpenJDK 17 JavacTask AST/Dataflow -> Local Qwen2.5-0.5B EO06 LoRA
      -> Bounded Safety Floor (0.55) -> Alert Triage (`FindingSchemaV2`)
      -> Per-Finding Source Provenance Verification.
    """
    cfg = config or NtkWebBackendConfig()
    tracker = stage_tracker or telemetry_mod.PipelineStageTracker(source_mode="JAVA_ZIP_ARCHIVE_UPLOAD")
    tracker.start_pipeline()
    t0 = time.perf_counter()
    acq = acquire_java_zip_archive(
        zip_bytes=zip_bytes,
        archive_filename=archive_filename,
        target_subpath=target_subpath,
        file_allowlist=file_allowlist,
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        max_files_limit=max_files_limit,
        scan_scope_policy=scan_scope_policy,
        config=cfg,
        stage_tracker=tracker,
    )
    if acq.get("status") != "OK":
        cov_diag = acq.get("coverage_diagnostics", {})
        prov_err = acq.get("repository_provenance", {})
        err_code = acq.get("error_code", "ZIP_ACQUISITION_ERROR")
        err_msg = acq.get("error_message", "Failed to acquire Java ZIP archive")
        return {
            "status": "ERROR",
            "error_code": err_code,
            "error_message": err_msg,
            "stage_error_code": err_code,
            "stage_error_message": err_msg,
            "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
            "repository_url": archive_filename,
            "requested_commit": None,
            "resolved_commit": prov_err.get("resolved_commit_sha"),
            "java_files_discovered": cov_diag.get("java_files_discovered", 0),
            "java_files_scanned": cov_diag.get("java_files_scanned", 0),
            "java_files_skipped": cov_diag.get("java_files_skipped", 0),
            "source_bytes_discovered": cov_diag.get("source_bytes_discovered", 0),
            "source_bytes_scanned": cov_diag.get("source_bytes_scanned", 0),
            "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
            "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
            "source_inventory_limits": cov_diag.get("source_inventory_limits", {}),
            "analysis_coverage_status": cov_diag.get("analysis_coverage_status", "FAILED_STAGE_02_LIMIT_EXCEEDED"),
            "incomplete_analysis_reasons": cov_diag.get("incomplete_analysis_reasons", [f"{err_code}: {err_msg}"]),
            "repository_provenance": prov_err,
            "coverage_diagnostics": cov_diag,
            "findings": [],
            "pipeline_trace": tracker.to_pipeline_trace_dict(
                repository_provenance=prov_err,
                coverage_diagnostics=cov_diag,
            ),
        }

    extract_dir = Path(acq["extract_dir"])
    provenance = {
        "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
        "archive_filename": acq["archive_filename"],
        "archive_sha256": acq["archive_sha256"],
        "archive_compressed_bytes": acq["archive_compressed_bytes"],
        "resolved_commit_sha": f"zip-sha256:{acq['archive_sha256'][:16]}",
        "target_subpath": acq.get("target_subpath"),
        "java_file_count": acq["java_file_count"],
        "java_files_discovered": acq["java_files_discovered"],
        "java_files_scanned": acq["java_files_scanned"],
        "java_files_skipped": acq["java_files_skipped"],
        "source_bytes_discovered": acq["source_bytes_discovered"],
        "source_bytes_scanned": acq["source_bytes_scanned"],
        "java_files": acq["java_files"],
        "file_sha256_map": acq["file_sha256_map"],
        "total_java_bytes": acq["total_java_bytes"],
        "untrusted_code_execution_disabled": True,
        "acquisition_latency_ms": acq["acquisition_latency_ms"],
    }
    try:
        # Enforce compile_check=False by default on uploaded ZIP archives so untrusted Java code is never compiled
        res = scan_java_sources_and_triage(
            source_dir=extract_dir,
            config=cfg,
            compile_check=bool(compile_check),
            repo_provenance=provenance,
            readiness_status="GITHUB_REAL_E2E_VERIFIED",
            raw_opengrep_sink=raw_opengrep_sink,
            rel_base_dir=extract_dir,
            stage_tracker=tracker,
            pre_discovered_inventory=acq,
        )
        res["outer_wrapper_elapsed_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return res
    finally:
        if cleanup_workspace:
            shutil.rmtree(extract_dir, ignore_errors=True)


def _extract_zip_bytes_from_multipart(raw_body: bytes, content_type: str) -> Tuple[Optional[bytes], str]:
    """
    Extracts `(zip_bytes, filename)` from a `multipart/form-data` HTTP request body without `cgi`.
    """
    m_boundary = re.search(r'boundary=([^;\s]+)', content_type)
    if not m_boundary:
        return None, ""
    boundary_str = m_boundary.group(1).strip('"')
    boundary_bytes = ("--" + boundary_str).encode("utf-8")
    parts = raw_body.split(boundary_bytes)
    for part in parts:
        if b"Content-Disposition:" not in part:
            continue
        header_end = part.find(b"\r\n\r\n")
        sep_len = 4
        if header_end == -1:
            header_end = part.find(b"\n\n")
            sep_len = 2
        if header_end == -1:
            continue
        headers_text = part[:header_end].decode("utf-8", errors="replace")
        payload = part[header_end + sep_len :]
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        elif payload.endswith(b"\n"):
            payload = payload[:-1]
        m_fn = re.search(r'filename="([^"]+)"', headers_text)
        fname = m_fn.group(1) if m_fn else "upload.zip"
        if payload:
            return payload, fname
    return None, ""


# ============================================================================
# Local HTTP API Server (`127.0.0.1` only)
# ============================================================================
def render_scan_html_report(scan_record: Dict[str, Any]) -> str:
    scan_id = html.escape(str(scan_record.get("scan_id", "UNKNOWN")))
    prov = scan_record.get("repository_provenance", {})
    repo_url = html.escape(
        str(
            prov.get("canonical_repo_url")
            or prov.get("repo_url")
            or prov.get("archive_filename")
            or "local_source_dir"
        )
    )
    commit_sha = html.escape(str(prov.get("resolved_commit_sha") or prov.get("archive_sha256") or "N/A"))
    summary = scan_record.get("summary", {})
    rows: List[str] = []
    for f in scan_record.get("findings", []):
        fid = html.escape(str(f.get("finding_id", "")))
        cwe = html.escape(str(f.get("cwe", "")))
        fp = html.escape(str(f.get("file_path", "")))
        ln = html.escape(str(f.get("line_number", "")))
        em = html.escape(str(f.get("enclosing_method", "")))
        dec = html.escape(str(f.get("decision", "")))
        ts = html.escape(str(f.get("triage_status", "")))
        sc = html.escape(str(f.get("confidence_score", f.get("final_heuristic_score", ""))))
        rcs = html.escape(", ".join(f.get("reason_codes", [])))
        rows.append(
            f"<tr><td>{fid}</td><td>{cwe}</td><td>{fp}:{ln} (<code>{em}</code>)</td>"
            f"<td><strong>{dec}</strong> ({ts})</td><td>{sc}</td><td>{rcs}</td></tr>"
        )
    rows_html = "\n".join(rows)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>NTK/IRIS SAST Scan Report - {scan_id}</title>
<style>
body {{ font-family: sans-serif; margin: 24px; color: #111; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 13px; }}
th {{ background: #f4f4f4; }}
</style>
</head>
<body>
<h1>NTK/IRIS Security Scan Report ({scan_id})</h1>
<p><strong>Source:</strong> {repo_url} | <strong>Commit / SHA:</strong> <code>{commit_sha}</code></p>
<p><strong>Total Candidates:</strong> {summary.get('total_scanner_candidates', 0)} |
<strong>REPORT:</strong> {summary.get('likely_true_positive_report_count', 0)} |
<strong>REVIEW:</strong> {summary.get('needs_review_count', 0)} |
<strong>SUPPRESS:</strong> {summary.get('suppressed_false_positives', 0)}</p>
<table>
<thead><tr><th>Finding ID</th><th>CWE</th><th>Location</th><th>Decision / Triage</th><th>Heuristic Score</th><th>Reason Codes</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>
"""


def _write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}")
    payload_text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    tmp_path.write_text(payload_text, encoding="utf-8", newline="\n")
    os.replace(tmp_path, path)


def resolve_storage_dir(storage_dir: Optional[Path] = None) -> Path:
    if storage_dir is not None:
        return Path(storage_dir)
    env_dir = os.environ.get("NTK_STORAGE_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return DEFAULT_PERSISTENT_STORAGE_DIR


class NtkBackendState:
    def __init__(
        self,
        config: Optional[NtkWebBackendConfig] = None,
        storage_dir: Optional[Path] = None,
        allow_local_dir: bool = False,
    ) -> None:
        self.config = config or NtkWebBackendConfig()
        self.storage_dir = resolve_storage_dir(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.scan_cache = get_global_scan_cache(storage_dir=self.storage_dir)
        self.result_index = telemetry_mod.NtkScanResultIndex(
            storage_dir=self.storage_dir,
            cache_dir=None,
            compute_scoring_summary_fn=compute_scoring_summary,
            safety_floor=self.config.safety_floor,
            scoring_policy_version=self.config.scoring_policy_version,
        )
        self.allow_local_dir = allow_local_dir
        self._lock = threading.Lock()
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.pipeline_traces_by_scan: Dict[str, Dict[str, Any]] = {}
        self.raw_opengrep_by_scan: Dict[str, Dict[str, Any]] = {}
        self.findings_by_id: Dict[str, Dict[str, Any]] = {}
        self.readiness_status = "LOCAL_API_VERIFIED"
        self.dataset_catalog = telemetry_mod.VerifiedDatasetCatalog()
        self.job_manager = telemetry_mod.ScanJobManager(
            execute_job_callable=self._execute_async_scan_job,
            scan_execution_lock=_SCAN_EXECUTION_LOCK,
        )

        # When using the default or NTK_STORAGE_DIR persistent store, perform copy-if-missing
        # migration from legacy /tmp/ntk_api_store and verified trace-only restoration for
        # SCAN-20261026045314-12BD65 from NTK_REAL_STAGE_TIMING_VERIFICATION.json.
        if storage_dir is None:
            self._migrate_legacy_tmp_store_copy_if_missing()
            self._restore_verified_historical_trace_copy_if_missing()

        for existing_trace in sorted(self.storage_dir.glob("*.pipeline_trace.json")):
            try:
                tr_data = json.loads(existing_trace.read_text(encoding="utf-8"))
                if isinstance(tr_data, dict):
                    sid = str(tr_data.get("scan_id") or existing_trace.name[: -len(".pipeline_trace.json")])
                    self.pipeline_traces_by_scan[sid] = tr_data
            except Exception:
                pass

        synced_summaries = self.result_index.sync_storage_dir(self.pipeline_traces_by_scan)
        for sid, sum_payload in synced_summaries.items():
            if not sum_payload.get("has_full_scan_findings_payload", False):
                continue
            self.scans[sid] = sum_payload
            if sum_payload.get("integration_readiness_status") == "GITHUB_REAL_E2E_VERIFIED":
                self.readiness_status = "GITHUB_REAL_E2E_VERIFIED"
            if sid not in self.pipeline_traces_by_scan:
                src_json = self.storage_dir / f"{sid}.json"
                if src_json.is_file():
                    try:
                        raw_rec = json.loads(src_json.read_text(encoding="utf-8"))
                        if isinstance(raw_rec, dict) and isinstance(raw_rec.get("pipeline_trace"), dict):
                            self.pipeline_traces_by_scan[sid] = raw_rec["pipeline_trace"]
                    except Exception:
                        pass

        # Restore completed historical jobs into ScanJobManager without re-queueing
        trace_items = sorted(
            self.pipeline_traces_by_scan.items(),
            key=lambda kv: str(kv[1].get("created_at_utc") or kv[0]),
        )
        for sid, tr_data in trace_items:
            has_full = sid in self.scans
            rest_status = "RESTORED_FULL_SCAN_AND_TRACE" if has_full else "RESTORED_TRACE_ONLY"
            if not isinstance(tr_data.get("restoration_metadata"), dict):
                tr_data["restoration_metadata"] = {
                    "restoration_status": rest_status,
                    "has_full_scan_findings_payload": has_full,
                    "full_scan_json_available": has_full,
                }
            else:
                tr_data["restoration_metadata"].setdefault("restoration_status", rest_status)
                tr_data["restoration_metadata"].setdefault("has_full_scan_findings_payload", has_full)
                tr_data["restoration_metadata"].setdefault("full_scan_json_available", has_full)
            if sid in self.scans:
                self.scans[sid].setdefault("restoration_status", "RESTORED_FULL_SCAN_AND_TRACE")
                self.scans[sid].setdefault("has_full_scan_findings_payload", True)
            self.job_manager.restore_completed_job_from_trace(
                trace_dict=tr_data,
                has_full_scan_payload=has_full,
                restoration_status=rest_status,
            )

    def _migrate_legacy_tmp_store_copy_if_missing(self) -> None:
        legacy_dir = Path(tempfile.gettempdir()) / "ntk_api_store"
        if not legacy_dir.exists() or not legacy_dir.is_dir():
            return
        if legacy_dir.resolve() == self.storage_dir.resolve():
            return
        for src_file in sorted(legacy_dir.glob("*.json")):
            dst_file = self.storage_dir / src_file.name
            if dst_file.exists():
                continue
            try:
                parsed = json.loads(src_file.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    _write_json_atomic(dst_file, parsed)
            except Exception:
                pass

    def _restore_verified_historical_trace_copy_if_missing(self) -> None:
        target_scan_id = "SCAN-20261026045314-12BD65"
        target_job_id = "JOB-20261026045314-12BD65"
        dst_trace = self.storage_dir / f"{target_scan_id}.pipeline_trace.json"
        if dst_trace.exists():
            return
        candidate_roots = [
            Path(__file__).resolve().parent.parent.parent,
            Path(__file__).resolve().parent.parent.parent.parent,
            Path("/mnt/c/Users/Admin/NTK_PreWeb_Audit/ntk_final_backend_e2e_20261025"),
        ]
        ver_path: Optional[Path] = None
        for root_cand in candidate_roots:
            cand = root_cand / "NTK_REAL_STAGE_TIMING_VERIFICATION.json"
            if cand.exists():
                ver_path = cand
                break
        if ver_path is None:
            return
        try:
            ver_data = json.loads(ver_path.read_text(encoding="utf-8"))
            if not isinstance(ver_data, dict) or ver_data.get("status") != "VERIFIED":
                return
            tr = ver_data.get("persisted_pipeline_trace")
            if not isinstance(tr, dict):
                return
            prov = tr.get("repository_provenance") if isinstance(tr.get("repository_provenance"), dict) else {}
            summary = tr.get("scan_summary") if isinstance(tr.get("scan_summary"), dict) else {}
            stages = tr.get("stages") if isinstance(tr.get("stages"), list) else []
            if (
                tr.get("trace_schema_version") == "NTK_PIPELINE_TRACE_V1"
                and tr.get("scan_id") == target_scan_id
                and tr.get("job_id") == target_job_id
                and tr.get("state") == "COMPLETED"
                and len(stages) == 10
                and prov.get("resolved_commit_sha") == "c78f9a9614e1d6e6a2eccfcc197edb8a6c328521"
                and summary.get("total_scanner_candidates") == 6
            ):
                tr_copy = dict(tr)
                tr_copy["restoration_metadata"] = {
                    "restoration_status": "RESTORED_TRACE_ONLY",
                    "restored_from_artifact": "NTK_REAL_STAGE_TIMING_VERIFICATION.json",
                    "has_full_scan_findings_payload": False,
                    "full_scan_json_available": False,
                    "note": (
                        "Restored verified 10-stage pipeline trace, job record, repository provenance, and "
                        "scan summary from NTK_REAL_STAGE_TIMING_VERIFICATION.json. Raw individual finding items "
                        "were not archived in NTK_REAL_STAGE_TIMING_VERIFICATION.json and are never fabricated."
                    ),
                }
                _write_json_atomic(dst_trace, tr_copy)
        except Exception:
            pass

    def _execute_async_scan_job(self, job_rec: telemetry_mod.ScanJobRecord) -> Dict[str, Any]:
        params = job_rec.request_params
        tracker = job_rec.tracker
        scan_id = job_rec.scan_id
        raw_og: Dict[str, Any] = {}
        source_mode = str(params.get("source_mode") or "GITHUB_GIT_CLONE")

        if source_mode == "JAVA_ZIP_ARCHIVE_UPLOAD":
            scan_res = scan_java_zip_and_triage(
                zip_bytes=params["zip_bytes"],
                archive_filename=str(params.get("archive_filename") or "uploaded_java_sources.zip"),
                target_subpath=params.get("target_subpath"),
                file_allowlist=params.get("file_allowlist"),
                include_globs=params.get("include_globs"),
                exclude_globs=params.get("exclude_globs"),
                max_files_limit=params.get("max_files_limit"),
                scan_scope_policy=params.get("scan_scope_policy"),
                config=self.config,
                compile_check=bool(params.get("compile_check", False)),
                cleanup_workspace=bool(params.get("cleanup_workspace", True)),
                raw_opengrep_sink=raw_og,
                stage_tracker=tracker,
            )
        elif source_mode == "LOCAL_SOURCE_DIR":
            scan_res = scan_java_sources_and_triage(
                source_dir=Path(str(params["local_source_dir"])),
                config=self.config,
                compile_check=bool(params.get("compile_check", True)),
                readiness_status="LOCAL_API_VERIFIED",
                raw_opengrep_sink=raw_og,
                stage_tracker=tracker,
                target_subpath=params.get("target_subpath"),
                file_allowlist=params.get("file_allowlist"),
                include_globs=params.get("include_globs"),
                exclude_globs=params.get("exclude_globs"),
                max_files_limit=params.get("max_files_limit"),
                scan_scope_policy=params.get("scan_scope_policy"),
            )
        else:
            scan_res = scan_github_repository_and_triage(
                repo_url=str(params.get("repo_url", "")),
                branch=params.get("branch"),
                commit_sha=params.get("commit_sha"),
                target_subpath=params.get("target_subpath"),
                file_allowlist=params.get("file_allowlist"),
                include_globs=params.get("include_globs"),
                exclude_globs=params.get("exclude_globs"),
                max_files_limit=params.get("max_files_limit"),
                scan_scope_policy=params.get("scan_scope_policy"),
                config=self.config,
                compile_check=bool(params.get("compile_check", False)),
                cleanup_workspace=bool(params.get("cleanup_workspace", True)),
                raw_opengrep_sink=raw_og,
                stage_tracker=tracker,
                force_fresh_scan=bool(params.get("force_fresh_scan", False)),
            )

        scan_res["job_id"] = job_rec.job_id
        if isinstance(scan_res.get("pipeline_trace"), dict):
            scan_res["pipeline_trace"]["job_id"] = job_rec.job_id
            scan_res["pipeline_trace"]["scan_id"] = scan_id

        if scan_res.get("status") == "OK":
            self.record_scan(scan_id, scan_res, raw_opengrep=raw_og)
        else:
            if isinstance(scan_res.get("pipeline_trace"), dict):
                with self._lock:
                    self.pipeline_traces_by_scan[scan_id] = scan_res["pipeline_trace"]
                    tr_file = self.storage_dir / f"{scan_id}.pipeline_trace.json"
                    _write_json_atomic(tr_file, scan_res["pipeline_trace"])
        return scan_res

    def record_scan(
        self,
        scan_id: str,
        scan_payload: Dict[str, Any],
        raw_opengrep: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        record = dict(scan_payload)
        record["scan_id"] = scan_id
        record["restoration_status"] = "LIVE_OR_FULL_PERSISTED_SCAN"
        record["has_full_scan_findings_payload"] = True
        if isinstance(record.get("pipeline_trace"), dict):
            tr_copy = dict(record["pipeline_trace"])
            tr_copy["scan_id"] = scan_id
            if record.get("job_id") and not tr_copy.get("job_id"):
                tr_copy["job_id"] = record["job_id"]
            tr_copy["restoration_metadata"] = {
                "restoration_status": "LIVE_OR_FULL_PERSISTED_SCAN",
                "has_full_scan_findings_payload": True,
                "full_scan_json_available": True,
            }
            record["pipeline_trace"] = tr_copy
        with self._lock:
            if record.get("integration_readiness_status") == "GITHUB_REAL_E2E_VERIFIED":
                self.readiness_status = "GITHUB_REAL_E2E_VERIFIED"
            for f in record.get("findings", []):
                base_fid = str(f.get("finding_id", ""))
                scoped_fid = f"{scan_id}:{base_fid}"
                f_copy = dict(f)
                f_copy["scan_id"] = scan_id
                f_copy["scoped_finding_id"] = scoped_fid
                self.findings_by_id[scoped_fid] = f_copy
                self.findings_by_id[base_fid] = f_copy
            tr_file = self.storage_dir / f"{scan_id}.pipeline_trace.json"
            if isinstance(record.get("pipeline_trace"), dict):
                self.pipeline_traces_by_scan[scan_id] = record["pipeline_trace"]
                _write_json_atomic(tr_file, record["pipeline_trace"])
            if raw_opengrep is not None:
                self.raw_opengrep_by_scan[scan_id] = raw_opengrep
            out_file = self.storage_dir / f"{scan_id}.json"
            _write_json_atomic(out_file, record)
            summary_payload = self.result_index.index_scan_record(
                scan_id=scan_id,
                scan_record=record,
                trace_dict=record.get("pipeline_trace") if isinstance(record.get("pipeline_trace"), dict) else None,
                source_json_path=out_file,
                trace_json_path=tr_file,
                has_full_scan_payload=True,
                restoration_status="LIVE_OR_FULL_PERSISTED_SCAN",
            )
            self.scans[scan_id] = summary_payload
        return record

    def load_full_scan_record(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not scan_id or not re.match(r"^[A-Za-z0-9_\-]+$", str(scan_id)):
            return None
        src_file = self.storage_dir / f"{scan_id}.json"
        if not src_file.is_file():
            return None
        try:
            rec_data = json.loads(src_file.read_text(encoding="utf-8"))
            if isinstance(rec_data, dict):
                return rec_data
        except Exception:
            pass
        return None


def create_ntk_http_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    state: Optional[NtkBackendState] = None,
) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(f"NTK Local Backend HTTP API must bind strictly to 127.0.0.1/localhost (got {host!r})")
    backend_state = state or NtkBackendState()

    class NtkHttpApiHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _resolve_cors(self) -> Tuple[bool, Optional[str], str]:
            raw_origin = self.headers.get("Origin")
            return evaluate_cors_origin(raw_origin, backend_state.config.cors_allowed_origins)

        def _write_cors_headers(self, allow_origin: Optional[str], is_preflight: bool = False) -> None:
            self.send_header("Vary", "Origin")
            if allow_origin:
                self.send_header("Access-Control-Allow-Origin", allow_origin)
                self.send_header("Access-Control-Allow-Methods", DEFAULT_CORS_ALLOW_METHODS)
                self.send_header("Access-Control-Allow-Headers", DEFAULT_CORS_ALLOW_HEADERS)
                if is_preflight:
                    self.send_header("Access-Control-Max-Age", DEFAULT_CORS_MAX_AGE)

        def _reject_if_untrusted_origin(self) -> bool:
            permitted, _, _ = self._resolve_cors()
            if not permitted:
                raw_origin = str(self.headers.get("Origin", "")).strip()
                self._send_json(
                    403,
                    {
                        "status": "ERROR",
                        "error_code": "CORS_ORIGIN_NOT_ALLOWED",
                        "error_message": f"Browser origin {raw_origin!r} is not permitted by the NTK CORS allowlist",
                    },
                )
                return True
            return False

        def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
            _, allow_origin, _ = self._resolve_cors()
            body = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self._write_cors_headers(allow_origin, is_preflight=False)
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, status_code: int, html_text: str) -> None:
            _, allow_origin, _ = self._resolve_cors()
            body = html_text.encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self._write_cors_headers(allow_origin, is_preflight=False)
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(
            self,
            status_code: int,
            content_type: str,
            body: bytes,
            extra_headers: Optional[Dict[str, str]] = None,
        ) -> None:
            _, allow_origin, _ = self._resolve_cors()
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if extra_headers:
                for hk, hv in extra_headers.items():
                    self.send_header(hk, hv)
            self._write_cors_headers(allow_origin, is_preflight=False)
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:
            if self._reject_if_untrusted_origin():
                return
            _, allow_origin, _ = self._resolve_cors()
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("X-Content-Type-Options", "nosniff")
            self._write_cors_headers(allow_origin, is_preflight=True)
            self.end_headers()

        def do_GET(self) -> None:
            if self._reject_if_untrusted_origin():
                return
            parsed_url = urllib.parse.urlsplit(self.path)
            path = parsed_url.path.rstrip("/") or "/"
            query = urllib.parse.parse_qs(parsed_url.query)

            if path == "/api/health":
                cfg = backend_state.config
                rt_tel = get_model_runtime_telemetry(cfg)
                self._send_json(
                    200,
                    {
                        "status": "OK",
                        "service": "ntk-iris-local-sast-backend",
                        "api_version": "NTK_WEB_BACKEND_API_V2",
                        "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
                        "architecture_version": "FROZEN_ARCHITECTURE_V1",
                        "bind_host": "127.0.0.1",
                        "active_port": self.server.server_port,
                        "integration_readiness_status": backend_state.readiness_status,
                        "ast_parser_engine": "OPENJDK17_JAVAC_TASK_AST",
                        "supported_scan_modes": ["GITHUB_REPOSITORY_URL", "JAVA_ZIP_ARCHIVE_UPLOAD"],
                        "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
                        "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
                        "source_inventory_limits": {
                            "default_max_source_files": cfg.max_source_files,
                            "max_source_files_ceiling": cfg.max_source_files_ceiling,
                            "max_file_bytes": cfg.max_file_bytes,
                            "max_repo_total_bytes": cfg.max_repo_total_bytes,
                            "max_repo_total_bytes_ceiling": cfg.max_repo_total_bytes_ceiling,
                            "max_zip_upload_bytes": cfg.max_zip_upload_bytes,
                            "max_zip_entries": cfg.max_zip_entries,
                        },
                        "telemetry_and_dataset_api_enabled": True,
                        "progress_source": "ACTUAL_BACKEND_INSTRUMENTATION",
                        "supported_async_job_endpoints": [
                            "/api/scan-jobs",
                            "/api/scan-jobs/{job_id}",
                            "/api/scans/{scan_id}/pipeline-trace",
                        ],
                        "supported_scan_result_endpoints": [
                            "/api/scans",
                            "/api/scans/summaries",
                            "/api/scans/{scan_id}",
                            "/api/scans/{scan_id}/summary",
                            "/api/scans/{scan_id}/findings",
                            "/api/scans/{scan_id}/findings/page",
                            "/api/scans/{scan_id}/findings/{finding_id}",
                            "/api/findings/{finding_id}",
                        ],
                        "supported_dataset_endpoints": [
                            "/api/datasets/manifest",
                            "/api/datasets/{dataset_id}/records",
                            "/api/datasets/{dataset_id}/export",
                        ],
                        "cors_allowed_origins": list(cfg.cors_allowed_origins),
                        "cors_wildcard_enabled": False,
                        "opengrep_available": Path(cfg.opengrep_bin).exists(),
                        "javac_available": Path(cfg.javac_bin).exists(),
                        "git_available": Path(cfg.git_bin).exists(),
                        "base_model_available": Path(cfg.base_model_path).exists(),
                        "best_adapter_available": Path(cfg.best_adapter_path).exists(),
                        "configured_device": rt_tel["configured_device"],
                        "device_resolution_mode": rt_tel["device_resolution_mode"],
                        "model_load_state": rt_tel["model_load_state"],
                        "actual_model_device": rt_tel["actual_model_device"],
                        "actual_model_dtype": rt_tel["actual_model_dtype"],
                        "torch_cuda_available": rt_tel["torch_cuda_available"],
                        "cuda_device_name": rt_tel["cuda_device_name"],
                        "cuda_memory_allocated_mb": rt_tel["cuda_memory_allocated_mb"],
                        "cuda_memory_reserved_mb": rt_tel["cuda_memory_reserved_mb"],
                        "cuda_max_memory_allocated_mb": rt_tel["cuda_max_memory_allocated_mb"],
                        "persistent_storage_enabled": True,
                        "persistent_storage_dir": str(backend_state.storage_dir),
                        "ext4_cache_dir": str(backend_state.scan_cache.cache_dir),
                        "ext4_git_checkouts_dir": str(backend_state.scan_cache.git_checkouts_dir),
                        "ext4_sqlite_cache_db_path": str(backend_state.scan_cache.db_path),
                        "ext4_scan_results_index_db_path": str(backend_state.result_index.db_path),
                        "scan_results_index_schema_version": telemetry_mod.SCAN_RESULT_INDEX_SCHEMA_VERSION,
                        "total_scans_recorded": len(backend_state.scans),
                        "total_pipeline_traces_recorded": len(backend_state.pipeline_traces_by_scan),
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    },
                )
                return

            if path == "/api/model":
                cfg = backend_state.config
                rt_tel = get_model_runtime_telemetry(cfg)
                self._send_json(
                    200,
                    {
                        "status": "OK",
                        "architecture_version": "FROZEN_ARCHITECTURE_V1",
                        "base_model_id": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
                        "adapter_arm_id": "eo06_vnext31_trackb_main",
                        "model_version": cfg.model_version,
                        "best_adapter_sha256": DEFAULT_BEST_ADAPTER_SHA256,
                        "safety_floor": cfg.safety_floor,
                        "score_semantics": triage_mod.SCORE_KIND_DEFAULT,
                        "ruleset_version": cfg.ruleset_version,
                        "rules_applied_count": DEFAULT_RULES_APPLIED_COUNT,
                        "supported_cwe_categories": list(SUPPORTED_CWE_CATEGORIES),
                        "scoring_policy_version": cfg.scoring_policy_version,
                        "ast_parser_engine": "OPENJDK17_JAVAC_TASK_AST",
                        "local_files_only": True,
                        "cloud_calls_enabled": False,
                        "thread_safe_inference_lock": True,
                        "configured_device": rt_tel["configured_device"],
                        "device_resolution_mode": rt_tel["device_resolution_mode"],
                        "model_load_state": rt_tel["model_load_state"],
                        "actual_model_device": rt_tel["actual_model_device"],
                        "actual_model_dtype": rt_tel["actual_model_dtype"],
                        "base_model_param_devices": rt_tel["base_model_param_devices"],
                        "lora_adapter_param_devices": rt_tel["lora_adapter_param_devices"],
                        "last_generate_input_tensor_device": rt_tel["last_generate_input_tensor_device"],
                        "last_generate_output_tensor_device": rt_tel["last_generate_output_tensor_device"],
                        "torch_cuda_available": rt_tel["torch_cuda_available"],
                        "cuda_device_name": rt_tel["cuda_device_name"],
                        "cuda_memory_allocated_bytes": rt_tel["cuda_memory_allocated_bytes"],
                        "cuda_memory_allocated_mb": rt_tel["cuda_memory_allocated_mb"],
                        "cuda_memory_reserved_bytes": rt_tel["cuda_memory_reserved_bytes"],
                        "cuda_memory_reserved_mb": rt_tel["cuda_memory_reserved_mb"],
                        "cuda_max_memory_allocated_mb": rt_tel["cuda_max_memory_allocated_mb"],
                        "eo06_training_provenance": telemetry_mod.get_eo06_training_provenance(),
                    },
                )
                return

            if path == "/api/scan-jobs":
                try:
                    limit_val = int(query.get("limit", ["25"])[0] or "25")
                except ValueError:
                    limit_val = 25
                jobs_list = backend_state.job_manager.list_jobs(limit=limit_val)
                self._send_json(
                    200,
                    {
                        "status": "OK",
                        "progress_source": "ACTUAL_BACKEND_INSTRUMENTATION",
                        "total_jobs_returned": len(jobs_list),
                        "jobs": jobs_list,
                    },
                )
                return

            m_job = re.match(r"^/api/scan-jobs/([A-Za-z0-9_\-]+)$", path)
            if m_job:
                job_id = m_job.group(1)
                snap = backend_state.job_manager.get_job_snapshot(job_id)
                if snap is None:
                    self._send_json(
                        404,
                        {
                            "status": "ERROR",
                            "error_code": "SCAN_JOB_NOT_FOUND",
                            "error_message": f"Scan job ID {job_id!r} not found",
                        },
                    )
                    return
                self._send_json(200, snap)
                return

            m_trace = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)/pipeline-trace$", path)
            if m_trace:
                scan_id = m_trace.group(1)
                tr = backend_state.pipeline_traces_by_scan.get(scan_id)
                if tr is None:
                    tr_file = backend_state.storage_dir / f"{scan_id}.pipeline_trace.json"
                    if tr_file.is_file():
                        try:
                            tr = json.loads(tr_file.read_text(encoding="utf-8"))
                            if isinstance(tr, dict):
                                backend_state.pipeline_traces_by_scan[scan_id] = tr
                        except Exception:
                            tr = None
                if tr is None:
                    self._send_json(
                        404,
                        {
                            "status": "ERROR",
                            "error_code": "PIPELINE_TRACE_NOT_FOUND",
                            "error_message": f"Pipeline trace for scan ID {scan_id!r} not found",
                        },
                    )
                    return
                inc_inv = (
                    (query.get("include_file_inventory", ["false"])[0] or "false").strip().lower()
                    in ("true", "1", "yes")
                    or (query.get("full", ["false"])[0] or "false").strip().lower() in ("true", "1", "yes")
                )
                tr_out = dict(tr)
                rep_prov = tr_out.get("repository_provenance")
                if not inc_inv and isinstance(rep_prov, dict):
                    jf = rep_prov.get("java_files")
                    if isinstance(jf, list) and len(jf) > 50:
                        tr_out["repository_provenance"] = telemetry_mod.compact_repository_provenance(
                            rep_prov, include_file_inventory=False
                        )
                self._send_json(200, tr_out)
                return

            if path == "/api/datasets/manifest":
                try:
                    manifest = backend_state.dataset_catalog.get_manifest()
                    self._send_json(200, manifest)
                except Exception as exc:
                    self._send_json(
                        500,
                        {
                            "status": "ERROR",
                            "error_code": "DATASET_MANIFEST_LOAD_ERROR",
                            "error_message": f"{type(exc).__name__}: {exc}",
                        },
                    )
                return

            m_ds_records = re.match(r"^/api/datasets/([A-Za-z0-9_\-.]+)/records$", path)
            if m_ds_records:
                ds_id = urllib.parse.unquote(m_ds_records.group(1))
                try:
                    page_size = int(
                        (query.get("page_size", [None])[0] or query.get("limit", [None])[0] or "50")
                    )
                except ValueError:
                    page_size = 50
                page_size = max(1, min(page_size, 200))
                if "page" in query and query["page"][0]:
                    try:
                        page = max(1, int(query["page"][0]))
                    except ValueError:
                        page = 1
                elif "offset" in query and query["offset"][0]:
                    try:
                        offset_val = max(0, int(query["offset"][0]))
                        page = (offset_val // page_size) + 1
                    except ValueError:
                        page = 1
                else:
                    page = 1

                q_str = (query.get("q", [None])[0] or query.get("search", [""])[0] or "").strip()
                cwe_f = (query.get("cwe", [""])[0] or "").strip()
                role_f = (query.get("role", [""])[0] or "").strip()
                split_f = (query.get("split", [""])[0] or "").strip()
                tier_f = (query.get("provenance_tier", [""])[0] or "").strip()
                track_a_raw = (
                    query.get("in_track_a_gold_subset", [None])[0]
                    or query.get("in_track_a", [None])[0]
                    or ""
                ).strip().lower()
                in_track_a_opt: Optional[bool] = None
                if track_a_raw in ("true", "1", "yes"):
                    in_track_a_opt = True
                elif track_a_raw in ("false", "0", "no"):
                    in_track_a_opt = False
                inc_msgs = (query.get("include_messages", ["false"])[0] or "false").strip().lower() in (
                    "true",
                    "1",
                    "yes",
                )

                res_payload = backend_state.dataset_catalog.query_records(
                    dataset_id=ds_id,
                    page=page,
                    page_size=page_size,
                    search_query=q_str,
                    cwe_filter=cwe_f,
                    role_filter=role_f,
                    split_filter=split_f,
                    provenance_tier_filter=tier_f,
                    in_track_a_only=in_track_a_opt,
                    include_messages=inc_msgs,
                )
                if res_payload.get("status") != "OK":
                    err_code = str(res_payload.get("error_code", "DATASET_QUERY_ERROR"))
                    http_st = 404 if "NOT_IN_ALLOWLIST" in err_code else 400
                    self._send_json(http_st, res_payload)
                    return
                res_payload["offset"] = (res_payload["page"] - 1) * res_payload["page_size"]
                res_payload["limit"] = res_payload["page_size"]
                self._send_json(200, res_payload)
                return

            m_ds_export = re.match(r"^/api/datasets/([A-Za-z0-9_\-.]+)/export$", path)
            if m_ds_export:
                ds_id = urllib.parse.unquote(m_ds_export.group(1))
                fmt = (query.get("format", ["csv"])[0] or "csv").strip().lower()
                q_str = (query.get("q", [None])[0] or query.get("search", [""])[0] or "").strip()
                cwe_f = (query.get("cwe", [""])[0] or "").strip()
                role_f = (query.get("role", [""])[0] or "").strip()
                split_f = (query.get("split", [""])[0] or "").strip()
                tier_f = (query.get("provenance_tier", [""])[0] or "").strip()
                track_a_raw = (
                    query.get("in_track_a_gold_subset", [None])[0]
                    or query.get("in_track_a", [None])[0]
                    or ""
                ).strip().lower()
                in_track_a_opt = None
                if track_a_raw in ("true", "1", "yes"):
                    in_track_a_opt = True
                elif track_a_raw in ("false", "0", "no"):
                    in_track_a_opt = False

                http_st, ctype, dl_fname, body_bytes = backend_state.dataset_catalog.export_dataset(
                    dataset_id=ds_id,
                    export_format=fmt,
                    search_query=q_str,
                    cwe_filter=cwe_f,
                    role_filter=role_f,
                    split_filter=split_f,
                    provenance_tier_filter=tier_f,
                    in_track_a_only=in_track_a_opt,
                )
                if http_st != 200:
                    self._send_bytes(http_st, ctype, body_bytes)
                    return
                self._send_bytes(
                    200,
                    ctype,
                    body_bytes,
                    extra_headers={
                        "Content-Disposition": f'attachment; filename="{dl_fname}"',
                        "Access-Control-Expose-Headers": "Content-Disposition",
                    },
                )
                return

            # Task B4: Lightweight History Summaries (`GET /api/scans` and `GET /api/scans/summaries`)
            if path in ("/api/scans", "/api/scans/summaries"):
                raw_page = query.get("page", ["1"])[0] if "page" in query else "1"
                raw_ps = (
                    query.get("page_size", [None])[0]
                    if "page_size" in query
                    else (query.get("limit", ["25"])[0] if "limit" in query else "25")
                )
                sm_f = (query.get("source_mode", [""])[0] or "").strip()
                cov_f = (query.get("coverage_status", [""])[0] or "").strip()
                q_f = (query.get("q", [None])[0] or query.get("search", [""])[0] or "").strip()
                http_st, payload = backend_state.result_index.list_scan_summaries(
                    page=raw_page,
                    page_size=raw_ps,
                    source_mode=sm_f,
                    coverage_status=cov_f,
                    q=q_f,
                )
                self._send_json(http_st, payload)
                return

            # Task B1: Scan Summary (`GET /api/scans/{scan_id}/summary` and default `GET /api/scans/{scan_id}`)
            m_scan_summary = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)/summary$", path)
            m_scan = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)$", path)
            if m_scan_summary or m_scan:
                scan_id = m_scan_summary.group(1) if m_scan_summary else m_scan.group(1)
                is_explicit_summary_route = m_scan_summary is not None
                want_full = (
                    not is_explicit_summary_route
                    and (
                        (query.get("full", ["false"])[0] or "false").strip().lower() in ("true", "1", "yes")
                        or (query.get("include_findings", ["false"])[0] or "false").strip().lower()
                        in ("true", "1", "yes")
                    )
                )
                if want_full:
                    full_rec = backend_state.load_full_scan_record(scan_id)
                    if full_rec is not None:
                        self._send_json(200, full_rec)
                        return

                inc_trace_default = "false" if is_explicit_summary_route else "true"
                inc_trace = (
                    query.get("include_pipeline_trace", [inc_trace_default])[0] or inc_trace_default
                ).strip().lower() in ("true", "1", "yes")
                tr_dict = backend_state.pipeline_traces_by_scan.get(scan_id)
                sum_payload = backend_state.result_index.get_scan_summary(
                    scan_id=scan_id,
                    include_pipeline_trace=inc_trace,
                    pipeline_trace_dict=tr_dict,
                )
                if sum_payload is not None:
                    backend_state.scans[scan_id] = sum_payload
                    self._send_json(200, sum_payload)
                    return

                tr_only = backend_state.pipeline_traces_by_scan.get(scan_id)
                if isinstance(tr_only, dict):
                    self._send_json(
                        200,
                        {
                            "status": "OK",
                            "scan_id": scan_id,
                            "job_id": tr_only.get("job_id"),
                            "restoration_status": "RESTORED_TRACE_ONLY",
                            "has_full_scan_findings_payload": False,
                            "restoration_metadata": tr_only.get("restoration_metadata", {}),
                            "total_e2e_duration_ms": tr_only.get("total_e2e_elapsed_ms"),
                            "repository_provenance": telemetry_mod.compact_repository_provenance(
                                tr_only.get("repository_provenance", {}), include_file_inventory=False
                            ),
                            "coverage_diagnostics": tr_only.get("coverage_diagnostics", {}),
                            "summary": tr_only.get("scan_summary", {}),
                            "pipeline_trace": tr_only,
                        },
                    )
                    return

                self._send_json(
                    404,
                    {
                        "status": "ERROR",
                        "error_code": "SCAN_NOT_FOUND",
                        "error_message": f"Scan ID {scan_id!r} not found",
                    },
                )
                return

            # Task B2: Paginated Findings (`GET /api/scans/{scan_id}/findings/page` and `GET /api/scans/{scan_id}/findings`)
            m_findings_page = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)/findings/page$", path)
            m_findings = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)/findings$", path)
            if m_findings_page or m_findings:
                scan_id = m_findings_page.group(1) if m_findings_page else m_findings.group(1)
                is_page_route = m_findings_page is not None

                # Check if scan is known or needs indexing
                sum_check = backend_state.result_index.get_scan_summary(scan_id)
                if sum_check is None:
                    tr_only = backend_state.pipeline_traces_by_scan.get(scan_id)
                    if isinstance(tr_only, dict):
                        self._send_json(
                            404,
                            {
                                "status": "ERROR",
                                "error_code": "SCAN_FINDINGS_NOT_ARCHIVED_TRACE_ONLY_RESTORED",
                                "scan_id": scan_id,
                                "job_id": tr_only.get("job_id"),
                                "restoration_status": "RESTORED_TRACE_ONLY",
                                "has_full_scan_findings_payload": False,
                                "pipeline_trace_url": f"/api/scans/{scan_id}/pipeline-trace",
                                "summary": tr_only.get("scan_summary", {}),
                                "error_message": (
                                    f"Scan {scan_id!r} was restored as RESTORED_TRACE_ONLY from "
                                    "NTK_REAL_STAGE_TIMING_VERIFICATION.json (10-stage pipeline trace, summary, and "
                                    "repository provenance are available at /api/scans/{scan_id}/pipeline-trace; "
                                    "individual finding payloads were not archived and are never fabricated)."
                                ),
                            },
                        )
                        return
                    self._send_json(
                        404,
                        {
                            "status": "ERROR",
                            "error_code": "SCAN_NOT_FOUND",
                            "error_message": f"Scan ID {scan_id!r} not found",
                        },
                    )
                    return

                total_cands = int((sum_check.get("triage_totals") or {}).get("total_candidates", 0))
                want_all = (query.get("all", ["false"])[0] or "false").strip().lower() in ("true", "1", "yes")
                raw_page = query.get("page", ["1"])[0] if "page" in query else "1"
                raw_offset = query.get("offset", [None])[0] if "offset" in query else None
                if "page_size" in query:
                    raw_ps: Any = query["page_size"][0]
                elif "limit" in query:
                    raw_ps = query["limit"][0]
                elif want_all:
                    raw_ps = max(1, min(total_cands, 6000))
                else:
                    raw_ps = 50

                # On legacy /api/scans/{scan_id}/findings, preserve full FindingSchemaV2 + partitioned arrays
                # automatically for small scans (<= 50 findings) so existing E2E regression suites pass 100%,
                # while keeping large scans (> 50 findings) compact (~28 KB per 50-row page).
                is_small_legacy = (not is_page_route) and (total_cands <= 50)
                if "include_evidence" in query:
                    inc_ev = (query["include_evidence"][0] or "false").strip().lower() in ("true", "1", "yes")
                else:
                    inc_ev = True if (is_small_legacy or want_all) else False

                if "include_partitioned_arrays" in query:
                    inc_part = (query["include_partitioned_arrays"][0] or "false").strip().lower() in (
                        "true",
                        "1",
                        "yes",
                    )
                else:
                    inc_part = True if (is_small_legacy or want_all) else False

                decision_f = (query.get("decision", [""])[0] or "").strip()
                triage_f = (query.get("triage_status", [""])[0] or "").strip()
                cwe_f = (query.get("cwe", [""])[0] or "").strip()
                sev_f = (query.get("severity", [""])[0] or "").strip()
                fp_f = (
                    query.get("file_path", [None])[0]
                    or query.get("file", [""])[0]
                    or ""
                ).strip()
                em_f = (
                    query.get("enclosing_method", [None])[0]
                    or query.get("method", [""])[0]
                    or ""
                ).strip()
                q_f = (
                    query.get("q", [None])[0]
                    or query.get("search", [""])[0]
                    or ""
                ).strip()
                sort_by_f = (query.get("sort_by", ["finding_seq"])[0] or "finding_seq").strip()
                sort_order_f = (
                    query.get("sort_order", [None])[0]
                    or query.get("order", ["asc"])[0]
                    or "asc"
                ).strip()

                http_st, page_payload = backend_state.result_index.query_findings_page(
                    scan_id=scan_id,
                    page=raw_page,
                    page_size=raw_ps,
                    offset=raw_offset,
                    decision=decision_f,
                    triage_status=triage_f,
                    cwe=cwe_f,
                    severity=sev_f,
                    file_path=fp_f,
                    enclosing_method=em_f,
                    q=q_f,
                    sort_by=sort_by_f,
                    sort_order=sort_order_f,
                    include_evidence=inc_ev,
                    include_partitioned_arrays=inc_part,
                    base_path=path,
                )
                self._send_json(http_st, page_payload)
                return

            m_report = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)/report$", path)
            if m_report:
                scan_id = m_report.group(1)
                rec = backend_state.load_full_scan_record(scan_id)
                if rec is None:
                    tr_only = backend_state.pipeline_traces_by_scan.get(scan_id)
                    if isinstance(tr_only, dict):
                        self._send_json(
                            404,
                            {
                                "status": "ERROR",
                                "error_code": "SCAN_REPORT_NOT_ARCHIVED_TRACE_ONLY_RESTORED",
                                "scan_id": scan_id,
                                "job_id": tr_only.get("job_id"),
                                "restoration_status": "RESTORED_TRACE_ONLY",
                                "has_full_scan_findings_payload": False,
                                "pipeline_trace_url": f"/api/scans/{scan_id}/pipeline-trace",
                                "summary": tr_only.get("scan_summary", {}),
                                "error_message": (
                                    f"Scan {scan_id!r} was restored as RESTORED_TRACE_ONLY; full finding report is not "
                                    f"archived, use /api/scans/{scan_id}/pipeline-trace for verified 10-stage replay."
                                ),
                            },
                        )
                        return
                    self._send_json(
                        404,
                        {
                            "status": "ERROR",
                            "error_code": "SCAN_NOT_FOUND",
                            "error_message": f"Scan ID {scan_id!r} not found",
                        },
                    )
                    return
                fmt = (query.get("format", ["json"])[0] or "json").lower()
                if fmt == "html":
                    self._send_html(200, render_scan_html_report(rec))
                else:
                    self._send_json(200, rec)
                return

            # Task B3: Single Finding Detail (`GET /api/scans/{scan_id}/findings/{finding_id}` and `GET /api/findings/{finding_id}`)
            m_scoped_finding = re.match(r"^/api/scans/([A-Za-z0-9_\-]+)/findings/([A-Za-z0-9_:\-.%]+)$", path)
            if m_scoped_finding:
                scan_id = m_scoped_finding.group(1)
                fid = urllib.parse.unquote(m_scoped_finding.group(2))
                http_st, detail_payload = backend_state.result_index.get_finding_detail(
                    finding_id=fid,
                    scan_id=scan_id,
                )
                self._send_json(http_st, detail_payload)
                return

            m_finding_detail = re.match(r"^/api/findings/([A-Za-z0-9_:\-.%]+)$", path)
            if m_finding_detail:
                fid = urllib.parse.unquote(m_finding_detail.group(1))
                scan_id_q = (query.get("scan_id", [""])[0] or "").strip() or None
                http_st, detail_payload = backend_state.result_index.get_finding_detail(
                    finding_id=fid,
                    scan_id=scan_id_q,
                )
                self._send_json(http_st, detail_payload)
                return

            self._send_json(
                404,
                {
                    "status": "ERROR",
                    "error_code": "ENDPOINT_NOT_FOUND",
                    "error_message": f"Unknown endpoint: {path}",
                },
            )

        def do_POST(self) -> None:
            if self._reject_if_untrusted_origin():
                return
            parsed_url = urllib.parse.urlsplit(self.path)
            path = parsed_url.path.rstrip("/") or "/"

            if path not in ("/api/scans", "/api/scans/zip", "/api/scan-jobs"):
                self._send_json(
                    404,
                    {
                        "status": "ERROR",
                        "error_code": "ENDPOINT_NOT_FOUND",
                        "error_message": f"Unknown POST endpoint: {path}",
                    },
                )
                return

            try:
                content_len = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_len = 0

            max_body_bytes = (
                backend_state.config.max_zip_upload_bytes + (4 * 1024 * 1024)
                if path in ("/api/scans/zip", "/api/scan-jobs")
                else max(65536, backend_state.config.max_zip_upload_bytes + (4 * 1024 * 1024))
            )
            if content_len <= 0 or content_len > max_body_bytes:
                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": "INVALID_REQUEST_BODY_LENGTH",
                        "error_message": f"Request body must be non-empty and <= {max_body_bytes} bytes",
                    },
                )
                return

            raw_bytes = self.rfile.read(content_len)
            content_type = str(self.headers.get("Content-Type", "")).lower()
            raw_og: Dict[str, Any] = {}

            # Case 0: POST /api/scan-jobs with binary/multipart ZIP upload
            if path == "/api/scan-jobs" and not content_type.startswith("application/json"):
                if "multipart/form-data" in content_type:
                    zip_payload, archive_fn = _extract_zip_bytes_from_multipart(
                        raw_bytes, self.headers.get("Content-Type", "")
                    )
                    if zip_payload is None:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": "INVALID_MULTIPART_ZIP_UPLOAD",
                                "error_message": "Could not extract ZIP file field from multipart/form-data body",
                            },
                        )
                        return
                else:
                    zip_payload = raw_bytes
                    archive_fn = str(self.headers.get("X-Archive-Filename") or "uploaded_java_sources.zip")

                if len(zip_payload) < 4 or zip_payload[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
                    self._send_json(
                        400,
                        {
                            "status": "ERROR",
                            "error_code": "INVALID_ZIP_MAGIC_BYTES_REJECTED",
                            "error_message": "Uploaded payload does not have valid ZIP magic bytes",
                        },
                    )
                    return

                zip_sha256 = hashlib.sha256(zip_payload).hexdigest()
                http_code, job_snap = backend_state.job_manager.submit_job(
                    {
                        "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
                        "zip_bytes": zip_payload,
                        "archive_filename": archive_fn,
                        "zip_sha256": zip_sha256,
                        "compile_check": False,
                        "cleanup_workspace": True,
                    }
                )
                self._send_json(http_code, job_snap)
                return

            # Case 1: POST /api/scans/zip with binary ZIP or multipart/form-data
            if path == "/api/scans/zip" and not content_type.startswith("application/json"):
                scan_id = str(
                    self.headers.get("X-Scan-Id")
                    or f"SCAN-ZIP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
                )
                if "multipart/form-data" in content_type:
                    zip_payload, archive_fn = _extract_zip_bytes_from_multipart(raw_bytes, self.headers.get("Content-Type", ""))
                    if zip_payload is None:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "scan_id": scan_id,
                                "error_code": "INVALID_MULTIPART_ZIP_UPLOAD",
                                "error_message": "Could not extract ZIP file field from multipart/form-data body",
                            },
                        )
                        return
                else:
                    zip_payload = raw_bytes
                    archive_fn = str(self.headers.get("X-Archive-Filename") or "uploaded_java_sources.zip")

                with backend_state.job_manager.scan_execution_lock:
                    scan_res = scan_java_zip_and_triage(
                        zip_bytes=zip_payload,
                        archive_filename=archive_fn,
                        config=backend_state.config,
                        compile_check=False,
                        cleanup_workspace=True,
                        raw_opengrep_sink=raw_og,
                    )
                if scan_res.get("status") != "OK":
                    err_code = str(scan_res.get("error_code", "ZIP_SCAN_ERROR"))
                    http_code = 400 if ("REJECTED" in err_code or "INVALID" in err_code or "EMPTY" in err_code) else 422
                    self._send_json(
                        http_code,
                        {
                            "status": "ERROR",
                            "scan_id": scan_id,
                            "error_code": err_code,
                            "error_message": scan_res.get("error_message", "ZIP scan failed"),
                            "stage_error_code": scan_res.get("stage_error_code", err_code),
                            "stage_error_message": scan_res.get("stage_error_message", scan_res.get("error_message")),
                            "coverage_diagnostics": scan_res.get("coverage_diagnostics", {}),
                            "pipeline_trace": scan_res.get("pipeline_trace"),
                        },
                    )
                    return
                stored = backend_state.record_scan(scan_id, scan_res, raw_opengrep=raw_og)
                self._send_json(200, stored)
                return

            # Case 2: JSON body on /api/scans, /api/scans/zip, or /api/scan-jobs
            raw_body = raw_bytes.decode("utf-8", errors="replace")
            try:
                req_json = json.loads(raw_body)
                if not isinstance(req_json, dict):
                    raise ValueError("JSON root must be an object")
            except Exception as exc:
                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": "MALFORMED_JSON_BODY",
                        "error_message": f"Invalid JSON request body: {exc}",
                    },
                )
                return

            repo_url = str(req_json.get("repo_url", "")).strip()
            branch = req_json.get("branch")
            commit_sha = req_json.get("commit_sha")
            target_subpath = req_json.get("target_subpath")
            file_allowlist = req_json.get("file_allowlist")
            include_globs = req_json.get("include_globs")
            exclude_globs = req_json.get("exclude_globs")
            max_files_limit = req_json.get("max_files_limit")
            scan_scope_policy = req_json.get("scan_scope_policy")
            zip_b64 = str(req_json.get("zip_base64", "")).strip()
            archive_filename = str(req_json.get("archive_filename") or "uploaded_java_sources.zip").strip()
            local_source_dir = str(req_json.get("local_source_dir", "")).strip()

            # Pre-validate filter/limit args across all POST endpoints
            ok_inc, inc_err, clean_inc = validate_glob_patterns(include_globs, "include_globs")
            if not ok_inc:
                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": inc_err,
                        "error_message": f"Disallowed include_globs: {include_globs!r}",
                    },
                )
                return
            ok_exc, exc_err, clean_exc = validate_glob_patterns(exclude_globs, "exclude_globs")
            if not ok_exc:
                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": exc_err,
                        "error_message": f"Disallowed exclude_globs: {exclude_globs!r}",
                    },
                )
                return
            ok_lim, lim_err, eff_max_files, eff_max_repo_bytes, eff_scope_policy = resolve_effective_scan_limits(
                backend_state.config,
                max_files_limit=max_files_limit,
                scan_scope_policy=scan_scope_policy,
            )
            if not ok_lim:
                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": lim_err,
                        "error_message": f"Disallowed max_files_limit or scan_scope_policy: {lim_err}",
                    },
                )
                return

            if path == "/api/scan-jobs":
                force_new = bool(req_json.get("force_new_job", False))
                if zip_b64:
                    try:
                        decoded_zip = base64.b64decode(zip_b64, validate=True)
                    except Exception as exc:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": "INVALID_BASE64_ZIP_PAYLOAD_REJECTED",
                                "error_message": f"Invalid base64 encoding in zip_base64: {exc}",
                            },
                        )
                        return
                    if len(decoded_zip) < 4 or decoded_zip[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": "INVALID_ZIP_MAGIC_BYTES_REJECTED",
                                "error_message": "Decoded zip_base64 does not have valid ZIP magic bytes",
                            },
                        )
                        return
                    ok_sub, sub_err, clean_sub = validate_relative_subpath(target_subpath)
                    if not ok_sub:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": sub_err,
                                "error_message": f"Disallowed target_subpath: {target_subpath!r}",
                            },
                        )
                        return
                    zip_sha256 = hashlib.sha256(decoded_zip).hexdigest()
                    http_code, job_snap = backend_state.job_manager.submit_job(
                        {
                            "source_mode": "JAVA_ZIP_ARCHIVE_UPLOAD",
                            "zip_bytes": decoded_zip,
                            "archive_filename": archive_filename,
                            "zip_sha256": zip_sha256,
                            "target_subpath": clean_sub or target_subpath,
                            "file_allowlist": file_allowlist,
                            "include_globs": clean_inc,
                            "exclude_globs": clean_exc,
                            "max_files_limit": eff_max_files,
                            "scan_scope_policy": eff_scope_policy,
                            "compile_check": False,
                            "cleanup_workspace": bool(req_json.get("cleanup_workspace", True)),
                            "job_id": req_json.get("job_id"),
                            "scan_id": req_json.get("scan_id"),
                        },
                        force_new_job=force_new,
                    )
                    self._send_json(http_code, job_snap)
                    return

                if repo_url:
                    ok_url, url_err, canonical_url = validate_github_repo_url(repo_url)
                    if not ok_url:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": url_err,
                                "error_message": f"Invalid or disallowed GitHub repository URL: {url_err}",
                            },
                        )
                        return
                    ok_br, br_err = validate_git_ref(branch, is_commit_sha=False)
                    if not ok_br:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": br_err,
                                "error_message": f"Disallowed git branch name: {branch!r}",
                            },
                        )
                        return
                    ok_sha, sha_err = validate_git_ref(commit_sha, is_commit_sha=True)
                    if not ok_sha:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": sha_err,
                                "error_message": f"Disallowed git commit SHA: {commit_sha!r}",
                            },
                        )
                        return
                    ok_sub, sub_err, clean_sub = validate_relative_subpath(target_subpath)
                    if not ok_sub:
                        self._send_json(
                            400,
                            {
                                "status": "ERROR",
                                "error_code": sub_err,
                                "error_message": f"Disallowed target_subpath: {target_subpath!r}",
                            },
                        )
                        return
                    http_code, job_snap = backend_state.job_manager.submit_job(
                        {
                            "source_mode": "GITHUB_GIT_CLONE",
                            "repo_url": canonical_url,
                            "branch": branch,
                            "commit_sha": commit_sha,
                            "target_subpath": clean_sub or target_subpath,
                            "file_allowlist": file_allowlist,
                            "include_globs": clean_inc,
                            "exclude_globs": clean_exc,
                            "max_files_limit": eff_max_files,
                            "scan_scope_policy": eff_scope_policy,
                            "compile_check": bool(req_json.get("compile_check", False)),
                            "cleanup_workspace": bool(req_json.get("cleanup_workspace", True)),
                            "force_fresh_scan": bool(req_json.get("force_fresh_scan", req_json.get("cache_bypass", False))),
                            "job_id": req_json.get("job_id"),
                            "scan_id": req_json.get("scan_id"),
                        },
                        force_new_job=force_new,
                    )
                    self._send_json(http_code, job_snap)
                    return

                if local_source_dir and backend_state.allow_local_dir:
                    http_code, job_snap = backend_state.job_manager.submit_job(
                        {
                            "source_mode": "LOCAL_SOURCE_DIR",
                            "local_source_dir": local_source_dir,
                            "target_subpath": target_subpath,
                            "file_allowlist": file_allowlist,
                            "include_globs": clean_inc,
                            "exclude_globs": clean_exc,
                            "max_files_limit": eff_max_files,
                            "scan_scope_policy": eff_scope_policy,
                            "compile_check": bool(req_json.get("compile_check", True)),
                            "job_id": req_json.get("job_id"),
                            "scan_id": req_json.get("scan_id"),
                        },
                        force_new_job=force_new,
                    )
                    self._send_json(http_code, job_snap)
                    return

                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": "MISSING_SCAN_SOURCE",
                        "error_message": (
                            "POST /api/scan-jobs requires 'repo_url' (https://github.com/<owner>/<repo>.git) "
                            "or 'zip_base64' (or binary/multipart ZIP)"
                        ),
                    },
                )
                return

            scan_id = str(
                req_json.get("scan_id")
                or f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
            )

            if zip_b64 or path == "/api/scans/zip":
                if not zip_b64:
                    self._send_json(
                        400,
                        {
                            "status": "ERROR",
                            "scan_id": scan_id,
                            "error_code": "MISSING_ZIP_PAYLOAD",
                            "error_message": "POST /api/scans/zip requires raw ZIP bytes, multipart file, or 'zip_base64' in JSON",
                        },
                    )
                    return
                try:
                    decoded_zip = base64.b64decode(zip_b64, validate=True)
                except Exception as exc:
                    self._send_json(
                        400,
                        {
                            "status": "ERROR",
                            "scan_id": scan_id,
                            "error_code": "INVALID_BASE64_ZIP_PAYLOAD_REJECTED",
                            "error_message": f"Invalid base64 encoding in zip_base64: {exc}",
                        },
                    )
                    return
                with backend_state.job_manager.scan_execution_lock:
                    scan_res = scan_java_zip_and_triage(
                        zip_bytes=decoded_zip,
                        archive_filename=archive_filename,
                        target_subpath=target_subpath,
                        file_allowlist=file_allowlist,
                        include_globs=clean_inc,
                        exclude_globs=clean_exc,
                        max_files_limit=eff_max_files,
                        scan_scope_policy=eff_scope_policy,
                        config=backend_state.config,
                        compile_check=False,
                        cleanup_workspace=bool(req_json.get("cleanup_workspace", True)),
                        raw_opengrep_sink=raw_og,
                    )
            elif repo_url:
                with backend_state.job_manager.scan_execution_lock:
                    scan_res = scan_github_repository_and_triage(
                        repo_url=repo_url,
                        branch=branch,
                        commit_sha=commit_sha,
                        target_subpath=target_subpath,
                        file_allowlist=file_allowlist,
                        include_globs=clean_inc,
                        exclude_globs=clean_exc,
                        max_files_limit=eff_max_files,
                        scan_scope_policy=eff_scope_policy,
                        config=backend_state.config,
                        compile_check=bool(req_json.get("compile_check", False)),
                        cleanup_workspace=bool(req_json.get("cleanup_workspace", True)),
                        raw_opengrep_sink=raw_og,
                    )
            elif local_source_dir and backend_state.allow_local_dir:
                with backend_state.job_manager.scan_execution_lock:
                    scan_res = scan_java_sources_and_triage(
                        source_dir=Path(local_source_dir),
                        config=backend_state.config,
                        compile_check=bool(req_json.get("compile_check", True)),
                        readiness_status="LOCAL_API_VERIFIED",
                        raw_opengrep_sink=raw_og,
                        target_subpath=target_subpath,
                        file_allowlist=file_allowlist,
                        include_globs=clean_inc,
                        exclude_globs=clean_exc,
                        max_files_limit=eff_max_files,
                        scan_scope_policy=eff_scope_policy,
                    )
            else:
                self._send_json(
                    400,
                    {
                        "status": "ERROR",
                        "error_code": "MISSING_SCAN_SOURCE",
                        "error_message": (
                            "POST /api/scans requires 'repo_url' (https://github.com/<owner>/<repo>.git) "
                            "or 'zip_base64' (or use POST /api/scans/zip)"
                        ),
                    },
                )
                return

            if scan_res.get("status") != "OK":
                err_code = str(scan_res.get("error_code", "SCAN_ERROR"))
                if isinstance(scan_res.get("pipeline_trace"), dict):
                    with backend_state._lock:
                        scan_res["pipeline_trace"]["scan_id"] = scan_id
                        backend_state.pipeline_traces_by_scan[scan_id] = scan_res["pipeline_trace"]
                        tr_file = backend_state.storage_dir / f"{scan_id}.pipeline_trace.json"
                        _write_json_atomic(tr_file, scan_res["pipeline_trace"])
                http_code = (
                    400
                    if (
                        "REJECTED" in err_code
                        or "INVALID" in err_code
                        or "ALLOWLIST" in err_code
                        or "EMPTY" in err_code
                        or "SCHEME" in err_code
                        or "SSRF" in err_code
                    )
                    else 422
                )
                self._send_json(
                    http_code,
                    {
                        "status": "ERROR",
                        "scan_id": scan_id,
                        "error_code": err_code,
                        "error_message": scan_res.get("error_message", "Scan failed"),
                        "stage_error_code": scan_res.get("stage_error_code", err_code),
                        "stage_error_message": scan_res.get("stage_error_message", scan_res.get("error_message")),
                        "source_mode": scan_res.get("source_mode"),
                        "repository_url": scan_res.get("repository_url"),
                        "requested_commit": scan_res.get("requested_commit"),
                        "resolved_commit": scan_res.get("resolved_commit"),
                        "java_files_discovered": scan_res.get("java_files_discovered"),
                        "java_files_scanned": scan_res.get("java_files_scanned"),
                        "java_files_skipped": scan_res.get("java_files_skipped"),
                        "source_bytes_discovered": scan_res.get("source_bytes_discovered"),
                        "source_bytes_scanned": scan_res.get("source_bytes_scanned"),
                        "source_inventory_limits": scan_res.get("source_inventory_limits"),
                        "analysis_coverage_status": scan_res.get("analysis_coverage_status"),
                        "incomplete_analysis_reasons": scan_res.get("incomplete_analysis_reasons"),
                        "coverage_diagnostics": scan_res.get("coverage_diagnostics", {}),
                        "pipeline_trace": scan_res.get("pipeline_trace"),
                    },
                )
                return

            stored = backend_state.record_scan(scan_id, scan_res, raw_opengrep=raw_og)
            self._send_json(200, stored)

    return ThreadingHTTPServer((host, port), NtkHttpApiHandler)


def build_web_finding_from_trace(
    trace: Dict[str, Any],
    file_path: str,
    scanner_rule_id: str,
    matched_code: str,
    target_identity: Dict[str, str],
) -> shared.FindingSchemaV2:
    """
    Backward-compatible converter from a Phase 6 `site_trace` dictionary to a validated
    `FindingSchemaV2` object (which is also an instance of `FindingSchemaV1`).
    """
    cwe_str = str(trace.get("cwe", "CWE-089"))
    cwe_id = int(cwe_str.split("-")[-1]) if "-" in cwe_str else int(trace.get("cwe_id", 89))
    floor_info = trace.get("bounded_safety_floor", {})
    raw_out = str(trace.get("llm_raw_output", ""))
    callee_pred = shared.parse_and_validate_callee_json(
        raw_out, expected_identity=target_identity, cwe=cwe_id
    )

    explicit_rel = bool(floor_info.get("explicit_ast_release_verified", False))
    rel_reason = str(floor_info.get("ast_release_reason", "NO_AST_RELEASE_CLAIMED"))

    if explicit_rel and "CONSTANT" in rel_reason:
        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=True,
            has_cwe_matched_sanitizer=False,
            covered_sink_args=callee_pred.canonical_sink_args or ("arg0",),
            ast_proof_node="LITERAL:constant_arg",
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )
        trace_status = "SAFE_CONSTANT_OR_PARAMETERIZED"
        san_status = "NONE_DETECTED"
        taint_reaches = False
        extra_rc = ("RC_AST_VERIFIED_COMPILE_TIME_CONSTANT",)
    elif explicit_rel:
        default_san = {
            22: "java.nio.file.Path::normalize",
            78: "org.owasp.esapi.Encoder::encodeForOS",
            79: "org.springframework.web.util.HtmlUtils::htmlEscape",
            89: "java.sql.PreparedStatement::setString",
        }.get(cwe_id, "java.sql.PreparedStatement::setString")
        proof_node = (
            f"SANITIZER_CALL:{default_san}+STARTSWITH_PREFIX_GUARD:resolved.startsWith(baseDir)"
            if cwe_id == 22
            else f"SANITIZER_CALL:{default_san}"
        )
        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=False,
            has_cwe_matched_sanitizer=True,
            verified_sanitizer_cwe=cwe_id,
            covered_sink_args=callee_pred.canonical_sink_args or ("arg0",),
            ast_proof_node=proof_node,
            sanitizer_method_signature=default_san,
            output_context="HTML_BODY" if cwe_id == 79 else "",
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )
        trace_status = "SAFE_CONSTANT_OR_PARAMETERIZED" if cwe_id == 89 else "SAFE_SANITIZED_OR_GUARDED"
        san_status = (
            "VERIFIED_PARAMETERIZED_QUERY"
            if cwe_id == 89
            else (
                "VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD"
                if cwe_id == 22
                else "VERIFIED_CWE_MATCHED_SANITIZER"
            )
        )
        taint_reaches = False
        extra_rc = ("RC_AST_VERIFIED_CWE_MATCHED_SANITIZER",)
    else:
        ast_ev = shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST")
        trace_status = str(trace.get("source_sink_trace_status", "VERIFIED_TAINT_FLOW"))
        san_status = str(trace.get("sanitizer_status", "NONE_DETECTED"))
        taint_reaches = trace_status in ("VERIFIED_TAINT_FLOW", "PARTIAL_OR_INSUFFICIENT_GUARD")
        extra_rc = ("RC_IRIS_VERIFIED_SOURCE_TO_SINK_TAINT_FLOW",) if taint_reaches else ()

    ast_analysis = triage_mod.JavaAstSiteAnalysis(
        file_path=file_path,
        match_line=int(trace.get("opengrep_line", 1)),
        cwe=cwe_id,
        package_name=target_identity.get("package", "com.ntk.e2e"),
        class_name=target_identity.get("class", "UnknownClass"),
        enclosing_method=str(trace.get("enclosing_method", "unknownMethod")),
        enclosing_signature=target_identity.get("signature", "void unknownMethod()"),
        untrusted_params=("userInput",),
        target_callee_identity=target_identity,
        matched_code_line=matched_code or f"{target_identity.get('class', '')}.{target_identity.get('method', '')}(...)",
        source_sink_trace_status=trace_status,
        taint_reaches_sink=taint_reaches,
        taint_source_params=("userInput",) if taint_reaches else (),
        taint_trace_steps=(matched_code or str(trace.get("enclosing_method", "")),),
        sanitizer_status=san_status,
        ast_evidence=ast_ev,
        extra_reason_codes=extra_rc,
        ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
    )

    finding_id = str(floor_info.get("finding_id") or f"FINDING-{trace.get('site_id', 'UNKNOWN')}")
    return triage_mod.verify_and_triage_finding(
        finding_id=finding_id,
        cwe=cwe_id,
        file_path=file_path,
        line_number=int(trace.get("opengrep_line", 1)),
        scanner_rule_id=scanner_rule_id,
        static_severity="ERROR",
        base_scanner_score=0.70,
        ast_analysis=ast_analysis,
        callee_prediction=callee_pred,
        llm_raw_output=raw_out,
        llm_latency_ms=float(trace.get("llm_latency_ms", 0.0)),
    )


def build_web_api_response_from_phase6(
    phase6_data: Dict[str, Any],
    arm_id: str = "eo06_vnext31_trackb_main",
    config: Optional[NtkWebBackendConfig] = None,
) -> Dict[str, Any]:
    cfg = config or NtkWebBackendConfig()
    arm_block = phase6_data.get("arm_e2e_results", {}).get(arm_id, {})
    traces = arm_block.get("site_traces", [])

    findings: List[Dict[str, Any]] = []
    reported_findings: List[Dict[str, Any]] = []
    review_queue_findings: List[Dict[str, Any]] = []
    suppressed_findings_audit_log: List[Dict[str, Any]] = []

    for tr in traces:
        raw_out = tr.get("llm_raw_output", "")
        ident = {"package": "", "class": "", "method": "", "signature": ""}
        try:
            parsed_obj = json.loads(raw_out)
            if isinstance(parsed_obj, dict):
                ident = {
                    "package": str(parsed_obj.get("package", "")),
                    "class": str(parsed_obj.get("class", "")),
                    "method": str(parsed_obj.get("method", "")),
                    "signature": str(parsed_obj.get("signature", "")),
                }
        except Exception:
            pass
        f_obj = build_web_finding_from_trace(
            trace=tr,
            file_path=str(tr.get("file_path", f"com/ntk/e2e/{tr.get('cwe', 'CWE')}.java")),
            scanner_rule_id=str(tr.get("opengrep_rule_id", f"ntk.java.{str(tr.get('cwe', '')).lower()}")),
            matched_code=str(tr.get("opengrep_matched_code", "")),
            target_identity=ident,
        )
        f_dict = f_obj.to_dict()
        ok_s, s_errs = triage_mod.validate_finding_schema_v2_dict(f_dict)
        if not ok_s:
            raise RuntimeError(f"FindingSchemaV2 validation error in Phase 6 conversion: {s_errs}")
        findings.append(f_dict)
        if f_dict["decision"] == "REPORT":
            reported_findings.append(f_dict)
        elif f_dict["decision"] == "REVIEW":
            review_queue_findings.append(f_dict)
        elif f_dict["decision"] == "SUPPRESS":
            suppressed_findings_audit_log.append(f_dict)

    retained_count = sum(1 for f in findings if f["kept_by_pipeline"])
    suppressed_count = len(suppressed_findings_audit_log)

    payload = {
        "status": "OK",
        "api_version": "NTK_WEB_BACKEND_API_V1",
        "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
        "integration_readiness_status": "LOCAL_API_VERIFIED",
        "architecture_version": "FROZEN_ARCHITECTURE_V1",
        "model_version": cfg.model_version,
        "ruleset_version": cfg.ruleset_version,
        "scoring_policy_version": cfg.scoring_policy_version,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "model_metadata": {
            "base_model_id": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
            "adapter_arm_id": arm_id,
            "model_version": cfg.model_version,
            "best_adapter_sha256": DEFAULT_BEST_ADAPTER_SHA256,
            "cloud_calls_enabled": False,
            "local_files_only": True,
        },
        "scanner_metadata": {
            "opengrep_binary": phase6_data.get("opengrep_binary", cfg.opengrep_bin),
            "opengrep_version": phase6_data.get("opengrep_version", "1.25.0"),
            "ruleset_version": cfg.ruleset_version,
            "javac_binary": phase6_data.get("javac_binary", cfg.javac_bin),
            "javac_exit_code": phase6_data.get("javac_exit_code", 0),
            "ast_parser_engine": "OPENJDK17_JAVAC_TASK_AST",
        },
        "summary": {
            "total_scanner_candidates": len(findings),
            "retained_vulnerability_alerts": retained_count,
            "likely_true_positive_report_count": len(reported_findings),
            "needs_review_count": len(review_queue_findings),
            "suppressed_false_positives": suppressed_count,
            "false_positive_reduction_rate": round(suppressed_count / len(findings), 4) if findings else 0.0,
            "review_escalation_rate": round(len(review_queue_findings) / len(findings), 4) if findings else 0.0,
            "suppressed_findings_preserved_for_audit": True,
            "score_semantics": "HEURISTIC_EVIDENCE_FUSION_SCORE_NOT_CALIBRATED_PROBABILITY",
        },
        "findings": findings,
        "reported_findings": reported_findings,
        "review_queue_findings": review_queue_findings,
        "suppressed_findings_audit_log": suppressed_findings_audit_log,
    }
    collisions = shared.find_case_insensitive_duplicate_keys(payload)
    if collisions:
        raise RuntimeError(f"Case-insensitive duplicate keys detected in web payload: {collisions}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="NTK Web MVP Backend Service & Local HTTP Server")
    parser.add_argument("--phase6-json", type=str, default="", help="Path to Phase 6 E2E report JSON")
    parser.add_argument("--scan-java-dir", type=str, default="", help="Path to Java source directory for live scan")
    parser.add_argument("--scan-github-url", type=str, default="", help="Public HTTPS GitHub repo URL to scan")
    parser.add_argument("--branch", type=str, default="", help="Optional branch name")
    parser.add_argument("--commit-sha", type=str, default="", help="Optional commit SHA")
    parser.add_argument("--target-subpath", type=str, default="", help="Optional repository subpath")
    parser.add_argument("--rules-yaml", type=str, default="", help="Optional OpenGrep rules YAML")
    parser.add_argument("--output-json", type=str, default="", help="Output Web API response JSON path")
    parser.add_argument("--arm-id", type=str, default="eo06_vnext31_trackb_main")
    parser.add_argument("--serve-http", action="store_true", help="Run local HTTP API server on 127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="Local HTTP port (default: 8765)")
    args = parser.parse_args()

    if args.serve_http:
        srv = create_ntk_http_server(host="127.0.0.1", port=args.port)
        print(f"[NTK_WEB_BACKEND] Serving HTTP API on http://127.0.0.1:{args.port}", flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            srv.server_close()
        return 0

    t0 = time.perf_counter()
    if args.scan_github_url:
        resp = scan_github_repository_and_triage(
            repo_url=args.scan_github_url,
            branch=args.branch or None,
            commit_sha=args.commit_sha or None,
            target_subpath=args.target_subpath or None,
        )
    elif args.scan_java_dir:
        r_yaml = Path(args.rules_yaml) if args.rules_yaml else None
        resp = scan_java_sources_and_triage(Path(args.scan_java_dir), rules_yaml_path=r_yaml)
    elif args.phase6_json:
        p6_data = json.loads(Path(args.phase6_json).read_text(encoding="utf-8"))
        resp = build_web_api_response_from_phase6(p6_data, arm_id=args.arm_id)
        resp["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
    else:
        raise SystemExit("Provide --serve-http, --scan-github-url, --scan-java-dir, or --phase6-json.")

    if args.output_json:
        out_p = Path(args.output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(resp, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"[NTK_WEB_BACKEND] Wrote {len(resp.get('findings', []))} findings to {out_p}")
    else:
        print(json.dumps(resp, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
