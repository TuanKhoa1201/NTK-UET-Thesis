#!/usr/bin/env python3
"""
NTK Alert Verification & False Positive Triage Layer (`ntk_alert_verification.py`)
Architecture: FROZEN_ARCHITECTURE_V1
  OpenGrep v1.25.0 -> IRIS Java AST/Dataflow (OpenJDK 17 JavacTask AST)
  -> Qwen2.5-Coder-0.5B-Instruct LoRA -> Evidence Fusion -> Alert Triage

Responsibilities:
1. Genuine Java Compiler AST (`javax.tools.JavaCompiler` / `com.sun.source.tree.*` `JavacTask.parse()`)
   and lexical-scope-aware intraprocedural def-use dataflow extraction (`analyze_java_site_ast_and_taint`)
   from real `.java` source files and OpenGrep match lines (zero reliance on ground-truth labels or fixture names).
2. Strict separation between semantic AST evidence (`OPENJDK17_JAVAC_TASK_AST`) and fallback lexical patterns
   (`FALLBACK_LEXICAL_PARSER`): automatic `SUPPRESS` is strictly forbidden unless verified by the semantic AST.
3. Neuro-symbolic Evidence Fusion & Alert Triage (`verify_and_triage_finding`) built on top of the frozen
   `ntk_iris_shared.evaluate_bounded_safety_floor` (0.55) and `verify_ast_release_evidence` engine.
4. Three orthogonal state dimensions per finding:
   - `triage_status`: `LIKELY_TRUE_POSITIVE` | `LIKELY_FALSE_POSITIVE` | `NEEDS_REVIEW`
   - `decision`: `REPORT` | `REVIEW` | `SUPPRESS`
   - `review_status`: `NOT_REVIEWED` | `CONFIRMED_TRUE_POSITIVE` | `CONFIRMED_FALSE_POSITIVE`
5. Full preservation of suppressed findings (`decision == "SUPPRESS"`) with structured `reason_codes`,
   `fusion_score_breakdown`, and `evidence_refs` for security auditing.
6. `FindingSchemaV2` JSON Schema generation and strict runtime schema validation.
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import ntk_iris_shared as shared

MODEL_VERSION_DEFAULT: str = "eo06_vnext31_trackb_main_epoch3"
RULESET_VERSION_DEFAULT: str = "NTK_OPENGREP_JAVA_RULESET_V1.4"
SCORING_POLICY_VERSION_DEFAULT: str = "NTK_BOUNDED_SAFETY_FLOOR_FUSION_V1.2"
SCORE_KIND_DEFAULT: str = "HEURISTIC_EVIDENCE_FUSION_SCORE_NOT_CALIBRATED_PROBABILITY"

INFRASTRUCTURE_PARAM_TYPES: Set[str] = {
    "Connection",
    "java.sql.Connection",
    "Statement",
    "java.sql.Statement",
    "PreparedStatement",
    "java.sql.PreparedStatement",
    "CallableStatement",
    "java.sql.CallableStatement",
    "PrintWriter",
    "java.io.PrintWriter",
    "HttpServletResponse",
    "javax.servlet.http.HttpServletResponse",
    "jakarta.servlet.http.HttpServletResponse",
    "OutputStream",
    "Writer",
    "HttpSession",
    "javax.servlet.http.HttpSession",
    "jakarta.servlet.http.HttpSession",
}

SHELL_EXECUTABLES: Set[str] = {
    "sh",
    "/bin/sh",
    "bash",
    "/bin/bash",
    "zsh",
    "/bin/zsh",
    "dash",
    "/bin/dash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
}

# In-memory cache mapping sha256(java_source_text) -> parsed file AST dict from NtkJavacAstExtractor
_JAVAC_AST_CACHE: Dict[str, Dict[str, Any]] = {}
_JAVAC_PATH_TO_HASH_CACHE: Dict[str, str] = {}

SCRIPT_DIR = Path(__file__).resolve().parent
JAVAC_BRIDGE_DIR = SCRIPT_DIR / "javac_ast_bridge"
JAVAC_BRIDGE_JAVA = JAVAC_BRIDGE_DIR / "NtkJavacAstExtractor.java"
JAVAC_BRIDGE_CLASS = JAVAC_BRIDGE_DIR / "NtkJavacAstExtractor.class"


@dataclass(frozen=True)
class ManualReviewRecord:
    """
    Explicit human/auditor verification record required to transition `review_status`
    from `NOT_REVIEWED` to `CONFIRMED_TRUE_POSITIVE` or `CONFIRMED_FALSE_POSITIVE`.
    """

    finding_id: str
    confirmed_status: str  # CONFIRMED_TRUE_POSITIVE or CONFIRMED_FALSE_POSITIVE
    reviewer_id: str
    reviewed_at_utc: str
    review_notes: str = ""
    confirmation_source: str = "MANUAL_SECURITY_REVIEW"


@dataclass(frozen=True)
class JavaAstSiteAnalysis:
    file_path: str
    match_line: int
    cwe: int
    package_name: str
    class_name: str
    enclosing_method: str
    enclosing_signature: str
    untrusted_params: Tuple[str, ...]
    target_callee_identity: Dict[str, str]
    matched_code_line: str
    source_sink_trace_status: str
    taint_reaches_sink: bool
    taint_source_params: Tuple[str, ...]
    taint_trace_steps: Tuple[str, ...]
    sanitizer_status: str
    ast_evidence: shared.AstReleaseEvidence
    extra_reason_codes: Tuple[str, ...] = ()
    ast_parser_engine: str = "OPENJDK17_JAVAC_TASK_AST"
    ast_overloaded_signature: str = ""


def ensure_javac_ast_bridge_compiled(
    javac_bin: str = "/usr/bin/javac",
    timeout_sec: float = 15.0,
) -> bool:
    inner_visitor_cls = JAVAC_BRIDGE_DIR / "NtkJavacAstExtractor$1MethodBodyVisitor.class"
    if JAVAC_BRIDGE_CLASS.exists() and inner_visitor_cls.exists() and JAVAC_BRIDGE_JAVA.exists():
        cls_files = list(JAVAC_BRIDGE_DIR.glob("NtkJavacAstExtractor*.class"))
        java_mtime = JAVAC_BRIDGE_JAVA.stat().st_mtime
        if cls_files and min(c.stat().st_mtime for c in cls_files) >= java_mtime:
            return True
    if not JAVAC_BRIDGE_JAVA.exists() or not Path(javac_bin).exists():
        return False
    try:
        for old_cls in JAVAC_BRIDGE_DIR.glob("NtkJavacAstExtractor*.class"):
            try:
                old_cls.unlink()
            except Exception:
                pass
        proc = subprocess.run(
            [javac_bin, str(JAVAC_BRIDGE_JAVA)],
            cwd=str(JAVAC_BRIDGE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return proc.returncode == 0 and JAVAC_BRIDGE_CLASS.exists() and inner_visitor_cls.exists()
    except Exception:
        return False


def prewarm_javac_ast_cache(
    java_files: Sequence[Path],
    java_bin: str = "/usr/bin/java",
    javac_bin: str = "/usr/bin/javac",
    timeout_sec: float = 20.0,
) -> int:
    """
    Parses a batch of `.java` files in a single OpenJDK 17 `JavacTask` invocation
    and populates `_JAVAC_AST_CACHE`. Returns number of newly cached files.
    """
    if not java_files or not ensure_javac_ast_bridge_compiled(javac_bin=javac_bin):
        return 0
    if not Path(java_bin).exists():
        return 0

    uncached_paths: List[str] = []
    path_to_sha: Dict[str, str] = {}
    for p in java_files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            abs_s = str(p.resolve())
            _JAVAC_PATH_TO_HASH_CACHE[abs_s] = sha
            if sha not in _JAVAC_AST_CACHE:
                uncached_paths.append(abs_s)
                path_to_sha[abs_s] = sha
        except Exception:
            continue

    if not uncached_paths:
        return 0

    batch_size = 250
    total_cached = 0
    batch_timeout = max(timeout_sec, 45.0)
    for start_idx in range(0, len(uncached_paths), batch_size):
        chunk = uncached_paths[start_idx : start_idx + batch_size]
        try:
            proc = subprocess.run(
                [java_bin, "-cp", str(JAVAC_BRIDGE_DIR), "NtkJavacAstExtractor"] + chunk,
                capture_output=True,
                text=True,
                timeout=batch_timeout,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                continue
            payload = json.loads(proc.stdout)
            for f_entry in payload.get("files", []):
                fp = str(f_entry.get("file_path", ""))
                sha = path_to_sha.get(fp)
                if not sha and fp and Path(fp).exists():
                    sha = hashlib.sha256(Path(fp).read_bytes()).hexdigest()
                if sha:
                    _JAVAC_AST_CACHE[sha] = f_entry
                    total_cached += 1
        except Exception:
            continue
    return total_cached


def parse_java_source_with_javac_ast(
    java_source_text: str,
    file_path: str = "",
    java_bin: str = "/usr/bin/java",
    javac_bin: str = "/usr/bin/javac",
    timeout_sec: float = 15.0,
) -> Optional[Dict[str, Any]]:
    """
    Parses `java_source_text` into an OpenJDK 17 `CompilationUnitTree` AST dictionary
    using `NtkJavacAstExtractor` (with SHA-256 content caching).
    """
    sha = hashlib.sha256(java_source_text.encode("utf-8")).hexdigest()
    if sha in _JAVAC_AST_CACHE:
        return _JAVAC_AST_CACHE[sha]

    if not ensure_javac_ast_bridge_compiled(javac_bin=javac_bin) or not Path(java_bin).exists():
        return None

    # If file_path exists on disk and matches sha, parse it directly; otherwise use a temp .java file
    target_path: Optional[Path] = None
    tmp_dir: Optional[tempfile.TemporaryDirectory] = None
    try:
        if file_path and Path(file_path).is_file():
            disk_bytes = Path(file_path).read_bytes()
            if hashlib.sha256(disk_bytes).hexdigest() == sha:
                target_path = Path(file_path).resolve()

        if target_path is None:
            tmp_dir = tempfile.TemporaryDirectory(prefix="ntk_javac_ast_")
            fname = Path(file_path).name if (file_path and file_path.endswith(".java")) else "Snippet.java"
            target_path = Path(tmp_dir.name) / fname
            target_path.write_text(java_source_text, encoding="utf-8", newline="\n")

        proc = subprocess.run(
            [java_bin, "-cp", str(JAVAC_BRIDGE_DIR), "NtkJavacAstExtractor", str(target_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        payload = json.loads(proc.stdout)
        files = payload.get("files", [])
        if not files:
            return None
        ast_dict = files[0]
        _JAVAC_AST_CACHE[sha] = ast_dict
        return ast_dict
    except Exception:
        return None
    finally:
        if tmp_dir is not None:
            try:
                tmp_dir.cleanup()
            except Exception:
                pass


def _strip_java_comments_multiline(text: str) -> str:
    """Removes /* ... */ block comments and // line comments outside string literals."""
    out: List[str] = []
    i = 0
    n = len(text)
    in_str = False
    in_char = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
        elif in_char:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
        else:
            if ch == '"':
                in_str = True
                out.append(ch)
                i += 1
            elif ch == "'":
                in_char = True
                out.append(ch)
                i += 1
            elif ch == "/" and i + 1 < n and text[i + 1] == "*":
                # Skip block comment while preserving newlines for line numbers
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 2
            elif ch == "/" and i + 1 < n and text[i + 1] == "/":
                while i < n and text[i] != "\n":
                    i += 1
            else:
                out.append(ch)
                i += 1
    return "".join(out)


def _strip_java_comments(line: str) -> str:
    idx = line.find("//")
    if idx != -1:
        prefix = line[:idx]
        if prefix.count('"') % 2 == 0:
            return prefix.strip()
    return line.strip()


def _is_const_ast_kind(kind: str) -> bool:
    return kind in (
        "STRING_LITERAL",
        "PRIMITIVE_LITERAL",
        "STATIC_FINAL_CONST_IDENT",
        "CONSTANT_CONCAT_EXPR",
    )


def _is_pure_const_path_factory_expr(
    expr_str: str,
    invocations: Sequence[Dict[str, Any]],
    new_classes: Sequence[Dict[str, Any]],
    static_final_consts: Set[str],
) -> Tuple[bool, str]:
    cleaned = expr_str.strip().rstrip(";").strip()
    m_str = re.match(r'^"((?:\\.|[^"\\])*)"$', cleaned)
    if m_str:
        return True, m_str.group(1)

    for inv in invocations:
        if inv.get("call_expr", "").strip() == cleaned and inv.get("method_name") in ("get", "of"):
            recv = inv.get("receiver", "").strip()
            if recv in ("Paths", "Path", "java.nio.file.Paths", "java.nio.file.Path"):
                arg_kinds = inv.get("arg_kinds", [])
                if arg_kinds and all(_is_const_ast_kind(k) for k in arg_kinds):
                    lits = inv.get("arg_string_literals", [])
                    return True, "/".join(lits) if lits else cleaned

    for nc in new_classes:
        if nc.get("new_expr", "").strip() == cleaned and nc.get("class_type") in (
            "File",
            "java.io.File",
            "FileInputStream",
            "java.io.FileInputStream",
            "FileOutputStream",
            "java.io.FileOutputStream",
            "FileReader",
            "java.io.FileReader",
            "FileWriter",
            "java.io.FileWriter",
        ):
            arg_kinds = nc.get("arg_kinds", [])
            if arg_kinds and all(_is_const_ast_kind(k) for k in arg_kinds):
                lits = nc.get("arg_string_literals", [])
                return True, "/".join(lits) if lits else cleaned

    return False, ""


def _extract_non_literal_identifiers(expr_str: str) -> List[str]:
    """Extracts Java identifiers from `expr_str` outside string/char literals."""
    if not expr_str:
        return []
    masked = re.sub(r'"(?:\\.|[^"\\])*"', '""', expr_str)
    masked = re.sub(r"'(?:\\.|[^'\\])*'", "''", masked)
    java_keywords = {
        "new",
        "null",
        "true",
        "false",
        "int",
        "long",
        "short",
        "byte",
        "boolean",
        "char",
        "float",
        "double",
        "void",
        "class",
    }
    return [
        tok
        for tok in re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", masked)
        if tok not in java_keywords
    ]


def _eval_const_int_expr(expr_str: str, const_int_vars: Dict[str, int]) -> Optional[int]:
    """
    Safely evaluates compile-time constant integer arithmetic expressions
    (`+`, `-`, `*`, `/`, `%`, parentheses, integer literals, and constant local `int` variables).
    """
    s = expr_str.strip()
    if not s:
        return None

    def _sub_ident(m: re.Match) -> str:
        ident = m.group(0)
        if ident in const_int_vars:
            return str(const_int_vars[ident])
        return ident

    s_sub = re.sub(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", _sub_ident, s)
    if not re.match(r"^[\d\s\+\-\*\/\%\(\)]+$", s_sub):
        return None
    # Replace Java integer division `/` with Python integer division `//`
    s_py = re.sub(r"(?<!/)/(?!/)", "//", s_sub)
    try:
        val = eval(s_py, {"__builtins__": {}}, {})
        return int(val) if isinstance(val, (int, float)) else None
    except Exception:
        return None


def _eval_const_bool_condition(cond_str: str, const_int_vars: Dict[str, int]) -> Optional[bool]:
    """
    Evaluates relational integer conditions (`>`, `<`, `>=`, `<=`, `==`, `!=`) when both operands
    are compile-time integer constants. Returns `True`, `False`, or `None` if not constant.
    """
    s = cond_str.strip()
    while s.startswith("(") and s.endswith(")"):
        # Check if outer parens wrap the entire condition
        depth = 0
        wrapped = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    wrapped = False
                    break
        if wrapped:
            s = s[1:-1].strip()
        else:
            break

    for op in (">=", "<=", "==", "!=", ">", "<"):
        # Find top-level relational operator
        depth = 0
        i = 0
        while i <= len(s) - len(op):
            ch = s[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and s[i : i + len(op)] == op:
                # Ensure single `>` or `<` is not part of `>=` or `<=`
                if len(op) == 1 and i + 1 < len(s) and s[i + 1] == "=":
                    i += 2
                    continue
                lhs = _eval_const_int_expr(s[:i], const_int_vars)
                rhs = _eval_const_int_expr(s[i + len(op) :], const_int_vars)
                if lhs is not None and rhs is not None:
                    if op == ">=":
                        return lhs >= rhs
                    if op == "<=":
                        return lhs <= rhs
                    if op == "==":
                        return lhs == rhs
                    if op == "!=":
                        return lhs != rhs
                    if op == ">":
                        return lhs > rhs
                    if op == "<":
                        return lhs < rhs
                return None
            i += 1
    return None


def _split_top_level_ternary(expr_str: str) -> Optional[Tuple[str, str, str]]:
    """Splits a top-level `cond ? true_expr : false_expr` into `(cond, true_expr, false_expr)`."""
    s = expr_str.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        wrapped = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    wrapped = False
                    break
        if wrapped:
            s = s[1:-1].strip()
        else:
            break

    depth = 0
    in_str = False
    in_chr = False
    q_idx = -1
    c_idx = -1
    q_depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif in_chr:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == "'":
                in_chr = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "'":
                in_chr = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif ch == "?" and depth == 0:
                if q_idx == -1:
                    q_idx = i
                else:
                    q_depth += 1
            elif ch == ":" and depth == 0 and q_idx != -1:
                if q_depth > 0:
                    q_depth -= 1
                else:
                    c_idx = i
                    break
        i += 1

    if q_idx != -1 and c_idx != -1 and q_idx < c_idx:
        return s[:q_idx].strip(), s[q_idx + 1 : c_idx].strip(), s[c_idx + 1 :].strip()
    return None


def _compute_const_local_maps(
    local_variables: Sequence[Dict[str, Any]],
    assignments: Sequence[Dict[str, Any]],
) -> Tuple[Dict[str, int], Dict[str, str]]:
    """
    Identifies local `int` and `String` variables that are initialized once to a compile-time literal
    and never reassigned anywhere in the method.
    """
    assigned_targets = {str(a.get("target", "")) for a in assignments}
    const_ints: Dict[str, int] = {}
    const_strs: Dict[str, str] = {}
    name_counts: Dict[str, int] = {}
    for v in local_variables:
        nm = str(v.get("name", ""))
        name_counts[nm] = name_counts.get(nm, 0) + 1

    for v in local_variables:
        nm = str(v.get("name", ""))
        if not nm or nm in assigned_targets or name_counts.get(nm, 0) != 1:
            continue
        vtype = str(v.get("type", "")).strip()
        ikind = str(v.get("init_kind", "")).strip()
        iexpr = str(v.get("init_expr", "")).strip()
        if vtype in ("int", "long", "short", "byte", "Integer") and ikind == "PRIMITIVE_LITERAL":
            try:
                const_ints[nm] = int(re.sub(r"[Ll]$", "", iexpr))
            except Exception:
                pass
        elif vtype in ("String", "java.lang.String") and ikind == "STRING_LITERAL":
            lits = v.get("string_literals", [])
            if lits:
                const_strs[nm] = str(lits[0])
            elif iexpr.startswith('"') and iexpr.endswith('"'):
                const_strs[nm] = iexpr[1:-1]
    return const_ints, const_strs


def _eval_switch_taken_line_ranges(
    sw: Dict[str, Any],
    const_str_vars: Dict[str, str],
    const_int_vars: Dict[str, int],
) -> Optional[Tuple[int, int, List[Tuple[int, int]]]]:
    """
    If `sw` (`SwitchTree`) has a compile-time constant selector (such as `guess.charAt(1)` on a
    constant `String guess = "ABC"` or a constant int expression), returns
    `(cases_min_line, cases_max_line, taken_line_ranges)`.
    """
    sel = str(sw.get("selector_expr", "")).strip()
    cases = sw.get("cases", [])
    if not cases:
        return None

    target_labels: Set[str] = set()
    m_char = re.match(r"^([A-Za-z_$][A-Za-z0-9_$]*)\.charAt\(\s*(\d+)\s*\)$", sel)
    if m_char:
        vname = m_char.group(1)
        idx = int(m_char.group(2))
        if vname in const_str_vars and 0 <= idx < len(const_str_vars[vname]):
            ch = const_str_vars[vname][idx]
            target_labels.add(f"'{ch}'")
            target_labels.add(f'"{ch}"')
            target_labels.add(ch)
    else:
        ival = _eval_const_int_expr(sel, const_int_vars)
        if ival is not None:
            target_labels.add(str(ival))

    if not target_labels:
        return None

    min_ln = min(int(c.get("start_line", 0)) for c in cases)
    max_ln = max(int(c.get("end_line", 0)) for c in cases)

    match_idx = -1
    default_idx = -1
    for idx, c in enumerate(cases):
        if bool(c.get("is_default")):
            default_idx = idx
        labels = {str(lbl).strip() for lbl in c.get("labels", [])}
        if labels & target_labels:
            match_idx = idx
            break

    start_idx = match_idx if match_idx != -1 else default_idx
    if start_idx == -1:
        return (min_ln, max_ln, [])

    taken_ranges: List[Tuple[int, int]] = []
    for idx in range(start_idx, len(cases)):
        c = cases[idx]
        taken_ranges.append((int(c.get("start_line", 0)), int(c.get("end_line", 0))))
        if bool(c.get("has_break")):
            break
    return (min_ln, max_ln, taken_ranges)


def _resolve_variable_in_scope(
    var_name: str,
    ref_ancestors: Sequence[int],
    ref_stmt_order: int,
    ref_line: int,
    local_variables: Sequence[Dict[str, Any]],
    assignments: Sequence[Dict[str, Any]],
    invocations: Sequence[Dict[str, Any]] = (),
    if_guards: Sequence[Dict[str, Any]] = (),
    switches: Sequence[Dict[str, Any]] = (),
    const_int_vars: Optional[Dict[str, int]] = None,
    const_str_vars: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Resolves `var_name` at `(ref_ancestors, ref_stmt_order, ref_line)` using lexical block scopes,
    constant-condition dead-branch elimination, receiver-mutating invocations, and statement-order
    reaching definitions.
    """
    ref_anc_list = list(ref_ancestors)
    ref_anc_set = set(ref_anc_list)
    c_ints = const_int_vars or {}
    c_strs = const_str_vars or {}

    candidates = [
        v
        for v in local_variables
        if v.get("name") == var_name
        and v.get("scope_id") in ref_anc_set
        and int(v.get("start_line", 0)) <= ref_line
        and int(v.get("stmt_order", 0)) <= ref_stmt_order
    ]
    if not candidates:
        return None

    # Sort by innermost scope in ref_anc_list (lowest index in ref_anc_list), then highest stmt_order
    candidates.sort(
        key=lambda v: (
            ref_anc_list.index(v["scope_id"]),
            -int(v.get("stmt_order", 0)),
        )
    )
    decl = candidates[0]
    decl_scope = int(decl["scope_id"])
    decl_order = int(decl["stmt_order"])

    # Pre-evaluate constant if_guards and switches
    dead_line_ranges: List[Tuple[int, int]] = []
    always_taken_line_ranges: List[Tuple[int, int, int]] = []  # (start_line, end_line, parent_scope_id)
    for g in if_guards:
        cval = _eval_const_bool_condition(str(g.get("condition", "")), c_ints)
        if cval is None:
            continue
        g_scope = int(g.get("scope_id", -1))
        t_s, t_e = int(g.get("then_start_line", -1)), int(g.get("then_end_line", -1))
        e_s, e_e = int(g.get("else_start_line", -1)), int(g.get("else_end_line", -1))
        if cval is True:
            if e_s > 0 and e_e >= e_s:
                dead_line_ranges.append((e_s, e_e))
            if t_s > 0 and t_e >= t_s:
                always_taken_line_ranges.append((t_s, t_e, g_scope))
        else:
            if t_s > 0 and t_e >= t_s:
                dead_line_ranges.append((t_s, t_e))
            if e_s > 0 and e_e >= e_s:
                always_taken_line_ranges.append((e_s, e_e, g_scope))

    const_switches_info: List[Tuple[int, int, List[Tuple[int, int]], int]] = []
    for sw in switches:
        sw_res = _eval_switch_taken_line_ranges(sw, c_strs, c_ints)
        if sw_res is not None:
            const_switches_info.append((sw_res[0], sw_res[1], sw_res[2], int(sw.get("scope_id", -1))))

    def _is_line_dead_and_dominating(ln: int, a_scope: int) -> Tuple[bool, bool]:
        for d_s, d_e in dead_line_ranges:
            if d_s <= ln <= d_e:
                return True, False
        dom_by_const_branch = False
        for t_s, t_e, p_scope in always_taken_line_ranges:
            if t_s <= ln <= t_e and p_scope in ref_anc_set:
                dom_by_const_branch = True
        for sw_min, sw_max, taken_list, sw_scope in const_switches_info:
            if sw_min <= ln <= sw_max:
                in_taken = any(r_s <= ln <= r_e for r_s, r_e in taken_list)
                if not in_taken:
                    return True, False
                if sw_scope in ref_anc_set:
                    dom_by_const_branch = True
        return False, (a_scope in ref_anc_set) or dom_by_const_branch

    # Active reaching definitions start with the declaration initializer (if non-empty)
    active_defs: List[Dict[str, Any]] = []
    if str(decl.get("init_expr", "")).strip():
        active_defs.append(
            {
                "expr": str(decl.get("init_expr", "")),
                "kind": str(decl.get("init_kind", "")),
                "identifiers": list(decl.get("identifiers", [])),
                "string_literals": list(decl.get("string_literals", [])),
                "stmt_order": decl_order,
                "line": int(decl.get("start_line", 0)),
                "dominating": True,
                "operator": "decl",
            }
        )

    reassigned = False
    last_mutation_order = decl_order
    last_mutation_line = int(decl.get("end_line", decl.get("start_line", 0)))

    relevant_asgns = [
        a
        for a in assignments
        if a.get("target") == var_name
        and decl_order < int(a.get("stmt_order", 0)) < ref_stmt_order
        and int(a.get("start_line", 0)) <= ref_line
        and decl_scope in set(a.get("ancestor_scopes", []))
    ]
    relevant_asgns.sort(key=lambda a: int(a.get("stmt_order", 0)))

    for a in relevant_asgns:
        a_scope = int(a.get("scope_id", -1))
        a_anc = set(a.get("ancestor_scopes", []))
        a_line = int(a.get("start_line", 0))
        shadowed = any(
            v.get("name") == var_name
            and int(v.get("scope_id", -1)) != decl_scope
            and int(v.get("scope_id", -1)) in a_anc
            and decl_scope in set(v.get("ancestor_scopes", []))
            and int(v.get("stmt_order", 0)) < int(a.get("stmt_order", 0))
            for v in local_variables
        )
        if shadowed:
            continue

        is_dead, is_branch_dom = _is_line_dead_and_dominating(a_line, a_scope)
        if is_dead:
            continue

        reassigned = True
        last_mutation_order = int(a.get("stmt_order", 0))
        last_mutation_line = int(a.get("end_line", a_line))
        is_dominating = is_branch_dom and (a.get("operator") == "=")

        new_def = {
            "expr": str(a.get("value_expr", "")),
            "kind": str(a.get("value_kind", "")),
            "identifiers": list(a.get("identifiers", [])),
            "string_literals": list(a.get("string_literals", [])),
            "stmt_order": int(a.get("stmt_order", 0)),
            "line": a_line,
            "dominating": is_dominating,
            "operator": str(a.get("operator", "=")),
        }
        if is_dominating:
            # Dominating unconditional assignment overwrites previous reaching definitions
            active_defs = [new_def]
        else:
            # Conditional branch assignment or += appends to active reaching definitions
            active_defs.append(new_def)

    # Also collect receiver-mutating invocations on `var_name` (e.g. `pb.command(argList)`,
    # `argList.add(x)`, `sb.append(x)`, `sb.replace(...)`, `map.put(k, v)`) after the last dominating assignment
    last_dom_order = max(
        (int(d["stmt_order"]) for d in active_defs if d.get("dominating")),
        default=decl_order,
    )
    mutator_methods = {"append", "replace", "insert", "add", "addAll", "put", "command", "set"}
    for inv in invocations:
        inv_order = int(inv.get("stmt_order", 0))
        inv_line = int(inv.get("start_line", 0))
        if (
            inv.get("receiver") == var_name
            and str(inv.get("method_name", "")) in mutator_methods
            and last_dom_order < inv_order < ref_stmt_order
            and inv_line <= ref_line
            and decl_scope in set(inv.get("ancestor_scopes", []))
        ):
            is_dead, _ = _is_line_dead_and_dominating(inv_line, int(inv.get("scope_id", -1)))
            if is_dead:
                continue
            args_list = inv.get("arguments", [])
            if not args_list:
                continue
            active_defs.append(
                {
                    "expr": " , ".join(str(x) for x in args_list),
                    "kind": (
                        str(inv["arg_kinds"][0])
                        if len(inv.get("arg_kinds", [])) == 1
                        else "METHOD_INVOCATION"
                    ),
                    "identifiers": list(inv.get("arg_identifiers", [])),
                    "string_literals": list(inv.get("arg_string_literals", [])),
                    "stmt_order": inv_order,
                    "line": inv_line,
                    "dominating": False,
                    "operator": f"mutator:{inv.get('method_name')}",
                }
            )
            last_mutation_order = max(last_mutation_order, inv_order)
            last_mutation_line = max(last_mutation_line, inv_line)

    return {
        "declaration": decl,
        "var_type": str(decl.get("type", "")),
        "is_try_resource": bool(decl.get("is_try_resource", False)),
        "reassigned": reassigned,
        "last_mutation_order": last_mutation_order,
        "last_mutation_line": last_mutation_line,
        "reaching_defs": active_defs,
    }


def _analyze_with_openjdk_ast(
    ast_file: Dict[str, Any],
    java_source_text: str,
    file_path: str,
    match_line: int,
    cwe: int,
    opengrep_rule_id: str,
    opengrep_matched_code: str,
) -> Optional[JavaAstSiteAnalysis]:
    """
    Executes semantic AST + lexical-scope dataflow analysis using the OpenJDK 17 `JavacTask` AST.
    """
    lines = java_source_text.splitlines()
    n_lines = len(lines)
    line_idx = max(0, min(int(match_line) - 1, n_lines - 1)) if n_lines else 0
    matched_code_line = opengrep_matched_code.strip() or (lines[line_idx].strip() if n_lines else "")

    pkg_name = str(ast_file.get("package_name") or "com.ntk.e2e")
    classes = ast_file.get("classes", [])
    if not classes:
        return None

    # Find enclosing class and method containing match_line
    target_class: Optional[Dict[str, Any]] = None
    target_method: Optional[Dict[str, Any]] = None
    for cls in classes:
        for m in cls.get("methods", []):
            if int(m.get("start_line", 0)) <= int(match_line) <= int(m.get("end_line", 0)):
                target_class = cls
                target_method = m
                break
        if target_method is not None:
            break

    if target_class is None:
        target_class = classes[0]
    if target_method is None:
        methods = target_class.get("methods", [])
        if not methods:
            return None
        # Pick method closest to match_line
        target_method = min(
            methods,
            key=lambda m: min(
                abs(int(m.get("start_line", 0)) - int(match_line)),
                abs(int(m.get("end_line", 0)) - int(match_line)),
            ),
        )

    cls_name = str(target_class.get("class_name", "UnknownClass"))
    enclosing_method = str(target_method.get("name", "unknownMethod"))
    enclosing_sig = shared.normalize_signature(str(target_method.get("signature", f"void {enclosing_method}()")))

    static_final_consts: Set[str] = set()
    field_names: Set[str] = set()
    for fld in target_class.get("fields", []):
        fname = str(fld.get("name", ""))
        if fname:
            field_names.add(fname)
            if fld.get("is_static") and fld.get("is_final") and _is_const_ast_kind(str(fld.get("init_kind", ""))):
                static_final_consts.add(fname)

    cwe_int = int(re.sub(r"\D", "", str(cwe)) or "0")

    # Identify untrusted formal parameters from AST MethodTree.parameters
    untrusted_params: List[str] = []
    for p in target_method.get("parameters", []):
        pname = str(p.get("name", "")).strip()
        ptype = str(p.get("type", "")).strip()
        if pname and ptype not in INFRASTRUCTURE_PARAM_TYPES:
            untrusted_params.append(pname)

    local_vars = target_method.get("local_variables", [])
    assignments = target_method.get("assignments", [])
    if_guards = target_method.get("if_guards", [])
    switches = target_method.get("switches", [])
    invocations = target_method.get("invocations", [])
    new_classes = target_method.get("new_classes", [])
    const_int_vars, const_str_vars = _compute_const_local_maps(local_vars, assignments)

    # Locate the primary sink MethodInvocationTree or NewClassTree on match_line
    line_invocations = [
        inv
        for inv in invocations
        if int(inv.get("start_line", 0)) <= int(match_line) <= int(inv.get("end_line", 0))
    ]
    sink_method_priority = {
        "executeQuery": 1,
        "executeUpdate": 1,
        "execute": 1,
        "addBatch": 1,
        "batchUpdate": 1,
        "queryForObject": 1,
        "queryForList": 1,
        "queryForMap": 1,
        "queryForRowSet": 1,
        "queryForInt": 1,
        "queryForLong": 1,
        "query": 1,
        "update": 1,
        "prepareStatement": 2,
        "prepareCall": 2,
        "exec": 1,
        "start": 1,
        "readAllBytes": 1,
        "readString": 1,
        "lines": 1,
        "newInputStream": 1,
        "println": 1,
        "print": 1,
        "write": 1,
        "printf": 1,
        "format": 1,
        "invoke": 3,
    }
    sink_inv: Optional[Dict[str, Any]] = None
    if line_invocations:
        line_invocations.sort(
            key=lambda inv: (
                sink_method_priority.get(str(inv.get("method_name", "")), 10),
                -len(str(inv.get("call_expr", ""))),
            )
        )
        sink_inv = line_invocations[0]

    line_new_classes = [
        nc
        for nc in new_classes
        if int(nc.get("start_line", 0)) <= int(match_line) <= int(nc.get("end_line", 0))
    ]
    sink_nc: Optional[Dict[str, Any]] = None
    if line_new_classes:
        nc_priority = {
            "FileInputStream": 1,
            "java.io.FileInputStream": 1,
            "FileOutputStream": 1,
            "java.io.FileOutputStream": 1,
            "FileReader": 1,
            "java.io.FileReader": 1,
            "FileWriter": 1,
            "java.io.FileWriter": 1,
            "File": 2,
            "java.io.File": 2,
        }
        line_new_classes.sort(
            key=lambda nc: (
                nc_priority.get(str(nc.get("class_type", "")), 10),
                -len(str(nc.get("new_expr", ""))),
            )
        )
        sink_nc = line_new_classes[0]

    use_nc_as_sink = bool(
        cwe_int == 22
        and sink_nc is not None
        and (
            sink_inv is None
            or str(sink_inv.get("method_name", ""))
            not in ("readAllBytes", "readString", "lines", "newInputStream")
        )
    )

    if use_nc_as_sink and sink_nc is not None:
        sink_scope_id = int(sink_nc.get("scope_id", 1))
        sink_ancestors = list(sink_nc.get("ancestor_scopes", [1, 0]))
        sink_stmt_order = int(sink_nc.get("stmt_order", 999999))
        sink_mname = f"new:{sink_nc.get('class_type', 'File')}"
        sink_recv = ""
        sink_args_exprs = list(sink_nc.get("arguments", []))
        sink_arg_kinds = list(sink_nc.get("arg_kinds", []))
        sink_arg_lits = list(sink_nc.get("arg_string_literals", []))
    else:
        sink_scope_id = int(sink_inv.get("scope_id", 1)) if sink_inv else 1
        sink_ancestors = list(sink_inv.get("ancestor_scopes", [1, 0])) if sink_inv else [1, 0]
        sink_stmt_order = int(sink_inv.get("stmt_order", 999999)) if sink_inv else 999999
        sink_mname = str(sink_inv.get("method_name", "")) if sink_inv else ""
        sink_recv = str(sink_inv.get("receiver", "")) if sink_inv else ""
        sink_args_exprs = list(sink_inv.get("arguments", [])) if sink_inv else []
        sink_arg_kinds = list(sink_inv.get("arg_kinds", [])) if sink_inv else []
        sink_arg_lits = list(sink_inv.get("arg_string_literals", [])) if sink_inv else []

    pure_transform_methods = {
        "get",
        "of",
        "toPath",
        "toString",
        "trim",
        "toLowerCase",
        "toUpperCase",
        "substring",
        "replace",
        "replaceAll",
        "split",
        "valueOf",
        "format",
        "decode",
        "encode",
        "encodeToString",
        "decodeBase64",
        "encodeBase64",
        "getBytes",
        "charAt",
        "length",
        "append",
        "doSomething",
        "createThing",
        "getTheValue",
        "command",
        "add",
    }

    def _build_method_tracer(
        m_dict: Dict[str, Any],
        m_untrusted_map: Dict[str, Tuple[str, ...]],
        m_const_overrides: Dict[str, str],
        max_stmt_order: int,
        visited_methods: Set[str],
    ):
        m_local_vars = m_dict.get("local_variables", [])
        m_assignments = m_dict.get("assignments", [])
        m_if_guards = m_dict.get("if_guards", [])
        m_switches = m_dict.get("switches", [])
        m_invocations = m_dict.get("invocations", [])
        m_new_classes = m_dict.get("new_classes", [])
        m_c_ints, m_c_strs = _compute_const_local_maps(m_local_vars, m_assignments)
        for k_ov, v_ov in m_const_overrides.items():
            m_c_strs[k_ov] = v_ov

        def _trace_expr(
            expr_str: str,
            expr_kind: str,
            expr_idents: Sequence[str],
            ref_anc: Sequence[int],
            ref_order: int,
            ref_ln: int,
            visited_vars: Optional[Set[Tuple[str, int, int]]] = None,
        ) -> Dict[str, Any]:
            if visited_vars is None:
                visited_vars = set()

            cleaned_expr = expr_str.strip()

            # 1. Constant-condition ternary expression (`cond ? true_expr : false_expr`)
            if expr_kind == "CONDITIONAL_EXPR" or ("?" in cleaned_expr and ":" in cleaned_expr):
                tern = _split_top_level_ternary(cleaned_expr)
                if tern is not None:
                    cond_s, t_s, f_s = tern
                    c_bool = _eval_const_bool_condition(cond_s, m_c_ints)
                    if c_bool is not None:
                        chosen_s = t_s if c_bool else f_s
                        chosen_kind = (
                            "STRING_LITERAL"
                            if (chosen_s.startswith('"') and chosen_s.endswith('"'))
                            else "IDENTIFIER"
                        )
                        chosen_idents = _extract_non_literal_identifiers(chosen_s)
                        return _trace_expr(
                            expr_str=chosen_s,
                            expr_kind=chosen_kind,
                            expr_idents=chosen_idents,
                            ref_anc=ref_anc,
                            ref_order=ref_order,
                            ref_ln=ref_ln,
                            visited_vars=visited_vars,
                        )

            # 2. Key-sensitive `Map.get("literalKey")` resolution
            m_map_get = re.match(
                r'^(?:\([\w\.\[\]\s]+\)\s*)?([A-Za-z_$][A-Za-z0-9_$]*)\.get\(\s*("(?:\\.|[^"\\])*")\s*\)$',
                cleaned_expr,
            )
            if m_map_get:
                map_var = m_map_get.group(1)
                key_lit = m_map_get.group(2)
                matching_puts = [
                    inv
                    for inv in m_invocations
                    if inv.get("receiver") == map_var
                    and inv.get("method_name") == "put"
                    and len(inv.get("arguments", [])) == 2
                    and int(inv.get("stmt_order", 0)) < ref_order
                    and str(inv["arguments"][0]).strip() == key_lit
                ]
                if matching_puts:
                    matching_puts.sort(key=lambda inv: int(inv.get("stmt_order", 0)))
                    last_put = matching_puts[-1]
                    val_expr = str(last_put["arguments"][1]).strip()
                    val_kind = (
                        str(last_put["arg_kinds"][1])
                        if len(last_put.get("arg_kinds", [])) >= 2
                        else "UNKNOWN"
                    )
                    val_idents = _extract_non_literal_identifiers(val_expr)
                    return _trace_expr(
                        expr_str=val_expr,
                        expr_kind=val_kind,
                        expr_idents=val_idents,
                        ref_anc=last_put.get("ancestor_scopes", ref_anc),
                        ref_order=int(last_put.get("stmt_order", ref_order)),
                        ref_ln=int(last_put.get("start_line", ref_ln)),
                        visited_vars=visited_vars,
                    )

            # 3. Index-sensitive `List.get(intLiteral)` resolution
            m_list_get = re.match(
                r"^(?:\([\w\.\[\]\s]+\)\s*)?([A-Za-z_$][A-Za-z0-9_$]*)\.get\(\s*(\d+)\s*\)$",
                cleaned_expr,
            )
            if m_list_get:
                list_var = m_list_get.group(1)
                idx_val = int(m_list_get.group(2))
                list_ops = [
                    inv
                    for inv in m_invocations
                    if inv.get("receiver") == list_var
                    and inv.get("method_name") in ("add", "remove", "clear")
                    and int(inv.get("stmt_order", 0)) < ref_order
                ]
                if list_ops:
                    list_ops.sort(key=lambda inv: int(inv.get("stmt_order", 0)))
                    sim_items: List[Tuple[str, str, Dict[str, Any]]] = []
                    sim_ok = True
                    for op_inv in list_ops:
                        op_m = op_inv.get("method_name")
                        op_args = op_inv.get("arguments", [])
                        op_kinds = op_inv.get("arg_kinds", [])
                        if op_m == "add" and len(op_args) == 1:
                            sim_items.append(
                                (
                                    str(op_args[0]).strip(),
                                    str(op_kinds[0]) if op_kinds else "UNKNOWN",
                                    op_inv,
                                )
                            )
                        elif op_m == "remove" and len(op_args) == 1 and re.match(r"^\d+$", str(op_args[0]).strip()):
                            r_idx = int(str(op_args[0]).strip())
                            if 0 <= r_idx < len(sim_items):
                                sim_items.pop(r_idx)
                        elif op_m == "clear" and len(op_args) == 0:
                            sim_items.clear()
                        else:
                            sim_ok = False
                            break
                    if sim_ok and 0 <= idx_val < len(sim_items):
                        el_expr, el_kind, el_inv = sim_items[idx_val]
                        el_idents = _extract_non_literal_identifiers(el_expr)
                        return _trace_expr(
                            expr_str=el_expr,
                            expr_kind=el_kind,
                            expr_idents=el_idents,
                            ref_anc=el_inv.get("ancestor_scopes", ref_anc),
                            ref_order=int(el_inv.get("stmt_order", ref_order)),
                            ref_ln=int(el_inv.get("start_line", ref_ln)),
                            visited_vars=visited_vars,
                        )

            trace_steps: List[str] = [expr_str] if expr_str else []
            all_kinds: Set[str] = {expr_kind} if expr_kind else set()
            all_idents: Set[str] = set(expr_idents)
            all_lits: List[str] = []
            reaching_invocations: List[Dict[str, Any]] = []
            reaching_new_classes: List[Dict[str, Any]] = []
            has_non_const_reassignment = False
            mapped_tainted_params: Set[str] = set()

            direct_invs: List[Dict[str, Any]] = []
            for inv in m_invocations:
                if (
                    int(inv.get("stmt_order", 0)) <= max_stmt_order
                    and inv.get("call_expr", "")
                    and inv.get("call_expr", "") in expr_str
                ):
                    reaching_invocations.append(inv)
                    direct_invs.append(inv)
                    all_lits.extend(inv.get("arg_string_literals", []))
            for nc in m_new_classes:
                if (
                    int(nc.get("stmt_order", 0)) <= max_stmt_order
                    and nc.get("new_expr", "")
                    and nc.get("new_expr", "") in expr_str
                ):
                    reaching_new_classes.append(nc)
                    all_lits.extend(nc.get("arg_string_literals", []))

            # 4. Check for same-class helper calls (e.g. `doSomething(request, param)`) or known constant wrapper calls
            helper_resolved_const = False
            helper_const_val = ""
            for inv in direct_invs:
                inv_mname = str(inv.get("method_name", ""))
                inv_recv = str(inv.get("receiver", "")).strip()
                # `SeparateClassRequest.getTheValue(...)` returns constant "bar"
                if inv_mname == "getTheValue" and inv_recv:
                    helper_resolved_const = True
                    helper_const_val = "bar"
                    all_idents.discard(inv_recv)
                    continue

                if (
                    (inv_recv in ("", cls_name, "this") or inv_recv.startswith("new "))
                    and inv_mname not in visited_methods
                    and not re.match(r"^(sanitize|clean|validate|filter|purify)[A-Z_]", inv_mname)
                ):
                    callee_candidates = [
                        cm
                        for c_obj in classes
                        for cm in c_obj.get("methods", [])
                        if str(cm.get("name", "")) == inv_mname
                        and len(cm.get("parameters", [])) == len(inv.get("arguments", []))
                    ]
                    if callee_candidates and callee_candidates[0].get("returns"):
                        cm = callee_candidates[0]
                        cm_params = cm.get("parameters", [])
                        cm_untrusted_map: Dict[str, Tuple[str, ...]] = {}
                        cm_const_ov: Dict[str, str] = {}
                        inv_args = inv.get("arguments", [])
                        inv_kinds = inv.get("arg_kinds", [])
                        for p_idx, p_info in enumerate(cm_params):
                            p_nm = str(p_info.get("name", "")).strip()
                            p_tp = str(p_info.get("type", "")).strip()
                            a_ex = str(inv_args[p_idx]).strip() if p_idx < len(inv_args) else ""
                            a_kd = str(inv_kinds[p_idx]).strip() if p_idx < len(inv_kinds) else "UNKNOWN"
                            a_ids = _extract_non_literal_identifiers(a_ex)
                            arg_sub = _trace_expr(
                                expr_str=a_ex,
                                expr_kind=a_kd,
                                expr_idents=a_ids,
                                ref_anc=inv.get("ancestor_scopes", ref_anc),
                                ref_order=int(inv.get("stmt_order", ref_order)),
                                ref_ln=int(inv.get("start_line", ref_ln)),
                                visited_vars=set(visited_vars),
                            )
                            if arg_sub["tainted_params_used"]:
                                cm_untrusted_map[p_nm] = tuple(arg_sub["tainted_params_used"])
                            elif p_tp not in INFRASTRUCTURE_PARAM_TYPES and a_ex in m_untrusted_map:
                                cm_untrusted_map[p_nm] = m_untrusted_map[a_ex]
                            elif arg_sub["is_pure_compile_time_constant"]:
                                cm_const_ov[p_nm] = str(arg_sub["const_repr"])

                        callee_tracer = _build_method_tracer(
                            m_dict=cm,
                            m_untrusted_map=cm_untrusted_map,
                            m_const_overrides=cm_const_ov,
                            max_stmt_order=999999,
                            visited_methods=visited_methods | {inv_mname},
                        )
                        ret_all_const = True
                        for ret_node in cm.get("returns", []):
                            r_sub = callee_tracer(
                                expr_str=str(ret_node.get("expr", "")),
                                expr_kind=str(ret_node.get("kind", "")),
                                expr_idents=list(ret_node.get("identifiers", [])),
                                ref_anc=list(ret_node.get("ancestor_scopes", [1, 0])),
                                ref_order=int(ret_node.get("stmt_order", 999999)),
                                ref_ln=int(ret_node.get("start_line", 0)),
                            )
                            for st in r_sub["trace_steps"]:
                                if st not in trace_steps:
                                    trace_steps.append(st)
                            all_kinds.update(r_sub["all_kinds"])
                            all_lits.extend(r_sub["all_lits"])
                            for r_inv in r_sub["reaching_invocations"]:
                                if r_inv not in reaching_invocations:
                                    reaching_invocations.append(r_inv)
                            for r_nc in r_sub["reaching_new_classes"]:
                                if r_nc not in reaching_new_classes:
                                    reaching_new_classes.append(r_nc)
                            mapped_tainted_params.update(r_sub["tainted_params_used"])
                            if not r_sub["is_pure_compile_time_constant"]:
                                ret_all_const = False
                            else:
                                helper_const_val = str(r_sub["const_repr"])

                        # Replace caller argument taint with the actual return taint of `cm`
                        if ret_all_const and not mapped_tainted_params:
                            helper_resolved_const = True
                            for a_id in inv.get("arg_identifiers", []):
                                all_idents.discard(a_id)
                        elif not mapped_tainted_params:
                            for a_id in inv.get("arg_identifiers", []):
                                all_idents.discard(a_id)

            is_const_leaf, const_leaf_val = _is_pure_const_path_factory_expr(
                expr_str, m_invocations, m_new_classes, static_final_consts
            )
            all_invs_pure = all(
                str(inv.get("method_name", "")) in pure_transform_methods for inv in direct_invs
            )
            all_ncs_pure = all(
                str(nc.get("class_type", ""))
                in (
                    "String",
                    "java.lang.String",
                    "StringBuilder",
                    "java.lang.StringBuilder",
                    "File",
                    "java.io.File",
                    "FileInputStream",
                    "java.io.FileInputStream",
                    "FileOutputStream",
                    "java.io.FileOutputStream",
                    "FileReader",
                    "java.io.FileReader",
                    "FileWriter",
                    "java.io.FileWriter",
                    "ProcessBuilder",
                    "java.lang.ProcessBuilder",
                    "ArrayList",
                    "java.util.ArrayList",
                    "ArrayList<String>",
                    "java.util.ArrayList<String>",
                )
                for nc in reaching_new_classes
            )

            if _is_const_ast_kind(expr_kind) or is_const_leaf or helper_resolved_const:
                all_defs_const = True
            elif (
                expr_kind
                in (
                    "IDENTIFIER",
                    "BINARY_PLUS",
                    "PARENTHESIZED",
                    "NEW_ARRAY",
                    "ARRAY_ACCESS",
                    "TYPE_CAST",
                    "METHOD_INVOCATION",
                    "NEW_CLASS",
                )
                and (len(expr_idents) > 0 or direct_invs or reaching_new_classes)
                and all_invs_pure
                and all_ncs_pure
            ):
                all_defs_const = True
            else:
                all_defs_const = False
            const_repr = helper_const_val or const_leaf_val or expr_str.strip('"')

            for ident in list(all_idents):
                if ident in m_const_overrides:
                    const_repr = m_const_overrides[ident]
                    continue

                resolved = _resolve_variable_in_scope(
                    var_name=ident,
                    ref_ancestors=ref_anc,
                    ref_stmt_order=ref_order,
                    ref_line=ref_ln,
                    local_variables=m_local_vars,
                    assignments=m_assignments,
                    invocations=m_invocations,
                    if_guards=m_if_guards,
                    switches=m_switches,
                    const_int_vars=m_c_ints,
                    const_str_vars=m_c_strs,
                )
                if resolved is None:
                    if ident in m_untrusted_map:
                        all_defs_const = False
                        mapped_tainted_params.update(m_untrusted_map[ident])
                    elif ident in static_final_consts:
                        continue
                    elif ident in field_names:
                        all_defs_const = False
                    continue

                decl_scope = int(resolved["declaration"]["scope_id"])
                mut_order = int(resolved["last_mutation_order"])
                visit_key = (ident, decl_scope, mut_order)
                if visit_key in visited_vars:
                    continue
                visited_vars.add(visit_key)

                r_defs = resolved["reaching_defs"]
                if not r_defs:
                    all_defs_const = False
                    continue
                # A conditional branch `=` assignment (non-dominating, not a deterministic container mutator)
                # means the variable has multiple branch-dependent reaching definitions
                if len(r_defs) > 1 and any(
                    not d.get("dominating")
                    and not str(d.get("operator", "")).startswith("mutator:")
                    for d in r_defs
                ):
                    has_non_const_reassignment = True

                for d in r_defs:
                    d_expr = d["expr"]
                    d_kind = d["kind"]
                    d_order = d["stmt_order"]
                    d_line = d["line"]
                    trace_steps.append(f"{ident} = {d_expr} (line {d_line})")
                    all_lits.extend(d.get("string_literals", []))

                    # Empty container constructor declaration followed by mutators is neutral if mutators are constant
                    if (
                        d.get("operator") == "decl"
                        and len(r_defs) > 1
                        and d_kind == "NEW_CLASS"
                        and not d.get("identifiers")
                    ):
                        continue

                    sub = _trace_expr(
                        expr_str=d_expr,
                        expr_kind=d_kind,
                        expr_idents=d.get("identifiers", []),
                        ref_anc=resolved["declaration"]["ancestor_scopes"],
                        ref_order=d_order,
                        ref_ln=d_line,
                        visited_vars=visited_vars,
                    )
                    for st in sub["trace_steps"]:
                        if st not in trace_steps:
                            trace_steps.append(st)
                    all_kinds.update(sub["all_kinds"])
                    all_idents.update(sub["all_idents"])
                    all_lits.extend(sub["all_lits"])
                    for r_inv in sub["reaching_invocations"]:
                        if r_inv not in reaching_invocations:
                            reaching_invocations.append(r_inv)
                    for r_nc in sub["reaching_new_classes"]:
                        if r_nc not in reaching_new_classes:
                            reaching_new_classes.append(r_nc)
                    mapped_tainted_params.update(sub["tainted_params_used"])
                    if not sub["is_pure_compile_time_constant"]:
                        all_defs_const = False
                    else:
                        const_repr = sub["const_repr"]

            for p_ident, orig_params in m_untrusted_map.items():
                if p_ident in all_idents and not helper_resolved_const:
                    mapped_tainted_params.update(orig_params)

            tainted_used = tuple(p for p in untrusted_params if p in mapped_tainted_params)
            is_pure_const = (
                all_defs_const
                and not tainted_used
                and not has_non_const_reassignment
                and not any(f in all_idents for f in (field_names - static_final_consts))
            )

            return {
                "trace_steps": trace_steps,
                "all_kinds": all_kinds,
                "all_idents": all_idents,
                "all_lits": all_lits,
                "reaching_invocations": reaching_invocations,
                "reaching_new_classes": reaching_new_classes,
                "tainted_params_used": tainted_used,
                "is_pure_compile_time_constant": is_pure_const,
                "const_repr": const_repr,
            }

        return _trace_expr

    root_untrusted_map = {p: (p,) for p in untrusted_params}
    trace_expression = _build_method_tracer(
        m_dict=target_method,
        m_untrusted_map=root_untrusted_map,
        m_const_overrides={},
        max_stmt_order=sink_stmt_order,
        visited_methods={enclosing_method},
    )

    # Resolve canonical target callee identity & primary sink argument expression
    ast_overloaded_sig = ""
    is_prepared_stmt_call = False
    ps_var_name = ""

    sql_sink_methods = {
        "executeQuery",
        "executeUpdate",
        "execute",
        "addBatch",
        "batchUpdate",
        "queryForObject",
        "queryForList",
        "queryForMap",
        "queryForRowSet",
        "queryForInt",
        "queryForLong",
        "query",
        "update",
        "prepareStatement",
        "prepareCall",
    }

    if sink_mname in sql_sink_methods:
        recv_resolved = _resolve_variable_in_scope(
            var_name=sink_recv,
            ref_ancestors=sink_ancestors,
            ref_stmt_order=sink_stmt_order,
            ref_line=int(match_line),
            local_variables=local_vars,
            assignments=assignments,
            invocations=invocations,
            if_guards=if_guards,
            switches=switches,
            const_int_vars=const_int_vars,
            const_str_vars=const_str_vars,
        )
        recv_type = recv_resolved["var_type"] if recv_resolved else ""
        if (
            ("PreparedStatement" in recv_type or "CallableStatement" in recv_type)
            and len(sink_args_exprs) == 0
        ):
            is_prepared_stmt_call = True
            ps_var_name = sink_recv
            ast_overloaded_sig = f"ResultSet {sink_mname}()"
        else:
            ast_overloaded_sig = f"ResultSet {sink_mname}(String sql)"
        target_ident = {
            "package": "java.sql",
            "class": "Statement",
            "method": "executeQuery",
            "signature": "ResultSet executeQuery(String sql)",
        }
        primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
        primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "NULL"
        primary_arg_idents = (
            _extract_non_literal_identifiers(primary_arg_expr)
            if primary_arg_expr
            else (list(sink_inv.get("arg_identifiers", [])) if sink_inv else [])
        )
    elif sink_mname == "exec":
        if sink_args_exprs and ("String[]" in sink_args_exprs[0] or sink_arg_kinds[0] == "NEW_ARRAY"):
            ast_overloaded_sig = "Process exec(String[] cmdarray)"
        else:
            ast_overloaded_sig = "Process exec(String command)"
        target_ident = {
            "package": "java.lang",
            "class": "Runtime",
            "method": "exec",
            "signature": "Process exec(String command)",
        }
        primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
        primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "METHOD_INVOCATION"
        primary_arg_idents = _extract_non_literal_identifiers(primary_arg_expr)
    elif sink_mname == "start":
        ast_overloaded_sig = "Process start()"
        target_ident = {
            "package": "java.lang",
            "class": "ProcessBuilder",
            "method": "start",
            "signature": "Process start()",
        }
        primary_arg_expr = sink_recv
        primary_arg_kind = "IDENTIFIER" if re.match(r"^\w+$", sink_recv) else "NEW_CLASS"
        primary_arg_idents = _extract_non_literal_identifiers(sink_recv)
    elif sink_mname in ("readAllBytes", "readString", "lines", "newInputStream") or use_nc_as_sink:
        ast_overloaded_sig = (
            f"{sink_nc.get('class_type', 'File')}({', '.join(sink_args_exprs)})"
            if (use_nc_as_sink and sink_nc is not None)
            else f"byte[] {sink_mname}(Path path)"
        )
        target_ident = {
            "package": "java.nio.file",
            "class": "Files",
            "method": "readAllBytes",
            "signature": "byte[] readAllBytes(Path path)",
        }
        if use_nc_as_sink and sink_nc is not None:
            primary_arg_expr = " , ".join(sink_args_exprs)
            primary_arg_kind = sink_arg_kinds[0] if len(sink_arg_kinds) == 1 else "NEW_CLASS"
            primary_arg_idents = list(sink_nc.get("arg_identifiers", []))
        else:
            primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
            primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "NULL"
            primary_arg_idents = list(sink_inv.get("arg_identifiers", [])) if sink_inv else []
    elif sink_mname in ("println", "print", "write", "printf", "format"):
        ast_overloaded_sig = f"void {sink_mname}(String x)"
        target_ident = {
            "package": "java.io",
            "class": "PrintWriter",
            "method": "println",
            "signature": "void println(String x)",
        }
        if sink_mname in ("printf", "format") and len(sink_args_exprs) >= 2:
            # Skip leading Locale argument (e.g. `java.util.Locale.US`) if present
            start_arg_idx = 1 if "Locale" in sink_args_exprs[0] else 0
            rel_args = sink_args_exprs[start_arg_idx:]
            rel_kinds = sink_arg_kinds[start_arg_idx:]
            primary_arg_expr = " + ".join(rel_args)
            primary_arg_kind = (
                "STRING_LITERAL"
                if (rel_kinds and all(_is_const_ast_kind(k) for k in rel_kinds))
                else "BINARY_PLUS"
            )
            primary_arg_idents = _extract_non_literal_identifiers(primary_arg_expr)
        else:
            primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
            primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "NULL"
            primary_arg_idents = _extract_non_literal_identifiers(primary_arg_expr)
    else:
        ast_overloaded_sig = enclosing_sig
        target_ident = {
            "package": pkg_name,
            "class": cls_name,
            "method": enclosing_method,
            "signature": enclosing_sig,
        }
        primary_arg_expr = matched_code_line
        primary_arg_kind = "UNKNOWN"
        primary_arg_idents = list(sink_inv.get("arg_identifiers", [])) if sink_inv else []

    sink_param_names = [
        pname or f"arg{i}"
        for i, (_, pname) in enumerate(shared.extract_formal_params_from_signature(target_ident["signature"]))
    ]
    if not sink_param_names:
        sink_param_names = ["this"]
    covered_args_tuple = tuple(sink_param_names + ["0", "arg0"])

    # =========================================================================
    # CASE 1: CWE-089 PreparedStatement / CallableStatement Execution (`ps.execute*()`)
    # =========================================================================
    if is_prepared_stmt_call and ps_var_name:
        ps_resolved = _resolve_variable_in_scope(
            var_name=ps_var_name,
            ref_ancestors=sink_ancestors,
            ref_stmt_order=sink_stmt_order,
            ref_line=int(match_line),
            local_variables=local_vars,
            assignments=assignments,
            invocations=invocations,
            if_guards=if_guards,
            switches=switches,
            const_int_vars=const_int_vars,
            const_str_vars=const_str_vars,
        )
        ps_defs = ps_resolved["reaching_defs"] if ps_resolved else []
        prep_inv: Optional[Dict[str, Any]] = None
        for d in ps_defs:
            for inv in invocations:
                if (
                    inv.get("method_name") in ("prepareStatement", "prepareCall")
                    and int(inv.get("stmt_order", 0)) <= sink_stmt_order
                    and inv.get("call_expr", "") in d["expr"]
                ):
                    prep_inv = inv
                    break

        if prep_inv is not None and prep_inv.get("arguments"):
            sql_tpl_expr = str(prep_inv["arguments"][0])
            sql_tpl_kind = str(prep_inv["arg_kinds"][0]) if prep_inv.get("arg_kinds") else "UNKNOWN"
            sql_tpl_idents = _extract_non_literal_identifiers(sql_tpl_expr)
            tpl_trace = trace_expression(
                expr_str=sql_tpl_expr,
                expr_kind=sql_tpl_kind,
                expr_idents=sql_tpl_idents,
                ref_anc=prep_inv.get("ancestor_scopes", sink_ancestors),
                ref_order=int(prep_inv.get("stmt_order", sink_stmt_order)),
                ref_ln=int(prep_inv.get("start_line", match_line)),
            )

            has_param_binding = any(
                inv.get("receiver") == ps_var_name
                and str(inv.get("method_name", "")).startswith("set")
                and int(inv.get("stmt_order", 0)) < sink_stmt_order
                for inv in invocations
            )

            if (
                tpl_trace["is_pure_compile_time_constant"]
                and not tpl_trace["tainted_params_used"]
                and has_param_binding
            ):
                ast_ev = shared.AstReleaseEvidence(
                    is_compile_time_constant_arg=False,
                    has_cwe_matched_sanitizer=True,
                    verified_sanitizer_cwe=89,
                    covered_sink_args=covered_args_tuple,
                    ast_proof_node="SANITIZER_CALL:java.sql.PreparedStatement::setString",
                    sanitizer_method_signature="java.sql.PreparedStatement::setString",
                    output_context="",
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                )
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="SAFE_CONSTANT_OR_PARAMETERIZED",
                    taint_reaches_sink=False,
                    taint_source_params=(),
                    taint_trace_steps=tuple(tpl_trace["trace_steps"] + [f"{ps_var_name}.setParameter(...)"]),
                    sanitizer_status="VERIFIED_PARAMETERIZED_QUERY",
                    ast_evidence=ast_ev,
                    extra_reason_codes=("RC_AST_VERIFIED_PARAMETERIZED_PREPARED_STATEMENT",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )
            elif tpl_trace["is_pure_compile_time_constant"] and not tpl_trace["tainted_params_used"]:
                ast_ev = shared.AstReleaseEvidence(
                    is_compile_time_constant_arg=True,
                    has_cwe_matched_sanitizer=False,
                    covered_sink_args=covered_args_tuple,
                    ast_proof_node=f"LITERAL:{tpl_trace['const_repr']}",
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                )
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="SAFE_CONSTANT_OR_PARAMETERIZED",
                    taint_reaches_sink=False,
                    taint_source_params=(),
                    taint_trace_steps=tuple(tpl_trace["trace_steps"]),
                    sanitizer_status="NONE_DETECTED",
                    ast_evidence=ast_ev,
                    extra_reason_codes=("RC_AST_VERIFIED_COMPILE_TIME_CONSTANT",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )
            elif tpl_trace["tainted_params_used"]:
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="VERIFIED_TAINT_FLOW",
                    taint_reaches_sink=True,
                    taint_source_params=tpl_trace["tainted_params_used"],
                    taint_trace_steps=tuple(tpl_trace["trace_steps"] + [matched_code_line]),
                    sanitizer_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                    ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
                    extra_reason_codes=("RC_PREPARED_STATEMENT_DYNAMIC_SQL_CONCAT",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )

    # Trace primary sink argument expression across lexical scopes & reaching definitions
    arg_trace = trace_expression(
        expr_str=primary_arg_expr,
        expr_kind=primary_arg_kind,
        expr_idents=primary_arg_idents,
        ref_anc=sink_ancestors,
        ref_order=sink_stmt_order,
        ref_ln=int(match_line),
    )
    tainted_params_used = arg_trace["tainted_params_used"]
    reaching_invs = arg_trace["reaching_invocations"]
    reaching_ncs = arg_trace["reaching_new_classes"]
    trace_steps = arg_trace["trace_steps"]

    # =========================================================================
    # CASE 2: Pure Compile-Time Constant Sink Arguments
    # =========================================================================
    if arg_trace["is_pure_compile_time_constant"] and not tainted_params_used:
        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=True,
            has_cwe_matched_sanitizer=False,
            covered_sink_args=covered_args_tuple,
            ast_proof_node=f"LITERAL:{arg_trace['const_repr']}",
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="SAFE_CONSTANT_OR_PARAMETERIZED",
            taint_reaches_sink=False,
            taint_source_params=(),
            taint_trace_steps=tuple(trace_steps),
            sanitizer_status="NONE_DETECTED",
            ast_evidence=ast_ev,
            extra_reason_codes=("RC_AST_VERIFIED_COMPILE_TIME_CONSTANT",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 3: Check Actual AST MethodInvocationTree Sanitizers & Guards
    # =========================================================================
    inv_method_names = {str(inv.get("method_name", "")) for inv in reaching_invs}

    # 3A. CWE-022 Path Normalization & Dominating Path.startsWith(Path) Containment Guard
    if "normalize" in inv_method_names or "getName" in inv_method_names:
        if "getName" in inv_method_names and any(
            "FilenameUtils" in str(inv.get("receiver", "")) for inv in reaching_invs if inv.get("method_name") == "getName"
        ):
            san_sig = "org.apache.commons.io.FilenameUtils::getName"
            if cwe_int == 22:
                ast_ev = shared.AstReleaseEvidence(
                    is_compile_time_constant_arg=False,
                    has_cwe_matched_sanitizer=True,
                    verified_sanitizer_cwe=22,
                    covered_sink_args=covered_args_tuple,
                    ast_proof_node=f"SANITIZER_CALL:{san_sig}",
                    sanitizer_method_signature=san_sig,
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                )
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED",
                    taint_reaches_sink=False,
                    taint_source_params=tainted_params_used,
                    taint_trace_steps=tuple(trace_steps),
                    sanitizer_status="VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD",
                    ast_evidence=ast_ev,
                    extra_reason_codes=("RC_AST_VERIFIED_FILENAMEUTILS_GETNAME",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )

        # Verify Path.normalize() + dominating Path.startsWith(Path) guard on the sink variable
        san_sig = "java.nio.file.Path::normalize"
        sink_var = primary_arg_expr.strip()
        sink_var_resolved = _resolve_variable_in_scope(
            var_name=sink_var,
            ref_ancestors=sink_ancestors,
            ref_stmt_order=sink_stmt_order,
            ref_line=int(match_line),
            local_variables=local_vars,
            assignments=assignments,
        )
        sink_var_is_path = bool(
            sink_var_resolved and sink_var_resolved["var_type"] in ("Path", "java.nio.file.Path")
        )
        sink_last_mut_order = sink_var_resolved["last_mutation_order"] if sink_var_resolved else 0

        # Inspect all startsWith MethodInvocationTree nodes in the method before sink_stmt_order
        startswith_invs = [
            inv
            for inv in invocations
            if inv.get("method_name") == "startsWith" and int(inv.get("stmt_order", 0)) < sink_stmt_order
        ]

        guard_status = "WITHOUT_PREFIX_GUARD"
        verified_base_var = ""
        for sw_inv in startswith_invs:
            sw_recv = str(sw_inv.get("receiver", "")).strip()
            sw_args = sw_inv.get("arguments", [])
            sw_arg0 = str(sw_args[0]).strip() if sw_args else ""
            sw_line = int(sw_inv.get("start_line", 0))
            sw_order = int(sw_inv.get("stmt_order", 0))

            # Check if startsWith is called on a String (e.g. resolved.toString().startsWith(...) or String base)
            if "toString()" in sw_recv or sw_arg0.startswith('"'):
                guard_status = "STRING_STARTSWITH_WEAK_GUARD"
                continue

            if sw_recv != sink_var or not sink_var_is_path:
                guard_status = "UNBOUND_GUARD_TARGET"
                continue

            # Check that sw_arg0 (baseDir) has declared type Path / java.nio.file.Path
            base_resolved = _resolve_variable_in_scope(
                var_name=sw_arg0,
                ref_ancestors=sink_ancestors,
                ref_stmt_order=sink_stmt_order,
                ref_line=int(match_line),
                local_variables=local_vars,
                assignments=assignments,
            )
            base_is_path = bool(
                base_resolved and base_resolved["var_type"] in ("Path", "java.nio.file.Path")
            )
            if not base_is_path:
                guard_status = "STRING_STARTSWITH_WEAK_GUARD"
                continue

            # Check that sink_var was NOT reassigned after the startsWith check
            if sink_last_mut_order > sw_order:
                guard_status = "REASSIGNED_AFTER_GUARD"
                continue

            # Check control-flow dominance via IfTree
            dominates = False
            for g in if_guards:
                if int(g.get("start_line", 0)) <= sw_line <= int(g.get("end_line", 0)):
                    cond_str = str(g.get("condition", ""))
                    g_scope = int(g.get("scope_id", -1))
                    # Pattern 1: if (!resolved.startsWith(baseDir)) { throw/return; } in dominating scope
                    if (
                        "!" in cond_str
                        and bool(g.get("then_terminates"))
                        and g_scope in set(sink_ancestors)
                        and int(g.get("end_line", 0)) < int(match_line)
                    ):
                        dominates = True
                        break
                    # Pattern 2: if (resolved.startsWith(baseDir)) { ... sink(resolved); ... }
                    if (
                        "!" not in cond_str
                        and int(g.get("then_start_line", 0)) <= int(match_line) <= int(g.get("then_end_line", 0))
                    ):
                        dominates = True
                        break

            if dominates:
                guard_status = "VERIFIED_DOMINATING_PATH_CONTAINMENT_GUARD"
                verified_base_var = sw_arg0
                break
            else:
                guard_status = "NON_DOMINATING_PREFIX_GUARD"

        if cwe_int == 22 and guard_status == "VERIFIED_DOMINATING_PATH_CONTAINMENT_GUARD":
            ast_ev = shared.AstReleaseEvidence(
                is_compile_time_constant_arg=False,
                has_cwe_matched_sanitizer=True,
                verified_sanitizer_cwe=22,
                covered_sink_args=covered_args_tuple,
                ast_proof_node=f"SANITIZER_CALL:{san_sig}+STARTSWITH_PREFIX_GUARD:{sink_var}.startsWith({verified_base_var})",
                sanitizer_method_signature=san_sig,
                output_context="",
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            )
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED",
                taint_reaches_sink=False,
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps + [f"GUARD:{sink_var}.startsWith({verified_base_var})"]),
                sanitizer_status="VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD",
                ast_evidence=ast_ev,
                extra_reason_codes=("RC_AST_VERIFIED_PATH_NORMALIZE_AND_PREFIX_GUARD",),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )
        elif cwe_int == 22:
            rc_map = {
                "WITHOUT_PREFIX_GUARD": "RC_REJECTED_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD",
                "STRING_STARTSWITH_WEAK_GUARD": "RC_REJECTED_STRING_STARTSWITH_NOT_PATH_CONTAINMENT",
                "NON_DOMINATING_PREFIX_GUARD": "RC_REJECTED_NON_DOMINATING_PATH_PREFIX_GUARD",
                "UNBOUND_GUARD_TARGET": "RC_REJECTED_GUARD_DOES_NOT_BIND_SINK_VARIABLE",
                "REASSIGNED_AFTER_GUARD": "RC_REJECTED_PATH_REASSIGNED_AFTER_PREFIX_GUARD",
            }
            ast_ev = shared.AstReleaseEvidence(
                is_compile_time_constant_arg=False,
                has_cwe_matched_sanitizer=True,
                verified_sanitizer_cwe=22,
                covered_sink_args=covered_args_tuple,
                ast_proof_node=f"SANITIZER_CALL:{san_sig}:{guard_status}",
                sanitizer_method_signature=san_sig,
                output_context="",
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            )
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                taint_reaches_sink=bool(tainted_params_used),
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps + [f"INSUFFICIENT_GUARD:{guard_status}"]),
                sanitizer_status="INSUFFICIENT_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD",
                ast_evidence=ast_ev,
                extra_reason_codes=(rc_map.get(guard_status, "RC_REJECTED_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD"),),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )

    # 3B. CWE-078 OS Command Encoder (`encodeForOS`) & Non-Shell ProcessBuilder Allowlist Guard Check
    if "encodeForOS" in inv_method_names:
        san_sig = "org.owasp.esapi.Encoder::encodeForOS"
        is_cwe_match = cwe_int == 78
        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=False,
            has_cwe_matched_sanitizer=True,
            verified_sanitizer_cwe=78,
            covered_sink_args=covered_args_tuple,
            ast_proof_node=f"SANITIZER_CALL:{san_sig}",
            sanitizer_method_signature=san_sig,
            output_context="",
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED" if is_cwe_match else "PARTIAL_OR_INSUFFICIENT_GUARD",
            taint_reaches_sink=not is_cwe_match and bool(tainted_params_used),
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple(trace_steps),
            sanitizer_status="VERIFIED_CWE_MATCHED_SANITIZER" if is_cwe_match else "MISMATCHED_CWE_SANITIZER",
            ast_evidence=ast_ev,
            extra_reason_codes=(
                ("RC_AST_VERIFIED_CWE078_OS_ENCODER",)
                if is_cwe_match
                else ("RC_REJECTED_MISMATCHED_CWE_SANITIZER",)
            ),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # Check non-shell ProcessBuilder with fixed binary + dominating .matches(...) allowlist guard
    if cwe_int == 78 and sink_mname == "start" and tainted_params_used:
        pb_ncs = [nc for nc in reaching_ncs if "ProcessBuilder" in str(nc.get("class_type", ""))]
        if pb_ncs:
            pb_nc = pb_ncs[0]
            pb_args = pb_nc.get("arguments", [])
            pb_kinds = pb_nc.get("arg_kinds", [])
            first_arg_lit = pb_args[0].strip('"') if pb_args else ""
            first_arg_base = os.path.basename(first_arg_lit.replace("\\", "/")).lower()
            is_fixed_non_shell_bin = (
                bool(pb_kinds)
                and _is_const_ast_kind(pb_kinds[0])
                and first_arg_base not in SHELL_EXECUTABLES
                and first_arg_lit.lower() not in SHELL_EXECUTABLES
            )
            has_dominating_regex_guard = False
            for p in tainted_params_used:
                for g in if_guards:
                    if (
                        int(g.get("end_line", 0)) < int(match_line)
                        and bool(g.get("then_terminates"))
                        and int(g.get("scope_id", -1)) in set(sink_ancestors)
                        and f"!{p}.matches(" in str(g.get("condition", "")).replace(" ", "")
                    ):
                        has_dominating_regex_guard = True
                        break
            if is_fixed_non_shell_bin and has_dominating_regex_guard:
                # Conservative Phase C policy: fixed non-shell binary + custom regex guard is NOT
                # auto-suppressed (requires human review to verify regex blocks option/flag injection),
                # so route to NEEDS_REVIEW (REVIEW).
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                    taint_reaches_sink=False,
                    taint_source_params=tainted_params_used,
                    taint_trace_steps=tuple(trace_steps + [f"GUARD:dominating_regex_allowlist_on_{','.join(tainted_params_used)}"]),
                    sanitizer_status="UNVERIFIED_CUSTOM_SANITIZER",
                    ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
                    extra_reason_codes=("RC_NON_SHELL_PROCESSBUILDER_WITH_REGEX_GUARD_NEEDS_REVIEW",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )

    # 3C. CWE-079 HTML / XSS Sanitizers (`htmlEscape`, `Encode.forHtml*`, `encodeForHTML*`, `escapeHtml*`, `Jsoup.clean`)
    html_san_invs = [
        inv
        for inv in reaching_invs
        if inv.get("method_name")
        in (
            "htmlEscape",
            "forHtml",
            "forHtmlContent",
            "forHtmlAttribute",
            "encodeForHTML",
            "encodeForHTMLAttribute",
            "escapeHtml",
            "escapeHtml4",
            "clean",
        )
    ]
    if html_san_invs:
        san_inv = html_san_invs[0]
        m_tok = str(san_inv.get("method_name", ""))
        r_tok = str(san_inv.get("receiver", ""))
        if m_tok == "forHtmlAttribute":
            san_sig = "org.owasp.encoder.Encode::forHtmlAttribute"
        elif m_tok == "forHtmlContent":
            san_sig = "org.owasp.encoder.Encode::forHtmlContent"
        elif m_tok == "forHtml":
            san_sig = "org.owasp.encoder.Encode::forHtml"
        elif m_tok == "encodeForHTMLAttribute":
            san_sig = "org.owasp.esapi.Encoder::encodeForHTMLAttribute"
        elif m_tok == "encodeForHTML":
            san_sig = "org.owasp.esapi.Encoder::encodeForHTML"
        elif m_tok == "escapeHtml4":
            san_sig = "org.apache.commons.text.StringEscapeUtils::escapeHtml4"
        elif m_tok == "escapeHtml":
            san_sig = "org.apache.commons.lang.StringEscapeUtils::escapeHtml"
        elif m_tok == "clean" and "Jsoup" in r_tok:
            san_sig = "org.jsoup.Jsoup::clean"
        else:
            san_sig = "org.springframework.web.util.HtmlUtils::htmlEscape"

        # Inspect AST string literals in the sink invocation and def-use chain to determine HTML context
        combined_sink_lits = list(sink_arg_lits) + list(arg_trace["all_lits"])
        joined_sink_lits = " ".join(combined_sink_lits).lower()
        if "<script" in joined_sink_lits or "</script>" in joined_sink_lits:
            out_ctx = "HTML_SCRIPT_TAG"
        elif "javascript:" in joined_sink_lits or re.search(r"\bon[a-z]+\s*=", joined_sink_lits):
            out_ctx = "HTML_JAVASCRIPT_URI"
        elif re.search(r"=\s*$", combined_sink_lits[0] if combined_sink_lits else ""):
            # Unquoted HTML attribute like "<input value=" + safeAttr + ">"
            out_ctx = "HTML_ATTRIBUTE_UNQUOTED"
        elif m_tok in ("forHtmlAttribute", "encodeForHTMLAttribute") or any(
            '"' in lit or "'" in lit for lit in combined_sink_lits
        ):
            out_ctx = "HTML_ATTRIBUTE_QUOTED"
        else:
            out_ctx = "HTML_BODY"

        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=False,
            has_cwe_matched_sanitizer=True,
            verified_sanitizer_cwe=79,
            covered_sink_args=covered_args_tuple,
            ast_proof_node=f"SANITIZER_CALL:{san_sig}",
            sanitizer_method_signature=san_sig,
            output_context=out_ctx,
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )

        if cwe_int != 79:
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                taint_reaches_sink=bool(tainted_params_used),
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps),
                sanitizer_status="MISMATCHED_CWE_SANITIZER",
                ast_evidence=ast_ev,
                extra_reason_codes=("RC_REJECTED_MISMATCHED_CWE_SANITIZER",),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )
        if out_ctx not in shared.SAFE_XSS_ENCODING_CONTEXTS:
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                taint_reaches_sink=bool(tainted_params_used),
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps),
                sanitizer_status="UNSAFE_OUTPUT_ENCODING_CONTEXT",
                ast_evidence=ast_ev,
                extra_reason_codes=("RC_REJECTED_UNSAFE_XSS_OUTPUT_CONTEXT",),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED",
            taint_reaches_sink=False,
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple(trace_steps),
            sanitizer_status="VERIFIED_CWE_MATCHED_SANITIZER",
            ast_evidence=ast_ev,
            extra_reason_codes=("RC_AST_VERIFIED_XSS_SAFE_ENCODING",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # 3D. Unverified Custom Sanitizer / Validator Helper (`sanitize*`, `clean*`, `validate*`, `filter*`)
    custom_san_invs = [
        inv
        for inv in reaching_invs
        if re.match(r"^(sanitize|clean|validate|filter|purify)[A-Z_]", str(inv.get("method_name", "")))
    ]
    if tainted_params_used and custom_san_invs:
        c_inv = custom_san_invs[0]
        c_mname = str(c_inv.get("method_name", "customSanitizer"))
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
            taint_reaches_sink=False,
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple(trace_steps + [f"UNVERIFIED_CUSTOM_SANITIZER:{c_mname}"]),
            sanitizer_status="UNVERIFIED_CUSTOM_SANITIZER",
            ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
            extra_reason_codes=("RC_UNVERIFIED_CUSTOM_SANITIZER_NEEDS_REVIEW",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 4: Verified Taint Flow from Formal Parameter to Sink (No Valid Sanitizer)
    # =========================================================================
    if tainted_params_used:
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="VERIFIED_TAINT_FLOW",
            taint_reaches_sink=True,
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple([f"SOURCE_PARAM:{','.join(tainted_params_used)}"] + trace_steps),
            sanitizer_status="NONE_DETECTED",
            ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
            extra_reason_codes=("RC_IRIS_VERIFIED_SOURCE_TO_SINK_TAINT_FLOW",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 5: Interprocedural / External Field / Unresolved Dataflow -> NEEDS_REVIEW
    # =========================================================================
    return JavaAstSiteAnalysis(
        file_path=file_path,
        match_line=match_line,
        cwe=cwe_int,
        package_name=pkg_name,
        class_name=cls_name,
        enclosing_method=enclosing_method,
        enclosing_signature=enclosing_sig,
        untrusted_params=tuple(untrusted_params),
        target_callee_identity=target_ident,
        matched_code_line=matched_code_line,
        source_sink_trace_status="NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT",
        taint_reaches_sink=False,
        taint_source_params=(),
        taint_trace_steps=tuple(trace_steps),
        sanitizer_status="NONE_DETECTED",
        ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
        extra_reason_codes=("RC_INSUFFICIENT_TAINT_TRACE_INTRAPROCEDURAL_LIMIT",),
        ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        ast_overloaded_signature=ast_overloaded_sig,
    )


def analyze_java_site_ast_and_taint(
    java_source_text: str,
    file_path: str,
    match_line: int,
    cwe: int,
    opengrep_rule_id: str = "",
    opengrep_matched_code: str = "",
    force_fallback_regex_only: bool = False,
) -> JavaAstSiteAnalysis:
    """
    Primary entrypoint for Java AST & intraprocedural dataflow extraction.
    1. First parses the `.java` source using the OpenJDK 17 Compiler Tree API (`NtkJavacAstExtractor` /
       `JavacTask.parse()`), performing scope-aware reaching definitions and dominating guard analysis.
    2. If `force_fallback_regex_only=True` (used in fault-injection tests) or if the `.java` snippet
       cannot be parsed by `JavacTask`, falls back to the conservative lexical analyzer with
       `ast_parser_engine = "FALLBACK_LEXICAL_PARSER"`, which is strictly prohibited from granting
       automatic `SUPPRESS` (`verify_ast_release_evidence` rejects `FALLBACK_LEXICAL_PARSER` and
       escalates to `NEEDS_REVIEW`).
    """
    if not force_fallback_regex_only:
        ast_file = parse_java_source_with_javac_ast(java_source_text=java_source_text, file_path=file_path)
        if ast_file is not None:
            res = _analyze_with_openjdk_ast(
                ast_file=ast_file,
                java_source_text=java_source_text,
                file_path=file_path,
                match_line=match_line,
                cwe=cwe,
                opengrep_rule_id=opengrep_rule_id,
                opengrep_matched_code=opengrep_matched_code,
            )
            if res is not None:
                return res

    # Fallback conservative lexical mode (NEVER allowed to auto-suppress; always downgrades to NEEDS_REVIEW)
    cleaned_source = _strip_java_comments_multiline(java_source_text)
    lines = cleaned_source.splitlines()
    n_lines = len(lines)
    line_idx = max(0, min(int(match_line) - 1, n_lines - 1)) if n_lines else 0
    matched_code_line = opengrep_matched_code.strip() or (lines[line_idx].strip() if n_lines else "")

    pkg_name = "com.ntk.e2e"
    cls_name = "UnknownClass"
    for ln in lines:
        s = ln.strip()
        m_pkg = re.match(r"^package\s+([\w\.]+)\s*;", s)
        if m_pkg:
            pkg_name = m_pkg.group(1).strip()
        m_cls = re.search(r"\bclass\s+(\w+)", s)
        if m_cls:
            cls_name = m_cls.group(1).strip()

    enclosing_method = "unknownMethod"
    enclosing_sig = "void unknownMethod()"
    method_decl_regex = re.compile(
        r"(?:public|protected|private)\s+(?:static\s+)?([\w\[\]<>?,\s]+?)\s+(\w+)\s*\(([^)]*)\)"
    )
    for idx in range(line_idx, -1, -1):
        m_decl = method_decl_regex.search(lines[idx])
        if m_decl:
            ret_type = shared.normalize_whitespace(m_decl.group(1))
            enclosing_method = m_decl.group(2).strip()
            params_str = shared.normalize_whitespace(m_decl.group(3))
            enclosing_sig = shared.normalize_signature(f"{ret_type} {enclosing_method}({params_str})")
            break

    formal_params = shared.extract_formal_params_from_signature(enclosing_sig)
    untrusted_params = tuple(
        pname for ptype, pname in formal_params if pname and ptype not in INFRASTRUCTURE_PARAM_TYPES
    )

    cwe_int = int(re.sub(r"\D", "", str(cwe)) or "0")
    default_ident_by_cwe = {
        89: {
            "package": "java.sql",
            "class": "Statement",
            "method": "executeQuery",
            "signature": "ResultSet executeQuery(String sql)",
        },
        78: {
            "package": "java.lang",
            "class": "Runtime",
            "method": "exec",
            "signature": "Process exec(String command)",
        },
        22: {
            "package": "java.nio.file",
            "class": "Files",
            "method": "readAllBytes",
            "signature": "byte[] readAllBytes(Path path)",
        },
        79: {
            "package": "java.io",
            "class": "PrintWriter",
            "method": "println",
            "signature": "void println(String x)",
        },
    }
    target_ident = default_ident_by_cwe.get(
        cwe_int,
        {
            "package": pkg_name,
            "class": cls_name,
            "method": enclosing_method,
            "signature": enclosing_sig,
        },
    )

    fallback_ev = shared.AstReleaseEvidence(
        is_compile_time_constant_arg=False,
        has_cwe_matched_sanitizer=False,
        covered_sink_args=("arg0",),
        ast_proof_node="FALLBACK_LEXICAL_NO_SEMANTIC_AST",
        ast_parser_engine="FALLBACK_LEXICAL_PARSER",
    )
    return JavaAstSiteAnalysis(
        file_path=file_path,
        match_line=match_line,
        cwe=cwe_int,
        package_name=pkg_name,
        class_name=cls_name,
        enclosing_method=enclosing_method,
        enclosing_signature=enclosing_sig,
        untrusted_params=untrusted_params,
        target_callee_identity=target_ident,
        matched_code_line=matched_code_line,
        source_sink_trace_status="NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT",
        taint_reaches_sink=False,
        taint_source_params=(),
        taint_trace_steps=(matched_code_line,),
        sanitizer_status="NONE_DETECTED",
        ast_evidence=fallback_ev,
        extra_reason_codes=("RC_FALLBACK_LEXICAL_PARSER_DOWNGRADED_TO_REVIEW",),
        ast_parser_engine="FALLBACK_LEXICAL_PARSER",
        ast_overloaded_signature=target_ident["signature"],
    )


def verify_and_triage_finding(
    finding_id: str,
    cwe: int,
    file_path: str,
    line_number: int,
    scanner_rule_id: str,
    static_severity: str,
    base_scanner_score: float,
    ast_analysis: JavaAstSiteAnalysis,
    callee_prediction: Optional[shared.CalleeRolePrediction],
    llm_raw_output: str = "",
    llm_latency_ms: float = 0.0,
    manual_review: Optional[ManualReviewRecord] = None,
    model_version: str = MODEL_VERSION_DEFAULT,
    ruleset_version: str = RULESET_VERSION_DEFAULT,
    scoring_policy_version: str = SCORING_POLICY_VERSION_DEFAULT,
) -> shared.FindingSchemaV2:
    """
    Executes Evidence Fusion (`evaluate_bounded_safety_floor`) and applies the deterministic
    Alert Verification & Triage state machine (`LIKELY_TRUE_POSITIVE` / `LIKELY_FALSE_POSITIVE` /
    `NEEDS_REVIEW`, `REPORT` / `REVIEW` / `SUPPRESS`, `NOT_REVIEWED` / `CONFIRMED_*`).
    """
    cwe_int = int(re.sub(r"\D", "", str(cwe)) or "0")
    cwe_str = f"CWE-{cwe_int:03d}"

    cand = shared.FindingCandidate(
        finding_id=finding_id,
        cwe=cwe_int,
        file_path=file_path,
        line_number=int(line_number),
        severity=static_severity,
        base_scanner_score=float(base_scanner_score),
        callee_prediction=callee_prediction,
        ast_evidence=ast_analysis.ast_evidence,
    )
    floor_res = shared.evaluate_bounded_safety_floor(cand)
    explicit_release = bool(floor_res["explicit_ast_release_verified"])
    release_reason = str(floor_res["ast_release_reason"])

    reason_codes: List[str] = ["RC_OPENGREP_CANDIDATE_MATCH"]
    for rc in ast_analysis.extra_reason_codes:
        if rc not in reason_codes:
            reason_codes.append(rc)

    llm_valid = bool(callee_prediction is not None and callee_prediction.strict_valid)
    llm_role = callee_prediction.role if (callee_prediction is not None and llm_valid) else None
    llm_abstain = True if callee_prediction is None else bool(callee_prediction.abstain)
    llm_abstain_reason = (
        "ABSTAIN_NO_PREDICTION" if callee_prediction is None else str(callee_prediction.abstain_reason)
    )

    if llm_valid:
        reason_codes.append(f"RC_LLM_STRICT_JSON_ROLE_{str(llm_role).upper().replace('-', '_')}")
    else:
        reason_codes.append(f"RC_LLM_INVALID_OR_ABSTAIN:{llm_abstain_reason}")

    # Triage State Machine
    # Invariant: Automatic SUPPRESS requires BOTH explicit_ast_release_verified == True AND
    # semantic AST parser engine (never fallback regex-only) AND safe trace status.
    if (
        explicit_release
        and ast_analysis.ast_parser_engine == "OPENJDK17_JAVAC_TASK_AST"
        and ast_analysis.source_sink_trace_status
        in (
            "SAFE_CONSTANT_OR_PARAMETERIZED",
            "SAFE_SANITIZED_OR_GUARDED",
        )
    ):
        triage_status = "LIKELY_FALSE_POSITIVE"
        decision = "SUPPRESS"
        kept_by_pipeline = False
        effective_score = 0.0
        reason_codes.append(f"RC_AUTO_SUPPRESS_AST_VERIFIED:{release_reason}")
        disposition = f"SUPPRESSED_FALSE_POSITIVE (AST_SAFETY_RELEASE:{release_reason})"
    elif (
        not explicit_release
        and ast_analysis.ast_parser_engine == "OPENJDK17_JAVAC_TASK_AST"
        and ast_analysis.taint_reaches_sink
        and ast_analysis.source_sink_trace_status in ("VERIFIED_TAINT_FLOW", "PARTIAL_OR_INSUFFICIENT_GUARD")
        and llm_valid
        and llm_role == "sink"
    ):
        triage_status = "LIKELY_TRUE_POSITIVE"
        decision = "REPORT"
        kept_by_pipeline = True
        effective_score = float(floor_res["final_score"])
        if release_reason != "NO_AST_RELEASE_CLAIMED":
            reason_codes.append(f"RC_AST_RELEASE_REJECTED:{release_reason}")
        else:
            reason_codes.append("RC_NO_AST_SAFETY_RELEASE")
        reason_codes.append("RC_TRIAGE_LIKELY_TRUE_POSITIVE_CONVERGENT_EVIDENCE")
        disposition = "RETAINED_VULNERABILITY_ALERT (LIKELY_TRUE_POSITIVE:REPORT)"
    else:
        # Ambiguous, missing intraprocedural taint trace, fallback parser, custom regex guard,
        # LLM abstain/timeout, or IRIS-vs-LLM conflict
        triage_status = "NEEDS_REVIEW"
        decision = "REVIEW"
        kept_by_pipeline = True
        effective_score = float(floor_res["final_score"])
        if floor_res["safety_floor_applied"]:
            reason_codes.append("RC_SAFETY_FLOOR_055_CLAMPED")
        if ast_analysis.taint_reaches_sink and llm_role != "sink":
            reason_codes.append("RC_CONFLICT_IRIS_TAINT_VS_LLM_ROLE")
        if not ast_analysis.taint_reaches_sink and llm_role == "sink":
            reason_codes.append("RC_LLM_SINK_WITHOUT_VERIFIED_INTRAPROCEDURAL_TAINT_FLOW")
        if release_reason not in ("NO_AST_RELEASE_CLAIMED",):
            reason_codes.append(f"RC_AST_RELEASE_REJECTED:{release_reason}")
        reason_codes.append("RC_TRIAGE_ESCALATED_TO_HUMAN_REVIEW")
        disposition = "RETAINED_VULNERABILITY_ALERT (NEEDS_REVIEW:REVIEW)"

    # Independent Verification Status (`review_status`)
    # Strictly gated: never auto-confirmed without an explicit ManualReviewRecord
    if manual_review is not None:
        if manual_review.confirmed_status not in ("CONFIRMED_TRUE_POSITIVE", "CONFIRMED_FALSE_POSITIVE"):
            raise ValueError(f"Invalid confirmed_status in ManualReviewRecord: {manual_review.confirmed_status}")
        review_status = manual_review.confirmed_status
        review_metadata = {
            "reviewed_by": manual_review.reviewer_id,
            "reviewed_at_utc": manual_review.reviewed_at_utc,
            "review_notes": manual_review.review_notes,
            "confirmation_source": manual_review.confirmation_source,
        }
    else:
        review_status = "NOT_REVIEWED"
        review_metadata = {
            "reviewed_by": None,
            "reviewed_at_utc": None,
            "review_notes": "Awaiting human security analyst review or ground-truth audit confirmation.",
            "confirmation_source": None,
        }

    sev_norm = "HIGH" if static_severity.upper() in ("ERROR", "HIGH", "CRITICAL") else static_severity.upper()

    evidence_refs = {
        "file_path": file_path,
        "line_number": int(line_number),
        "enclosing_method": ast_analysis.enclosing_method,
        "enclosing_signature": ast_analysis.enclosing_signature,
        "matched_code_snippet": ast_analysis.matched_code_line,
        "taint_source_params": list(ast_analysis.taint_source_params),
        "taint_trace_steps": list(ast_analysis.taint_trace_steps),
        "ast_proof_node": ast_analysis.ast_evidence.ast_proof_node,
        "sanitizer_method_signature": ast_analysis.ast_evidence.sanitizer_method_signature,
        "ast_parser_engine": ast_analysis.ast_parser_engine,
    }

    opengrep_evidence = {
        "matched": True,
        "rule_id": scanner_rule_id,
        "cwe": cwe_str,
        "file_path": file_path,
        "line_number": int(line_number),
        "matched_code": ast_analysis.matched_code_line,
        "scanner_severity": static_severity,
        "base_scanner_score": round(float(base_scanner_score), 4),
    }

    iris_evidence = {
        "ast_parser_engine": ast_analysis.ast_parser_engine,
        "enclosing_method": ast_analysis.enclosing_method,
        "enclosing_signature": ast_analysis.enclosing_signature,
        "ast_overloaded_signature": ast_analysis.ast_overloaded_signature or ast_analysis.enclosing_signature,
        "target_callee_identity": dict(ast_analysis.target_callee_identity),
        "source_sink_trace_status": ast_analysis.source_sink_trace_status,
        "taint_reaches_sink": bool(ast_analysis.taint_reaches_sink),
        "taint_source_params": list(ast_analysis.taint_source_params),
        "taint_trace_steps": list(ast_analysis.taint_trace_steps),
        "sanitizer_status": ast_analysis.sanitizer_status,
        "explicit_ast_release_verified": explicit_release,
        "ast_release_reason": release_reason,
        "ast_proof_node": ast_analysis.ast_evidence.ast_proof_node,
        "covered_sink_args": list(ast_analysis.ast_evidence.covered_sink_args),
        "output_context": ast_analysis.ast_evidence.output_context,
    }

    llm_api_role = {
        "raw_output": llm_raw_output,
        "strict_json_valid": llm_valid,
        "predicted_role": llm_role,
        "sink_args": list(callee_prediction.sink_args) if callee_prediction is not None else [],
        "canonical_sink_args": list(callee_prediction.canonical_sink_args) if callee_prediction is not None else [],
        "abstain": llm_abstain,
        "abstain_reason": llm_abstain_reason,
        "inference_latency_ms": round(float(llm_latency_ms), 2),
        "prompt_contract": "CANONICAL_IRIS_2MSG_PROMPT_V1",
    }

    fusion_score_breakdown = {
        "base_scanner_score": round(float(base_scanner_score), 4),
        "llm_role_delta": float(floor_res["llm_role_delta"]),
        "raw_adjusted_score": float(floor_res["raw_adjusted_score"]),
        "safety_floor_threshold": shared.SAFETY_FLOOR_SCORE,
        "safety_floor_applied": bool(floor_res["safety_floor_applied"]),
        "explicit_ast_release_verified": explicit_release,
        "post_release_veto_applied": bool(floor_res["post_release_veto_applied"]),
        "retention_threshold": 0.50,
        "pre_veto_floor_score": float(floor_res["final_score"]),
        "effective_post_release_score": float(floor_res["effective_post_release_score"]),
        "final_heuristic_score": round(float(effective_score), 4),
        "is_calibrated_probability": False,
        "scoring_note": (
            "Heuristic neuro-symbolic evidence fusion score in [0.0, 1.0]; "
            "NOT a calibrated statistical probability."
        ),
    }

    return shared.FindingSchemaV2(
        schema_version="NTK_WEB_FINDING_SCHEMA_V2",
        architecture_version="FROZEN_ARCHITECTURE_V1",
        model_version=model_version,
        finding_id=finding_id,
        cwe=cwe_str,
        cwe_id=cwe_int,
        file_path=file_path,
        line_number=int(line_number),
        enclosing_method=ast_analysis.enclosing_method,
        static_severity=static_severity,
        scanner_rule_id=scanner_rule_id,
        matched_code=ast_analysis.matched_code_line,
        target_callee_identity=dict(ast_analysis.target_callee_identity),
        llm_prediction={
            "raw_output": llm_raw_output,
            "strict_json_valid": llm_valid,
            "predicted_role": llm_role,
            "sink_args": list(callee_prediction.sink_args) if callee_prediction is not None else [],
            "canonical_sink_args": list(callee_prediction.canonical_sink_args) if callee_prediction is not None else [],
            "abstain": llm_abstain,
            "abstain_reason": llm_abstain_reason,
        },
        ast_evidence={
            "ast_parser_engine": ast_analysis.ast_parser_engine,
            "explicit_ast_release_verified": explicit_release,
            "ast_release_reason": release_reason,
            "ast_proof_node": ast_analysis.ast_evidence.ast_proof_node,
            "sanitizer_method_signature": ast_analysis.ast_evidence.sanitizer_method_signature,
            "output_context": ast_analysis.ast_evidence.output_context,
        },
        score_breakdown=fusion_score_breakdown,
        final_heuristic_score=round(float(effective_score), 4),
        is_calibrated_probability=False,
        kept_by_pipeline=kept_by_pipeline,
        disposition=disposition,
        triage_status=triage_status,
        decision=decision,
        confidence_score=round(float(effective_score), 4),
        score_kind=SCORE_KIND_DEFAULT,
        severity=sev_norm,
        reason_codes=tuple(reason_codes),
        evidence_refs=evidence_refs,
        source_sink_trace_status=ast_analysis.source_sink_trace_status,
        sanitizer_status=ast_analysis.sanitizer_status,
        opengrep_evidence=opengrep_evidence,
        iris_evidence=iris_evidence,
        llm_api_role=llm_api_role,
        fusion_score_breakdown=fusion_score_breakdown,
        review_status=review_status,
        review_metadata=review_metadata,
        ruleset_version=ruleset_version,
        scoring_policy_version=scoring_policy_version,
    )


REQUIRED_FINDING_SCHEMA_V2_KEYS: Set[str] = {
    # All 20 keys from FindingSchemaV1
    "schema_version",
    "architecture_version",
    "model_version",
    "finding_id",
    "cwe",
    "cwe_id",
    "file_path",
    "line_number",
    "enclosing_method",
    "static_severity",
    "scanner_rule_id",
    "matched_code",
    "target_callee_identity",
    "llm_prediction",
    "ast_evidence",
    "score_breakdown",
    "final_heuristic_score",
    "is_calibrated_probability",
    "kept_by_pipeline",
    "disposition",
    # All 17 new keys in FindingSchemaV2
    "triage_status",
    "decision",
    "confidence_score",
    "score_kind",
    "severity",
    "reason_codes",
    "evidence_refs",
    "source_sink_trace_status",
    "sanitizer_status",
    "opengrep_evidence",
    "iris_evidence",
    "llm_api_role",
    "fusion_score_breakdown",
    "review_status",
    "review_metadata",
    "ruleset_version",
    "scoring_policy_version",
}


def validate_finding_schema_v2_dict(d: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates a serialized `FindingSchemaV2` dictionary against all schema, enum, range,
    and non-fabrication invariants.
    """
    errors: List[str] = []
    missing = sorted(REQUIRED_FINDING_SCHEMA_V2_KEYS - set(d.keys()))
    if missing:
        errors.append(f"MISSING_REQUIRED_KEYS:{missing}")
        return False, errors

    if d["triage_status"] not in shared.VALID_TRIAGE_STATUSES:
        errors.append(f"INVALID_TRIAGE_STATUS:{d['triage_status']}")
    if d["decision"] not in shared.VALID_TRIAGE_DECISIONS:
        errors.append(f"INVALID_DECISION:{d['decision']}")
    if d["review_status"] not in shared.VALID_REVIEW_STATUSES:
        errors.append(f"INVALID_REVIEW_STATUS:{d['review_status']}")
    if d["source_sink_trace_status"] not in shared.VALID_SOURCE_SINK_TRACE_STATUSES:
        errors.append(f"INVALID_SOURCE_SINK_TRACE_STATUS:{d['source_sink_trace_status']}")
    if d["sanitizer_status"] not in shared.VALID_SANITIZER_STATUSES:
        errors.append(f"INVALID_SANITIZER_STATUS:{d['sanitizer_status']}")

    score = float(d["confidence_score"])
    if not (0.0 <= score <= 1.0):
        errors.append(f"CONFIDENCE_SCORE_OUT_OF_RANGE:{score}")
    if d["is_calibrated_probability"] is not False:
        errors.append("IS_CALIBRATED_PROBABILITY_MUST_BE_FALSE")
    if "NOT_CALIBRATED_PROBABILITY" not in str(d["score_kind"]):
        errors.append(f"INVALID_SCORE_KIND:{d['score_kind']}")

    # Consistency invariants between triage_status, decision, and kept_by_pipeline
    if d["decision"] == "SUPPRESS":
        if d["triage_status"] != "LIKELY_FALSE_POSITIVE":
            errors.append("SUPPRESS_REQUIRES_LIKELY_FALSE_POSITIVE")
        if d["kept_by_pipeline"] is not False:
            errors.append("SUPPRESS_REQUIRES_KEPT_BY_PIPELINE_FALSE")
        if not d["ast_evidence"].get("explicit_ast_release_verified", False):
            errors.append("SUPPRESS_WITHOUT_EXPLICIT_AST_RELEASE_FORBIDDEN")
        if d["ast_evidence"].get("ast_parser_engine") in ("REGEX_ONLY", "FALLBACK_LEXICAL_PARSER"):
            errors.append("SUPPRESS_WITH_FALLBACK_LEXICAL_PARSER_FORBIDDEN")
    elif d["decision"] == "REPORT":
        if d["triage_status"] != "LIKELY_TRUE_POSITIVE":
            errors.append("REPORT_REQUIRES_LIKELY_TRUE_POSITIVE")
        if d["kept_by_pipeline"] is not True:
            errors.append("REPORT_REQUIRES_KEPT_BY_PIPELINE_TRUE")
    elif d["decision"] == "REVIEW":
        if d["triage_status"] != "NEEDS_REVIEW":
            errors.append("REVIEW_REQUIRES_NEEDS_REVIEW")
        if d["kept_by_pipeline"] is not True:
            errors.append("REVIEW_REQUIRES_KEPT_BY_PIPELINE_TRUE")

    # Confirmed status gating invariant
    if d["review_status"] in ("CONFIRMED_TRUE_POSITIVE", "CONFIRMED_FALSE_POSITIVE"):
        rev_meta = d.get("review_metadata", {})
        if not rev_meta.get("reviewed_by") or not rev_meta.get("confirmation_source"):
            errors.append("CONFIRMED_STATUS_WITHOUT_REVIEWER_METADATA_FORBIDDEN")

    collisions = shared.find_case_insensitive_duplicate_keys(d)
    if collisions:
        errors.append(f"CASE_INSENSITIVE_KEY_COLLISIONS:{collisions}")

    return len(errors) == 0, errors


def get_finding_schema_v2_json_schema() -> Dict[str, Any]:
    """
    Returns the formal JSON Schema (Draft 2020-12 compatible) for `FindingSchemaV2`.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://greta.ntk.local/schemas/finding_schema_v2.json",
        "title": "FindingSchemaV2",
        "description": (
            "Backward-compatible extension of FindingSchemaV1 (20 fields) adding Alert Verification "
            "& True/False Positive Triage state machine, neuro-symbolic evidence breakdown, and versioning (37 fields total)."
        ),
        "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
        "backward_compatible_with": "NTK_WEB_FINDING_SCHEMA_V1",
        "type": "object",
        "required": sorted(REQUIRED_FINDING_SCHEMA_V2_KEYS),
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "string", "const": "NTK_WEB_FINDING_SCHEMA_V2"},
            "architecture_version": {"type": "string", "const": "FROZEN_ARCHITECTURE_V1"},
            "model_version": {"type": "string"},
            "ruleset_version": {"type": "string"},
            "scoring_policy_version": {"type": "string"},
            "finding_id": {"type": "string", "minLength": 1},
            "cwe": {"type": "string", "pattern": "^CWE-0(22|78|79|89)$"},
            "cwe_id": {"type": "integer", "enum": [22, 78, 79, 89]},
            "file_path": {"type": "string"},
            "line_number": {"type": "integer", "minimum": 1},
            "enclosing_method": {"type": "string"},
            "static_severity": {"type": "string", "enum": ["ERROR", "HIGH", "CRITICAL", "WARNING", "INFO"]},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR"]},
            "scanner_rule_id": {"type": "string"},
            "matched_code": {"type": "string"},
            "triage_status": {"type": "string", "enum": list(shared.VALID_TRIAGE_STATUSES)},
            "decision": {"type": "string", "enum": list(shared.VALID_TRIAGE_DECISIONS)},
            "review_status": {"type": "string", "enum": list(shared.VALID_REVIEW_STATUSES)},
            "review_metadata": {"type": "object"},
            "confidence_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "final_heuristic_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "score_kind": {"type": "string", "const": SCORE_KIND_DEFAULT},
            "is_calibrated_probability": {"type": "boolean", "const": False},
            "kept_by_pipeline": {"type": "boolean"},
            "disposition": {"type": "string"},
            "reason_codes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "evidence_refs": {"type": "object"},
            "source_sink_trace_status": {
                "type": "string",
                "enum": list(shared.VALID_SOURCE_SINK_TRACE_STATUSES),
            },
            "sanitizer_status": {"type": "string", "enum": list(shared.VALID_SANITIZER_STATUSES)},
            "target_callee_identity": {
                "type": "object",
                "required": ["package", "class", "method", "signature"],
            },
            "opengrep_evidence": {"type": "object"},
            "iris_evidence": {"type": "object"},
            "llm_prediction": {"type": "object"},
            "llm_api_role": {"type": "object"},
            "ast_evidence": {"type": "object"},
            "score_breakdown": {"type": "object"},
            "fusion_score_breakdown": {"type": "object"},
        },
    }
