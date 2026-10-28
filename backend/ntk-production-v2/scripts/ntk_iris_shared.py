#!/usr/bin/env python3
"""
NTK EO05 Overnight - Shared Contract & Neuro-Symbolic Verification Module (`ntk_iris_shared.py`)
Architecture: EO04.2 FROZEN_ARCHITECTURE_V1

Responsibilities:
1. Physical 6-key JSON wire contract (`{"package", "class", "method", "signature", "sink_args", "type"}`)
   with Python dataclass attribute `.class_name` mapped from wire key `"class"`.
2. Two-mechanism sink argument validation (`ARGUMENT_SINK` vs `RECEIVER_STATE_SINK` with `["this"]`),
   including strict bounds checking on nameless-parameter signatures (Work Package D repair).
3. Two-tier split isolation keys (`api_family_without_cwe` without CWE dimension; Tier-A third-party class
   isolation including Spring & Apache Commons vs Tier-B core JDK/Jakarta method-family isolation).
4. Bounded Safety Floor (`evaluate_bounded_safety_floor`) with structural AST release verification
   (`verify_ast_release_evidence`).
5. Exact Maximum-Cardinality Minimum-Cost Bipartite Matching (`_solve_min_cost_max_bipartite_matching`,
   `global_bipartite_match_findings`) and combinatorial brute-force oracle (`brute_force_bipartite_oracle`).
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

VALID_ROLES: Tuple[str, ...] = ("source", "sink", "taint-propagator", "none")
TARGET_CWES: Tuple[int, ...] = (22, 78, 79, 89)
REQUIRED_JSON_KEYS: Set[str] = {
    "package",
    "class",
    "method",
    "signature",
    "sink_args",
    "type",
}

CORE_JAVA_PREFIXES: Tuple[str, ...] = (
    "java.",
    "javax.",
    "jakarta.",
    "jdk.",
    "org.w3c.dom",
    "org.xml.sax",
)

SAFETY_FLOOR_SCORE: float = 0.55
HIGH_SEVERITY_LEVELS: Set[str] = {"HIGH", "CRITICAL", "ERROR"}

SAFE_XSS_ENCODING_CONTEXTS: Set[str] = {"HTML_BODY", "HTML_ATTRIBUTE_QUOTED"}

APPROVED_CWE_SANITIZER_SIGNATURES: Dict[int, Set[str]] = {
    22: {
        "java.nio.file.Path::normalize",
        "org.apache.commons.io.FilenameUtils::getName",
    },
    78: {
        "org.owasp.esapi.Encoder::encodeForOS",
    },
    79: {
        "org.owasp.encoder.Encode::forHtml",
        "org.owasp.encoder.Encode::forHtmlContent",
        "org.owasp.encoder.Encode::forHtmlAttribute",
        "org.owasp.esapi.Encoder::encodeForHTML",
        "org.owasp.esapi.Encoder::encodeForHTMLAttribute",
        "org.apache.commons.lang.StringEscapeUtils::escapeHtml",
        "org.apache.commons.lang3.StringEscapeUtils::escapeHtml4",
        "org.apache.commons.text.StringEscapeUtils::escapeHtml4",
        "org.springframework.web.util.HtmlUtils::htmlEscape",
        "org.jsoup.Jsoup::clean",
    },
    89: {
        "java.sql.PreparedStatement::setString",
        "java.sql.PreparedStatement::setInt",
        "java.sql.PreparedStatement::setLong",
        "java.sql.PreparedStatement::setObject",
        "java.sql.PreparedStatement::setBoolean",
        "java.sql.CallableStatement::setString",
        "java.sql.CallableStatement::setInt",
    },
}

KNOWN_ZERO_PARAM_RECEIVER_SINKS: Set[Tuple[int, str, str, str]] = {
    (78, "java.lang", "ProcessBuilder", "start"),
    (78, "org.codehaus.plexus.util.cli", "Commandline", "execute"),
    (78, "com.jcraft.jsch", "ChannelExec", "start"),
    (78, "org.zeroturnaround.exec", "ProcessExecutor", "execute"),
    (78, "org.zeroturnaround.exec", "ProcessExecutor", "executeNoTimeout"),
    (78, "org.zeroturnaround.exec", "ProcessExecutor", "start"),
    (78, "net.schmizz.sshj.connection.channel.direct", "Session", "startShell"),
    (78, "org.apache.commons.exec", "CommandLine", "toStrings"),
}


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip())


def normalize_outer_class(cls_name: str) -> str:
    cleaned = normalize_whitespace(cls_name)
    if "$" in cleaned:
        return cleaned.split("$", 1)[0].strip()
    return cleaned


def is_core_java_package(package_name: str) -> bool:
    pkg = normalize_whitespace(package_name)
    return any(pkg == p.rstrip(".") or pkg.startswith(p) for p in CORE_JAVA_PREFIXES)


def api_family_without_cwe(package_name: str, class_name: str, method_name: str) -> str:
    pkg = normalize_whitespace(package_name)
    outer_cls = normalize_outer_class(class_name)
    m = normalize_whitespace(method_name)
    return f"{pkg}.{outer_cls}::{m}"


def third_party_class_key(package_name: str, class_name: str) -> Optional[str]:
    if is_core_java_package(package_name):
        return None
    pkg = normalize_whitespace(package_name)
    outer_cls = normalize_outer_class(class_name)
    return f"{pkg}.{outer_cls}"


def normalize_signature(signature: str) -> str:
    sig = normalize_whitespace(signature)
    sig = re.sub(r"\s*\(\s*", "(", sig)
    sig = re.sub(r"\s*\)\s*", ")", sig)
    sig = re.sub(r"\s*,\s*", ", ", sig)
    return sig


def cwe_conditioned_sample_key(
    cwe: int,
    package_name: str,
    class_name: str,
    method_name: str,
    signature: str,
) -> Tuple[int, str, str, str, str]:
    return (
        int(cwe),
        normalize_whitespace(package_name),
        normalize_whitespace(class_name),
        normalize_whitespace(method_name),
        normalize_signature(signature),
    )


def _split_top_level_params(param_blob: str) -> List[str]:
    blob = param_blob.strip()
    if not blob:
        return []
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in blob:
        if ch == "<":
            depth += 1
            cur.append(ch)
        elif ch == ">":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def extract_formal_params_from_signature(signature: str) -> List[Tuple[str, Optional[str]]]:
    """
    Extracts a list of (param_type, param_name_or_None) from a Java method/constructor signature.
    """
    sig = normalize_whitespace(signature)
    lpar = sig.find("(")
    rpar = sig.rfind(")")
    if lpar == -1 or rpar == -1 or rpar < lpar:
        return []
    inner = sig[lpar + 1 : rpar].strip()
    if not inner:
        return []
    raw_params = _split_top_level_params(inner)
    parsed: List[Tuple[str, Optional[str]]] = []
    for rp in raw_params:
        cleaned = re.sub(r"\bfinal\b", "", rp).strip()
        tokens = cleaned.split()
        if len(tokens) >= 2:
            pname = tokens[-1].strip()
            ptype = " ".join(tokens[:-1]).strip()
            if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", pname):
                parsed.append((ptype, pname))
            else:
                parsed.append((cleaned, None))
        else:
            parsed.append((cleaned, None))
    return parsed


def validate_and_canonicalize_sink_args(
    role: str,
    sink_args: Sequence[Any],
    signature: str,
    cwe: Optional[int] = None,
    package_name: str = "",
    class_name: str = "",
    method_name: str = "",
) -> Tuple[bool, str, Tuple[str, ...]]:
    """
    Validates sink_args under EO04.2 PATCH A + EO05 Work Package D bounds fix:
      - If role != 'sink': sink_args MUST be empty.
      - If role == 'sink':
          * For 0-parameter methods: only valid if sink_args == ['this'] (RECEIVER_STATE_SINK).
          * For methods with >= 1 parameters: each sink_arg must match a formal parameter name,
            or positional 'argK' / 'pK' / 'paramK' / bare integer 'K' within [0, num_params - 1],
            or 'this' if explicitly receiver-state sink.
    """
    if not isinstance(sink_args, (list, tuple)):
        return False, "ABSTAIN_SINK_ARGS_NOT_LIST", ()
    raw_items = [str(x).strip() for x in sink_args if str(x).strip()]
    if len(raw_items) != len(list(sink_args)):
        return False, "ABSTAIN_EMPTY_STRING_IN_SINK_ARGS", ()

    if role != "sink":
        if raw_items:
            return False, "ABSTAIN_NON_SINK_HAS_SINK_ARGS", ()
        return True, "OK_NON_SINK_EMPTY_ARGS", ()

    if not raw_items:
        return False, "ABSTAIN_SINK_MISSING_SINK_ARGS", ()

    params = extract_formal_params_from_signature(signature)
    num_params = len(params)
    formal_names = [pname for _, pname in params if pname is not None]

    if num_params == 0:
        if raw_items == ["this"]:
            return True, "OK_RECEIVER_STATE_ZERO_PARAM_SINK", ("this",)
        return False, "ABSTAIN_ZERO_PARAM_SINK_REQUIRES_THIS", ()

    canonical: List[str] = []
    for item in raw_items:
        if item == "this":
            if "this" not in canonical:
                canonical.append("this")
            continue
        if item in formal_names:
            if item not in canonical:
                canonical.append(item)
            continue
        m_pos = re.match(r"^(?:arg|param|p)?(\d+)$", item, flags=re.IGNORECASE)
        if m_pos:
            # Bare integer index '0', '1' is only allowed when signature lacks formal parameter names
            is_bare_int = item.isdigit()
            if is_bare_int and formal_names:
                return False, f"ABSTAIN_BARE_INDEX_WHEN_FORMAL_NAMES_PRESENT:{item}", ()
            idx = int(m_pos.group(1))
            if 0 <= idx < num_params:
                mapped = params[idx][1] or f"arg{idx}"
                if mapped not in canonical:
                    canonical.append(mapped)
                continue
            return False, f"ABSTAIN_SINK_ARG_INDEX_OUT_OF_RANGE:{item}", ()
        return False, f"ABSTAIN_UNKNOWN_SINK_ARG_NAME:{item}", ()

    return True, "OK_ARGUMENT_SINK", tuple(canonical)


@dataclass(frozen=True)
class CalleeRolePrediction:
    package: str
    class_name: str
    method: str
    signature: str
    role: str
    sink_args: Tuple[str, ...]
    canonical_sink_args: Tuple[str, ...]
    strict_valid: bool
    abstain: bool
    abstain_reason: str
    raw_wire_dict: Dict[str, Any] = field(default_factory=dict)

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "class": self.class_name,
            "method": self.method,
            "signature": self.signature,
            "sink_args": list(self.sink_args),
            "type": self.role,
        }


def parse_and_validate_callee_json(
    raw_text: str,
    expected_identity: Optional[Dict[str, str]] = None,
    cwe: Optional[int] = None,
) -> CalleeRolePrediction:
    """
    Enforces the exact 6-key EO03 JSON contract:
      {"package", "class", "method", "signature", "sink_args", "type"}
    Maps physical key "class" -> CalleeRolePrediction.class_name.
    """
    text = (raw_text or "").strip()
    try:
        obj = json.loads(text)
    except Exception as exc:
        return CalleeRolePrediction(
            package="",
            class_name="",
            method="",
            signature="",
            role="none",
            sink_args=(),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason=f"ABSTAIN_JSON_PARSE_ERROR:{type(exc).__name__}",
            raw_wire_dict={},
        )

    if not isinstance(obj, dict):
        return CalleeRolePrediction(
            package="",
            class_name="",
            method="",
            signature="",
            role="none",
            sink_args=(),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason="ABSTAIN_NOT_JSON_OBJECT",
            raw_wire_dict={},
        )

    actual_keys = set(obj.keys())
    if actual_keys != REQUIRED_JSON_KEYS:
        if "class_name" in actual_keys and "class" not in actual_keys:
            reason = "ABSTAIN_SCHEMA_KEY_DRIFT_CLASS_NAME_INSTEAD_OF_CLASS"
        else:
            reason = f"ABSTAIN_SCHEMA_KEY_MISMATCH:got={sorted(actual_keys)}"
        return CalleeRolePrediction(
            package=str(obj.get("package", "")),
            class_name=str(obj.get("class", obj.get("class_name", ""))),
            method=str(obj.get("method", "")),
            signature=str(obj.get("signature", "")),
            role=str(obj.get("type", "none")),
            sink_args=(),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason=reason,
            raw_wire_dict=obj,
        )

    pkg = obj.get("package")
    cls = obj.get("class")
    method = obj.get("method")
    sig = obj.get("signature")
    role = obj.get("type")
    sargs = obj.get("sink_args")

    if not all(isinstance(v, str) and v.strip() for v in (pkg, cls, method, sig, role)):
        return CalleeRolePrediction(
            package=str(pkg or ""),
            class_name=str(cls or ""),
            method=str(method or ""),
            signature=str(sig or ""),
            role=str(role or "none"),
            sink_args=(),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason="ABSTAIN_EMPTY_OR_NON_STRING_IDENTITY_FIELD",
            raw_wire_dict=obj,
        )

    if role not in VALID_ROLES:
        return CalleeRolePrediction(
            package=pkg,
            class_name=cls,
            method=method,
            signature=sig,
            role=role,
            sink_args=(),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason=f"ABSTAIN_INVALID_ROLE:{role}",
            raw_wire_dict=obj,
        )

    if expected_identity is not None:
        exp_pkg = expected_identity.get("package", "")
        exp_cls = expected_identity.get("class", expected_identity.get("class_name", ""))
        exp_method = expected_identity.get("method", "")
        exp_sig = expected_identity.get("signature", "")
        if (
            pkg != exp_pkg
            or cls != exp_cls
            or method != exp_method
            or normalize_signature(sig) != normalize_signature(exp_sig)
        ):
            return CalleeRolePrediction(
                package=pkg,
                class_name=cls,
                method=method,
                signature=sig,
                role=role,
                sink_args=tuple(str(x) for x in sargs) if isinstance(sargs, list) else (),
                canonical_sink_args=(),
                strict_valid=False,
                abstain=True,
                abstain_reason="ABSTAIN_IDENTITY_ECHO_MISMATCH",
                raw_wire_dict=obj,
            )

    if not isinstance(sargs, list) or any(not isinstance(x, str) for x in sargs):
        return CalleeRolePrediction(
            package=pkg,
            class_name=cls,
            method=method,
            signature=sig,
            role=role,
            sink_args=(),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason="ABSTAIN_INVALID_SINK_ARGS_TYPE",
            raw_wire_dict=obj,
        )

    ok_args, arg_reason, canon_args = validate_and_canonicalize_sink_args(
        role=role,
        sink_args=sargs,
        signature=sig,
        cwe=cwe,
        package_name=pkg,
        class_name=cls,
        method_name=method,
    )
    if not ok_args:
        return CalleeRolePrediction(
            package=pkg,
            class_name=cls,
            method=method,
            signature=sig,
            role=role,
            sink_args=tuple(sargs),
            canonical_sink_args=(),
            strict_valid=False,
            abstain=True,
            abstain_reason=arg_reason,
            raw_wire_dict=obj,
        )

    return CalleeRolePrediction(
        package=pkg,
        class_name=cls,
        method=method,
        signature=sig,
        role=role,
        sink_args=tuple(sargs),
        canonical_sink_args=canon_args,
        strict_valid=True,
        abstain=False,
        abstain_reason="OK",
        raw_wire_dict=obj,
    )


@dataclass(frozen=True)
class AstReleaseEvidence:
    is_compile_time_constant_arg: bool = False
    has_cwe_matched_sanitizer: bool = False
    verified_sanitizer_cwe: Optional[int] = None
    covered_sink_args: Tuple[str, ...] = ()
    ast_proof_node: str = ""
    sanitizer_method_signature: str = ""
    output_context: str = ""
    ast_parser_engine: str = "OPENJDK17_JAVAC_TASK_AST"


@dataclass(frozen=True)
class GroundTruthSiteRecord:
    gt_id: str
    cwe: int
    file_path: str
    start_line: int
    end_line: int
    is_vulnerable: bool = True


@dataclass(frozen=True)
class FindingCandidate:
    finding_id: str
    cwe: int
    file_path: str
    line_number: int
    severity: str
    base_scanner_score: float
    callee_prediction: Optional[CalleeRolePrediction] = None
    ast_evidence: AstReleaseEvidence = field(default_factory=AstReleaseEvidence)


def verify_ast_release_evidence(finding: FindingCandidate) -> Tuple[bool, str]:
    """
    Prevents releasing the Bounded Safety Floor on bare boolean flags or regex-only evidence.
    Requires:
      0. Genuine semantic AST parser (`OPENJDK17_JAVAC_TASK_AST` or `VERIFIED_UNIT_AST`); rejects
         any release claimed solely via regex/pattern fallback (`REGEX_ONLY`, `FALLBACK_LEXICAL_PARSER`).
      1. Full coverage of all required canonical_sink_args on the sink prediction (or non-empty covered_sink_args).
      2. Concrete AST proof node / literal or approved CWE-matched sanitizer signature.
      3. For CWE-022 (Path Traversal), verified Path.normalize() + dominating Path.startsWith(Path) guard
         on the exact variable passed to the sink (rejecting String.startsWith or non-dominating guards).
      4. For CWE-079 (XSS), safe encoding context (HTML_BODY or HTML_ATTRIBUTE_QUOTED).
    """
    ast_ev = finding.ast_evidence
    if not ast_ev.is_compile_time_constant_arg and not ast_ev.has_cwe_matched_sanitizer:
        return False, "NO_AST_RELEASE_CLAIMED"

    if str(ast_ev.ast_parser_engine).strip() in (
        "REGEX_ONLY",
        "FALLBACK_LEXICAL_PARSER",
        "MISSING_AST_PARSER",
        "UNVERIFIED_PATTERN",
    ):
        return False, f"REJECTED_NON_SEMANTIC_REGEX_ONLY_EVIDENCE:{ast_ev.ast_parser_engine}"

    if not str(ast_ev.ast_proof_node).strip():
        return False, "REJECTED_MISSING_AST_PROOF_NODE"

    required_args: Tuple[str, ...] = ()
    if finding.callee_prediction is not None:
        required_args = (
            finding.callee_prediction.canonical_sink_args
            or finding.callee_prediction.sink_args
        )

    covered = tuple(str(x).strip() for x in ast_ev.covered_sink_args if str(x).strip())
    if not covered:
        return False, "REJECTED_EMPTY_COVERED_SINK_ARGS"
    if required_args and not set(required_args).issubset(set(covered)):
        return (
            False,
            f"REJECTED_PARTIAL_SINK_ARG_COVERAGE:required={required_args},covered={covered}",
        )

    if ast_ev.is_compile_time_constant_arg:
        if (
            "LITERAL:" not in ast_ev.ast_proof_node
            and "CONST_EXPR:" not in ast_ev.ast_proof_node
        ):
            return False, "REJECTED_CONSTANT_CLAIM_WITHOUT_LITERAL_AST_NODE"
        return True, "VERIFIED_COMPILE_TIME_CONSTANT_SINK_ARGS"

    if ast_ev.has_cwe_matched_sanitizer:
        if ast_ev.verified_sanitizer_cwe != finding.cwe:
            return (
                False,
                f"REJECTED_SANITIZER_CWE_MISMATCH:{ast_ev.verified_sanitizer_cwe}!=finding({finding.cwe})",
            )
        san_sig = str(ast_ev.sanitizer_method_signature).strip()
        allowed_sigs = APPROVED_CWE_SANITIZER_SIGNATURES.get(finding.cwe, set())
        if not san_sig or san_sig not in allowed_sigs:
            return False, f"REJECTED_UNVERIFIED_SANITIZER_SIGNATURE:{san_sig}"
        if finding.cwe == 22 and san_sig == "java.nio.file.Path::normalize":
            proof_str = str(ast_ev.ast_proof_node)
            if "WITHOUT_PREFIX_GUARD" in proof_str:
                return False, "REJECTED_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD"
            if "STRING_STARTSWITH_WEAK_GUARD" in proof_str:
                return False, "REJECTED_STRING_STARTSWITH_NOT_PATH_CONTAINMENT"
            if "NON_DOMINATING_PREFIX_GUARD" in proof_str:
                return False, "REJECTED_NON_DOMINATING_PATH_PREFIX_GUARD"
            if "UNBOUND_GUARD_TARGET" in proof_str:
                return False, "REJECTED_GUARD_DOES_NOT_BIND_SINK_VARIABLE"
            if "REASSIGNED_AFTER_GUARD" in proof_str:
                return False, "REJECTED_PATH_REASSIGNED_AFTER_PREFIX_GUARD"
        if (
            finding.cwe == 79
            and ast_ev.output_context not in SAFE_XSS_ENCODING_CONTEXTS
        ):
            return (
                False,
                f"REJECTED_UNSAFE_XSS_OUTPUT_CONTEXT:{ast_ev.output_context}",
            )
        return True, "VERIFIED_CWE_MATCHED_SANITIZER_RELEASE"

    return False, "REJECTED_UNVERIFIED_AST_EVIDENCE"


def evaluate_bounded_safety_floor(
    finding: FindingCandidate,
    safety_floor: float = SAFETY_FLOOR_SCORE,
    benign_penalty: float = 0.35,
    sink_boost: float = 0.15,
) -> Dict[str, Any]:
    raw_score = float(finding.base_scanner_score)
    pred = finding.callee_prediction
    role_delta = 0.0

    if pred is not None and pred.strict_valid:
        if pred.role == "sink":
            raw_score = min(1.0, raw_score + sink_boost)
            role_delta = round(sink_boost, 4)
        elif pred.role == "none":
            raw_score = max(0.0, raw_score - benign_penalty)
            role_delta = round(-benign_penalty, 4)

    explicit_release, release_reason = verify_ast_release_evidence(finding)

    floor_applied = False
    final_score = raw_score
    if finding.severity.upper() in HIGH_SEVERITY_LEVELS and not explicit_release:
        if final_score < safety_floor:
            final_score = safety_floor
            floor_applied = True

    effective_post_release_score = 0.0 if explicit_release else round(final_score, 4)
    return {
        "finding_id": finding.finding_id,
        "base_scanner_score": round(float(finding.base_scanner_score), 4),
        "llm_role_delta": role_delta,
        "raw_adjusted_score": round(raw_score, 4),
        "final_score": round(final_score, 4),
        "effective_post_release_score": effective_post_release_score,
        "safety_floor_applied": floor_applied,
        "explicit_ast_release_verified": explicit_release,
        "post_release_veto_applied": bool(explicit_release),
        "ast_release_reason": release_reason,
        "retained_above_threshold": final_score >= 0.50,
        "retained_after_ast_veto": (not explicit_release) and (final_score >= 0.50),
    }


def _solve_min_cost_max_bipartite_matching(
    num_left: int,
    num_right: int,
    admissible_edges: List[Tuple[int, int, int]],
) -> Dict[int, int]:
    """
    Exact Maximum-Cardinality Minimum-Cost Bipartite Matching.
    Weight scaling invariant:
      - Let max_k = min(num_left, num_right) be the maximum number of matched edges.
      - Any 1-unit difference in total line distance strictly exceeds the maximum possible
        sum of tie-break costs across all `max_k` edges in any matching.
    """
    if num_left == 0 or num_right == 0 or not admissible_edges:
        return {}

    source = 0
    left_offset = 1
    right_offset = 1 + num_left
    sink = 1 + num_left + num_right
    total_nodes = sink + 1

    graph: List[List[List[int]]] = [[] for _ in range(total_nodes)]

    def add_directed_edge(u: int, v: int, cap: int, cost: int) -> None:
        graph[u].append([v, len(graph[v]), cap, cost])
        graph[v].append([u, len(graph[u]) - 1, 0, -cost])

    for gi in range(num_left):
        add_directed_edge(source, left_offset + gi, 1, 0)

    for ci in range(num_right):
        add_directed_edge(right_offset + ci, sink, 1, 0)

    max_k = max(1, min(num_left, num_right))
    tie_gi_scale = max_k * (num_right + 1) + 1
    max_possible_tie_sum = max_k * ((num_left + 1) * tie_gi_scale + (num_right + 1))
    dist_scale = max_possible_tie_sum + 1

    for dist, gi, ci in sorted(admissible_edges, key=lambda x: (x[0], x[1], x[2])):
        composite_cost = int(dist) * dist_scale + int(gi) * tie_gi_scale + int(ci)
        add_directed_edge(left_offset + gi, right_offset + ci, 1, composite_cost)

    inf_cost = 10**30
    while True:
        best_dist = [inf_cost] * total_nodes
        parent_node = [-1] * total_nodes
        parent_edge = [-1] * total_nodes
        in_queue = [False] * total_nodes

        best_dist[source] = 0
        queue: List[int] = [source]
        in_queue[source] = True

        head = 0
        while head < len(queue):
            u = queue[head]
            head += 1
            in_queue[u] = False
            for e_idx, edge in enumerate(graph[u]):
                v, _, cap, cost = edge
                if cap > 0 and best_dist[u] + cost < best_dist[v]:
                    best_dist[v] = best_dist[u] + cost
                    parent_node[v] = u
                    parent_edge[v] = e_idx
                    if not in_queue[v]:
                        queue.append(v)
                        in_queue[v] = True

        if best_dist[sink] >= inf_cost:
            break

        cur = sink
        while cur != source:
            p = parent_node[cur]
            idx = parent_edge[cur]
            rev_idx = graph[p][idx][1]
            graph[p][idx][2] -= 1
            graph[cur][rev_idx][2] += 1
            cur = p

    matched_gt_to_cand: Dict[int, int] = {}
    for gi in range(num_left):
        u = left_offset + gi
        for v, _, cap, _ in graph[u]:
            if right_offset <= v < sink and cap == 0:
                matched_gt_to_cand[gi] = v - right_offset
                break

    return matched_gt_to_cand


def brute_force_bipartite_oracle(
    num_left: int,
    num_right: int,
    admissible_edges: List[Tuple[int, int, int]],
) -> Tuple[int, int, Dict[int, int]]:
    """
    Exact combinatorial brute-force oracle for small synthetic graphs.
    """
    edge_map: Dict[Tuple[int, int], int] = {}
    adj: Dict[int, List[int]] = {gi: [] for gi in range(num_left)}
    for dist, gi, ci in admissible_edges:
        if (gi, ci) not in edge_map or dist < edge_map[(gi, ci)]:
            edge_map[(gi, ci)] = int(dist)
            if ci not in adj[gi]:
                adj[gi].append(ci)

    max_k = max(1, min(num_left, num_right))
    tie_gi_scale = max_k * (num_right + 1) + 1

    best_card = -1
    best_dist_sum = 10**18
    best_tie_sum = 10**18
    best_match: Dict[int, int] = {}

    def backtrack(
        gi: int,
        used_right: Set[int],
        cur_map: Dict[int, int],
        cur_dist: int,
        cur_tie: int,
    ) -> None:
        nonlocal best_card, best_dist_sum, best_tie_sum, best_match
        if gi == num_left:
            card = len(cur_map)
            if (
                card > best_card
                or (card == best_card and cur_dist < best_dist_sum)
                or (
                    card == best_card
                    and cur_dist == best_dist_sum
                    and cur_tie < best_tie_sum
                )
            ):
                best_card = card
                best_dist_sum = cur_dist
                best_tie_sum = cur_tie
                best_match = dict(cur_map)
            return

        for ci in sorted(adj[gi]):
            if ci not in used_right:
                used_right.add(ci)
                cur_map[gi] = ci
                backtrack(
                    gi + 1,
                    used_right,
                    cur_map,
                    cur_dist + edge_map[(gi, ci)],
                    cur_tie + gi * tie_gi_scale + ci,
                )
                del cur_map[gi]
                used_right.remove(ci)

        backtrack(gi + 1, used_right, cur_map, cur_dist, cur_tie)

    backtrack(0, set(), {}, 0, 0)
    return best_card, best_dist_sum, best_match


def global_bipartite_match_findings(
    ground_truth_sites: Sequence[GroundTruthSiteRecord],
    candidate_pool: Sequence[FindingCandidate],
    retained_finding_ids: Set[str],
    line_tolerance: int = 3,
) -> Dict[str, Any]:
    """
    Canonical-sorts both `ground_truth_sites` and `candidate_pool` before constructing the graph
    so that the matching is 100% invariant to input list permutations.
    """
    vuln_gts = sorted(
        (g for g in ground_truth_sites if g.is_vulnerable),
        key=lambda g: (g.cwe, g.file_path, g.start_line, g.end_line, g.gt_id),
    )
    sorted_cands = sorted(
        candidate_pool,
        key=lambda c: (c.cwe, c.file_path, c.line_number, c.finding_id),
    )

    admissible_edges: List[Tuple[int, int, int]] = []
    for gi, gt in enumerate(vuln_gts):
        for ci, cand in enumerate(sorted_cands):
            if cand.cwe == gt.cwe and cand.file_path == gt.file_path:
                if (gt.start_line - line_tolerance) <= cand.line_number <= (
                    gt.end_line + line_tolerance
                ):
                    if gt.start_line <= cand.line_number <= gt.end_line:
                        dist = 0
                    else:
                        dist = min(
                            abs(cand.line_number - gt.start_line),
                            abs(cand.line_number - gt.end_line),
                        )
                    admissible_edges.append((dist, gi, ci))

    matched_gt_to_cand = _solve_min_cost_max_bipartite_matching(
        num_left=len(vuln_gts),
        num_right=len(sorted_cands),
        admissible_edges=admissible_edges,
    )
    used_cands: Set[int] = set(matched_gt_to_cand.values())

    tp_retained = 0
    fn_scanner = 0
    fn_scoring = 0
    gt_outcomes: Dict[str, str] = {}

    for gi, gt in enumerate(vuln_gts):
        if gi not in matched_gt_to_cand:
            fn_scanner += 1
            gt_outcomes[gt.gt_id] = "FN_SCANNER_UNMATCHED"
        else:
            ci = matched_gt_to_cand[gi]
            cand = sorted_cands[ci]
            if cand.finding_id in retained_finding_ids:
                tp_retained += 1
                gt_outcomes[gt.gt_id] = f"TP_RETAINED:{cand.finding_id}"
            else:
                fn_scoring += 1
                gt_outcomes[gt.gt_id] = f"FN_SCORING_SUPPRESSED:{cand.finding_id}"

    fp_retained = 0
    tn_suppressed = 0
    for ci, cand in enumerate(sorted_cands):
        if ci not in used_cands:
            if cand.finding_id in retained_finding_ids:
                fp_retained += 1
            else:
                tn_suppressed += 1

    total_gt = len(vuln_gts)
    total_fn = fn_scanner + fn_scoring
    assert tp_retained + total_fn == total_gt, "Ground truth accounting identity violated!"

    precision = (
        tp_retained / (tp_retained + fp_retained)
        if (tp_retained + fp_retained) > 0
        else 0.0
    )
    recall_e2e = tp_retained / total_gt if total_gt > 0 else 0.0
    f1_e2e = (
        (2 * precision * recall_e2e / (precision + recall_e2e))
        if (precision + recall_e2e) > 0
        else 0.0
    )

    matched_pairs = [
        (vuln_gts[gi].gt_id, sorted_cands[ci].finding_id)
        for gi, ci in sorted(matched_gt_to_cand.items())
    ]

    return {
        "total_vulnerable_gt": total_gt,
        "matched_cardinality": len(matched_gt_to_cand),
        "matched_gt_count": len(matched_gt_to_cand),
        "matched_pairs": matched_pairs,
        "tp_retained": tp_retained,
        "fn_scanner": fn_scanner,
        "fn_scoring": fn_scoring,
        "total_fn": total_fn,
        "fp_retained": fp_retained,
        "tn_suppressed": tn_suppressed,
        "precision": round(precision, 4),
        "end_to_end_recall": round(recall_e2e, 4),
        "end_to_end_f1": round(f1_e2e, 4),
        "gt_outcomes": gt_outcomes,
    }


CANONICAL_IRIS_SYSTEM_PROMPT: str = (
    "You are a security expert.\n"
    "You will receive exactly ONE API and must classify it for the requested CWE.\n\n"
    "Return exactly ONE JSON object with this format:\n"
    "{\n"
    '  "package": "<package name>",\n'
    '  "class": "<class name>",\n'
    '  "method": "<method name>",\n'
    '  "signature": "<signature>",\n'
    '  "sink_args": [],\n'
    '  "type": "<source, sink, taint-propagator, or none>"\n'
    "}\n\n"
    "Use:\n"
    "- source only when the API can introduce attacker-controlled data.\n"
    "- sink only when the API can directly consume tainted data in a way relevant to the requested CWE.\n"
    "- taint-propagator only when it propagates tainted data without sanitizing it.\n"
    "- none when the API does not satisfy any of the above for the requested CWE.\n\n"
    "For a sink, sink_args must contain only the argument names/positions that consume tainted data.\n"
    "For every other type, sink_args must be an empty list.\n\n"
    "Do not classify an API merely because it is security-sensitive in some unrelated context.\n"
    "Do not output anything except the JSON object."
)

CANONICAL_IRIS_USER_PROMPT_PREFIX_BY_CWE: Dict[int, str] = {
    22: (
        "A path traversal vulnerability allows an attacker to access files on your web server to which they should "
        "not have access. They do this by tricking either the web server or the web application running on it into "
        "returning files that exist outside of the web root folder. Another attack pattern is that users can pass in "
        'malicious Zip file which may contain directories like "../". Typical sources of this vulnerability involves '
        "obtaining information from untrusted user input through web requests, getting entry directory from Zip files. "
        "Sinks will relate to file system manipulation, such as creating file, listing directories, and etc.\n\n"
        "Some example source/sink/taint-propagator methods are:\n"
        "[\n"
        "  {\n"
        '    "package": "java.util.zip",\n'
        '    "class": "ZipEntry",\n'
        '    "method": "getName",\n'
        '    "signature": "String getName()",\n'
        '    "sink_args": [],\n'
        '    "type": "source"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.io",\n'
        '    "class": "FileInputStream",\n'
        '    "method": "FileInputStream",\n'
        '    "signature": "FileInputStream(File file)",\n'
        '    "sink_args": [\n'
        '      "file"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.net",\n'
        '    "class": "URL",\n'
        '    "method": "URL",\n'
        '    "signature": "URL(String url)",\n'
        '    "sink_args": [],\n'
        '    "type": "taint-propagator"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.io",\n'
        '    "class": "File",\n'
        '    "method": "File",\n'
        '    "signature": "File(String path)",\n'
        '    "sink_args": [],\n'
        '    "type": "taint-propagator"\n'
        "  }\n"
        "]\n\n"
        "Among the following methods, assuming that the arguments passed to the given function is malicious, "
        "what are the functions that are potential source, sink, or taint-propagators to Path Traversal or Zip Slip attack (CWE-022)?\n\n"
        "Package,Class,Method,Signature"
    ),
    78: (
        "OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) "
        "commands on the server that is running an application, and typically fully compromise the application and its data. "
        "Often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting "
        "infrastructure, and exploit trust relationships to pivot the attack to other systems within the organization.\n\n"
        "Some example source/sink/taint-propagator methods are:\n"
        "[\n"
        "  {\n"
        '    "package": "javax.servlet.http",\n'
        '    "class": "HTTPServletRequest",\n'
        '    "method": "getCookies()",\n'
        '    "signature": "Cookie[] getCookies()",\n'
        '    "type": "source"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.lang",\n'
        '    "class": "Runtime",\n'
        '    "method": "exec",\n'
        '    "signature": "Process exec(String[] cmdarray)",\n'
        '    "sink_args": [\n'
        '      "cmdarray"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  },\n"
        "  {\n"
        '    "package": "com.jcraft.jsch",\n'
        '    "class": "ChannelExec",\n'
        '    "method": "setCommand",\n'
        '    "signature": "void setCommand(String command)",\n'
        '    "sink_args": [\n'
        '      "command"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  }\n"
        "]\n\n"
        "Among the following methods, assuming that the arguments passed to the given function is malicious, "
        "what are the functions that are potential source, sink, or taint-propagators to OS Command Injection attack (CWE-078)?\n\n"
        "Package,Class,Method,Signature"
    ),
    79: (
        "Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable scripts into the code "
        "of a trusted application or website. Attackers often initiate an XSS attack by sending a malicious link to a user "
        "and enticing the user to click it. If the app or website lacks proper data sanitization, the malicious link executes "
        "the attacker's chosen code on the user's system. As a result, the attacker can steal the user's active session cookie. "
        "Logging functions are NOT sinks for XSS attacks.\n\n"
        "Some example source/sink/taint-propagator methods are:\n"
        "[\n"
        "  {\n"
        '    "package": "org.apache.wicket.core.request.handler",\n'
        '    "class": "IPartialPageRequestHandler",\n'
        '    "method": "appendJavaScript",\n'
        '    "signature": "void appendJavaScript(CharSequence seq)",\n'
        '    "sink_args": [\n'
        '      "seq"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  },\n"
        "  {\n"
        '    "package": "org.thymeleaf",\n'
        '    "class": "TemplateEngine",\n'
        '    "method": "process",\n'
        '    "signature": "void process(String template, IContext context, Writer writer)",\n'
        '    "sink_args": [\n'
        '      "context"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  },\n"
        "  {\n"
        '    "package": "org.jboss.resteasy.spi",\n'
        '    "class": "HttpRequest",\n'
        '    "method": "getDecodedFormParameters",\n'
        '    "signature": "MultivaluedMap<String,String> getDecodedFormParameters()",\n'
        '    "type": "source"\n'
        "  }\n"
        "]\n\n"
        "Among the following methods, assuming that the arguments passed to the given function is malicious, "
        "what are the functions that are potential source, sink, or taint-propagators to Cross-Site Scripting attack (CWE-079)?\n\n"
        "Package,Class,Method,Signature"
    ),
    89: (
        "SQL Injection is a critical vulnerability that arises when user input is used to construct SQL queries without "
        "proper validation. This allows attackers to inject malicious SQL code into the query, bypass authentication, "
        "retrieve sensitive data, or execute arbitrary commands on the database server.This vulnerability occurs when "
        "applications dynamically build SQL strings using input from sources such as HTTP request parameters without using "
        "parameterized queries or prepared statements. Attackers can exploit this to perform unauthorized reads, data "
        "modification, or denial of service.\n"
        "To address SQL injection, use parameterized queries, prepared statements, etc. Input validation, least privilege "
        "database access, and error message suppression are also important secondary defenses.\n"
        "      \n\n"
        "Some example source/sink/taint-propagator methods are:\n"
        "[\n"
        "  {\n"
        '    "package": "javax.servlet.http",\n'
        '    "class": "HttpServletRequest",\n'
        '    "method": "getParameter",\n'
        '    "signature": "String getParameter(String name)",\n'
        '    "sink_args": [],\n'
        '    "type": "source"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.sql",\n'
        '    "class": "Statement",\n'
        '    "method": "execute",\n'
        '    "signature": "boolean execute(String sql)",\n'
        '    "sink_args": [\n'
        '      "sql"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.sql",\n'
        '    "class": "Statement",\n'
        '    "method": "executeQuery",\n'
        '    "signature": "ResultSet executeQuery(String sql)",\n'
        '    "sink_args": [\n'
        '      "sql"\n'
        "    ],\n"
        '    "type": "sink"\n'
        "  },\n"
        "  {\n"
        '    "package": "java.lang",\n'
        '    "class": "StringBuilder",\n'
        '    "method": "append",\n'
        '    "signature": "StringBuilder append(String str)",\n'
        '    "sink_args": [],\n'
        '    "type": "taint-propagator"\n'
        "  }\n"
        "]\n\n"
        "Among the following methods, assuming that the arguments passed to the given function is malicious, "
        "what are the functions that are potential source, sink, or taint-propagators to SQL Injection via string concatenation attack (CWE-089)?\n\n"
        "Package,Class,Method,Signature"
    ),
}


def build_canonical_iris_prompt_messages(
    cwe: int,
    ident: Dict[str, str],
) -> List[Dict[str, str]]:
    """
    Constructs the exact training-aligned 2-message prompt (`system` + `user`) used across
    Dataset VNext.3.1 (`Track A`, `Track B`, `Dev-166`) and IRIS `prompts.py`.
    Eliminates training-to-runtime prompt distribution shift in Phase 6 E2E and Web MVP inference.
    """
    cwe_int = int(cwe)
    if cwe_int not in CANONICAL_IRIS_USER_PROMPT_PREFIX_BY_CWE:
        raise ValueError(f"Unsupported CWE for canonical IRIS prompt: {cwe_int}")
    pkg = normalize_whitespace(ident.get("package", ""))
    cls = normalize_whitespace(ident.get("class", ident.get("class_name", "")))
    method = normalize_whitespace(ident.get("method", ""))
    sig = normalize_signature(ident.get("signature", ""))
    prefix = CANONICAL_IRIS_USER_PROMPT_PREFIX_BY_CWE[cwe_int]
    user_content = f"{prefix}\n{pkg},{cls},{method},{sig}\n"
    return [
        {"role": "system", "content": CANONICAL_IRIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def find_case_insensitive_duplicate_keys(obj: Any, path: str = "$") -> List[Dict[str, Any]]:
    """
    Recursively scans a JSON-serializable structure for dictionaries that contain keys colliding
    under case-insensitive comparison (which breaks Windows PowerShell 5.1 `ConvertFrom-Json`).
    """
    collisions: List[Dict[str, Any]] = []
    if isinstance(obj, dict):
        by_lower: Dict[str, List[str]] = {}
        for k in obj.keys():
            ks = str(k)
            by_lower.setdefault(ks.lower(), []).append(ks)
        for low_k, orig_keys in by_lower.items():
            if len(orig_keys) > 1:
                collisions.append({"path": path, "lower_key": low_k, "colliding_keys": orig_keys})
        for k, v in obj.items():
            collisions.extend(find_case_insensitive_duplicate_keys(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            collisions.extend(find_case_insensitive_duplicate_keys(item, f"{path}[{idx}]"))
    return collisions


@dataclass(frozen=True)
class FindingSchemaV1:
    """
    Unified Web-Ready SAST Finding Schema (`FROZEN_ARCHITECTURE_V1`) for GretaAI Web MVP integration.
    Explicitly separates static severity (`ERROR`/`WARNING`/`INFO`) from heuristic fusion score
    (`[0.0, 1.0]`, explicitly marked `is_calibrated_probability = False`).
    """

    schema_version: str
    finding_id: str
    cwe: str
    cwe_id: int
    file_path: str
    line_number: int
    enclosing_method: str
    static_severity: str
    scanner_rule_id: str
    matched_code: str
    target_callee_identity: Dict[str, str]
    llm_prediction: Dict[str, Any]
    ast_evidence: Dict[str, Any]
    score_breakdown: Dict[str, Any]
    final_heuristic_score: float
    is_calibrated_probability: bool
    kept_by_pipeline: bool
    disposition: str
    architecture_version: str = "FROZEN_ARCHITECTURE_V1"
    model_version: str = "eo06_vnext31_trackb_main_epoch3"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "architecture_version": self.architecture_version,
            "model_version": self.model_version,
            "finding_id": self.finding_id,
            "cwe": self.cwe,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "enclosing_method": self.enclosing_method,
            "static_severity": self.static_severity,
            "scanner_rule_id": self.scanner_rule_id,
            "matched_code": self.matched_code,
            "target_callee_identity": dict(self.target_callee_identity),
            "llm_prediction": dict(self.llm_prediction),
            "ast_evidence": dict(self.ast_evidence),
            "score_breakdown": dict(self.score_breakdown),
            "final_heuristic_score": round(float(self.final_heuristic_score), 4),
            "is_calibrated_probability": bool(self.is_calibrated_probability),
            "kept_by_pipeline": bool(self.kept_by_pipeline),
            "disposition": self.disposition,
        }


VALID_TRIAGE_STATUSES: Tuple[str, ...] = (
    "LIKELY_TRUE_POSITIVE",
    "LIKELY_FALSE_POSITIVE",
    "NEEDS_REVIEW",
)
VALID_TRIAGE_DECISIONS: Tuple[str, ...] = (
    "REPORT",
    "REVIEW",
    "SUPPRESS",
)
VALID_REVIEW_STATUSES: Tuple[str, ...] = (
    "NOT_REVIEWED",
    "CONFIRMED_TRUE_POSITIVE",
    "CONFIRMED_FALSE_POSITIVE",
)
VALID_SOURCE_SINK_TRACE_STATUSES: Tuple[str, ...] = (
    "VERIFIED_TAINT_FLOW",
    "SAFE_CONSTANT_OR_PARAMETERIZED",
    "SAFE_SANITIZED_OR_GUARDED",
    "PARTIAL_OR_INSUFFICIENT_GUARD",
    "NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT",
)
VALID_SANITIZER_STATUSES: Tuple[str, ...] = (
    "NONE_DETECTED",
    "VERIFIED_CWE_MATCHED_SANITIZER",
    "VERIFIED_PARAMETERIZED_QUERY",
    "VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD",
    "INSUFFICIENT_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD",
    "PARTIAL_OR_INSUFFICIENT_GUARD",
    "MISMATCHED_CWE_SANITIZER",
    "UNSAFE_OUTPUT_ENCODING_CONTEXT",
    "UNVERIFIED_CUSTOM_SANITIZER",
)


@dataclass(frozen=True)
class FindingSchemaV2(FindingSchemaV1):
    """
    Backward-compatible extension of `FindingSchemaV1` (`NTK_WEB_FINDING_SCHEMA_V2`)
    adding Alert Verification & True/False Positive Triage fields required by Phase C & GretaAI Web MVP.
    Preserves all 20 keys of `FindingSchemaV1.to_dict()` while adding the 17 structured triage,
    provenance, evidence, and versioning fields.
    """

    triage_status: str = "NEEDS_REVIEW"
    decision: str = "REVIEW"
    confidence_score: float = 0.55
    score_kind: str = "HEURISTIC_EVIDENCE_FUSION_SCORE_NOT_CALIBRATED_PROBABILITY"
    severity: str = "HIGH"
    reason_codes: Tuple[str, ...] = ()
    evidence_refs: Dict[str, Any] = field(default_factory=dict)
    source_sink_trace_status: str = "NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT"
    sanitizer_status: str = "NONE_DETECTED"
    opengrep_evidence: Dict[str, Any] = field(default_factory=dict)
    iris_evidence: Dict[str, Any] = field(default_factory=dict)
    llm_api_role: Dict[str, Any] = field(default_factory=dict)
    fusion_score_breakdown: Dict[str, Any] = field(default_factory=dict)
    review_status: str = "NOT_REVIEWED"
    review_metadata: Dict[str, Any] = field(default_factory=dict)
    ruleset_version: str = "NTK_OPENGREP_JAVA_RULESET_V1.2"
    scoring_policy_version: str = "NTK_BOUNDED_SAFETY_FLOOR_FUSION_V1.1"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "triage_status": self.triage_status,
                "decision": self.decision,
                "confidence_score": round(float(self.confidence_score), 4),
                "score_kind": self.score_kind,
                "severity": self.severity,
                "reason_codes": list(self.reason_codes),
                "evidence_refs": dict(self.evidence_refs),
                "source_sink_trace_status": self.source_sink_trace_status,
                "sanitizer_status": self.sanitizer_status,
                "opengrep_evidence": dict(self.opengrep_evidence),
                "iris_evidence": dict(self.iris_evidence),
                "llm_api_role": dict(self.llm_api_role),
                "fusion_score_breakdown": dict(self.fusion_score_breakdown),
                "review_status": self.review_status,
                "review_metadata": dict(self.review_metadata),
                "ruleset_version": self.ruleset_version,
                "scoring_policy_version": self.scoring_policy_version,
            }
        )
        return base


