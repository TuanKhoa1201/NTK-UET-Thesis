#!/usr/bin/env bash

set -u

ROOT="$HOME/iris"
INTEGRATION="$ROOT/integration"

usage() {
    echo "Usage:"
    echo "  ./integration/run_local_project.sh <PROJECT>"
    echo "  ./integration/run_local_project.sh <PROJECT> --new-run"
    echo
    echo "Default:"
    echo "  stable run-id -> maximum IRIS cache reuse"
    echo
    echo "--new-run:"
    echo "  new IRIS output namespace"
    echo "  exact LLM caches may still be reused"
}

PROJECT="${1:-}"
RUN_MODE="${2:-}"

if [ "$PROJECT" = "-h" ] || [ "$PROJECT" = "--help" ]; then
    usage
    exit 0
fi

if [ -z "$PROJECT" ]; then
    usage
    exit 2
fi

if [ -n "$RUN_MODE" ] && [ "$RUN_MODE" != "--new-run" ]; then
    echo "ERROR: unsupported option: $RUN_MODE"
    echo
    usage
    exit 2
fi

cd "$ROOT" || exit 1


# ============================================================
# PATHS
# ============================================================

SRC="$ROOT/data/project-sources/$PROJECT"
DB="$ROOT/data/codeql-dbs/$PROJECT"
PKG="$ROOT/data/package-names/$PROJECT.txt"

OPENGREP_BIN="$HOME/.opengrep/cli/v1.25.0/opengrep"

RULE_ROOT="$INTEGRATION/rules/opengrep/p-java-pinned-20260929"


# ============================================================
# PROJECT POLICY
# ============================================================

case "$PROJECT" in

    spark_CVE-2016-9177_vuln|\
    spark_CVE-2016-9177_fixed)

        DISPATCH_MODE="hybrid"
        QUERIES="cwe-022wLLM"
        TARGET="CWE-22/CWE-23"
        ;;


    mini_vulnerable_java_CVE-89_1.0|\
    sqli_mini_CVE-2026-TEST-0001_1.0|\
    webgoat_sql_CVE-2026-0006_1.0)

        DISPATCH_MODE="hybrid"
        QUERIES="cwe-089wLLM"
        TARGET="CWE-89"
        ;;


    WebGoat|\
    owasp_benchmark_CVE-2026-0005_1.0|\
    spring-petclinic)

        DISPATCH_MODE="detected"
        QUERIES=""
        TARGET="AUTO_FROM_OPENGREP"
        ;;


    *)

        DISPATCH_MODE="detected"
        QUERIES=""
        TARGET="AUTO_FROM_OPENGREP"
        ;;

esac


# ============================================================
# CACHE / OUTPUT IDENTITY
# ============================================================

STAMP="$(date +%Y%m%d_%H%M%S)"

CACHE_NAMESPACE="manual-local-production-v1"

if [ "$RUN_MODE" = "--new-run" ]; then

    RUN_TAG="${CACHE_NAMESPACE}-${STAMP}"
    CACHE_POLICY="NEW_RUN"

else

    RUN_TAG="$CACHE_NAMESPACE"
    CACHE_POLICY="REUSE"

fi

# EXEC_TAG is always unique so OpenGrep/temp/report files
# from separate executions never collide.
EXEC_TAG="${RUN_TAG}-exec-${STAMP}"

RUN_ID="${PROJECT}/${RUN_TAG}"

TEMP_REL="temp/manual-projects/${PROJECT}/${EXEC_TAG}"
REPORT_REL="reports/manual-projects/${PROJECT}/${EXEC_TAG}"
LOG_REL="logs/manual-projects/${PROJECT}/${EXEC_TAG}"

GENERATED_DIR="$INTEGRATION/generated-manual-configs/$PROJECT"
mkdir -p "$GENERATED_DIR"

CFG="$GENERATED_DIR/${EXEC_TAG}.yaml"

EXTERNAL_LOG_DIR="$HOME/migration/manual_project_runs/$PROJECT"
mkdir -p "$EXTERNAL_LOG_DIR"

LOG="$EXTERNAL_LOG_DIR/${EXEC_TAG}.log"


# ============================================================
# PRECHECK
# ============================================================

echo "============================================================"
echo " IRIS LOCAL PROJECT LAUNCHER"
echo "============================================================"
echo "PROJECT       = $PROJECT"
echo "SOURCE        = $SRC"
echo "TARGET        = $TARGET"
echo "DISPATCH_MODE = $DISPATCH_MODE"
echo "QUERIES       = ${QUERIES:-<detected-only>}"
echo "RUN_ID        = $RUN_ID"
echo "RUN_TAG       = $RUN_TAG"
echo "EXEC_TAG      = $EXEC_TAG"
echo "CACHE_POLICY  = $CACHE_POLICY"
echo "============================================================"
echo


if [ ! -d "$SRC" ]; then
    echo "ERROR: source missing:"
    echo "  $SRC"
    exit 10
fi


if [ ! -d "$DB" ]; then
    echo "ERROR: CodeQL database missing:"
    echo "  $DB"
    echo
    echo "This project needs CodeQL preparation first."
    exit 11
fi


if [ ! -s "$PKG" ]; then
    echo "ERROR: package-names missing/empty:"
    echo "  $PKG"
    echo
    echo "This project needs package-name preparation first."
    exit 12
fi


if [ ! -x "$OPENGREP_BIN" ]; then
    echo "ERROR: pinned OpenGrep missing:"
    echo "  $OPENGREP_BIN"
    exit 13
fi


mapfile -t RULE_FILES < <(
    find "$RULE_ROOT" \
        -type f \
        -name 'p-java.yaml' \
        -print 2>/dev/null
)

if [ "${#RULE_FILES[@]}" -ne 1 ]; then
    echo "ERROR: expected exactly one pinned p-java.yaml"
    echo "RULE_COUNT=${#RULE_FILES[@]}"
    printf '%s\n' "${RULE_FILES[@]}"
    exit 14
fi

OPENGREP_RULE="${RULE_FILES[0]}"


if ! command -v ollama >/dev/null 2>&1; then
    echo "ERROR: ollama command not found"
    exit 15
fi


if ! ollama list 2>/dev/null \
    | grep -q 'qwen2.5-coder:1.5b'; then

    echo "ERROR: Ollama model unavailable:"
    echo "  qwen2.5-coder:1.5b"
    exit 16
fi


# ============================================================
# OPENGREP GIT POLICY
# ============================================================

ALL_JAVA="$(
    find "$SRC" \
        -type f \
        -name '*.java' \
        2>/dev/null \
    | wc -l \
    | tr -d ' '
)"

TRACKED_JAVA=0
GIT_TOP=""

if git -C "$SRC" \
    rev-parse --is-inside-work-tree \
    >/dev/null 2>&1
then
    GIT_TOP="$(
        git -C "$SRC" \
            rev-parse --show-toplevel
    )"

    SRC_REL="$(
        realpath \
            --relative-to="$GIT_TOP" \
            "$SRC"
    )"

    TRACKED_JAVA="$(
        git -C "$GIT_TOP" \
            ls-files -- "$SRC_REL" \
            2>/dev/null \
        | grep -Ec '\.java$' \
        || true
    )"
fi


if [ "$ALL_JAVA" -gt 0 ] && \
   [ "$TRACKED_JAVA" -eq 0 ]
then

    OPENGREP_EXTRA_ARGS="--no-git-ignore"
    OPENGREP_GIT_POLICY="AUTO_NO_GIT_IGNORE"

else

    OPENGREP_EXTRA_ARGS=""
    OPENGREP_GIT_POLICY="RESPECT_GIT"

fi


echo "JAVA_FILES_ALL       = $ALL_JAVA"
echo "JAVA_FILES_TRACKED   = $TRACKED_JAVA"
echo "OPENGREP_GIT_POLICY  = $OPENGREP_GIT_POLICY"
echo "OPENGREP_EXTRA_ARGS  = ${OPENGREP_EXTRA_ARGS:-<none>}"
echo


# ============================================================
# GENERATE EXECUTION CONFIG
# ============================================================

PROJECT="$PROJECT" \
SRC="$SRC" \
OPENGREP_BIN="$OPENGREP_BIN" \
OPENGREP_RULE="$OPENGREP_RULE" \
OPENGREP_EXTRA_ARGS="$OPENGREP_EXTRA_ARGS" \
DISPATCH_MODE="$DISPATCH_MODE" \
QUERIES="$QUERIES" \
RUN_ID="$RUN_ID" \
TEMP_REL="$TEMP_REL" \
REPORT_REL="$REPORT_REL" \
LOG_REL="$LOG_REL" \
CFG="$CFG" \
python3 - <<'PY'
from pathlib import Path
import os
import yaml

project = os.environ["PROJECT"]
src = os.environ["SRC"]

queries_raw = os.environ["QUERIES"].strip()

queries = (
    [x for x in queries_raw.split(",") if x]
    if queries_raw
    else []
)

cfg = {
    "project": {
        "name": project,
        "source": src,
    },

    "opengrep": {
        "executable":
            os.environ["OPENGREP_BIN"],

        "extra_args": [
            x
            for x in
            os.environ.get(
                "OPENGREP_EXTRA_ARGS",
                "",
            ).split()
            if x
        ],

        "config":
            os.environ["OPENGREP_RULE"],

        "output":
            os.environ["TEMP_REL"]
            + "/opengrep.sarif",
    },

    "iris": {
        "executable": "python3",

        "script": "src/iris.py",

        "queries": queries,

        "run_id":
            os.environ["RUN_ID"],

        "llm":
            "ollama-qwen-coder-1.5b",

        "overwrite_llm_cache":
            False,

        "overwrite_label_cache":
            False,

        "dispatch_mode":
            os.environ["DISPATCH_MODE"],
    },

    "report": {
        "output_dir":
            os.environ["REPORT_REL"],

        "project_name":
            (
                "OpenGrep + IRIS + "
                "Local Qwen2.5-Coder 1.5B"
            ),

        "analyzer_version":
            "1.0.0",
    },

    "metadata": {
        "author":
            "Tuan Khoa",

        "organization":
            "VNU University of Engineering and Technology",

        "description":
            (
                "Manual local project regression run; "
                "not part of the locked final holdout."
            ),
    },

    "paths": {
        "normalized_findings":
            os.environ["TEMP_REL"]
            + "/normalized_findings.json",

        "iris_jobs":
            os.environ["TEMP_REL"]
            + "/iris_jobs.json",
    },

    "logging": {
        "log_dir":
            os.environ["LOG_REL"],

        "level":
            "INFO",
    },

    "runtime": {
        "save_temp_files":
            True,

        "generate_json":
            True,

        "generate_csv":
            True,

        "generate_html":
            True,

        "verbose":
            True,
    },
}

dest = Path(os.environ["CFG"])

dest.write_text(
    yaml.safe_dump(
        cfg,
        sort_keys=False,
        allow_unicode=True,
    ),
    encoding="utf-8",
)

print("CONFIG_CREATED =", dest)
print("CONFIG_PROJECT =", project)
print("CONFIG_RUN_ID =", cfg["iris"]["run_id"])
print(
    "CONFIG_DISPATCH_MODE =",
    cfg["iris"]["dispatch_mode"],
)
print(
    "CONFIG_QUERIES =",
    cfg["iris"]["queries"],
)
PY

rc=$?

if [ "$rc" -ne 0 ]; then
    echo "CONFIG_GENERATION_PASS=False"
    exit "$rc"
fi


# ============================================================
# LOCAL RUNTIME SETTINGS
# ============================================================

export OLLAMA_HOST="http://127.0.0.1:11434"

export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=false

export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1


echo
echo "PINNED_OPENGREP = $OPENGREP_BIN"
echo "PINNED_RULE     = $OPENGREP_RULE"
echo "CODEQL_DB       = $DB"
echo "PACKAGE_NAMES   = $PKG"
echo "CONFIG          = $CFG"
echo "LOG             = $LOG"
echo
echo "PRECHECK_PASS=True"
echo
echo "Starting pipeline..."
echo


# ============================================================
# PIPELINE
# ============================================================

python3 -u integration/main.py \
    --config "$CFG" \
    --verbose \
    2>&1 | tee "$LOG"

rc=${PIPESTATUS[0]}


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " RUN SUMMARY"
echo "============================================================"
echo "PROJECT       = $PROJECT"
echo "RUN_ID        = $RUN_ID"
echo "CACHE_POLICY  = $CACHE_POLICY"
echo "EXEC_TAG      = $EXEC_TAG"
echo "CONFIG        = $CFG"
echo "LOG           = $LOG"
echo "RC            = $rc"

if [ "$rc" -eq 0 ]; then
    echo "PROJECT_RUN_PASS=True"
else
    echo "PROJECT_RUN_PASS=False"
fi

echo "============================================================"

exit "$rc"
