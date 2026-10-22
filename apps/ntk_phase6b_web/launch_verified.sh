#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PY="${NTK_IRIS_PYTHON:-$(command -v python)}"
test -x "$PY"

printf '\n===== 1. VERIFY V2.3 WEBSITE BY SHA256 =====\n'
sha256sum -c SHA256SUMS

printf '\n===== 2. CPU TESTS (PLAYWRIGHT OPTIONAL) =====\n'
for TEST in test_app.py test_fast_artifacts.py test_fast_web.py test_github_prep.py test_fastscan_v23_patch.py test_fastscan_v23_bridge.py; do
  "$PY" -m unittest discover -s tests -p "$TEST" -q
done
printf 'CPU_FUNCTIONAL_TESTS=PASS\n'
printf 'BROWSER_PLAYWRIGHT_TESTS=OPTIONAL_NOT_REQUIRED_IN_IRIS\n'

printf '\n===== 3. INSTALL INDEPENDENT PINNED V2.3 EXPERIMENTAL RUNNER =====\n'
"$PY" -I -B "$ROOT/install_fastscan_v23.py"

W="$HOME/migration/ntk_stage3_verified_v5_work"
DEVPATH="$HOME/migration/ntk_fastscan_dev_20261021/engine_candidate_v23/run_fastscan.py"
RUN="$W/ntk_fastscan_runs/ntkfast_20261021T085514Z_e86a3942"
RESULT="/mnt/c/Users/HP/Downloads/ntkfast_20261021T085514Z_e86a3942_result.zip"
EXPECTED='4d4f1c887f8a50f6e4ec7f94e82d29cc877236ab8afb801c044f06153eea7055'
DATA="$W/batch28_silver_parallel_runs/batch28_b21de8b3f3c10f42_a001/dataset"
TRAIN="$DATA/01_TRAIN_SILVER_WEAK_950.jsonl"
VALID="$DATA/02_VALIDATION_WEAK_DISJOINT.jsonl"

printf '\n===== 4. VERIFY HISTORICAL FASTSCAN RESULT (NO GPU) =====\n'
test -f "$DEVPATH"
test -d "$RUN"
printf '%s  %s\n' "$EXPECTED" "$RESULT" | sha256sum -c -

printf '\n===== 5. VERIFY PINNED WEAK/SILVER DATASET =====\n'
test -f "$TRAIN"
test -f "$VALID"
printf '%s  %s\n' 'f11b42783a75f3e8dfe4e23cf58e9af2d4caf3bef5347c6f18f9cca809744f2a' "$TRAIN" | sha256sum -c -
printf '%s  %s\n' 'd7e380b13a1c297a983bd2e7959b89fdb05c52c04a702d71268874b91dedc93f' "$VALID" | sha256sum -c -

printf '\n===== 6. PREVIOUS 285s READ-ONLY PERFORMANCE AUDIT =====\n'
"$PY" tools/audit_runtime.py --run "$RUN"

if [[ "${1:-}" == '--prepare-only' ]]; then
  echo 'V23_PREPARE_ONLY_PASS=TRUE'
  echo 'GPU_EXECUTION=NO'
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo 'USAGE: bash launch_verified.sh [--prepare-only]' >&2
  exit 2
fi

printf '\n===== 7. START V2.3 WEBSITE (NO AUTOMATIC NEW SCAN) =====\n'
printf 'RUNTIME_V23_NEW_SCAN=USER_OPT_IN_ONLY\n'
exec bash "$ROOT/start.sh" --enable-scan \
  --fast-runner "$DEVPATH" \
  --import-fast-run "$RUN" \
  --import-name 'GitHub SemgrepDemo (completed previously)' \
  --train-file "$TRAIN" \
  --validation-file "$VALID"
