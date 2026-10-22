#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
sha256sum -c SHA256SUMS >/dev/null
printf 'PHASE6B_SITE_HASHES=VERIFIED\n'
PY="${NTK_IRIS_PYTHON:-$(command -v python)}"
test -x "$PY"
W="$HOME/migration/ntk_stage3_verified_v5_work"
FAST="$HOME/migration/ntk_fastscan_dev_20261021/engine_candidate_v23/run_fastscan.py"
P51="$HOME/migration/ntk_fullproject_phase51_runs/fullproj51_20261021T171346Z_64e3491d"
DATA="$W/batch28_silver_parallel_runs/batch28_b21de8b3f3c10f42_a001/dataset"
TRAIN="$DATA/01_TRAIN_SILVER_WEAK_950.jsonl"
VALID="$DATA/02_VALIDATION_WEAK_DISJOINT.jsonl"
UI="$HOME/.local/share/ntk-sast-ui-phase6b"
test -f "$P51/FULLPROJECT_PHASE51_RESULT.json"
test -f "$P51/SHA256SUMS"
test -f "$FAST"
test -f "$TRAIN"
test -f "$VALID"
printf '%s  %s\n' 'f11b42783a75f3e8dfe4e23cf58e9af2d4caf3bef5347c6f18f9cca809744f2a' "$TRAIN" | sha256sum -c -
printf '%s  %s\n' 'd7e380b13a1c297a983bd2e7959b89fdb05c52c04a702d71268874b91dedc93f' "$VALID" | sha256sum -c -
export NTK_IRIS_PYTHON="$PY"
exec bash "$ROOT/start.sh" --enable-scan --fast-runner "$FAST" \
  --fullproject-phase51 "$P51" --ui-state "$UI" \
  --fullproject-live-root "$HOME/migration/ntk_fullproject_web_runs_phase6b" \
  --train-file "$TRAIN" --validation-file "$VALID"
