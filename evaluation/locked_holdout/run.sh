#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"; sha256sum -c SHA256SUMS >/dev/null
MODE="${1:-}"
case "$MODE" in
  prepare)
    : "${NTK_IRIS_PYTHON:?Activate conda iris and export NTK_IRIS_PYTHON}"
    : "${NTK_REVIEWER:?Set NTK_REVIEWER}"
    exec "$NTK_IRIS_PYTHON" -I -B "$HERE/prepare_holdout.py" --work "$HOME/migration/ntk_stage3_verified_v5_work" --downloads "/mnt/c/Users/HP/Downloads" --reviewer "$NTK_REVIEWER" --package-root "$HERE"
    ;;
  run-and-evaluate) exec bash "$HERE/run_and_evaluate.sh" ;;
  *) echo 'Usage: bash run.sh prepare | run-and-evaluate' >&2; exit 2;;
esac
