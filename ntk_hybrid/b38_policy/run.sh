#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
W="${NTK_WORK:-$HOME/migration/ntk_stage3_verified_v5_work}"
PY="$W/.ntk_v5_lora_venv/bin/python"
test -x "$PY" || { echo "BLOCKED: MLPY missing: $PY"; exit 2; }
cd "$ROOT"
printf '\n===== B38: VERIFY SOURCE PACKAGE =====\n'
sha256sum -c SHA256SUMS
printf '\n===== B38: CPU SAFETY AND REGRESSION TESTS =====\n'
PYTHONDONTWRITEBYTECODE=1 "$PY" -B "$ROOT/run_selftests.py"
printf '\n===== B38: REAL RUNTIME START =====\n'
exec "$PY" -B -u "$ROOT/run_batch38.py" "$@"
