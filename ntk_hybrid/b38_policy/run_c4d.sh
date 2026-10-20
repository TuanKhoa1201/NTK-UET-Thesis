#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
W="${NTK_WORK:-$HOME/migration/ntk_stage3_verified_v5_work}"
PY="$W/.ntk_v5_lora_venv/bin/python"
test -x "$PY"
cd "$ROOT"
printf '\n===== C4/D: VERIFY PACKAGE =====\n'
sha256sum -c SHA256SUMS
printf '\n===== C4/D: BASELINE CPU REGRESSION =====\n'
"$PY" -B run_selftests.py
printf '\n===== C4/D: NEW TESTS (NO CODEQL/GPU) =====\n'
"$PY" -B -m unittest discover -s newtests -v
printf '\n===== C4/D: REAL RUN =====\n'
exec "$PY" -B -u run_policy.py "$@"
