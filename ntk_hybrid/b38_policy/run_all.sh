#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ARM="${1:-epoch_1}"
W="${NTK_WORK:-$HOME/migration/ntk_stage3_verified_v5_work}"
D="${NTK_DOWNLOADS:-/mnt/c/Users/HP/Downloads}"
PY="$W/.ntk_v5_lora_venv/bin/python"
case "$ARM" in epoch_1|epoch_2) ;; *) echo "Use epoch_1 or epoch_2"; exit 2;; esac
test -x "$PY" || { echo "BLOCKED: MLPY missing: $PY"; exit 2; }
cd "$ROOT"
printf '\n===== B38R1: VERIFY SOURCE PACKAGE =====\n'
sha256sum -c SHA256SUMS
printf '\n===== B38R1: CPU SAFETY AND REGRESSION TESTS =====\n'
PYTHONDONTWRITEBYTECODE=1 "$PY" -B "$ROOT/run_selftests.py"
printf '\n===== B38R1: REAL SCANNER PREFLIGHT ALL PROFILES BEFORE CODEQL/GPU =====\n'
"$PY" -B -u "$ROOT/preflight_scanner.py" --work "$W" --downloads "$D"
for PHASE in A B C D; do
  printf '\n===== RUN PHASE %s WITH %s =====\n' "$PHASE" "$ARM"
  bash "$ROOT/run.sh" --phase "$PHASE" --arm "$ARM" --work "$W" --downloads "$D"
done
printf '\nB38 A B C D gates completed. Web has NOT been auto-started.\n'
printf 'Run: bash "%s/serve.sh"\n' "$ROOT"
