#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="${NTK_IRIS_PYTHON:-$(command -v python3)}"
test -x "$PY"
cd "$ROOT"
printf '\n===== VERIFY B39B6 PACKAGE =====\n'
sha256sum -c SHA256SUMS
if [ "$#" -eq 0 ]; then set -- prepare; fi
if [ "$1" = prepare ]; then
  LOG="$(mktemp "$ROOT/SELFTEST_XXXXXXXX.log")"
  printf '\n===== CPU EVALUATOR SELFTESTS: SYNTHETIC ONLY =====\n'
  if ! "$PY" -I -B "$ROOT/test_eval.py" > "$LOG" 2>&1; then cat "$LOG"; exit 2; fi
  tail -n 5 "$LOG"
  TERMLOG="$(mktemp "$ROOT/TERMINAL_XXXXXXXX.log")"
  RC=0
  "$PY" -I -B -u "$ROOT/cli.py" "$@" 2>&1 | tee "$TERMLOG" || RC=$?
  printf 'COLLECTOR_EXIT_CODE=%s\nTERMINAL_LOG=%s\n' "$RC" "$TERMLOG"
  exit "$RC"
fi
exec "$PY" -I -B -u "$ROOT/cli.py" "$@"
