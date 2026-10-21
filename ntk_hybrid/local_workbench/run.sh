#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="${NTK_IRIS_PYTHON:?Activate conda iris and export NTK_IRIS_PYTHON first}"
test -x "$PY"
cd "$ROOT"
printf '\n===== VERIFY B39B5 PACKAGE =====\n'
sha256sum -c SHA256SUMS
printf '\n===== NEW WORKBENCH SELFTESTS (SYNTHETIC DATA) =====\n'
if ! "$PY" -I -B "$ROOT/test_workbench.py" > "$ROOT/SELFTEST.log" 2>&1; then
    tail -n 90 "$ROOT/SELFTEST.log"
    exit 2
fi
tail -n 5 "$ROOT/SELFTEST.log"
L="$(mktemp "$ROOT/B39B5_TERMINAL_XXXXXXXX.log")"
RC=0
"$PY" -I -B -u "$ROOT/setup_workbench.py" --host-python "$PY" "$@" 2>&1 | tee "$L" || RC=$?
printf '\nCOLLECTOR_EXIT_CODE=%s\nTERMINAL_LOG=%s\n' "$RC" "$L"
exit "$RC"
