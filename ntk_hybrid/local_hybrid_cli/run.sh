#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="${NTK_IRIS_PYTHON:?Activate conda iris and export NTK_IRIS_PYTHON first}"
test -x "$PY"
cd "$ROOT"
printf '\n===== VERIFY B39B4 PACKAGE =====\n'
sha256sum -c SHA256SUMS
printf '\n===== B39B4 SYNTHETIC SELFTESTS =====\n'
for TEST in test_b39b2.py test_b39b3.py test_hybrid.py test_hybrid_lifecycle.py; do
    if ! "$PY" -I -B "$ROOT/$TEST" > "$ROOT/${TEST%.py}.log" 2>&1; then
        tail -n 70 "$ROOT/${TEST%.py}.log"
        exit 2
    fi
    tail -n 5 "$ROOT/${TEST%.py}.log"
done
L="$(mktemp "$ROOT/B39B4_TERMINAL_XXXXXXXX.log")"
printf '\n===== B39B4 REAL HYBRID CLI =====\n'
RC=0
"$PY" -I -B -u "$ROOT/run_hybrid.py" --host-python "$PY" "$@" 2>&1 | tee "$L" || RC=$?
printf '\nCOLLECTOR_EXIT_CODE=%s\nTERMINAL_LOG=%s\n' "$RC" "$L"
exit "$RC"
