#!/usr/bin/env bash
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
W="${W:-$HOME/migration/ntk_stage3_verified_v5_work}"
D="${D:-/mnt/c/Users/HP/Downloads}"
G="${G:-$HOME/migration/ntk_github_publish_20261020}"
RPO="${RPO:-$HOME/iris}"
HOST="${NTK_IRIS_PYTHON:-}"
[ -n "$HOST" ] && [ -x "$HOST" ] || { echo 'BLOCKED: activate conda iris and export NTK_IRIS_PYTHON'; exit 2; }
cd "$HERE"; sha256sum -c SHA256SUMS >/dev/null
PTR="$W/NTK_B39B7_HOLDOUT_WORKSPACE.txt"; [ -f "$PTR" ] || { echo 'BLOCKED: holdout lock not prepared'; exit 2; }
WS="$(cat "$PTR")"; [ -f "$WS/HOLDOUT_LOCK.json" ] || { echo 'BLOCKED: lock missing'; exit 2; }
PROJECT="$WS/private/B39B7_HOLDOUT_JDK.zip"; [ -f "$PROJECT" ] || { echo 'BLOCKED: project zip missing'; exit 2; }
B4="$D/ntk_batch39b4_hybrid_cli_20261020.zip"; B4H='e30a7fc1434b083c87bda80da1667bd2e9d64664d8cb2bf80d00534efaf3791c'
B3="$D/b39b3_20261020T051708Z_d535d53e_result.zip"; B3H='26666def24a3ad71af54d520c9c3c9f9c425675865184a35c53ea2c22e2318ea'
[ -f "$B4" ] && [ -f "$B3" ] || { echo 'BLOCKED: B39B4 package or B39B3 result missing in Downloads'; exit 2; }
printf '%s  %s\n' "$B4H" "$B4" | sha256sum -c -
printf '%s  %s\n' "$B3H" "$B3" | sha256sum -c -
BT="$(mktemp -d "$W/b39b7_backend_tools_XXXXXXXX")"; unzip -q -n "$B4" -d "$BT"; (cd "$BT" && sha256sum -c SHA256SUMS >/dev/null)
LOG="$WS/B39B7_BACKEND_TERMINAL.log"
set +e
"$HOST" -I -B -u "$BT/run_hybrid.py" --work "$W" --repo "$RPO" --github "$G" --downloads "$D" --host-python "$HOST" --project-zip "$PROJECT" --run-hybrid 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e
if [ "$RC" -ne 0 ]; then echo "B39B7_BACKEND_EXIT_CODE=$RC"; echo "BACKEND_LOG=$LOG"; exit "$RC"; fi
OUT="$(awk -F= '/^OUTPUT_ZIP=/{print substr($0,index($0,"=")+1)}' "$LOG" | tail -n1)"
[ -n "$OUT" ] && [ -f "$OUT" ] || { echo 'BLOCKED: backend output zip not found in terminal log'; exit 2; }
"$HOST" -I -B - "$WS" "$OUT" <<'PY'
import json,sys,hashlib
from pathlib import Path
ws=Path(sys.argv[1]);out=Path(sys.argv[2])
lock=json.loads((ws/'HOLDOUT_LOCK.json').read_text())
h=hashlib.sha256(out.read_bytes()).hexdigest()
(ws/'PREDICTION_RUN_LINK.json').write_text(json.dumps({'backend_result_zip':str(out),'backend_result_sha256':h,'holdout_lock_sha256':hashlib.sha256((ws/'HOLDOUT_LOCK.json').read_bytes()).hexdigest()},indent=2)+'\n')
PY
"$HOST" -I -B "$HERE/evaluate_holdout.py" --work "$W" --workspace "$WS" --result-zip "$OUT" --downloads "$D"
