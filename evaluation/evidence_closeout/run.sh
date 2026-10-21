#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${1:-}" != "--audit-closeout" || "$#" -ne 1 ]]; then
    printf '%s\n' 'USAGE: bash run.sh --audit-closeout' >&2
    exit 2
fi

P="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
W="$HOME/migration/ntk_stage3_verified_v5_work"
D="/mnt/c/Users/HP/Downloads"
PY="${NTK_IRIS_PYTHON:?Activate conda iris and export NTK_IRIS_PYTHON}"

B4="$D/b39b4_20261020T100814Z_63d29938_result.zip"
EVAL="$D/b39b7_eval_20261020T103624Z_364e7982_result.zip"
R="$(cat "$W/NTK_B39B7_HOLDOUT_WORKSPACE.txt")"
SOURCE="$R/private/B39B7_HOLDOUT_JDK.zip"

printf '\n===== B39B8 VERIFY PACKAGE =====\n'
(cd "$P" && sha256sum -c SHA256SUMS)

printf '\n===== B39B8 VERIFY INPUT ARCHIVES =====\n'
test -x "$PY"
test -d "$W"
test -d "$D"
test -d "$R"
test -f "$R/HOLDOUT_LOCK.json"
test -f "$R/PREDICTION_RUN_LINK.json"
test -f "$B4"
test -f "$EVAL"
test -f "$SOURCE"
printf '%s  %s\n' \
    '560020e7a5d78e0b2b8500652eaf951e835b758fdcd3c596374c72a2a2e59bf2' "$B4" | sha256sum -c -
printf '%s  %s\n' \
    '8d95a918da2f4601415a12eba0ea9dc7e93a28c8e4a107a53e2ed4ec01dbc0fd' "$EVAL" | sha256sum -c -
printf '%s  %s\n' \
    '6e968d05c11073a71a218950c80250ad10ed59a97d8ac04faa354746a489c15a' "$SOURCE" | sha256sum -c -
printf '%s  %s\n' \
    '5bccf51fcc98611abde6c01049816a9d02681b89d52f1befacced6a51387597d' "$R/HOLDOUT_LOCK.json" | sha256sum -c -

printf '\n===== B39B8 CPU TESTS AND PINNED REPLAY =====\n'
export NTK_B39B8_EVAL_ZIP="$EVAL"
export NTK_B39B8_BACKEND_ZIP="$B4"
export NTK_B39B8_SOURCE_ZIP="$SOURCE"
"$PY" -I -B "$P/test_closeout.py"

printf '\n===== B39B8 FULL LOCAL PRIVATE EVIDENCE CLOSEOUT =====\n'
"$PY" -I -B "$P/closeout.py" \
    --work "$W" \
    --downloads "$D" \
    --workspace "$R" \
    --backend-zip "$B4" \
    --evaluation-zip "$EVAL" \
    --source-zip "$SOURCE"
