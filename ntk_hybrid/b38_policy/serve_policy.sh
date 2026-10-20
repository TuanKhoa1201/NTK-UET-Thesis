#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
W="${NTK_WORK:-$HOME/migration/ntk_stage3_verified_v5_work}"
PY="$W/.ntk_v5_lora_venv/bin/python"
test -x "$PY"
cd "$ROOT"
sha256sum -c SHA256SUMS
exec "$PY" -B -u web_policy.py --work "$W" "$@"
