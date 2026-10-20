#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
W="${NTK_WORKROOT:-$HOME/migration/ntk_stage3_verified_v5_work}"
PY="$W/.ntk_v5_lora_venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "BLOCKER=B37A_LORA_PYTHON_MISSING: $PY" >&2
  exit 2
fi
cd "$HERE"
sha256sum -c SHA256SUMS
export PYTHONDONTWRITEBYTECODE=1
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1
export CODEQL_TELEMETRY_DISABLE=1 SEMGREP_SEND_METRICS=off OPENGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0 OPENGREP_ENABLE_VERSION_CHECK=0
export WANDB_DISABLED=true TOKENIZERS_PARALLELISM=false
args=()
found=false
for item in "$@"; do
  if [ "$item" = "--project-zip" ]; then found=true; fi
done
if [ "$found" = false ]; then
  args=(--project-zip "$HERE/sample_new_java_project.zip")
fi
exec "$PY" -B -u "$HERE/run_batch37a.py" --work "$W" "${args[@]}" "$@"
