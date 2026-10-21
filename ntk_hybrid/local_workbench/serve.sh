#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="${NTK_IRIS_PYTHON:?Activate conda iris and export NTK_IRIS_PYTHON first}"
test -x "$PY"
test -f "$ROOT/INSTALL.json"
cd "$ROOT"
sha256sum -c SHA256SUMS
exec "$PY" -I -B -u "$ROOT/launch.py" "$@"
