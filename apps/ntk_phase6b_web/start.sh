#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
sha256sum -c SHA256SUMS
PY="${NTK_IRIS_PYTHON:-$(command -v python)}"
test -x "$PY"
exec "$PY" -I -B -u "$ROOT/server.py" --port 8770 "$@"
