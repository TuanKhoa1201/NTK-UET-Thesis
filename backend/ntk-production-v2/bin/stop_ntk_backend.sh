#!/usr/bin/env bash
set -euo pipefail
PORT="${NTK_BACKEND_PORT:-8765}"
PIDS="$(pgrep -f "ntk_web_backend_service.py.*--port ${PORT}" || true)"
if [[ -z "${PIDS}" ]]; then
  echo "No running ntk_web_backend_service.py process found on port ${PORT}."
  exit 0
fi
echo "Stopping ntk_web_backend_service.py (PIDs: ${PIDS})..."
kill ${PIDS}
