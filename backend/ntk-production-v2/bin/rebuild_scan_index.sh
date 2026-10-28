#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
STORAGE_DIR="${1:-${NTK_STORAGE_DIR:-${ROOT_DIR}/persisted_api_store}}"
exec "${PYTHON_BIN}" "${ROOT_DIR}/scripts/rebuild_scan_index.py" --storage-dir "${STORAGE_DIR}"
