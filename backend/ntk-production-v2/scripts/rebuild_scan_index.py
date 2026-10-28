#!/usr/bin/env python3
"""
Portable SQLite Scan Index Rebuild Utility (`scripts/rebuild_scan_index.py`)
Rebuilds `scan_result_index.sqlite3` from persisted `<scan_id>.json` and `<scan_id>.pipeline_trace.json`
files in `NTK_STORAGE_DIR` (or `--storage-dir`). Safe to run offline before starting the HTTP server.
"""
import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ntk_pipeline_telemetry_and_datasets import NtkScanResultIndex


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild NTK SQLite scan result index from persisted JSON files.")
    parser.add_argument(
        "--storage-dir",
        default=os.environ.get("NTK_STORAGE_DIR", "./persisted_api_store"),
        help="Path to persisted_api_store directory containing SCAN-*.json files.",
    )
    parser.add_argument(
        "--force-clean",
        action="store_true",
        help="Remove existing scan_result_index.sqlite3 before rebuilding from JSON files.",
    )
    args = parser.parse_args()
    storage_dir = Path(args.storage_dir).resolve()
    if not storage_dir.is_dir():
        print(f"ERROR: storage directory does not exist: {storage_dir}", file=sys.stderr)
        return 1

    db_file = storage_dir / "scan_result_index.sqlite3"
    if args.force_clean and db_file.exists():
        for suffix in ["", "-wal", "-shm"]:
            p = Path(str(db_file) + suffix)
            if p.exists():
                p.unlink()

    traces_map = {}
    for tr_file in sorted(storage_dir.glob("*.pipeline_trace.json")):
        sid = tr_file.name[: -len(".pipeline_trace.json")]
        try:
            traces_map[sid] = json.loads(tr_file.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"WARN: failed to parse trace {tr_file.name}: {exc}", file=sys.stderr)

    idx = NtkScanResultIndex(storage_dir=storage_dir)
    summaries = idx.sync_storage_dir(pipeline_traces_by_scan=traces_map)
    print(json.dumps({
        "status": "OK",
        "storage_dir": str(storage_dir),
        "sqlite_db": str(idx.db_path),
        "indexed_scan_count": len(summaries),
        "indexed_scan_ids": sorted(summaries.keys()),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
