#!/usr/bin/env python3
"""Real OpenGrep-only checks for all pinned B38 input/rule combinations.

No CodeQL, no model inference, no semantic PASS receipts. Check every profile
in one run and retain all failures rather than failing at the first profile.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import sys
import traceback
import uuid
from bootstrap import ROOT
from ntk_b33.common import Blocker, COMMIT, sha_file, write_json
from ntk_b38.scanner import scan
from run_batch38 import (PHASES, implementation_sha, fixture_for,
                         verify_fixture_scanner, ensure_safe_input, frozen_state, pack)

PROFILES = ('A', 'B', 'C', 'SQL', 'D')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    parser.add_argument('--downloads', type=Path, default=Path('/mnt/c/Users/HP/Downloads'))
    parser.add_argument('--repo', type=Path, default=Path.home()/'iris')
    args = parser.parse_args(argv)
    args.work = args.work.resolve(); args.repo = args.repo.resolve(); args.downloads = args.downloads.resolve()
    if args.work == args.repo or args.repo in args.work.parents:
        raise Blocker('WORK_CANNOT_BE_INSIDE_FROZEN_REPOSITORY')
    if not args.downloads.is_dir():
        raise Blocker('DOWNLOADS_DIRECTORY_MISSING')
    args.work.mkdir(parents=True, exist_ok=True)
    lock = (args.work/'batch38_gpu_scan.lock').open('a+')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close(); raise Blocker('ANOTHER_B38_SCAN_IS_RUNNING')
    run = args.work/'batch38_scanner_preflight_runs'/(
        'batch38r1_scannerpreflight_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:6])
    run.mkdir(parents=True, exist_ok=False)
    summary = {'revision': 'B38R1_SCANNER_ENVIRONMENT', 'status': 'RUNNING',
        'scope': 'OPENGREP_SCANNER_INFRASTRUCTURE_ONLY_NOT_CWE_DETECTION_ACCEPTANCE',
        'implementation_sha256': implementation_sha(), 'profiles': {},
        'codeql_dataflow': 'NOT_EXECUTED', 'model_inference': 'NOT_EXECUTED',
        'training': 'NOT_EXECUTED', 'semantic_gate_receipts_written': False,
        'run_dir': str(run)}
    before = None
    try:
        before = frozen_state(args.repo); write_json(run/'FROZEN_BEFORE.json', before)
        if before['head'] != COMMIT or before['status_porcelain']:
            raise Blocker('FROZEN_REPOSITORY_CHANGED')
        mlpy = args.work/'.ntk_v5_lora_venv/bin/python'
        if not mlpy.is_file():
            raise Blocker('PINNED_ML_PYTHON_MISSING')
        for phase in PROFILES:
            print('B38R1_SCANNER_PREFLIGHT_PROFILE=' + phase, flush=True)
            one = run/'checks'/phase; one.mkdir(parents=True)
            record = {'status': 'RUNNING', 'cwes': PHASES[phase]}
            summary['profiles'][phase] = record
            try:
                archive = ROOT/'samples'/('B38'+phase+'_JAVA.zip')
                target = run/'uploaded_project'/phase
                provenance = ensure_safe_input(archive, target)
                fixture = fixture_for(provenance['archive_sha256'])
                if fixture is None or provenance['java_source_hashes'] != fixture['files']:
                    raise Blocker('PINNED_PREFLIGHT_SAMPLE_DRIFT')
                write_json(one/'INPUT_PROVENANCE.json', provenance)
                og = scan(one, target, PHASES[phase], mlpy)
                coverage = verify_fixture_scanner(og, fixture, target, PHASES[phase])
                write_json(one/'FIXTURE_COVERAGE.json', coverage)
                record.update(status='PASS', findings=len(og['results']),
                    coverage=coverage, input_sha256=provenance['archive_sha256'])
            except Exception as exc:
                record.update(status='BLOCKED', blocker=str(exc))
                (one/'FAILURE.txt').write_text(traceback.format_exc())
            write_json(one/'SUMMARY.json', record)
            print('B38R1_SCANNER_PROFILE_RESULT=' + phase + ' ' + record['status'], flush=True)
        summary['status'] = ('B38R1_SCANNER_PREFLIGHT_PASS' if
            all(summary['profiles'][p]['status']=='PASS' for p in PROFILES) else 'B38R1_SCANNER_PREFLIGHT_BLOCKED')
    except Exception as exc:
        summary.update(status='B38R1_SCANNER_PREFLIGHT_BLOCKED', blocker=str(exc))
        (run/'FAILURE.txt').write_text(traceback.format_exc())
    finally:
        try:
            after = frozen_state(args.repo); write_json(run/'FROZEN_AFTER.json', after)
            summary['frozen_unchanged'] = before is not None and before == after
        except Exception as exc:
            summary['frozen_unchanged'] = False
            summary['frozen_check_error'] = str(exc)
        if not summary['frozen_unchanged']:
            summary['status'] = 'B38R1_SCANNER_PREFLIGHT_BLOCKED'
        write_json(run/'00_SUMMARY.json', summary)
        try:
            output, _ = pack(run, args.downloads, summary)
        finally:
            lock.close()
    print('\n===== B38R1 SCANNER PREFLIGHT RESULT =====', flush=True)
    print('STATUS=' + summary['status'])
    print('SCOPE=' + summary['scope'])
    print('CODEQL_DATAFLOW=NOT_EXECUTED')
    print('MODEL_INFERENCE=NOT_EXECUTED')
    print('FROZEN_REPO_UNCHANGED=' + str(summary['frozen_unchanged']))
    print('RUN_DIR=' + str(run))
    print('OUTPUT_ZIP=' + str(output))
    print('OUTPUT_SHA256=' + sha_file(output))
    return 0 if summary['status']=='B38R1_SCANNER_PREFLIGHT_PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
