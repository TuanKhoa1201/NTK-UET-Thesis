#!/usr/bin/env python3
"""Read-only timing audit for NTK local hybrid runs. No model or scanner is launched."""
from __future__ import annotations
import argparse
import collections
import json
from pathlib import Path
from typing import Any

DEFAULT_WORK = Path.home() / 'migration/ntk_stage3_verified_v5_work'


def load_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        return None
    if path.stat().st_size > 32 * 1024 * 1024:
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def seconds(item: dict) -> float | None:
    for key in ('elapsed_s', 'duration_s', 'elapsed_seconds', 'duration_seconds', 'wall_s',
                'wall_seconds', 'seconds', 'elapsed', 'duration', 'runtime_s', 'time_s'):
        value = item.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            return float(value)
    start = item.get('start_monotonic') or item.get('started_at')
    end = item.get('end_monotonic') or item.get('ended_at')
    if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
        return float(end-start)
    return None


def bucket(item: dict) -> str:
    log = str(item.get('log', '')).lower()
    if 'database_create' in log or 'database' in log and 'create' in log:
        return 'CODEQL_DATABASE'
    if (any(k in log for k in ('live_', 'context_policy', 'flow_')) or
        ('analysis/' in log and any(k in log for k in ('/run.log','/compile.log','/interpret.log')))):
        return 'CODEQL_DATAFLOW_OR_POLICY'
    if any(k in log for k in ('compile_', 'pack_resolve', 'resolve')):
        return 'CODEQL_COMPILE_PREFLIGHT'
    if any(k in log for k in ('apicalls', 'argumentspans', 'httpcontexts', 'sources_', '_query', '_decode')):
        return 'CODEQL_EXTRACTION'
    if any(k in log for k in ('driver', 'tokenizer', 'gpu', 'worker')):
        return 'LLM_AND_NATIVE_IRIS'
    if any(k in log for k in ('opengrep', 'semgrep')):
        return 'OPENGREP'
    if any(k in log for k in ('javac', 'encoding', 'build_jdk')):
        return 'JAVAC_AND_ENCODING'
    return 'OTHER'


def summarize(root: Path) -> None:
    root = root.resolve()
    assert root.is_dir(), f'No run directory: {root}'
    print('\n===== RUN: ' + root.name + ' =====')
    summary = load_json(root/'00_RESULT.json') or load_json(root/'PROGRESS.json') or {}
    for key in ('status','elapsed_s','opengrep_state','codeql_database_state','model_inference_state',
                'raw_opengrep_findings','new_native_requests','current_stage'):
        if key in summary:
            print(f'{key}: {summary[key]}')
    for blocker in summary.get('blockers', []):
        print('BLOCKER:',str(blocker)[:350])
    completed = summary.get('completed_arms')
    if completed is not None:
        print('completed_arms:',completed)
    timings = load_json(root/'COMMAND_TIMINGS.json')
    if not isinstance(timings, list):
        print('TIMINGS: not found or invalid')
    else:
        durations = []
        unknown = []
        groups = collections.defaultdict(lambda: [0, 0.0])
        for item in timings:
            if not isinstance(item, dict):
                continue
            t = seconds(item)
            label = str(item.get('log', '[unnamed]'))
            if t is None:
                unknown.append((label, sorted(item.keys())))
                continue
            typ = bucket(item)
            groups[typ][0] += 1
            groups[typ][1] += t
            durations.append((t,label,typ, item.get('returncode')))
        print(f'COMMAND_COUNT: {len(timings)}')
        print(f'TIMED_COUNT: {len(durations)}; UNRECOGNIZED_TIMING_FIELDS: {len(unknown)}')
        if unknown:
            print('FIRST_UNKNOWN_FIELDS:', unknown[0][1])
        if durations:
            print('\nCATEGORY_TOTALS (command seconds, may overlap if commands parallel):')
            for k, v in sorted(groups.items(),key=lambda kv:kv[1][1],reverse=True):
                print(f'{k:29s} {v[1]:10.1f}s  {v[0]:3d} command(s)')
            print('\nSLOWEST_COMMANDS:')
            for t,label,typ,ret in sorted(durations,reverse=True)[:20]:
                print(f'  {t:9.2f}s  rc={ret}  {typ:28s} {label[:115]}')
    candidates = load_json(root/'private/CANDIDATES_BY_CWE.json')
    if isinstance(candidates, dict):
        print('CANDIDATES_BY_CWE:', {str(k):len(v) if isinstance(v,list) else '?' for k,v in candidates.items()})
    else:
        print('CANDIDATES_BY_CWE: unavailable (runner may fail before writing file)')
    for name in ('ApiCalls.csv','ArgumentSpans.csv','HttpContexts.csv',
                 'Sources_22.csv','Sources_78.csv','Sources_79.csv','Sources_89.csv'):
        p = root/'private'/name
        if p.is_file():
            print(f'EXTRACTION_OUTPUT_PRESENT: {name} ({p.stat().st_size} bytes)')
    failure = root/'private/FAILURE.txt'
    if failure.is_file():
        # No traceback content printed: can contain source or local paths.
        print('FAILURE_TRACEBACK_AVAILABLE: yes (not displayed for privacy)')


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work',type=Path,default=DEFAULT_WORK)
    ap.add_argument('--run',type=Path,action='append',help='Full run directory, repeat for comparison')
    ap.add_argument('--latest',type=int,default=3,help='Used only when --run omitted')
    args=ap.parse_args()
    if args.run:
        roots=args.run
    else:
        base=args.work.expanduser()/'batch39b4_hybrid_runs'
        assert base.is_dir(), f'Run root not found: {base}'
        roots=sorted((p for p in base.iterdir() if p.is_dir() and p.name.startswith('b39b4_')),
                     key=lambda p:p.name,reverse=True)[:max(1,min(20,args.latest))]
    for root in roots:
        summarize(root)
    print('\nAUDIT_READ_ONLY=TRUE; NO_NEW_SCAN_OR_MODEL_INFERENCE=TRUE')
    return 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit('READ_ONLY_AUDIT_BLOCKED='+str(exc)) from None
