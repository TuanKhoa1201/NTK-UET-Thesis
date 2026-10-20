#!/usr/bin/env python3
"""Run every test module in a fresh process with a bounded lifetime.

This separates mock-runner state, HTTP threads and child seccomp tests. No test
is skipped and failures/timeouts block execution before real scanner preflight.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    total = 0
    files = sorted((ROOT/'tests').glob('test_*.py'))
    if not files:
        raise RuntimeError('NO_SELFTEST_MODULES')
    for file in files:
        print('\n===== SELFTEST MODULE: ' + file.name + ' =====', flush=True)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        process = subprocess.Popen([sys.executable, '-B', '-m', 'unittest', 'discover',
            '-s', str(ROOT/'tests'), '-p', file.name, '-v'], cwd=ROOT,
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True)
        try:
            output, _ = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate(timeout=15)
            print(output, end='', flush=True)
            print('SELFTEST_MODULE_TIMEOUT=' + file.name, flush=True)
            return 2
        print(output, end='', flush=True)
        match = re.search(r'Ran (\d+) tests? in ', output)
        if process.returncode or not match or re.search(r'OK \(skipped=',output):
            print('SELFTEST_MODULE_FAILED=' + file.name, flush=True)
            return 2
        total += int(match.group(1))
    print('\nSELFTESTS_PASSED=' + str(total), flush=True)
    print('SELFTEST_MODULES=' + str(len(files)), flush=True)
    print('SELFTESTS_SKIPPED=0', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
