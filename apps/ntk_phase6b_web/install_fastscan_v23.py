#!/usr/bin/env python3
"""Idempotently clone the experimental runner into an independent, hash-verified v2.3 candidate.

Runs CPU-only.  Never executes CodeQL, OpenGrep, GPU inference or changes existing runs.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from fastscan_v23_patch import BASE_SHA, RESEARCH_SHA, sha, upgrade_bytes


def check_regular(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('REQUIRED_REGULAR_FILE_MISSING:'+str(path))
    return path.read_bytes()


def verify_manifest(root):
    root=Path(root)
    entries=check_regular(root/'SHA256SUMS').decode('ascii').splitlines()
    seen=set()
    for item in entries:
        h,separator,relative=item.partition('  ')
        if separator!='  ' or len(h)!=64 or any(c not in '0123456789abcdef' for c in h):
            raise ValueError('INVALID_ENGINE_MANIFEST_LINE')
        path=Path(relative)
        if path.is_absolute() or any(p in ('.','..') for p in path.parts) or relative in seen:
            raise ValueError('UNSAFE_OR_DUPLICATE_ENGINE_MANIFEST')
        seen.add(relative)
        if sha(check_regular(root/path))!=h:
            raise ValueError('ENGINE_MANIFEST_FILE_CHANGED:'+relative)
    return sha(check_regular(root/'SHA256SUMS'))


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('--dev-root',type=Path,default=Path.home()/'migration/ntk_fastscan_dev_20261021')
    a=p.parse_args(argv)
    dev=a.dev_root.expanduser().resolve()
    ref=dev/'engine_reference'
    old=dev/'engine_candidate'
    new=dev/'engine_candidate_v23'
    report=dev/'FASTSCAN_PATCH_REPORT_V23.json'
    for pth in (ref,old):
        if not pth.is_dir() or pth.is_symlink():
            raise ValueError('ORIGINAL_ENGINE_DIRECTORY_MISSING')
    ref_hash=verify_manifest(ref)
    if verify_manifest(old)!=ref_hash:
        raise ValueError('ORIGINAL_CANDIDATE_DRIFT')
    if check_regular(ref/'run_hybrid.py')!=check_regular(old/'run_hybrid.py'):
        raise ValueError('RESEARCH_RUNNER_DRIFT')
    if sha(check_regular(old/'run_hybrid.py'))!=RESEARCH_SHA:
        raise ValueError('RESEARCH_RUNNER_PIN_MISMATCH')
    source=check_regular(old/'run_fastscan.py')
    if sha(source)!=BASE_SHA:
        raise ValueError('PREVIOUS_SUCCESSFUL_FAST_RUNNER_SHA_MISMATCH')
    result=upgrade_bytes(source)
    target=new/'run_fastscan.py'
    if not new.exists():
        if report.exists():
            raise ValueError('PATCH_REPORT_WITHOUT_CANDIDATE')
        shutil.copytree(old,new,symlinks=True)
        # The cloned experimental script is disposable. Never touch the old one.
        if sha(check_regular(target))!=BASE_SHA:
            raise ValueError('CLONE_SOURCE_SHA_DRIFT')
        tmp=new/'run_fastscan.py.v23.tmp'
        if tmp.exists() or tmp.is_symlink():
            raise ValueError('PATCH_TEMP_PATH_ALREADY_EXISTS')
        with tmp.open('xb') as f:
            f.write(result)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,target)
        os.chmod(target,0o600)
    elif new.is_symlink() or not new.is_dir():
        raise ValueError('CANDIDATE_DIRECTORY_NOT_VALID')
    if verify_manifest(new)!=ref_hash or check_regular(new/'run_hybrid.py')!=check_regular(old/'run_hybrid.py'):
        raise ValueError('CLONE_RESEARCH_MANIFEST_DRIFT')
    if check_regular(target)!=result:
        raise ValueError('V23_PATCHED_RUNNER_MISMATCH')
    proof={'status':'NTK_FAST_E1_V23_CPU_PATCH_VERIFIED',
           'source_runner_sha256':BASE_SHA,
           'patched_runner_sha256':sha(result),
           'research_runner_sha256':RESEARCH_SHA,
           'frozen_engine_manifest_sha256':ref_hash,
           'runner':str(target),
           'frozen_sources_modified':False,
           'original_fastscan_modified':False,
           'web_v22_modified':False,
           'new_training':False,'new_gpu_execution':False,
           'codeql_executed_during_install':False,
           'full_hybrid_under_120s':'NOT_YET_VERIFIED'}
    if report.exists():
        if report.is_symlink() or json.loads(report.read_text())!=proof:
            raise ValueError('PRIOR_PATCH_PROOF_CONFLICT')
    else:
        with report.open('x',encoding='utf-8') as f:
            json.dump(proof,f,indent=2,ensure_ascii=False)
            f.write('\n')
    print(json.dumps(proof,indent=2,ensure_ascii=False))
    print('V23_PATCH_CPU_VERIFIED=TRUE')
    return 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print('V23_PATCH_REFUSED='+type(e).__name__+': '+str(e),file=sys.stderr)
        sys.exit(2)
