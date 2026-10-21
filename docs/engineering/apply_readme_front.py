#!/usr/bin/env python3
"""Safe README front-matter replacement in a clean copy of the pinned public repository."""
from pathlib import Path
import hashlib
import sys
repo=Path(sys.argv[1]).resolve()
readme=repo/'README.md'
original=readme.read_bytes()
# The checked public main README has an old front-matter section before its first --- divider.
old=b'# NTK SAST '
if not original.startswith(old):
    raise SystemExit('BLOCKED: unexpected README header; edit manually, do not overwrite')
if original.count(b'\n---\n',0,1000)!=1:
    raise SystemExit('BLOCKED: expected one top disclaimer separator in first 1000 bytes')
a,b=original.split(b'\n---\n',1)
if b'Batch 38DPA' not in a:
    raise SystemExit('BLOCKED: old README front matter already changed')
new=(repo/'docs/engineering/README_FRONT_MATTER.md').read_bytes()
if b'NTK SAST - Local OpenGrep' not in new:
    raise SystemExit('BLOCKED: missing new README text')
# Use a write-to-temp then atomic rename; no modification if there is any unexpected state.
tmp=readme.with_name('.README.staging.tmp')
if tmp.exists():raise SystemExit('BLOCKED: temporary README already exists')
with tmp.open('xb') as f:f.write(new+b)
tmp.replace(readme)
print('README_PROLOGUE_UPDATED=YES')
print('README_SHA256='+hashlib.sha256(readme.read_bytes()).hexdigest())
