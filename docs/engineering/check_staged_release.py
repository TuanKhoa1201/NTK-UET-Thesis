#!/usr/bin/env python3
"""Fail-closed public release check of exactly the staged Git blobs."""
import io
import re
import subprocess
from pathlib import Path
from zipfile import ZipFile

ALLOWED_DIRS = (
    'ntk_hybrid/local_hybrid_cli/', 'ntk_hybrid/local_workbench/',
    'evaluation/dataset_sast/', 'evaluation/label_review/',
    'evaluation/locked_holdout/', 'evaluation/evidence_closeout/',
    'docs/engineering/',
)
ALLOWED_ZIPS = {
    'ntk_hybrid/local_hybrid_cli/samples/B39B4_JDK_INTEGRATION.zip',
    'ntk_hybrid/local_workbench/backend_b39b4.zip',
    'evaluation/locked_holdout/samples/B39B7_HOLDOUT_JDK.zip',
}
PATTERNS = [
    ('PRIVATE_KEY', rb'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----'),
    ('GITHUB_PAT', rb'gh[pousr]_[A-Za-z0-9_]{24,}'),
    ('OPENAI_API_KEY', rb'sk-[A-Za-z0-9]{20,}'),
    ('AWS_ACCESS_KEY', rb'AKIA[0-9A-Z]{16}'),
    ('PLAINTEXT_PASSWORD', rb'(?i)(?:password|passwd|secret_key|api_key)[ \t]*[:=][ \t]*[\x22\x27][^\x22\x27]{12,}'),
]

def git(*args):
    result=subprocess.run(['git',*args],capture_output=True)
    if result.returncode:
        raise SystemExit('BLOCKED: git '+ ' '.join(args)+': '+result.stderr.decode('utf-8','replace')[:1000])
    return result.stdout


def main():
    entries=git('diff','--cached','--name-only','--diff-filter=ACMR','-z').split(b'\0')
    files=[p.decode('utf-8','strict') for p in entries if p]
    if not files:raise SystemExit('BLOCKED: no staged files')
    for p in files:
        if not (p=='README.md' or any(p.startswith(prefix) for prefix in ALLOWED_DIRS)):
            raise SystemExit('BLOCKED: unexpected staged path '+p)
        if p.startswith('/') or '..' in Path(p).parts:
            raise SystemExit('BLOCKED: traversal '+p)
        if any(t in Path(p).parts for t in ('private','state','.venv','.git','__pycache__','model_weights','adapters')):
            raise SystemExit('BLOCKED: sensitive directory '+p)
        if p.endswith(('.safetensors','.pt','.pth','.ckpt','.gguf','.pyc','.db','.sqlite3','.log')):
            raise SystemExit('BLOCKED: forbidden file '+p)
        if p.lower().endswith('.zip') and p not in ALLOWED_ZIPS:
            raise SystemExit('BLOCKED: unexpected ZIP '+p)
        mode=git('ls-files','--stage','--',p).decode('utf-8').split()[0]
        if mode not in ('100644','100755'):
            raise SystemExit('BLOCKED: nonregular staged entry '+p+' mode='+mode)
        data=git('show',':'+p)
        if len(data)>1_500_000:
            raise SystemExit('BLOCKED: file too large '+p)
        for name,pat in PATTERNS:
            if re.search(pat,data):
                raise SystemExit('BLOCKED: possible '+name+' in '+p)
        if p.endswith('.zip'):
            with ZipFile(io.BytesIO(data)) as z:
                infos=z.infolist()
                if len(infos)>100:raise SystemExit('BLOCKED: unexpected ZIP size '+p)
                for n in infos:
                    if n.filename.startswith('/') or '..' in Path(n.filename).parts:
                        raise SystemExit('BLOCKED: unsafe ZIP member '+p)
                    if n.file_size>1_500_000:
                        raise SystemExit('BLOCKED: large ZIP member '+p)
                    if any(x in n.filename.lower() for x in ('safetensors','private/','password','.env','credentials')):
                        raise SystemExit('BLOCKED: private ZIP member '+p)
    git('diff','--cached','--check')
    print('PUBLIC_SOURCE_STAGING_CHECK=PASS')
    print('STAGED_FILE_COUNT='+str(len(files)))
    print('CHECK_SCOPE=STAGED_PATHS_MODES_SIZES_ZIP_CONTENT_AND_COMMON_SECRET_PATTERNS_NOT_A_FULL_SECURITY_AUDIT')

if __name__=='__main__':main()
