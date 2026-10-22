#!/usr/bin/env python3
"""Fetch 3 pin-verified Java source examples from GitHub and create NTK ZIPs.

For local static analysis only. Never executes the downloaded Java applications.
Requires outbound GitHub HTTPS just for downloading public source; no LLM API calls.
Usage: python tools/prepare_github_java_samples.py --output-dir /mnt/c/Users/HP/Downloads
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SOURCE_FILES = (
    {
        'name': 'NTK_GitHub_Test_01_SemgrepDemo',
        'repository': 'sbmaggarwal/java-semgrep-demo',
        'branch': 'vulnerable',
        'commit': '3977bfe42df747d810aa16b722bf44df9e7a0250',
        'files': (
            ('src/main/java/com/example/demo/VulnerableApp.java',
             'src/com/example/demo/VulnerableApp.java',
             'cf0d9093c7e76a111b0914d669f697f515254483'),
        ),
        'note': '1 Java file; purposely vulnerable vs. fixed branches; CWE-22/78/89 examples',
    },
    {
        'name': 'NTK_GitHub_Test_02_DevSentinel',
        'repository': 'parig2005/devsentinel',
        'branch': 'main',
        'commit': 'd7b9e78f1a556e7ebc5a078247390b32e1c76628',
        'files': (
            ('samples/VulnerableExample.java',
             'src/com/example/demo/VulnerableExample.java',
             '01571b2cff4226b99770a3d5a89d866c112eeae9'),
        ),
        'note': '1 Java file; JDK-only examples of SQL/command/path issues',
    },
    {
        'name': 'NTK_GitHub_Test_03_SonarSamples',
        'repository': 'xibuka/sonarscanner-example',
        'branch': 'main',
        'commit': '298d0e009bcd3c3532b0c4e42d049c496a0e7e58',
        'files': (
            ('Java/DataProcessor.java',
             'src/DataProcessor.java',
             'a5dad99697d8ef215767b9a5498d74cadf6a162b'),
            ('Java/UserAuthentication.java',
             'src/UserAuthentication.java',
             '5efd21bbf2d291379578ce6a501eff76830e13cb'),
        ),
        'note': '2 Java files; SQL/command/path patterns plus other quality issues',
    },
)

MAX_SOURCE_BYTES=2*1024*1024
MAX_DOWNLOAD_BYTES=MAX_SOURCE_BYTES+1


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def blob_sha(blob: bytes) -> str:
    # Git blob object identifier; independent of HTTP headers/metadata.
    prefix=b'blob '+str(len(blob)).encode('ascii')+b'\0'
    return hashlib.sha1(prefix+blob).hexdigest()


def fetch(repo: str, commit: str, original: str) -> bytes:
    assert re.fullmatch(r'[0-9a-f]{40}',commit)
    parts=repo.split('/')
    assert len(parts)==2 and all(re.fullmatch(r'[A-Za-z0-9_.-]+',x) for x in parts)
    assert original.endswith('.java') and '..' not in Path(original).parts
    link='https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+urllib.parse.quote(original)
    req=urllib.request.Request(link,headers={'User-Agent':'NTK-local-Java-fixture-prep/1.0',
         'Accept':'text/plain'})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read(MAX_DOWNLOAD_BYTES)


def checked_source(repo: str, commit: str, original: str, expected_blob: str, fetcher=fetch) -> bytes:
    blob=fetcher(repo,commit,original)
    if not 0<len(blob)<=MAX_SOURCE_BYTES:
        raise ValueError('Missing or oversized Java file: '+original)
    if blob_sha(blob)!=expected_blob:
        raise ValueError('Git blob checksum mismatch: '+original)
    blob.decode('utf-8')
    return blob


def create_prepared_zip(spec: dict, output_dir: Path, fetcher=fetch) -> tuple[Path,dict]:
    if len(spec['files']) not in range(1,25):
        raise ValueError('Outside 1-24 Java-file contract')
    source={}
    record=[]
    for original,dest,expected in spec['files']:
        p=Path(dest)
        if p.is_absolute() or any(x in ('.','..') for x in p.parts) or not str(p).endswith('.java'):
            raise ValueError('Unsafe package destination')
        if dest in source:
            raise ValueError('Duplicate destination')
        raw=checked_source(spec['repository'],spec['commit'],original,expected,fetcher)
        source[dest]=raw
        record.append({'source_path':original,'zip_path':dest,'github_blob_sha1':expected,
                       'source_sha256':sha256(raw),'bytes':len(raw)})
    if sum(len(b) for b in source.values())>16*1024*1024:
        raise ValueError('ZIP outside 16 MiB bound')
    with tempfile.TemporaryDirectory(prefix='ntk-github-compile-') as work:
        root=Path(work); src=root/'sources';out=root/'classes';empty=root/'empty'
        for p in (src,out,empty):p.mkdir()
        for rel,raw in source.items():
            f=src/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw)
        cmd=['javac','--release','21','-proc:none','-encoding','UTF-8',
             '-classpath',str(empty),'-sourcepath',str(empty),'-d',str(out),
             *[str(src/p) for p in sorted(source)]]
        check=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=120)
        if check.returncode:
            raise ValueError('JDK-only javac preflight failed for '+spec['name']+':\n'+check.stderr[-2000:])
    outbuf=io.BytesIO()
    with zipfile.ZipFile(outbuf,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(source):
            info=zipfile.ZipInfo(path,date_time=(2020,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100644<<16)
            archive.writestr(info,source[path],compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    packed=outbuf.getvalue()
    assert len(packed)<=16*1024*1024
    filename=spec['name']+'.zip'
    dest=output_dir/filename
    if dest.exists():
        if not dest.is_file() or sha256(dest.read_bytes())!=sha256(packed):
            raise ValueError('Destination already exists with different bytes: '+str(dest))
    else:
        with dest.open('xb') as f:f.write(packed)
    proof={'name':spec['name'],'source_repository':'https://github.com/'+spec['repository'],
           'source_branch':spec['branch'],'commit':spec['commit'],'notes':spec['note'],
           'zip_sha256':sha256(packed),'zip_bytes':len(packed), 'java_files':len(source),
           'javac_21_preflight':'PASS', 'warning':'External examples, not guaranteed scanner detections or independent gold',
           'files':record}
    proof_path=output_dir/(spec['name']+'_PROVENANCE.json')
    proof_bytes=(json.dumps(proof,indent=2,ensure_ascii=False)+'\n').encode('utf-8')
    if proof_path.exists():
        if proof_path.read_bytes()!=proof_bytes:raise ValueError('Conflicting provenance file: '+str(proof_path))
    else:
        with proof_path.open('xb') as f:f.write(proof_bytes)
    return dest,proof


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
    opts=parser.parse_args()
    opts.output_dir=opts.output_dir.expanduser().resolve()
    if not opts.output_dir.is_dir():parser.error('Output directory does not exist: '+str(opts.output_dir))
    for spec in SOURCE_FILES:
        print('FETCHING',spec['repository'],spec['commit'],flush=True)
        path,details=create_prepared_zip(spec,opts.output_dir)
        print('READY',str(path), 'FILES='+str(details['java_files']), 'SHA256='+details['zip_sha256'],flush=True)
    print('DONE: 3 Java-only ZIPs; no programs executed and no NTK scan was launched',flush=True)

if __name__=='__main__':main()
