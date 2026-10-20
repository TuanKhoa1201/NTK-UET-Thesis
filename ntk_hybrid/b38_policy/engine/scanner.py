"""Pinned, offline OpenGrep Java callsite scan. This is NOT a hybrid scan."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

PINNED_OPENGREP_SHA='9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33'
RULE_ID='ntk-b34-java-sql-call-review'
PINNED_RULE_SHA='8ba2f0d1cac8725d966f0b09d8c147fcb5453f74858cfbd80cdf43d6291380bf'
ROOT=Path(__file__).resolve().parent

class ScanError(RuntimeError):
    pass

def sha_file(path:Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()

def resolve_scanner(binary=None, *, expected_sha=PINNED_OPENGREP_SHA):
    binary=Path(binary or os.environ.get('NTK_OPENGREP_BIN') or str(Path.home()/'.opengrep/cli/v1.25.0/opengrep')).expanduser().resolve()
    if not binary.is_file() or not os.access(binary,os.X_OK):
        raise ScanError('PINNED_OPENGREP_EXECUTABLE_MISSING: '+str(binary))
    digest=sha_file(binary)
    if digest!=expected_sha:
        raise ScanError('OPENGREP_PINNED_SHA_MISMATCH')
    return binary,digest

def canonical_rule_id(check_id):
    """Map OpenGrep's optional dotted config namespace to our pinned YAML rule ID.

    Only a canonical exact ID or a dotted prefix followed by that exact rule ID
    is supported. Prefixes are emitted by OpenGrep based on the config location.
    Do not use generic substring matching: similar/wrong rules must fail closed.
    """
    if not isinstance(check_id, str):
        raise ScanError('OPENGREP_UNEXPECTED_RULE_ID: non-string')
    if check_id == RULE_ID:
        return RULE_ID
    if (check_id.endswith('.' + RULE_ID)
            and len(check_id) <= 1024
            and check_id[0] not in '.-'
            and all(ch.isascii() and (ch.isalnum() or ch in '._/-')
                    for ch in check_id)):
        return RULE_ID
    raise ScanError('OPENGREP_UNEXPECTED_RULE_ID: observed=' + repr(check_id[:240]))


def offline_command(job_dir:Path, workspace:Path, binary:Path):
    return [sys.executable,'-B',str(ROOT/'offline_opengrep.py'),str(job_dir/'isolation.json'),
            str(binary),'scan','--config',str(ROOT/'opengrep_demo_rules.yml'),
            '--json','--output',str(job_dir/'raw_opengrep.json'),str(workspace)]

def scan_offline(job_dir:Path, workspace:Path, *,binary=None,expected_sha=PINNED_OPENGREP_SHA,timeout=180):
    binary,sha=resolve_scanner(binary, expected_sha=expected_sha)
    # Rule content is part of the fixed experiment; never silently substitute a
    # different YAML rule when accepting namespaced check_id values.
    if sha_file(ROOT/'opengrep_demo_rules.yml') != PINNED_RULE_SHA:
        raise ScanError('OPENGREP_PINNED_RULE_SHA_MISMATCH')
    job_dir=job_dir.resolve(); workspace=workspace.resolve()
    cmd=offline_command(job_dir,workspace,binary)
    env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(job_dir),
         'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TMPDIR':str(job_dir),
         'PYTHONPATH':str(ROOT),'PYTHONDONTWRITEBYTECODE':'1',
         'SEMGREP_SEND_METRICS':'off','OPENGREP_SEND_METRICS':'off',
         'SEMGREP_ENABLE_VERSION_CHECK':'0','OPENGREP_ENABLE_VERSION_CHECK':'0',
         'HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','HF_HUB_DISABLE_TELEMETRY':'1',
         'NO_COLOR':'1','CI':'true'}
    (job_dir/'.cache').mkdir(exist_ok=True)
    env['XDG_CACHE_HOME']=str(job_dir/'.cache')
    env['XDG_CONFIG_HOME']=str(job_dir/'.cache')
    started=time.monotonic()
    with (job_dir/'opengrep.log').open('wb') as log:
        p=subprocess.Popen(cmd, cwd=job_dir, env=env, stdout=log, stderr=subprocess.STDOUT,
                           start_new_session=True)
        try:
            code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGKILL)
            p.wait()
            raise ScanError('OPENGREP_SCAN_TIMED_OUT')
    if code:
        raise ScanError('OPENGREP_COMMAND_FAILED_'+str(code))
    proof=job_dir/'isolation.json'
    if not proof.is_file():
        raise ScanError('OPENGREP_OFFLINE_ISOLATION_PROOF_MISSING')
    status=json.loads(proof.read_text())
    if status.get('network',{}).get('AF_INET')!='DENIED_EPERM' or status.get('network',{}).get('AF_INET6')!='DENIED_EPERM':
        raise ScanError('OPENGREP_OFFLINE_PROOF_INVALID')
    outfile=job_dir/'raw_opengrep.json'
    if not outfile.is_file():
        raise ScanError('OPENGREP_RESULT_JSON_MISSING')
    payload=json.loads(outfile.read_text(encoding='utf-8'))
    findings=parse_opengrep(payload,workspace)
    return {'scanner_sha256':sha,'rule_sha256':sha_file(ROOT/'opengrep_demo_rules.yml'),
            'raw_json_sha256':sha_file(outfile),'duration_s':round(time.monotonic()-started,3),
            'offline_network':status['network'],'findings':findings,
            'stage_execution':{'OpenGrep':'EXECUTED','IRIS Stage 3':'NOT_EXECUTED',
                               'Local LoRA':'NOT_EXECUTED','CodeQL':'NOT_EXECUTED',
                               'SAST Scoring':'NOT_EXECUTED'}}

def parse_opengrep(payload:dict,workspace:Path)->list:
    if not isinstance(payload,dict) or not isinstance(payload.get('results'),list) or payload.get('errors'):
        raise ScanError('OPENGREP_OUTPUT_INVALID_OR_HAS_ERRORS')
    findings=[]
    for i,row in enumerate(payload['results']):
        if not isinstance(row, dict):
            raise ScanError('OPENGREP_RESULT_ENTRY_INVALID')
        original_check_id = row.get('check_id')
        canonical_rule_id(original_check_id)
        raw=Path(row.get('path') or '')
        src=raw if raw.is_absolute() else workspace/raw
        resolved=src.resolve()
        if not resolved.is_relative_to(workspace) or not resolved.is_file() or resolved.suffix.lower()!='.java':
            raise ScanError('OPENGREP_RESULT_OUTSIDE_WORKSPACE')
        uri=resolved.relative_to(workspace).as_posix()
        start=row.get('start'); end=row.get('end')
        for pos in (start,end):
            if not isinstance(pos,dict) or type(pos.get('line')) is not int or pos['line']<1 or type(pos.get('col',1)) is not int or pos['col']<1:
                raise ScanError('OPENGREP_INVALID_RESULT_LOCATION')
        if (start['line'],start.get('col',1))>(end['line'],end.get('col',1)):
            raise ScanError('OPENGREP_REVERSED_RESULT_LOCATION')
        extra=row.get('extra') or {}
        message=str(extra.get('message') or 'SQL API call requires review')
        if len(message)>1000: message=message[:1000]
        rec={'id':hashlib.sha256((uri+str(start)+RULE_ID).encode()).hexdigest()[:20],
             'uri':uri,'start_line':start['line'],'start_column':start.get('col',1),
             'end_line':end['line'],'end_column':end.get('col',1),
             'rule_id':RULE_ID,'scanner_check_id':original_check_id,'cwe':'CWE-89','severity':extra.get('severity','ERROR'),
             'message':message,'classification':'API_CALL_PRESENCE_REQUIRES_REVIEW',
             'confirmed_vulnerability':False,'risk_score':None,'source':'OPENGREP',
             'dataflow_status':'NOT_ANALYZED','model_role_status':'NOT_ANALYZED'}
        findings.append(rec)
    if len(findings)>5000:
        raise ScanError('OPENGREP_EXCESSIVE_FINDINGS')
    return findings

def to_sarif(report:dict)->dict:
    rows=[]
    for f in report.get('findings',[]):
        rows.append({'ruleId':f['rule_id'],'level':'error' if f.get('severity')=='ERROR' else 'warning',
                     'message':{'text':f['message']},
                     'locations':[{'physicalLocation':{'artifactLocation':{'uri':f['uri']},
                     'region':{'startLine':f['start_line'],'startColumn':f['start_column'],
                               'endLine':f['end_line'],'endColumn':f['end_column']}}}],
                     'properties':{'cwe':f['cwe'],'classification':f['classification'],
                                   'codeqlExecuted':False,'llmExecuted':False,
                                   'convertedFrom':'OpenGrep JSON'}})
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'NTK Web — OpenGrep JSON conversion (not hybrid)',
                                      'rules':[{'id':RULE_ID,'shortDescription':{'text':'SQL API callsite review'}}]}},
                     'results':rows,'properties':{'analysisMode':'OPENGREP_ONLY','hybridExecuted':False}}]}
