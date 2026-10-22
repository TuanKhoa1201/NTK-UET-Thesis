#!/usr/bin/env python3
"""NTK Phase5.1: exact CodeQL argument spans + pinned local LoRA sink labels.

Uses existing Phase2--5 runs. Runs only a small fresh CodeQL table query on an
isolated database copy when --run is supplied. No project build, Security suite,
model inference, training, or historical artifact modification.

A semantic API sink label does NOT prove an exploitable vulnerability.
"""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

PROJECTS=('spark_CVE-2016-9177_vuln','webgoat_sql_CVE-2026-0006_1.0')
P4_NAME='fullproj4_20261021T164458Z_8d498c38'
P5_NAME='fullproj5_20261021T165954Z_32238fcc'
P31_NAME='fullproj31_20261021T114118Z_3502ed0e'
P4_SHA='965210997af2a2eab3adb54480c90bddc7674ad8ac4df5118f1bbc27ab289f17'
FUSE_SHA='35e5103bf225f3b44408a4d4a2923cf6e37dd1b3de230c34aeb01eebe976003e'
BRIDGE_SHA='74a07d5a2021d9264111bcc7c4f7186d3357eea769851dff3a7bf24355667eee'
CWE={'22','78','89'}
IDENTITY=('package','class','method','signature')
FIELDS=('uri','call_line','call_column','argument_index','arg_start_line','arg_start_column',
        'arg_end_line','arg_end_column','package','clazz','method','compiler_signature','parameter_name')

class BindError(RuntimeError):pass

def require(value,msg):
    if not value:raise BindError(msg)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def jread(path,max_bytes=128*1024**2):
    path=Path(path)
    require(path.is_file() and not path.is_symlink(),'FILE_MISSING_OR_SYMLINK:'+str(path))
    require(path.stat().st_size <= max_bytes,'FILE_LIMIT:'+path.name)
    return json.loads(path.read_text('utf-8'))

def writenew(path,object):
    path=Path(path)
    with path.open('x',encoding='utf-8') as f:
        json.dump(object,f,ensure_ascii=False,indent=2,sort_keys=True,allow_nan=False)
        f.write('\n')
    path.chmod(0o600)

def manifest_verified(root):
    root=Path(root)
    require(root.is_dir() and not root.is_symlink(),'MANIFEST_ROOT_MISSING')
    sums=root/'SHA256SUMS'
    require(sums.is_file() and not sums.is_symlink(),'SHA256SUMS_MISSING')
    found={}
    for line in sums.read_text('ascii').splitlines():
        m=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
        require(m is not None,'MANIFEST_LINE_INVALID')
        path=Path(m[2]);require(not path.is_absolute() and '..' not in path.parts and m[2] not in found,'MANIFEST_PATH_INVALID')
        found[m[2]]=m[1]
    require(bool(found),'EMPTY_MANIFEST')
    for name,expected in found.items():
        p=root/name
        require(p.is_file() and not p.is_symlink() and sha(p)==expected,'MANIFEST_HASH_INVALID:'+name)
    return found

def import_pinned(path,name,expected):
    path=Path(path)
    require(sha(path)==expected,'HELPER_HASH_CHANGED:'+name)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

def native_key(candidate):
    return digest([candidate['cwe'],[candidate[k] for k in IDENTITY]])

def read_model_sinks(p4root,p4result,bridge):
    """Read *parsed labels*, never prompts or completions; bind to P4 exact candidates."""
    p4=p4result
    native=p4['native']
    require(p4['status']=='PHASE4_NATIVE_LORA_E1_COMPLETE' and native['status']=='NATIVE_STAGE3_EPOCH1_COMPLETED','P4_NOT_COMPLETED')
    audit=jread(p4root/'NATIVE_EPOCH1_AUDIT.json')
    require(sha(p4root/'NATIVE_EPOCH1_AUDIT.json')==native['native_audit_sha256'],'P4_AUDIT_HASH_MISMATCH')
    details={r['case_key']:r for r in audit['details']}
    require(len(details)==native['new_native_requests'] and native['new_native_requests']==5,'P4_NATIVE_REQUEST_COUNT_DRIFT')
    tracepath=p4root/'private_native/epoch_1/native_trace.jsonl'
    require(tracepath.is_file() and not tracepath.is_symlink(),'P4_PRIVATE_TRACE_MISSING')
    trace={}
    for line in tracepath.read_text('utf-8').splitlines():
        if not line.strip():continue
        entry=json.loads(line)
        if entry.get('phase')!='cold':continue
        k=entry['case_key']
        require(k not in trace,'DUPLICATE_COLD_TRACE')
        trace[k]=entry
    require(set(trace)==set(details),'NATIVE_CASE_KEYS_DRIFT')
    candidates={}
    for project in PROJECTS:
        f=p4root/project/'COMPILER_IDENTITIES.json'
        if not f.exists():continue
        for record in jread(f):
            c=record['candidate'];k=native_key(c)
            require(k in details and k in trace,'NATIVE_CANDIDATE_NO_AUDIT')
            audit_row=details[k];raw=trace[k]
            require(raw['status']==audit_row['status'] and raw['reason']==audit_row['reason'], 'COLD_AUDIT_DISAGREES')
            require(raw['candidate']=={field:c[field] for field in (*IDENTITY,'cwe')},'COLD_IDENTITY_CHANGED')
            role=audit_row['role']
            require(role==('ABSTAIN' if raw.get('label') is None else raw['label']['type']),'COLD_ROLE_CHANGED')
            if role!='sink' or raw['status']!='ACCEPTED':continue
            require(c['cwe'] in CWE,'MODEL_XSS_NOT_SUPPORTED')
            label=raw['label'];args=label.get('sink_args')
            require(isinstance(args,list) and args and len(args)==len(set(args)) and all(isinstance(a,str) for a in args),'MODEL_SINK_ARGS_INVALID')
            require('this' not in args,'MODEL_RECEIVER_NOT_APPROVED')
            for field in IDENTITY:require(label[field]==c[field],'MODEL_LABEL_IDENTITY_MISMATCH')
            needtypes=bridge.split_types(c['compiler_signature'])
            require(len(needtypes)>=len(args),'MODEL_PARAMETER_INDEX_INVALID')
            if (project,k) in candidates:raise BindError('DUPLICATE_MODEL_PROJECT_IDENTITY')
            candidates[project,k]={'project':project,'case_key':k,'cwe':c['cwe'],
                'package':c['package'],'clazz':c['class'],'method':c['method'],
                'compiler_signature':c['compiler_signature'],'sink_args':tuple(args),
                'origin':record['origin']}
    return list(candidates.values()),{'accepted':sum(d['status']=='ACCEPTED' for d in details.values()),
                                      'abstain':sum(d['status']=='ABSTAIN' for d in details.values()),
                                      'sink_accepted':sum(d['status']=='ACCEPTED' and d['role']=='sink' for d in details.values())}

def escaped_ql_string(v):
    require(isinstance(v,str) and v and len(v)<700 and '\x00' not in v,'INVALID_CODEQL_LITERAL')
    return json.dumps(v,ensure_ascii=True)

def emit_query(sinks):
    """Only exact compiler owners and overloads that the model called a sink."""
    require(0<len(sinks)<=32,'QUERY_SINK_BUDGET')
    selected=sorted(set((s['package'],s['clazz'],s['method'],s['compiler_signature']) for s in sinks))
    clauses=[]
    for pkg,cls,method,sig in selected:
        clauses.append('  (m.getDeclaringType().getPackage().getName() = '+escaped_ql_string(pkg)+
          ' and m.getDeclaringType().getName() = '+escaped_ql_string(cls)+
          ' and m.getName() = '+escaped_ql_string(method)+
          ' and m.getSignature() = '+escaped_ql_string(sig)+')')
    return '''/** @name NTK full-project exact CodeQL sink argument AST locations
 * @description Maps a model-labelled compiler method parameter to argument AST spans.
 * @kind table
 * @id java/ntk-fullproj51/exact-sink-arguments
 */
import java
from MethodCall call, Method m, int i
where m = call.getMethod() and i >= 0 and i < call.getNumArgument() and
      i < m.getNumberOfParameters() and
  (\n'''+ '\n  or\n'.join(clauses) + '''\n  )
select
  call.getFile().getRelativePath() as uri,
  call.getLocation().getStartLine() as call_line,
  call.getLocation().getStartColumn() as call_column,
  i as argument_index,
  call.getArgument(i).getLocation().getStartLine() as arg_start_line,
  call.getArgument(i).getLocation().getStartColumn() as arg_start_column,
  call.getArgument(i).getLocation().getEndLine() as arg_end_line,
  call.getArgument(i).getLocation().getEndColumn() as arg_end_column,
  m.getDeclaringType().getPackage().getName() as package,
  m.getDeclaringType().getName() as clazz,
  m.getName() as method,
  m.getSignature() as compiler_signature,
  m.getParameter(i).getName() as parameter_name
'''

def safe_relative_uri(uri):
    require(isinstance(uri,str) and uri and len(uri)<5000 and '\\' not in uri,'UNSAFE_URI')
    p=Path(uri)
    require(not p.is_absolute() and '..' not in p.parts and ':' not in uri,'UNSAFE_URI')
    return p.as_posix()

def read_args(csvfile,max_rows=50000):
    out=[]
    with Path(csvfile).open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        require(reader.fieldnames is not None and set(FIELDS).issubset(reader.fieldnames),'ARG_CSV_SCHEMA_MISMATCH')
        for r in reader:
            require(len(out)<max_rows,'ARG_QUERY_OUTPUT_LIMIT')
            d={k:r[k] for k in FIELDS}
            d['uri']=safe_relative_uri(d['uri'])
            for k in ('call_line','call_column','argument_index','arg_start_line','arg_start_column','arg_end_line','arg_end_column'):
                try:d[k]=int(d[k])
                except (TypeError,ValueError):raise BindError('ARG_POSITION_INVALID') from None
            require(d['arg_start_line']>=1 and d['arg_start_column']>=1 and d['arg_end_line']>=1 and d['arg_end_column']>=1 and d['call_line']>=1 and d['call_column']>=1 and d['argument_index']>=0,'ARG_POSITION_ZERO')
            require((d['arg_start_line'],d['arg_start_column']) <= (d['arg_end_line'],d['arg_end_column']),'ARG_SPAN_BACKWARDS')
            out.append(d)
    require(len({(x['uri'],x['call_line'],x['call_column'],x['argument_index'],x['compiler_signature']) for x in out})==len(out),'DUPLICATE_ARG_AST_RECORD')
    return out

def covers(row,pt):
    return row['uri']==pt['uri'] and type(pt.get('line')) is int and type(pt.get('column')) is int and (
      (row['arg_start_line'],row['arg_start_column']) <= (pt['line'],pt['column']) <= (row['arg_end_line'],row['arg_end_column']))

def collect_binding_for_record(record,sinks,argument_rows):
    """Require the SARIF *terminal* to be inside the exact compiler argument."""
    if record['origin']!='CODEQL_SECURITY_EXTENDED' or record.get('cwe') not in {'CWE-22','CWE-78','CWE-89'}:
        return []
    terminal_paths=[(idx,flow[-1]) for idx,flow in enumerate(record.get('codeql_paths',[])) if len(flow)>=2]
    # Callers set codeql_paths from the original SARIF, not just Phase5 display's first path.
    candidates=[]
    for idx,terminal in terminal_paths:
        for sink in sinks:
            if record['project']!=sink['project'] or record['cwe']!='CWE-'+sink['cwe']:continue
            for row in argument_rows:
                if not covers(row,terminal):continue
                if (row['package'],row['clazz'],row['method'],row['compiler_signature'])!=(sink['package'],sink['clazz'],sink['method'],sink['compiler_signature']):continue
                if row['parameter_name'] not in sink['sink_args']:continue
                candidates.append({'project':sink['project'],'case_key':sink['case_key'],'cwe':sink['cwe'],
                   'uri':row['uri'],'call_line':row['call_line'],'call_column':row['call_column'],
                   'argument_index':row['argument_index'],'argument_name':row['parameter_name'],
                   'arg_start_line':row['arg_start_line'],'arg_start_column':row['arg_start_column'],
                   'arg_end_line':row['arg_end_line'],'arg_end_column':row['arg_end_column'],
                   'path_index':idx,'terminal':terminal,'compiler_identity_sha256':digest((row['package'],row['clazz'],row['method'],row['compiler_signature']))})
    keys={(x['case_key'],x['uri'],x['call_line'],x['call_column'],x['argument_index']) for x in candidates}
    if len(keys)!=1:return []  # Multiple model/AST endpoints are ambiguous, do not elevate.
    candidates.sort(key=lambda x:x['path_index'])
    return candidates[:1]

def verify_inputs(p5run,p4run,p31run,source,phase5_tool,phase4_tool):
    fusion=import_pinned(phase5_tool,'phase51_pinned_phase5',FUSE_SHA)
    bridge=import_pinned(phase4_tool,'phase51_pinned_phase4',BRIDGE_SHA)
    p5sums=manifest_verified(p5run)
    p5=jread(p5run/'FULLPROJECT_PHASE5_RESULT.json')
    require(p5['status']=='PHASE5_CONSERVATIVE_EVIDENCE_FUSION_COMPLETE' and p5['model_qualified_dataflow_paths']==0,'P5_STATUS_DRIFT')
    require(p5['input_result_sha256']['phase4']==P4_SHA and p5['scorer_sha256']==fusion.SCORER_SHA,'P5_INPUT_PINS_DRIFT')
    for path in ('FULLPROJECT_PHASE5_RESULT.json',*(f'{p}/result.json' for p in PROJECTS),*(f'{p}/report.sarif' for p in PROJECTS)):
        require(path in p5sums,'P5_REPORT_NOT_PINNED:'+path)
    p4=manifest_verified(p4run)
    require(p4.get('FULLPROJECT_PHASE4_RESULT.json')==P4_SHA,'P4_RESULT_DRIFT')
    p4result=jread(p4run/'FULLPROJECT_PHASE4_RESULT.json')
    require(p4result['status']=='PHASE4_NATIVE_LORA_E1_COMPLETE','P4_NOT_COMPLETE')
    require(Path(p5['input_runs']['phase4']).resolve()==Path(p4run).resolve(),'P4_RUN_PATH_CHANGED')
    p31manifest=manifest_verified(p31run)
    p31=jread(p31run/'FULLPROJECT_PHASE31_RESULT.json')
    require(p31['status']=='INVENTORY_RECOVERED','P31_NOT_COMPLETE')
    require(Path(p5['input_runs']['phase31']).resolve()==Path(p31run).resolve(),'P31_RUN_PATH_CHANGED')
    model_sinks,stats=read_model_sinks(p4run,p4result,bridge)
    scorer=fusion.load_scorer(p4run/'private_native/snapshot/simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py')
    proj={}
    for project in PROJECTS:
        orig=source/'data/project-sources'/project
        p5data=jread(p5run/project/'result.json')
        require(p5data['status']=='PHASE5_STATIC_FINDINGS_SCORED_MODEL_API_SIDECARE_ONLY','P5_PROJECT_STATUS_INVALID')
        expected=next(r for r in p5['project_rows'] if r['project']==project)
        require(len(p5data['findings'])==expected['total_engine_findings'],'P5_FINDINGS_COUNT_DRIFT')
        p31row=next(r for r in p31['rows'] if r['project']==project)
        require(fusion.source_inventory(orig)=={'files':p31row['source_java_count'],'source_hash':p31row['source_hash']},'JAVA_SOURCE_DRIFT:'+project)
        database=source/'data/codeql-dbs'/project
        require(database.is_dir() and not database.is_symlink() and sha(database/'codeql-database.yml')==p31row['database_metadata_sha256'],'DATABASE_DRIFT:'+project)
        for rec in p5data['findings']:
            existing=rec.pop('score')
            require(asdict(scorer.score_finding(rec))==existing,'P5_SCORE_REPLAY_DRIFT')
            rec['score']=existing
        proj[project]={'data':p5data,'p31row':p31row,'database':database,'source_root':orig}
    return fusion,bridge,p5,proj,model_sinks,stats,scorer

def run_command(args,log,timeout):
    from subprocess import PIPE
    st=time.monotonic();log=Path(log)
    env=os.environ.copy()
    for secret in ('GITHUB_TOKEN','GH_TOKEN','CODEQL_REGISTRIES_AUTH'):env.pop(secret,None)
    env.update(CODEQL_TELEMETRY_DISABLE='1',GIT_TERMINAL_PROMPT='0',
               HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONDONTWRITEBYTECODE='1')
    with log.open('xb') as out:
        p=subprocess.Popen(list(map(str,args)),stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True,env=env)
        try:rc=p.wait(timeout)
        except subprocess.TimeoutExpired:
            import signal
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:p.wait(10)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(10)
            rc=None
    return {'returncode':rc,'seconds':round(time.monotonic()-st,3),'timeout':rc is None}

def stage_packs(p31,p31result,run):
    staged=[];total=0
    for name,info in sorted(p31result['qlpack_inventory'].items()):
        old=Path(info['isolated_copy'])
        require(old.is_dir() and not old.is_symlink() and old.is_relative_to(p31),'HISTORIC_PACK_NOT_PINNED')
        require(sha(old/'qlpack.yml')==info['meta_sha256'],'HISTORIC_PACK_HASH_DRIFT')
        dest=run/'packages'/name/info['version'];dest.parent.mkdir(parents=True,exist_ok=True)
        # Physical copy/reflink: no writes to the frozen source pack or historical shared cache.
        proc=subprocess.run(['cp','-a','--reflink=auto','--',str(old),str(dest)],capture_output=True,text=True,timeout=600)
        require(proc.returncode==0,'PACK_COPY_FAILED:'+name)
        require(sha(dest/'qlpack.yml')==info['meta_sha256'],'COPIED_PACK_HASH_DRIFT')
        staged.append(str(dest));total+=sum(f.stat().st_size for f in dest.rglob('*') if f.is_file())
    require(len(staged)==16,'PINNED_PACK_COUNT')
    return staged,total

def run_project_query(project,sinks,p31,run,codeql,bridge,db,timeout,staged_packs):
    out=run/project;out.mkdir()
    qp=out/'querypack';qp.mkdir()
    template=p31/project/'inventory_querypack'
    lock=template/'codeql-pack.lock.yml'
    require(lock.is_file(),'P31_PACK_LOCK_MISSING')
    shutil.copy2(lock,qp/'codeql-pack.lock.yml')
    (qp/'qlpack.yml').write_text('name: ntk/fullproject-phase51-exact-sink-binding\nversion: 0.0.1\ndependencies:\n  codeql/java-all: "9.1.2"\n',encoding='ascii')
    qfile=qp/'ExactSinkArgs.ql';qfile.write_text(emit_query(sinks),encoding='ascii')
    opts=['--additional-packs='+os.pathsep.join(str(p) for p in staged_packs),
          '--common-caches='+str(run/'codeql-common-caches')]
    commands=[('PACK_RESOLVE',[codeql,'pack','resolve-dependencies','--mode=verify',*opts,qp],180),
              ('QUERY_COMPILE',[codeql,'query','compile','--check-only',qfile,*opts,'--threads=2','--ram=3072'],360)]
    timings=[]
    for label,cmd,limit in commands:
        info=run_command(cmd,out/(label+'.log'),limit);timings.append({'stage':label,**info})
        if info['returncode']!=0:raise BindError('CODEQL_'+label+'_FAILED:'+str(out/(label+'.log')))
    snap=out/'db_snapshot'
    bridge.safe_db_copy(db,snap,limit=8*1024**3)
    try:
        bqrs=out/'ExactSinkArgs.bqrs'
        cmd=[codeql,'query','run',qfile,'--database='+str(snap),'--output='+str(bqrs),
             '--threads=2','--ram=3072',*opts,'--no-default-compilation-cache',
             '--compilation-cache='+str(out/'ql-compilation-cache')]
        info=run_command(cmd,out/'QUERY_RUN.log',timeout);timings.append({'stage':'QUERY_RUN',**info})
        if info['returncode']!=0:raise BindError('CODEQL_QUERY_RUN_FAILED:'+str(out/'QUERY_RUN.log'))
        csvfile=out/'ExactSinkArgs.csv'
        info=run_command([codeql,'bqrs','decode',bqrs,'--format=csv','--output='+str(csvfile)],out/'QUERY_DECODE.log',120)
        timings.append({'stage':'QUERY_DECODE',**info})
        if info['returncode']!=0:raise BindError('CODEQL_QUERY_DECODE_FAILED:'+str(out/'QUERY_DECODE.log'))
        rows=read_args(csvfile)
        return rows,{'query_sha256':sha(qfile),'arg_csv_sha256':sha(csvfile),'timings':timings,'argument_rows':len(rows)}
    finally:
        if snap.is_dir() and not snap.is_symlink() and snap.parent==out:
            shutil.rmtree(snap)

def update_project(project,entry,model_sinks,arg_rows,fusion,scorer,source,p3sarif):
    # Preserve every prior finding, attach exact proof only to CodeQL dataflow rows.
    records=deepcopy(entry['data']['findings'])
    parent=jread(p3sarif)
    original=[]
    for run in parent.get('runs',[]):
        original.extend(run.get('results',[]))
    codeql_results=[r for r in records if r['origin']=='CODEQL_SECURITY_EXTENDED']
    require(len(codeql_results)==len(original),'CODEQL_RESULT_COUNT_CHANGED')
    # Phase5 rows are resorted by score; raw_source_index is the stable join to original SARIF.
    originals={i:row for i,row in enumerate(original)}
    linked=[]
    for row in records:
        if row['origin']!='CODEQL_SECURITY_EXTENDED':continue
        original=originals[row['raw_source_index']]
        require(original['ruleId']==row['rule_id'],'RAW_SOURCE_INDEX_RULE_MISMATCH')
        flowpaths=fusion.codeql_flows(original,source)
        augmented={**row,'codeql_paths':flowpaths}
        links=collect_binding_for_record(augmented,model_sinks,arg_rows)
        if not links:continue
        proof=links[0]
        row['model_annotation']={'case_key':proof['case_key'],'status':'ACCEPTED','role':'sink',
             'origin':'LOCAL_NATIVE_IRIS_STAGE3_LORA_EPOCH1',
             'join_basis':'EXACT_COMPILER_OWNER_OVERLOAD_SINK_PARAM_AND_CODEQL_TERMINAL_ARGUMENT_AST',
             'sink_argument_and_path_binding':'PROVEN','model_qualified_vulnerability':False}
        row['exact_argument_binding']={k:v for k,v in proof.items() if k!='project'}
        row['model_qualified_dataflow_path']=True
        row['ai_validation']={'verdict':'API_ROLE_SINK_ONLY','api_role':'sink','parse_status':'ACCEPTED'}
        row['score']=asdict(scorer.score_finding(row))
        row['scoring_policy']='FROZEN_SAST_V22_MODEL_ONLY_FOR_EXACT_SINK_ARG_CODEQL_PATH'
        row['vulnerability_confirmed']=False
        linked.append({'finding_id':row['id'],'case_key':proof['case_key'],'arg_index':proof['argument_index'],
                       'location':proof['uri']+':'+str(proof['call_line'])+':'+str(proof['call_column']),
                       'path_index':proof['path_index']})
    records.sort(key=lambda x:(-x['score']['final_score'],x['origin'],x['id']))
    sarif=fusion.make_sarif(records,project)
    for run in sarif['runs']:
        own=[r for r in records if r['origin']==run['properties']['original_engine']]
        require(len(own)==len(run['results']),'OUTPUT_SARIF_MISMATCH')
        for item,row in zip(run['results'],own):
            item['properties']['model_qualified_dataflow_path']=bool(row.get('model_qualified_dataflow_path'))
            item['properties']['exact_argument_binding']=row.get('exact_argument_binding')
            item['properties']['sast_priority_score']=row['score']['final_score']
            item['properties']['vulnerability_confirmed']=False
    return records,sarif,linked

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    home=Path.home()
    p.add_argument('--source',type=Path,default=home/'iris')
    p.add_argument('--phase5-tool',type=Path,default=home/'migration/ntk_fullproject_phase5_tools/NTK_FullProject_Phase5_20261021/fuse_phase5.py')
    p.add_argument('--phase4-tool',type=Path,default=home/'migration/ntk_fullproject_phase4_tools/NTK_FullProject_Phase4_20261021/phase4_bridge.py')
    p.add_argument('--phase4',type=Path,default=home/'migration/ntk_fullproject_phase4_runs'/P4_NAME)
    p.add_argument('--phase5',type=Path,default=home/'migration/ntk_fullproject_phase5_runs'/P5_NAME)
    p.add_argument('--phase31',type=Path,default=home/'migration/ntk_fullproject_phase31_runs'/P31_NAME)
    p.add_argument('--phase3',type=Path,default=home/'migration/ntk_fullproject_phase3_runs/fullproj3_20261021T111518Z_1d5bdb66')
    p.add_argument('--out-root',type=Path,default=home/'migration/ntk_fullproject_phase51_runs')
    p.add_argument('--codeql',type=Path,default=home/'tools/codeql/codeql')
    p.add_argument('--run',action='store_true',help='Explicitly run new CodeQL exact-argument query on a temporary database copy')
    p.add_argument('--timeout',type=int,default=1200)
    args=p.parse_args(argv)
    require(60<=args.timeout<=3600,'TIME_BUDGET_INVALID')
    source=args.source.expanduser().resolve(strict=True)
    p5=args.phase5.expanduser().resolve(strict=True)
    p4=args.phase4.expanduser().resolve(strict=True)
    p31=args.phase31.expanduser().resolve(strict=True)
    p3=args.phase3.expanduser().resolve(strict=True)
    fusion,bridge,p5report,projects,sinks,stats,scorer=verify_inputs(p5,p4,p31,source,args.phase5_tool,args.phase4_tool)
    require(sha(p3/'FULLPROJECT_PHASE3_RESULT.json')==p5report['input_result_sha256']['phase3'],'P3_RESULT_SHA_MISMATCH')
    require(sha(args.phase4_tool)==BRIDGE_SHA,'PHASE4_BRIDGE_SHA_MISMATCH')
    print('PHASE51_BASELINE_VERIFIED=TRUE',flush=True)
    print('MODEL_ACCEPTED='+str(stats['accepted'])+' ABSTAIN='+str(stats['abstain'])+
          ' ACCEPTED_SINKS='+str(stats['sink_accepted']),flush=True)
    for project in PROJECTS:
        print('PROJECT='+project+' MODELABLE_SINKS='+str(sum(s['project']==project for s in sinks)),flush=True)
    if not args.run:
        print('PHASE51_READY=TRUE; NEW_CODEQL_EXECUTION=NO; RUN_WITH_--run_TO_VERIFY_ENDPOINTS',flush=True)
        return 0
    codeql=args.codeql.expanduser().resolve(strict=True)
    ver=subprocess.run([codeql,'version'],capture_output=True,text=True,timeout=30)
    require(ver.returncode==0 and 'release 2.25.6.' in ver.stdout,'CODEQL_VERSION_DRIFT')
    out=args.out_root.expanduser().resolve(strict=False)
    require(not out.is_relative_to(source) and not out.is_relative_to(p5) and not out.is_relative_to(p4),'OUTPUT_INSIDE_FROZEN_INPUT')
    out.mkdir(mode=0o700,parents=True,exist_ok=True)
    run=out/('fullproj51_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]);run.mkdir(mode=0o700)
    import fcntl
    lock=out/'.phase51.lock'
    with lock.open('a+') as lockfile:
        try:fcntl.flock(lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise BindError('ANOTHER_PHASE51_RUN_ACTIVE') from None
        started=time.monotonic()
        sinks_by_project={pr:[s for s in sinks if s['project']==pr] for pr in PROJECTS}
        summary={'status':'IN_PROGRESS','phase4_result_sha256':P4_SHA,
                 'phase5_result_sha256':sha(p5/'FULLPROJECT_PHASE5_RESULT.json'),
                 'phase31_result_sha256':sha(p31/'FULLPROJECT_PHASE31_RESULT.json'),
                 'native_audit':stats,'sourceguard_effect':'NOT_APPLIED_IN_FULLPROJECT',
                 'model_was_run_in_phase4':True,'model_inference_this_phase':False,
                 'codeql_security_suite_rerun':False,'opengrep_rerun':False,'training_executed':False,
                 'output_sast':'FROZEN_SAST_V2_2','risk_semantics':'REVIEW_PRIORITY_NOT_PROBABILITY',
                 'vulnerabilities_confirmed':0,'ground_truth_quality_metric':False,
                 'scanned_project_source_unchanged':True,'website_8770_integration':'NOT_YET',
                 'project_rows':[]}
        qlinfo={}
        arg_by_project={pr:[] for pr in PROJECTS}
        if sinks:
            p31report=jread(p31/'FULLPROJECT_PHASE31_RESULT.json')
            staged,total_bytes=stage_packs(p31,p31report,run)
            summary['pinned_packs_copied']=len(staged)
            summary['pinned_pack_copy_bytes']=total_bytes
            print('PINNED_PACKS_COPIED='+str(len(staged)),flush=True)
            for pr in PROJECTS:
                if not sinks_by_project[pr]:
                    print('PROJECT='+pr+' EXACT_QUERY=SKIPPED_NO_ACCEPTED_MODEL_SINK',flush=True)
                    continue
                print('PROJECT='+pr+' EXACT_QUERY=RUNNING',flush=True)
                arg_by_project[pr],qlinfo[pr]=run_project_query(pr,sinks_by_project[pr],p31,run,codeql,bridge,
                    projects[pr]['database'],args.timeout,staged)
                print('PROJECT='+pr+' ARGUMENT_AST_ROWS='+str(len(arg_by_project[pr])),flush=True)
        else:
            summary['pinned_packs_copied']=0
            summary['pinned_pack_copy_bytes']=0
            print('NO_ACCEPTED_MODEL_SINKS=TRUE; CODEQL_QUERY_NOT_REQUIRED=TRUE',flush=True)
        for pr in PROJECTS:
            # Pin source SARIF to the original Phase3 security analysis; no replay of Security suite.
            old_sarif=p3/pr/'CODEQL_SECURITY_EXTENDED.sarif'
            p3_summary=jread(p3/'FULLPROJECT_PHASE3_RESULT.json')
            p3row=next(row for row in p3_summary['project_rows'] if row['project']==pr)
            require(sha(old_sarif)==p3row['codeql_security']['sarif_sha256'],'ORIGINAL_SECURITY_SARIF_CHANGED:'+pr)
            projroot=projects[pr]['source_root']
            records,sarif,linked=update_project(pr,projects[pr],sinks_by_project[pr],arg_by_project[pr],
                 fusion,scorer,projroot,old_sarif)
            require(fusion.source_inventory(projroot)=={'source_hash':projects[pr]['p31row']['source_hash'],
                'files':projects[pr]['p31row']['source_java_count']},'JAVA_CHANGED_DURING_PHASE51:'+pr)
            require(sha(projects[pr]['database']/'codeql-database.yml')==projects[pr]['p31row']['database_metadata_sha256'],
                'DATABASE_CHANGED_DURING_PHASE51:'+pr)
            folder=run/pr;folder.mkdir(mode=0o700,exist_ok=True)
            outfile=folder/'result.json';sariffile=folder/'report.sarif'
            sourceobj=projects[pr]['data']
            result={**sourceobj,'status':'PHASE51_EXACT_BINDING_AUDITED',
                'findings':records,'exact_argument_bindings':linked,
                'model_qualified_dataflow_paths':len(linked),
                'vulnerability_confirmed':False,
                'score_semantics':'REVIEW_PRIORITY_NOT_PROBABILITY',
                'model_evidence_used_for_scoring_only_when_exact_sink_argument_linked':True,
                'all_other_scores_unchanged':True,
                'security_analysis_reused':True}
            writenew(outfile,result);writenew(sariffile,sarif)
            require(len(result['findings'])==sum(len(r['results']) for r in sarif['runs']),'OUTPUT_COUNT_MISMATCH')
            oldid={r['id']:r['score'] for r in sourceobj['findings']}
            matched={r['finding_id'] for r in linked}
            require(len(matched)==len(linked),'DUPLICATE_SAME_FINDING_PROOF')
            for finding in records:
                if finding['id'] not in matched:
                    require(finding['score']==oldid[finding['id']],'UNLINKED_SCORE_CHANGED')
                require(finding['vulnerability_confirmed'] is False,'VULNERABILITY_CONFIRMED_WITHOUT_GOLD')
            pinfo={'project':pr,'original_findings':len(sourceobj['findings']),
                'reported_findings':len(records),'model_sink_identities':len(sinks_by_project[pr]),
                'compiler_argument_rows':len(arg_by_project[pr]),
                'exact_compiler_sink_argument_links':len(linked),
                'original_codeql_security_findings':p3row['codeql_security']['findings'],
                'codeql_paths_proven_by_security_query':p3row['codeql_security']['results_with_codeflows'],
                'codeql_exact_argument_query':qlinfo.get(pr,{}),
                'report_json_sha256':sha(outfile),'report_sarif_sha256':sha(sariffile),
                'unlinked_scores_unchanged':True,'no_confirmed_vulnerabilities_claimed':True}
            summary['project_rows'].append(pinfo)
            print('PROJECT='+pr+' OLD_FINDINGS='+str(pinfo['original_findings'])+
                ' RETAINED='+str(pinfo['reported_findings'])+
                ' EXACT_SINK_ARGUMENT_LINKS='+str(len(linked)),flush=True)
        total=sum(x['exact_compiler_sink_argument_links'] for x in summary['project_rows'])
        summary['exact_model_linked_paths']=total
        summary['elapsed_s']=round(time.monotonic()-started,3)
        summary['status']='PHASE51_EXACT_MODEL_LINKS_VERIFIED' if total else 'PHASE51_NO_EXACT_MODEL_LINKS_PROVEN'
        writenew(run/'FULLPROJECT_PHASE51_RESULT.json',summary)
        files=['FULLPROJECT_PHASE51_RESULT.json']
        for pr in PROJECTS:files.extend([pr+'/result.json',pr+'/report.sarif'])
        if sinks:
            for pr in qlinfo:files.extend([pr+'/ExactSinkArgs.csv',pr+'/querypack/ExactSinkArgs.ql'])
        (run/'SHA256SUMS').write_text(''.join(sha(run/f)+'  '+f+'\n' for f in files),encoding='ascii')
        print('===== PHASE5.1 SUMMARY =====',flush=True)
        print('STATUS='+summary['status'],flush=True)
        print('EXACT_MODEL_LINKED_PATHS='+str(total),flush=True)
        print('FINDINGS_RETAINED='+str(sum(x['reported_findings'] for x in summary['project_rows'])),flush=True)
        print('SCORER=FROZEN_SAST_V2_2',flush=True)
        print('PHASE51_RUN_DIR='+str(run),flush=True)
        print('GPU_OR_LLM_THIS_PHASE=NO',flush=True)
        print('CODEQL_SECURITY_SUITE_RERUN=NO',flush=True)
        print('WEBSITE_8770_INTEGRATION=NOT_YET',flush=True)
        return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (BindError,KeyError,ValueError,TypeError,FileNotFoundError,OSError,IndexError) as e:
        print('PHASE51_BLOCKER='+type(e).__name__+':'+str(e)[:650],file=sys.stderr,flush=True)
        sys.exit(2)
