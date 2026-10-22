#!/usr/bin/env python3
"""Phase4 experimental real full-project API -> native IRIS Stage3 -> local E1 bridge.

This tool does not claim SAST dataflow attribution or re-score CodeQL SARIF.
It performs strict provenance, compiler parameter enrichment from existing DB,
bounded model-only API role inference, and native frozen protocol validation.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
import zipfile

PROJECTS = ('spark_CVE-2016-9177_vuln','webgoat_sql_CVE-2026-0006_1.0')
PREVIOUS = 'fullproj31_20261021T114118Z_3502ed0e'
PREVIOUS_SHA256 = '444482111e5b228385027dfe7923b257943a7af8583131b5364069638e230fdf'
IRIS_COMMIT = '51c2aafaf2746a6246ab057752791cc397c272d4'
SUPPORTED = ('22','78','89')  # CWE-79 has a separate contextual policy, not E1 XSS training.

class BridgeError(RuntimeError): pass

def need(ok, reason):
    if not ok: raise BridgeError(reason)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def digest(obj):
    return hashlib.sha256(json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def write_json(p, value):
    p=Path(p)
    with p.open('x',encoding='utf-8') as f: json.dump(value,f,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False);f.write('\n')
    p.chmod(0o600)

def load(p):
    p=Path(p)
    need(p.is_file() and not p.is_symlink(),'INPUT_JSON_MISSING_OR_SYMLINK:'+str(p))
    return json.loads(p.read_text('utf-8'))

def verify_sums(root, required):
    p=root/'SHA256SUMS'
    need(p.is_file(),'SHA256SUMS_MISSING:'+str(root))
    for rel in required:
        target=root/rel
        need(target.is_file() and not target.is_symlink(),'PINNED_FILE_MISSING:'+str(target))
        found={ln.split('  ',1)[1]:ln.split('  ',1)[0] for ln in p.read_text('ascii').splitlines() if '  ' in ln}
        need(found.get(rel)==sha(target),'SHA256_MISMATCH:'+str(target))

def source_inventory(root):
    skip={'.git','target','build','.gradle','.idea','node_modules','.venv','__pycache__','out'}
    need(root.is_dir() and not root.is_symlink(),'PROJECT_SOURCE_UNAVAILABLE')
    files=[]
    for directory,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in skip and not (Path(directory)/d).is_symlink())
        for name in sorted(names):
            p=Path(directory)/name
            if name.endswith('.java') and p.is_file() and not p.is_symlink():files.append(p)
    files.sort(key=lambda p:p.relative_to(root).as_posix())
    h=hashlib.sha256()
    for p in files:
        b=p.relative_to(root).as_posix().encode()
        h.update(len(b).to_bytes(4,'big'));h.update(b);h.update(bytes.fromhex(sha(p)))
    return {'source_hash':h.hexdigest(),'files':len(files)}

def read_inventory(path):
    need(path.is_file() and not path.is_symlink(),'CSV_MISSING')
    need(path.stat().st_size<=160*1024**2,'CSV_TOO_LARGE')
    with path.open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        expected={'uri','start_line','start_column','package','clazz','method','compiler_signature','is_static'}
        need(reader.fieldnames is not None and expected.issubset(reader.fieldnames),'CSV_SCHEMA_DRIFT')
        rows=[]
        for r in reader:
            need(len(rows)<200000,'CSV_ROW_CAP')
            for k in expected:need(isinstance(r[k],str),'CSV_VALUE_MISSING:'+k)
            try:
                r['start_line_int']=int(r['start_line']);r['start_column_int']=int(r['start_column'])
            except ValueError:raise BridgeError('CSV_POSITION_NOT_INTEGER') from None
            need(r['start_line_int']>0 and r['start_column_int']>0,'CSV_POSITION_INVALID')
            need(r['is_static'] in ('true','false'),'CSV_STATIC_UNKNOWN')
            uri=PurePosixPath(r['uri'])
            need(not uri.is_absolute() and '..' not in uri.parts and '\\' not in r['uri'],'CSV_UNSAFE_PATH')
            rows.append(r)
    return rows

def relevant(row):
    """Only modeled Java API families; no inference of role from rule labels.

    CWE-79 and all unmodeled Spring/Hibernate APIs remain CodeQL-only.
    Candidate selection does not create sink/source verdicts.
    """
    pkg,cl,m=row['package'],row['clazz'],row['method']
    result=[]
    if pkg=='java.lang' and cl=='Runtime' and m=='exec':result.append('78')
    if pkg=='java.lang' and cl=='ProcessBuilder' and m in ('command','start'):result.append('78')
    if pkg=='java.sql' and cl in ('Statement','PreparedStatement','CallableStatement') and m in ('execute','executeQuery','executeUpdate','executeLargeUpdate','executeBatch'):result.append('89')
    if pkg=='java.sql' and cl=='Connection' and m in ('prepareStatement','prepareCall'):result.append('89')
    if pkg=='java.nio.file' and cl=='Files' and m in ('readString','readAllBytes','newInputStream','newOutputStream','write','writeString','copy','move'):result.append('22')
    if pkg=='java.nio.file' and cl in ('Paths','Path') and m in ('get','resolve'):result.append('22')
    if pkg=='java.io' and cl=='File' and m in ('getCanonicalPath','getCanonicalFile','listFiles','toPath'):result.append('22')
    return result

def sarif_positions(sarif_path):
    """Extract SARIF path terminal positions to rank API calls, not to claim exact join."""
    sarif=load(sarif_path)
    need(sarif.get('version')=='2.1.0','SECURITY_SARIF_VERSION')
    pts=[]
    for run in sarif.get('runs',[]):
        for finding in run.get('results',[]):
            for flow in finding.get('codeFlows',[]):
                for tf in flow.get('threadFlows',[]):
                    locs=tf.get('locations',[])
                    if not locs:continue
                    p=locs[-1].get('location',{}).get('physicalLocation',{})
                    art=p.get('artifactLocation',{})
                    region=p.get('region',{})
                    if isinstance(art.get('uri'),str) and type(region.get('startLine')) is int:
                        pts.append((art['uri'].replace('\\','/'),region['startLine'],finding.get('ruleId','')))
    return pts

def rank_and_select(rows,points,max_per_cwe=4,max_total=16):
    need(1<=max_per_cwe<=8 and 1<=max_total<=32,'CANDIDATE_BUDGET_INVALID')
    pool={c:{} for c in SUPPORTED}
    for r in rows:
        for c in relevant(r):
            ident=(r['package'],r['clazz'],r['method'],r['compiler_signature'])
            key=(c,*ident)
            pt=r['uri'].replace('\\','/')
            near=tuple(sorted(set(rule for uri,line,rule in points
                if (uri==pt or uri.endswith('/'+pt) or pt.endswith('/'+uri)) and abs(line-r['start_line_int'])<=3)))
            priority=0 if near else 1
            old=pool[c].get(ident)
            candidate={**r,'cwe':c,'security_nearby_rules':list(near),
                       'selection_reason':'SARIF_PATH_TERMINAL_PROXIMITY' if near else 'SUPPORTED_JAVA_API_FAMILY',
                       'all_calls_same_identity':1}
            if old is None:pool[c][ident]=candidate
            else:
                old['all_calls_same_identity']+=1
                if (priority,pt,r['start_line_int'],r['start_column_int']) < (
                        0 if old['security_nearby_rules'] else 1,old['uri'],old['start_line_int'],old['start_column_int']):
                    candidate['all_calls_same_identity']=old['all_calls_same_identity'];pool[c][ident]=candidate
    counts={c:len(pool[c]) for c in SUPPORTED}
    chosen=[]
    for c in SUPPORTED:
        group=sorted(pool[c].values(),key=lambda r:(not bool(r['security_nearby_rules']),r['uri'],r['start_line_int'],r['compiler_signature']))
        chosen.extend(group[:max_per_cwe])
    chosen=sorted(chosen,key=lambda r:(not bool(r['security_nearby_rules']),r['cwe'],r['uri'],r['start_line_int']))[:max_total]
    return chosen,counts

def query_for_rows(selected):
    need(len(selected)<=32,'MAX_QUERY_CASES')
    where=[]
    for r in selected:
        uri=json.dumps(r['uri'],ensure_ascii=True)
        where.append(f'(call.getFile().getRelativePath() = {uri} and call.getLocation().getStartLine() = {r["start_line_int"]} and call.getLocation().getStartColumn() = {r["start_column_int"]})')
    need(bool(where),'ZERO_CANDIDATES_NOT_A_MODEL_SCAN')
    return '''/** @name NTK full-project selected API compiler-parameter identity
 * @description Selected MethodCall type and parameter symbols in this CodeQL database.
 * @kind table
 * @id java/ntk-fullproj4/selected-api-parameters
 */
import java
from MethodCall call, Method m, string static_flag
where m = call.getMethod() and
  ((m.isStatic() and static_flag = "true") or (not m.isStatic() and static_flag = "false")) and
  (\n''' + '    '+'\n    or '.join(where) + '''\n  )
select
  call.getFile().getRelativePath() as uri,
  call.getLocation().getStartLine() as start_line,
  call.getLocation().getStartColumn() as start_column,
  m.getDeclaringType().getPackage().getName() as package,
  m.getDeclaringType().getName() as clazz,
  m.getName() as method,
  m.getSignature() as compiler_signature,
  m.getReturnType().getName() as return_type,
  m.getNumberOfParameters() as arity,
  concat(int i | i = [0 .. m.getNumberOfParameters()-1] |
    m.getParameter(i).getName(), ";" order by i asc) as parameter_names,
  static_flag as is_static
'''

def split_types(signature):
    if '(' not in signature or not signature.endswith(')'):
        raise BridgeError('COMPILER_SIGNATURE_INVALID')
    s=signature[signature.index('(')+1:-1]
    if not s.strip():return []
    parts=[];buf='';depth=0
    for ch in s:
        if ch=='<':depth+=1
        if ch=='>':depth-=1
        if ch==',' and depth==0:parts.append(buf.strip());buf='';continue
        buf+=ch
    parts.append(buf.strip())
    need(depth==0 and all(parts),'COMPILER_SIGNATURE_TYPE_LIST_INVALID')
    return parts

def merge_identity(selected, enriched):
    unique={}
    for q in enriched:
        k=(q['uri'],q['start_line'],q['start_column'],q['package'],q['clazz'],q['method'],q['compiler_signature'])
        need(k not in unique,'DUPLICATE_IDENTITY_QUERY_ROW')
        unique[k]=q
    ok=[];rejected=[]
    for r in selected:
        key=tuple(r[x] for x in ('uri','start_line','start_column','package','clazz','method','compiler_signature'))
        q=unique.get(key)
        if q is None:
            rejected.append({'reason':'COMPILER_PARAMETER_IDENTITY_NOT_FOUND','case_sha256':digest(key)})
            continue
        try:
            types=split_types(r['compiler_signature'])
            names=q['parameter_names'].split(';') if q['parameter_names'] else []
            arity=int(q['arity'])
            need(arity==len(types)==len(names),'COMPILER_PARAMETER_ARITY_MISMATCH')
            need(all(re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*',n) for n in names),'COMPILER_PARAMETER_NAME_NOT_USABLE')
            need(len(set(names))==len(names),'COMPILER_PARAMETER_NAMES_DUPLICATED')
            rt=q['return_type']
            need(rt and q['is_static'] in ('true','false'),'COMPILER_RETURN_OR_STATIC_MISSING')
            signature=f'{rt} {r["method"]}('+', '.join(t+' '+n for t,n in zip(types,names))+')'
            candidate={k:r[k] for k in ('package','method','cwe')}
            candidate.update({'class':r['clazz'],'signature':signature,'compiler_signature':r['compiler_signature'],
                              'is_static':q['is_static']=='true','receiver_policy':'HOLD_THIS_UNTIL_SEMANTIC_REVIEW',
                              'source_record_sha256':digest({'original_csv':{k:r[k] for k in ('uri','start_line','start_column','package','clazz','method','compiler_signature')},
                                                             'parameter_ql':q})})
            ok.append({'candidate':candidate,'origin':{'uri':r['uri'],'line':r['start_line_int'],
                'column':r['start_column_int'],'nearby_codeql_rules':r['security_nearby_rules'],
                'rank_reason':r['selection_reason'],'call_count':r['all_calls_same_identity']}})
        except (BridgeError,ValueError) as e:
            rejected.append({'reason':str(e),'case_sha256':digest(key)})
    return ok,rejected

def read_enriched(path):
    with path.open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        expected={'uri','start_line','start_column','package','clazz','method','compiler_signature','arity','return_type','parameter_names','is_static'}
        need(reader.fieldnames is not None and expected.issubset(reader.fieldnames),'ENRICHED_SCHEMA')
        return list(reader)

def shell(cmd,log,timeout,*,cwd=None,env=None):
    st=time.monotonic()
    log.parent.mkdir(parents=True,exist_ok=True)
    expired=False
    with log.open('xb') as f:
        p=subprocess.Popen(list(map(str,cmd)),stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,
                           start_new_session=True,cwd=cwd,env=env)
        try:rc=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired=True
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:p.wait(10)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(10)
            rc=None
    return {'returncode':rc,'timed_out':expired,'seconds':round(time.monotonic()-st,3),'log':str(log)}


def safe_db_copy(source,dest,limit=8*1024**3):
    need(source.is_dir() and not source.is_symlink() and (source/'db-java').is_dir(), 'HISTORICAL_DB_MISSING')
    need(not dest.exists() and not dest.is_symlink(),'SNAPSHOT_ALREADY_EXISTS')
    total=0
    for folder,dirs,files in os.walk(source,followlinks=False):
        for name in list(dirs)+list(files):
            p=Path(folder)/name
            if p.is_symlink():
                need(not p.readlink().is_absolute() and p.resolve(strict=False).is_relative_to(source.resolve()),'DB_LINK_ESCAPES_DATABASE')
            elif p.is_file():total+=p.stat().st_size
    need(total<limit,'DB_COPY_SIZE_LIMIT')
    need(shutil.disk_usage(dest.parent).free>total+512*1024**2,'INSUFFICIENT_DISK_DB_COPY')
    proc=subprocess.run(['cp','-a','--reflink=auto','--',str(source),str(dest)],
        stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=900,check=False)
    need(proc.returncode==0 and (dest/'db-java').is_dir() and
         sha(source/'codeql-database.yml')==sha(dest/'codeql-database.yml'),
         'DATABASE_COPY_FAILED:'+proc.stderr[-200:])
    return total

def project_preflight(repo, prev, manifest, project):
    matches=[r for r in manifest['rows'] if r.get('project')==project]
    need(len(matches)==1,'PROJECT_NOT_IN_PHASE31:'+project)
    row=matches[0]
    need(row.get('status')=='COMPLETE' and row.get('source_unchanged') is True and
         row.get('database_metadata_unchanged') is True, 'PHASE31_ROW_NOT_VERIFIED')
    source=repo/'data/project-sources'/project
    inventory=source_inventory(source)
    need(inventory['source_hash']==row['source_hash'] and inventory['files']==row['source_java_count'],
         'PROJECT_SOURCE_DRIFT:'+project)
    db=repo/'data/codeql-dbs'/project
    need(db.is_dir() and not db.is_symlink() and (db/'db-java').is_dir(), 'CODEQL_DB_MISSING')
    need(sha(db/'codeql-database.yml')==row['database_metadata_sha256'],'CODEQL_DB_METADATA_CHANGED')
    csv_file=prev/project/'API_CALL_INVENTORY.csv'
    need(sha(csv_file)==row['api_csv_sha256'],'API_INVENTORY_SHA_MISMATCH')
    sarif_file=Path(row['prior_sarif_path'])
    # SARIF must be in the expected earlier experiment directory (not arbitrary path).
    expected=Path.home()/'migration/ntk_fullproject_phase3_runs'/'fullproj3_20261021T111518Z_1d5bdb66'/project/'CODEQL_SECURITY_EXTENDED.sarif'
    need(sarif_file.resolve()==expected.resolve() and
         sha(sarif_file)==row['prior_sarif_sha256'],'CODEQL_SECURITY_SARIF_DRIFT')
    inventory_rows=read_inventory(csv_file)
    need(len(inventory_rows)==row['inventory']['total_method_calls'],'API_CALL_ROW_COUNT_MISMATCH')
    return row,source,db,sarif_file,inventory_rows

def stage_packs(prev,manifest,workspace):
    root=workspace/'codeql-packs'
    need(not root.exists(),'QLPACK_COPY_EXISTS')
    total=0;paths={}
    for name,meta in sorted(manifest['qlpack_inventory'].items()):
        source=Path(meta['isolated_copy'])
        need(source.is_dir() and not source.is_symlink() and source.is_relative_to(prev),
             'QLPACK_SOURCE_ESCAPES_PHASE31')
        need(sha(source/'qlpack.yml')==meta['meta_sha256'],'QLPACK_SOURCE_SHA_MISMATCH')
        destination=root/'packages'/name/meta['version']
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copytree(source,destination,symlinks=True)
        for folder,dirs,files in os.walk(destination,followlinks=False):
            for child in list(dirs)+list(files):
                p=Path(folder)/child
                need(not p.is_symlink(),'PACK_SYMLINK_FORBIDDEN:'+name)
                if p.is_file():total+=p.stat().st_size
        need(sha(destination/'qlpack.yml')==meta['meta_sha256'],'QLPACK_COPY_SHA_DRIFT')
        paths[name]=destination
    need(len(paths)==16,'EXPECTED_16_PINNED_QLPACKS')
    return paths,total

def make_enrichment_querypack(prev,project,selected,out):
    target=out/'parameter_querypack';target.mkdir(mode=0o700)
    original=prev/project/'inventory_querypack'
    lock=original/'codeql-pack.lock.yml';qlpack=original/'qlpack.yml'
    need(qlpack.is_file() and lock.is_file(),'PHASE31_QUERY_LOCK_MISSING')
    need('codeql/java-all: "9.1.2"' in qlpack.read_text(), 'QUERY_PACK_PIN_DRIFT')
    shutil.copy2(lock,target/lock.name)
    (target/'qlpack.yml').write_text('name: ntk/fullproject-phase4-parameter-bridge\nversion: 0.0.1\ndependencies:\n  codeql/java-all: "9.1.2"\n',encoding='ascii')
    query=target/'SelectedApiParameters.ql';query.write_text(query_for_rows(selected),encoding='ascii')
    return target,query

def run_parameter_query(prev,project,selected,db,codeql,packs,root,timeout):
    output=root/project
    output.mkdir(mode=0o700,exist_ok=True)
    qp,query=make_enrichment_querypack(prev,project,selected,output)
    options=['--additional-packs='+os.pathsep.join(str(packs[name]) for name in sorted(packs)),
             '--common-caches='+str(root/'codeql-common-caches')]
    env=os.environ.copy()
    env.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',CODEQL_TELEMETRY_DISABLE='1',
               GIT_TERMINAL_PROMPT='0',PYTHONDONTWRITEBYTECODE='1')
    for key in ('GITHUB_TOKEN','GH_TOKEN','CODEQL_REGISTRIES_AUTH'):env.pop(key,None)
    summary={'status':'NOT_STARTED','candidate_calls':len(selected),'queries_executed':[],
             'database_original':'UNCHANGED','codeql_security_suite':'REUSED_NOT_EXECUTED'}
    try:
        commands=[('PACK_RESOLVE',[codeql,'pack','resolve-dependencies','--mode=verify',*options,str(qp)],180),
                  ('PARAM_QUERY_COMPILE',[codeql,'query','compile','--check-only',str(query),*options,'--threads=2','--ram=3072'],360)]
        for name,cmd,limit in commands:
            info=shell(cmd,output/(name+'.log'),limit,env=env)
            summary['queries_executed'].append({'name':name,**info})
            if info['returncode']!=0 or info['timed_out']:
                summary['status']=name+'_ERROR';return summary,[]
        snap=output/'database_snapshot'
        summary['snapshot_bytes']=safe_db_copy(db,snap)
        try:
            bqrs=output/'SelectedApiParameters.bqrs'
            query_cmd=[codeql,'query','run',str(query),'--database='+str(snap),'--output='+str(bqrs),
                       '--threads=2','--ram=3072',*options,
                       '--no-default-compilation-cache','--compilation-cache='+str(output/'ql-compilation-cache')]
            info=shell(query_cmd,output/'PARAM_QUERY_RUN.log',timeout,env=env)
            summary['queries_executed'].append({'name':'PARAM_QUERY_RUN',**info})
            if info['returncode']!=0 or info['timed_out'] or not bqrs.is_file():
                summary['status']='PARAM_QUERY_RUN_ERROR';return summary,[]
            csv_path=output/'SelectedApiParameters.csv'
            info=shell([codeql,'bqrs','decode',str(bqrs),'--format=csv','--output='+str(csv_path)],
                       output/'PARAM_QUERY_DECODE.log',120,env=env)
            summary['queries_executed'].append({'name':'PARAM_QUERY_DECODE',**info})
            if info['returncode']!=0 or info['timed_out'] or not csv_path.is_file():
                summary['status']='PARAM_QUERY_DECODE_ERROR';return summary,[]
            rows=read_enriched(csv_path)
            accepted,rejected=merge_identity(selected,rows)
            summary.update(status='COMPLETE',identity_verified=len(accepted),identity_rejected=len(rejected),
                           compiler_parameter_query_sha256=sha(query),compiler_parameter_table_sha256=sha(csv_path),
                           unsupported_identity_reasons=dict(Counter(x['reason'] for x in rejected)))
            write_json(output/'COMPILER_IDENTITIES.json',accepted)
            write_json(output/'IDENTITY_REJECTED.json',rejected)
            return summary,accepted
        finally:
            if snap.is_dir() and not snap.is_symlink() and snap.parent==output:
                shutil.rmtree(snap)
            summary['temporary_database_snapshot_deleted']=True
    except Exception as e:
        summary.update(status='BLOCKED',blocker_type=type(e).__name__,blocker=str(e)[:400])
        return summary,[]

def native_case_aggregate(per_project):
    seen={}
    for project,cases in per_project.items():
        for x in cases:
            c=x['candidate'];key=tuple(c[k] for k in ('cwe','package','class','method','signature'))
            if key not in seen:seen[key]={'candidate':dict(c),'origin':[]}
            else:
                need(seen[key]['candidate']['compiler_signature']==c['compiler_signature'] and
                     seen[key]['candidate']['is_static']==c['is_static'],'SHARED_API_IDENTITY_CONFLICT')
            seen[key]['origin'].append({'project':project,**x['origin'],
                                        'identity_source_sha256':c['source_record_sha256']})
    result=[]
    for key,r in sorted(seen.items()):
        r['candidate']['source_record_sha256']=digest(r['origin'])
        result.append(r)
    need(len(result)<=32,'NATIVE_CASE_TOTAL_BUDGET')
    return result

def verify_engine(root):
    need((root/'SHA256SUMS').is_file(),'REFERENCE_ENGINE_MANIFEST_MISSING')
    proc=subprocess.run(['sha256sum','-c','SHA256SUMS'],cwd=root,stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
    need(proc.returncode==0,'REFERENCE_ENGINE_INTEGRITY_FAILURE:'+proc.stdout[-200:])

def native_infer(*,cases,run,reference,repo,work,downloads,host_python):
    """Run real native driver with original locked Epoch1 adapter, no synthetic inference."""
    need(cases and len(cases)<=32,'NATIVE_CANDIDATES_MISSING_OR_TOO_MANY')
    verify_engine(reference)
    sys.path.insert(0,str(reference))
    from hybrid_core import native_inputs,trace_check
    from run_b39b2 import PINS,make_runtime_configs
    from run_b39b3 import unpack_snapshot
    from ntk_core import jsonl,loads,read_checked,zip_members,write_json as native_write_json
    from ntk_runtime import offline_env
    need(PINS['iris_commit']==IRIS_COMMIT,'IRIS_COMMIT_CHANGED')
    host_python=Path(host_python).resolve(strict=True)
    ml=work/'.ntk_v5_lora_venv/bin/python'
    need(ml.is_file(),'FROZEN_ML_PYTHON_NOT_FOUND')
    own=run/'private_native';own.mkdir(mode=0o700)
    assets=own/'assets';assets.mkdir()
    states={}
    configs=make_runtime_configs(work,downloads,assets,states)
    runtime=loads((assets/'RUNTIME_CONFIG_PROVENANCE.json').read_bytes())
    snapshot=own/'snapshot'
    arc=subprocess.run(['git','-C',str(repo),'archive','--format=tar',IRIS_COMMIT],
                       capture_output=True,timeout=180,env=offline_env(),check=False)
    need(arc.returncode==0,'PINNED_IRIS_GIT_ARCHIVE_FAILED')
    proof=unpack_snapshot(arc.stdout,snapshot)
    need(proof['commit']==IRIS_COMMIT,'PINNED_IRIS_COMMIT_MISMATCH')
    members=zip_members(read_checked(downloads/PINS['b33_name'],PINS['b33_sha256'],states=states))
    prot=own/'runtime_protocol.json';prot.write_bytes(members['inputs/runtime_protocol.json'])
    release=Path((work/'NTK_BATCH38_POLICY_TOOL_PATH.txt').read_text().strip()).resolve(strict=True)
    engine=release/'engine'
    need(engine.is_dir(),'NATIVE_PATCH_ENGINE_NOT_AVAILABLE')
    raw_cases=native_inputs([r['candidate'] for r in cases])
    prep=own/'prepare';prep.mkdir()
    cfg={'snapshot':str(snapshot),'engine':str(engine),'protocol_path':str(prot),
         'prepare_dir':str(prep),'raw_cases':raw_cases}
    preparer=own/'native_prepare_config.json';native_write_json(preparer,cfg)
    cmd=[str(host_python),'-I','-B','-u',str(reference/'hybrid_native_driver.py'),'prepare',str(preparer)]
    info=shell(cmd,prep/'DRIVER.log',300,cwd=prep,env=offline_env())
    need(info['returncode']==0 and not info['timed_out'],'NATIVE_PREPARE_FAILED:'+str(prep/'DRIVER.log'))
    proof=loads((prep/'PREPARED.json').read_bytes());prepared=loads((prep/'NATIVE_INPUTS.json').read_bytes())
    need(len(prepared)==len(cases),'PREPARED_CASE_COUNT_MISMATCH')
    tokenizer=own/'tokenizer_config.json';native_write_json(tokenizer,{**configs['base'],'cases':prepared})
    token=own/'TOKENIZER_PREFLIGHT.json'
    cmd=[str(ml),'-I','-B',str(reference/'tokenizer_preflight.py'),str(tokenizer),str(token)]
    tk=shell(cmd,own/'TOKENIZER.log',300,cwd=own,env=offline_env())
    need(tk['returncode']==0 and not tk['timed_out'],'TOKENIZER_PREFLIGHT_FAILED')
    tokenproof=loads(token.read_bytes())
    need(tokenproof['status']=='TOKENIZER_CPU_PREFLIGHT_COMPLETE' and tokenproof['n']==len(cases),
         'TOKENIZER_INPUT_DRIFT')
    runfolder=own/'epoch_1';runfolder.mkdir()
    ac={**cfg,**configs['epoch_1'],'cases':prepared,'preparation_proof':proof,
        'output_dir':str(runfolder),'cache_dir':str(runfolder/'cache'),'cache_mode':'readwrite',
        'frozen_root':str(repo),'ml_python':str(ml),
        'adapter_sha256':runtime['adapter_sha256']['epoch_1'],
        'adapter_config_sha256':'b6305fec9b9ae3a10043fb7cfdeda6c28839ab0604e5f4e388194b65e5211d7e',
        'load_timeout_s':300,'request_timeout_s':configs['epoch_1']['generation']['generation_timeout_s']+30}
    cfgpath=runfolder/'config.json';native_write_json(cfgpath,ac)
    locks=[]
    try:
        for name in ('batch38_gpu_scan.lock','batch39b2_gpu.lock','batch39b3_gpu.lock','batch39b4_gpu.lock','ntk_fullproj4_gpu.lock'):
            f=(work/name).open('a+');locks.append(f)
            try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise BridgeError('ANOTHER_SCAN_ACTIVE_LOCK:'+name) from None
        probe=subprocess.run(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'],
            capture_output=True,text=True,timeout=30,env=offline_env())
        need(probe.returncode==0 and not probe.stdout.strip(),'GPU_NOT_IDLE')
        cmd=[str(host_python),'-I','-B','-u',str(reference/'hybrid_native_driver.py'),'run',str(cfgpath)]
        model=shell(cmd,runfolder/'DRIVER.log',3600,cwd=runfolder,env=offline_env())
        need(model['returncode']==0 and not model['timed_out'],'NATIVE_EPOCH1_FAILED:'+str(runfolder/'DRIVER.log'))
    finally:
        for f in reversed(locks):f.close()
    driver=loads((runfolder/'DRIVER_RESULT.json').read_bytes())
    trace=jsonl((runfolder/'native_trace.jsonl').read_bytes())
    traceinfo=trace_check(prepared,trace,driver,'epoch_1',configs['epoch_1']['runtime_versions'],tokenproof)
    need(traceinfo['new_requests']==len(cases),'LIVE_REQUEST_COVERAGE_MISMATCH')
    native_write_json(run/'NATIVE_EPOCH1_AUDIT.json',traceinfo)
    # Never include raw prompts, source files or model completions in this summary.
    return {'status':'NATIVE_STAGE3_EPOCH1_COMPLETED','native_source':'FULL_IMPORTED_IRIS_STAGE3_ONLY',
            'model_arm':'epoch_1','new_native_requests':traceinfo['new_requests'],
            'warm_cache_hits':traceinfo['cache_hits'],'accepted':traceinfo['accepted'],
            'abstain':traceinfo['abstain'],'reason_counts':traceinfo['reasons'],
            'new_training':False,'model_xss_gate_granted':False,
            'native_audit_sha256':sha(run/'NATIVE_EPOCH1_AUDIT.json'),
            'raw_prompt_and_response_files':'LOCAL_PRIVATE_NOT_EXPORTED',
            'driver_result_status':driver['status']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path.home()/'iris')
    p.add_argument('--previous',type=Path,default=Path.home()/'migration/ntk_fullproject_phase31_runs'/PREVIOUS)
    p.add_argument('--output-base',type=Path,default=Path.home()/'migration/ntk_fullproject_phase4_runs')
    p.add_argument('--reference-engine',type=Path,default=Path.home()/'migration/ntk_fastscan_dev_20261021/engine_reference')
    p.add_argument('--work',type=Path,default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    p.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
    p.add_argument('--host-python',type=Path,default=Path(os.environ.get('NTK_IRIS_PYTHON',sys.executable)))
    p.add_argument('--codeql',type=Path,default=Path.home()/'tools/codeql/codeql')
    p.add_argument('--projects',nargs='+',choices=PROJECTS,default=list(PROJECTS))
    p.add_argument('--max-per-cwe',type=int,default=2)
    p.add_argument('--max-total',type=int,default=12)
    p.add_argument('--ql-timeout',type=int,default=1200)
    p.add_argument('--preflight-only',action='store_true',help='Only verify inventories and plan candidates; no CodeQL/GPU')
    p.add_argument('--run-native',action='store_true',help='Explicitly run real native IRIS Stage 3 + Epoch1 GPU after CodeQL param proofs')
    a=p.parse_args(argv)
    need(1<=a.max_per_cwe<=8 and 1<=a.max_total<=32 and 60<=a.ql_timeout<=3600,'INVALID_BUDGET')
    repo=a.root.expanduser().resolve(strict=True)
    prev=a.previous.expanduser().resolve(strict=True)
    outputbase=a.output_base.expanduser().resolve(strict=False)
    work=a.work.expanduser().resolve(strict=True)
    codeql=a.codeql.expanduser().resolve(strict=True)
    need(not outputbase.is_relative_to(repo) and not outputbase.is_relative_to(prev) and not outputbase.is_relative_to(work),
         'OUTPUT_TARGET_INSIDE_FROZEN_INPUT')
    need(codeql.is_file() and os.access(codeql,os.X_OK),'CODEQL_NOT_EXECUTABLE')
    cv=subprocess.run([str(codeql),'version'],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30,check=False)
    need(cv.returncode==0 and re.search(r'\brelease\s+2\.25\.6\b',cv.stdout) is not None,
         'CODEQL_VERSION_NOT_PINNED_2_25_6')
    print('CODEQL_VERSION=2.25.6_VERIFIED',flush=True)
    verify_sums(prev,['FULLPROJECT_PHASE31_RESULT.json'])
    need(sha(prev/'FULLPROJECT_PHASE31_RESULT.json')==PREVIOUS_SHA256,'PHASE31_MANIFEST_SHA_DRIFT')
    manifest=load(prev/'FULLPROJECT_PHASE31_RESULT.json')
    need(manifest['status']=='INVENTORY_RECOVERED' and
         manifest['security_extended_reused_without_execution'] is True and
         manifest['model_stage3_executed'] is False,'PHASE31_PROVENANCE_INVALID')
    print('PHASE31_VERIFIED=TRUE',flush=True)
    selections={};contexts={};records={}
    for project in dict.fromkeys(a.projects):
        row,source,db,sarif_file,raw=project_preflight(repo,prev,manifest,project)
        positions=sarif_positions(sarif_file)
        chosen,counts=rank_and_select(raw,positions,a.max_per_cwe,a.max_total)
        selections[project]=chosen
        contexts[project]=(source,db,sarif_file)
        records[project]={'inventory_calls':len(raw),'by_cwe_distinct_modelable_apis':counts,
            'selected_callsite_count':len(chosen),
            'security_findings_reused':row['prior_security_findings'],
            'security_codeflows_reused':row['prior_security_paths'],
            'selected_with_nearby_sarif_path':sum(bool(r['security_nearby_rules']) for r in chosen),
            'candidate_count_is_not_vulnerability_count':True}
        print('PROJECT='+project,flush=True)
        print('  COMPILER_CALLS='+str(len(raw)),flush=True)
        print('  DISTINCT_MODELABLE_APIS='+json.dumps(counts,sort_keys=True),flush=True)
        print('  SELECTED_FOR_PARAMETER_PROOF='+str(len(chosen)),flush=True)
        print('  SECURITY_REUSED_FINDINGS='+str(row['prior_security_findings']),flush=True)
    if a.preflight_only:
        print('PHASE4_PREFLIGHT=PASS; CODEQL_EXECUTED=NO; GPU_EXECUTED=NO',flush=True)
        return 0
    outputbase.mkdir(mode=0o700,parents=True,exist_ok=True)
    runid='fullproj4_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    run=outputbase/runid;run.mkdir(mode=0o700)
    print('PHASE4_RUN_DIR='+str(run),flush=True)
    summary={'status':'IN_PROGRESS','phase31_run':str(prev),'phase31_sha256':PREVIOUS_SHA256,
        'projects':records,'native':{'status':'NOT_EXECUTED'},'security_suite_rerun':False,
        'codeql_db_create':False,'maven_gradle_execution':False,'original_project_source_modified':False,
        'sast_v22_scoring_executed':False,'codeql_security_sarif_not_a_model_finding':True,
        'cwe79_policy_only_not_model_derived':True,'new_training':False,
        'website_8770_untouched':True,'independent_gold_evaluation':False,
        'mode':'EXPERIMENTAL_FULLPROJECT_NATIVE_STAGE3_API_ROLE_BRIDGE_NOT_COMPLETE_HYBRID_SAST'}
    began=time.monotonic()
    try:
        print('===== CODEQL PARAMETER IDENTITY QUERY =====',flush=True)
        if any(selections.values()):
            packs,bytes_total=stage_packs(prev,manifest,run)
            print('PINNED_QPACKS_COPIED='+str(len(packs))+'/16; PACK_BYTES='+str(bytes_total),flush=True)
        else:packs={}
        verified={}
        for project in selections:
            if not selections[project]:
                records[project]['identity_enrichment']={'status':'NO_MODELED_API_CANDIDATES'}
                verified[project]=[];continue
            _,db,_=contexts[project]
            result, accepted=run_parameter_query(prev,project,selections[project],db,str(codeql),packs,run,a.ql_timeout)
            records[project]['identity_enrichment']=result
            verified[project]=accepted
            print('PARAM_IDENTITIES='+project+' STATUS='+result['status']+
                  ' VERIFIED='+str(result.get('identity_verified',0))+ 
                  ' REJECTED='+str(result.get('identity_rejected',0)),flush=True)
            if result['status']!='COMPLETE':
                log=run/project/'PARAM_QUERY_COMPILE.log'
                if result['status']=='PARAM_QUERY_RUN_ERROR':log=run/project/'PARAM_QUERY_RUN.log'
                if log.is_file():
                    lines=log.read_text(encoding='utf-8',errors='replace').splitlines()
                    for ln in [s for s in lines if re.search(r'error|fatal|unresolved|failed|exception',s,re.I)][-8:]:
                        print('QUERY_ERROR_DETAIL='+ln[:450],flush=True)
        bad=[p for p in verified if records[p]['identity_enrichment']['status']!='COMPLETE' and
             records[p]['identity_enrichment']['status']!='NO_MODELED_API_CANDIDATES']
        if bad:
            summary['status']='PARTIAL_IDENTITY_QUERY_ERROR'
            summary['native']={'status':'BLOCKED_BEFORE_INFERENCE','failed_projects':bad}
        else:
            merged=native_case_aggregate(verified)
            public=[{'cwe':r['candidate']['cwe'],
                     'api_identity_sha256':digest({k:r['candidate'][k] for k in ('package','class','method','signature')}),
                     'projects':sorted({o['project'] for o in r['origin']}),
                     'codeql_path_nearby':any(o['nearby_codeql_rules'] for o in r['origin'])} for r in merged]
            write_json(run/'SELECTED_API_SUMMARY.json',public)
            summary['native_candidate_identities']=len(merged)
            summary['selected_api_summary_sha256']=sha(run/'SELECTED_API_SUMMARY.json')
            print('NATIVE_CANDIDATES_AFTER_CROSS_PROJECT_DEDUP='+str(len(merged)),flush=True)
            if not merged:
                summary['status']='NO_NATIVE_SUPPORTED_CANDIDATES'
                summary['native']={'status':'NOT_EXECUTED_NO_SUPPORTED_CANDIDATES'}
            elif not a.run_native:
                summary['status']='CODEQL_API_IDENTITIES_READY_MODEL_NOT_RUN'
                summary['native']={'status':'NOT_EXECUTED_FLAG_NOT_SET'}
            else:
                print('===== REAL LOCAL IRIS STAGE3 + LORA EPOCH1 =====',flush=True)
                summary['native']=native_infer(cases=merged,run=run,
                    reference=a.reference_engine.expanduser().resolve(strict=True),repo=repo,work=work,
                    downloads=a.downloads.expanduser().resolve(strict=True),
                    host_python=a.host_python.expanduser().resolve(strict=True))
                summary['status']='PHASE4_NATIVE_LORA_E1_COMPLETE'
    except (Exception,KeyboardInterrupt) as e:
        summary['status']='PHASE4_BLOCKED'
        summary['blocker_type']=type(e).__name__
        summary['blocker']=str(e)[:600]
        print('PHASE4_BLOCKER='+str(e)[:350],flush=True)
    finally:
        for project in selections:
            source,db,_=contexts[project]
            old=next(r for r in manifest['rows'] if r['project']==project)
            unchanged=(source_inventory(source)['source_hash']==old['source_hash'] and
                       sha(db/'codeql-database.yml')==old['database_metadata_sha256'])
            records[project]['source_and_db_metadata_unchanged']=unchanged
            if not unchanged:
                summary['status']='SOURCE_OR_DATABASE_DRIFT_DETECTED'
        summary['elapsed_s']=round(time.monotonic()-began,3)
        out=run/'FULLPROJECT_PHASE4_RESULT.json'
        write_json(out,summary)
        (run/'SHA256SUMS').write_text(sha(out)+'  FULLPROJECT_PHASE4_RESULT.json\n','ascii')
        print('\n===== PHASE 4 SUMMARY =====',flush=True)
        print('RESULT_JSON='+str(out),flush=True)
        print('RESULT_SHA256='+sha(out),flush=True)
        print('STATUS='+summary['status'],flush=True)
        print('NATIVE_STAGE3_LORA='+summary['native']['status'],flush=True)
        print('CODEQL_SECURITY_RERUN=NO',flush=True)
        print('ORIGINAL_JAVA_DB_MODIFIED=NO' if all(records[p]['source_and_db_metadata_unchanged'] for p in records) else 'ORIGINAL_INPUT_DRIFT=CHECK',flush=True)
        print('SAST_SCORING_EXECUTED=NO',flush=True)
        print('WEB_8770_INTEGRATION=NOT_YET',flush=True)
        print('ELAPSED_S='+str(summary['elapsed_s']),flush=True)
    return 0 if summary['status'] in ('PHASE4_NATIVE_LORA_E1_COMPLETE','CODEQL_API_IDENTITIES_READY_MODEL_NOT_RUN','NO_NATIVE_SUPPORTED_CANDIDATES') else 2

if __name__=='__main__':
    try:sys.exit(main())
    except (BridgeError,ValueError,FileNotFoundError,OSError) as e:
        print('PHASE4_PREFLIGHT_BLOCKER='+str(e)[:500],file=sys.stderr)
        sys.exit(2)
