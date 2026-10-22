#!/usr/bin/env python3
"""NTK Phase 6B: new Java GitHub ZIP -> real tools -> optional native E1 -> SAST.

Output is NEVER mixed with the verified Phase 2--5.1 history. No Maven/Gradle,
no javac and no project build scripts are invoked. CodeQL uses build-mode=none.
Never treat a model API role as independent proof of a vulnerability.
"""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile

HERE=Path(__file__).resolve().parent
VENDOR=HERE/'vendor'
SCORER_SHA='c1b9cbf071739ca6d96062032867835dbf4db185f4e0ac1e2d609bd319e0de7e'
VENDOR_SHA={'phase4_bridge.py':'74a07d5a2021d9264111bcc7c4f7186d3357eea769851dff3a7bf24355667eee',
            'fuse_phase5.py':'35e5103bf225f3b44408a4d4a2923cf6e37dd1b3de230c34aeb01eebe976003e',
            'phase51_exact_binding.py':'8ae516df2ab7bfa87614dee25d41140695e45e97ac7413fcaa4518e666ce5052'}
MAX_ZIP=64*1024**2
MAX_UNPACK=512*1024**2
MAX_ENTRIES=40000
MAX_JAVA=15000
MAX_ONE=64*1024**2
SKIP={'.git','.gradle','.idea','node_modules','target','build','dist','out','__pycache__','.venv','.mvn/wrapper'}
SUITE='codeql/java-queries:codeql-suites/java-security-extended.qls'
QL_INVENTORY='''/** @name NTK live compiler-resolved Java API inventory
 * @kind table
 * @id java/ntk-live/api-inventory
 */
import java
from MethodCall call, Method m, string static_flag
where m = call.getMethod() and
  ((m.isStatic() and static_flag = "true") or (not m.isStatic() and static_flag = "false"))
select
  call.getLocation().getFile().getRelativePath() as uri,
  call.getLocation().getStartLine() as start_line,
  call.getLocation().getStartColumn() as start_column,
  m.getDeclaringType().getPackage().getName() as package,
  m.getDeclaringType().getName() as clazz,
  m.getName() as method,
  m.getSignature() as compiler_signature,
  m.getNumberOfParameters() as arity,
  static_flag as is_static
'''

class ScanError(RuntimeError): pass
class ScanStopped(ScanError): pass
ACTIVE=None
STOP=False

def demand(value,msg):
    if not value:raise ScanError(msg)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def save(path,data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name('.'+path.name+'.tmp-'+str(os.getpid()))
    with tmp.open('x',encoding='utf-8') as f:
        json.dump(data,f,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)
        f.write('\n');f.flush();os.fsync(f.fileno())
    tmp.chmod(0o600)
    os.replace(tmp,path)

def read(path,maxsize=160*1024**2):
    p=Path(path)
    demand(p.is_file() and not p.is_symlink() and p.stat().st_size<=maxsize,'REQUIRED_JSON_INVALID:'+str(p))
    return json.loads(p.read_text(encoding='utf-8'))

def import_verified(name):
    p=VENDOR/(name+'.py')
    demand(sha(p)==VENDOR_SHA[p.name],'PINNED_HELPER_SHA_DRIFT:'+name)
    spec=importlib.util.spec_from_file_location('ntk6b_'+name,p)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module

def zip_inventory(file):
    """Reject symlinks and all path ambiguities before writing any ZIP member."""
    p=Path(file)
    demand(p.is_file() and not p.is_symlink() and 0<p.stat().st_size<=MAX_ZIP,'ZIP_COMPRESSED_LIMIT')
    records=[];seen=set();total=0;java=0
    try:
        with zipfile.ZipFile(p,'r') as z:
            infos=z.infolist()
            demand(0<len(infos)<=MAX_ENTRIES,'ZIP_ENTRY_LIMIT_FULLPROJECT')
            for info in infos:
                name=info.filename
                norm=PurePosixPath(name)
                demand(name.rstrip('/') == norm.as_posix(), 'ZIP_NONCANONICAL_MEMBER')
                demand(isinstance(name,str) and name and not name.startswith('/') and not name.startswith('\\') and
                    '\\' not in name and ':' not in name and len(norm.parts)<=24 and len(name)<=900 and
                    all(x not in ('.','..','') and not re.search(r'[\x00-\x1f\x7f]',x) for x in norm.parts),
                    'ZIP_UNSAFE_MEMBER_PATH')
                low=name.rstrip('/').casefold()
                demand(low not in seen,'ZIP_DUPLICATE_OR_CASE_COLLISION')
                seen.add(low)
                kind=stat.S_IFMT(info.external_attr>>16)
                demand(kind in (0,stat.S_IFREG,stat.S_IFDIR),'ZIP_SPECIAL_OR_SYMLINK_ENTRY')
                demand(not (info.flag_bits & 1),'ZIP_ENCRYPTED')
                demand(info.file_size<=MAX_ONE,'ZIP_MEMBER_TOO_LARGE')
                total+=info.file_size
                demand(total<=MAX_UNPACK,'ZIP_EXPANDED_LIMIT')
                if not info.is_dir():
                    demand(info.compress_size>0 or info.file_size==0,'ZIP_INVALID_COMPRESSION')
                    demand(info.file_size<= max(1000000,info.compress_size*400),'ZIP_RATIO_LIMIT')
                    if name.lower().endswith('.java'):java+=1
                    records.append(info)
            demand(1<=java<=MAX_JAVA,'JAVA_FILE_COUNT_OUT_OF_BOUNDS')
    except (zipfile.BadZipFile,RuntimeError) as ex:
        raise ScanError('ZIP_INVALID:'+type(ex).__name__) from None
    return {'members':len(infos),'java_files_zip':java,'unpacked_bytes':total,'compressed_bytes':p.stat().st_size},records

def extract_zip(file,dest):
    meta,records=zip_inventory(file)
    dest=Path(dest)
    demand(not dest.exists(),'PROJECT_EXTRACT_DEST_EXISTS')
    dest.mkdir(mode=0o700,parents=True)
    with zipfile.ZipFile(file,'r') as z:
        for item in records:
            relative=PurePosixPath(item.filename)
            target=dest.joinpath(*relative.parts)
            demand(target.resolve(strict=False).is_relative_to(dest.resolve()),'ZIP_PATH_TRAVERSAL')
            if any(n in SKIP for n in relative.parts):continue
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with z.open(item) as inp,target.open('xb') as out:
                copied=0
                while True:
                    b=inp.read(1024*1024)
                    if not b:break
                    copied+=len(b)
                    demand(copied<=item.file_size and copied<=MAX_ONE,'ZIP_EXTRACT_SIZE_DRIFT')
                    out.write(b)
                demand(copied==item.file_size,'ZIP_EXTRACT_FILE_TRUNCATED')
            target.chmod(0o600) # no executable bits carried from source
    candidates=[]
    for parent,ds,fs in os.walk(dest,followlinks=False):
        ds[:]=[d for d in ds if not (Path(parent)/d).is_symlink()]
        for name in fs:
            if name.endswith('.java'):candidates.append(Path(parent)/name)
    demand(bool(candidates),'JAVA_SOURCE_MISSING_AFTER_EXTRACT')
    roots={f.relative_to(dest).parts[0] for f in candidates}
    if len(roots)==1 and (dest/next(iter(roots))).is_dir():
        source=dest/next(iter(roots))
    else:source=dest
    meta['java_files_extracted']=len(candidates)
    meta['source_relative_to_unpack']=str(source.relative_to(dest))
    return source,meta

def source_fingerprint(source):
    files=[];total=0
    for parent,ds,fs in os.walk(source,followlinks=False):
        ds[:]=sorted(n for n in ds if n not in SKIP and not (Path(parent)/n).is_symlink())
        for name in sorted(fs):
            p=Path(parent)/name
            if p.suffix=='.java' and p.is_file() and not p.is_symlink():files.append(p)
    files.sort(key=lambda p:p.relative_to(source).as_posix())
    digest=hashlib.sha256()
    for p in files:
        rel=p.relative_to(source).as_posix().encode()
        digest.update(len(rel).to_bytes(4,'big'));digest.update(rel)
        digest.update(bytes.fromhex(sha(p)));total+=p.stat().st_size
    return {'files':len(files),'java_bytes':total,'source_hash':digest.hexdigest()}

def runtime_env(root):
    env=os.environ.copy()
    for k in ('GITHUB_TOKEN','GH_TOKEN','CODEQL_REGISTRIES_AUTH','HF_TOKEN','HUGGING_FACE_HUB_TOKEN','PYTHONPATH','PYTHONHOME'):
        env.pop(k,None)
    env.update(CODEQL_TELEMETRY_DISABLE='1',SEMGREP_SEND_METRICS='off',OPENGREP_SEND_METRICS='off',
      SEMGREP_ENABLE_VERSION_CHECK='0',OPENGREP_ENABLE_VERSION_CHECK='0',GIT_TERMINAL_PROMPT='0',
      HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',WANDB_DISABLED='true',PYTHONDONTWRITEBYTECODE='1',
      XDG_CACHE_HOME=str(root/'cache'),CODEQL_PLATFORM='linux64')
    return env

def _interrupt(signum,frame):
    global STOP,ACTIVE
    STOP=True
    # The native E1 helper starts its own subprocess groups. Terminate only
    # descendants of THIS worker, never a system-wide Java or Python process.
    visited=set()
    def descend(pid):
        if pid in visited:return
        visited.add(pid)
        source=Path('/proc')/str(pid)/'task'/str(pid)/'children'
        try:children=[int(v) for v in source.read_text().split()]
        except (OSError,ValueError):return
        for child in children:descend(child)
    descend(os.getpid())
    for pid in sorted(visited-{os.getpid()},reverse=True):
        try:os.killpg(pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass
    if ACTIVE is not None:
        try:os.killpg(ACTIVE.pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass

def run_cmd(argv,log,seconds,env,*,cwd=None):
    global ACTIVE
    demand(not STOP,'STOP_REQUESTED')
    log=Path(log);log.parent.mkdir(parents=True,exist_ok=True)
    started=time.monotonic();expired=False
    with log.open('xb') as f:
        p=subprocess.Popen([str(v) for v in argv],stdin=subprocess.DEVNULL,
            stdout=f,stderr=subprocess.STDOUT,start_new_session=True,cwd=cwd,env=env,close_fds=True)
        ACTIVE=p
        try:
            while True:
                if STOP:raise ScanStopped('STOP_REQUESTED')
                try:rc=p.wait(timeout=0.5);break
                except subprocess.TimeoutExpired:
                    if time.monotonic()-started>seconds:
                        expired=True
                        raise ScanError('COMMAND_TIMEOUT:'+Path(str(argv[0])).name)
        except (ScanStopped,ScanError):
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=10)
            raise
        finally:ACTIVE=None
    return {'returncode':rc,'seconds':round(time.monotonic()-started,2),
            'timed_out':expired,'log':log.name}

def toolchain(root):
    home=Path.home()
    opengrep=home/'.opengrep/cli/v1.25.0/opengrep'
    codeql=home/'tools/codeql/codeql'
    rules=home/'iris/integration/rules/opengrep/p-java-pinned-20260929/5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1/p-java.yaml'
    scorer=home/'iris/simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py'
    for p,label in ((opengrep,'OPENGREP'),(codeql,'CODEQL')):
        demand(p.is_file() and os.access(p,os.X_OK),label+'_EXECUTABLE_NOT_FOUND')
    demand(rules.is_file() and not rules.is_symlink(),'PINNED_OPENGREP_RULES_MISSING')
    demand(scorer.is_file() and sha(scorer)==SCORER_SHA,'FROZEN_SAST_SCORER_HASH_DRIFT')
    return {'opengrep':opengrep,'codeql':codeql,'rules':rules,'scorer':scorer}

def make_query_pack(run,ql,lock,query_name,query_text):
    folder=run/query_name
    folder.mkdir(mode=0o700,parents=True,exist_ok=False)
    (folder/'qlpack.yml').write_text('name: ntk/fullproject-live-6b\nversion: 0.0.1\ndependencies:\n  codeql/java-all: "9.1.2"\n',encoding='ascii')
    shutil.copy2(lock,folder/'codeql-pack.lock.yml')
    query=folder/(query_name+'.ql')
    query.write_text(query_text,encoding='utf-8')
    return folder,query

def run_query(codeql,db,qp,query,packs,run,tag,env):
    opts=['--additional-packs='+os.pathsep.join(str(p) for p in packs.values()),
          '--common-caches='+str(run/'ql-cache')]
    cmds=[('PACK',[codeql,'pack','resolve-dependencies','--mode=verify',*opts,qp],240),
          ('COMPILE',[codeql,'query','compile','--check-only',query,*opts,'--threads=2','--ram=3072'],420)]
    folder=run/'ql-artifacts'/tag;folder.mkdir(parents=True,exist_ok=False)
    for name,cmd,t in cmds:
        result=run_cmd(cmd,folder/(name+'.log'),t,env)
        demand(result['returncode']==0,'CODEQL_'+tag+'_'+name+'_ERROR')
    bqrs=folder/'query.bqrs'
    info=run_cmd([codeql,'query','run',query,'--database='+str(db),'--output='+str(bqrs),
        '--threads=2','--ram=3072',*opts,'--no-default-compilation-cache',
        '--compilation-cache='+str(run/'ql-compilation-cache')],folder/'RUN.log',1800,env)
    demand(info['returncode']==0 and bqrs.is_file(),'CODEQL_'+tag+'_RUN_ERROR')
    csv=folder/(tag+'.csv')
    result=run_cmd([codeql,'bqrs','decode',bqrs,'--format=csv','--output='+str(csv)],folder/'DECODE.log',180,env)
    demand(result['returncode']==0 and csv.is_file(),'CODEQL_'+tag+'_DECODE_ERROR')
    return csv

def pin_packs(run):
    prev=Path.home()/'migration/ntk_fullproject_phase31_runs/fullproj31_20261021T114118Z_3502ed0e'
    prior=prev/'FULLPROJECT_PHASE31_RESULT.json'
    demand(prior.is_file() and not prior.is_symlink(),'PINNED_PHASE31_NOT_FOUND')
    result=read(prior)
    demand(result.get('status')=='INVENTORY_RECOVERED','PHASE31_NOT_COMPLETE')
    bridge=import_verified('phase4_bridge')
    demand(sha(prior)==bridge.PREVIOUS_SHA256,'PINNED_PHASE31_SHA_DRIFT')
    paths,total=bridge.stage_packs(prev,result,run/'pack-stage')
    return paths,total

def score_and_export(run,source,og,sarif,model_sinks,argument_rows,project,scorer):
    fuse=import_verified('fuse_phase5')
    exact=import_verified('phase51_exact_binding')
    records=[]
    for i,item in enumerate(og.get('results',[])):
        records.append(fuse.score_inputs_for_opengrep(item,source,project,i,{}))
    original=[]
    for entry in (sarif or {}).get('runs',[]):
        rules={x.get('id'):x for x in ((entry.get('tool') or {}).get('driver') or {}).get('rules',[])}
        for finding in entry.get('results',[]):
            j=len(original)
            records.append(fuse.score_inputs_for_codeql(finding,rules.get(finding.get('ruleId'),{}),source,project,j,{}))
            original.append(finding)
    links=[]
    for row in records:
        fuse.score_record(row,scorer)
        if row['origin']!='CODEQL_SECURITY_EXTENDED':continue
        source_item=original[row['raw_source_index']]
        pts=fuse.codeql_flows(source_item,source)
        bound=exact.collect_binding_for_record({**row,'codeql_paths':pts},model_sinks,argument_rows)
        if not bound:continue
        x=bound[0]
        row['model_annotation']={'case_key':x['case_key'],'status':'ACCEPTED','role':'sink',
          'origin':'LOCAL_NATIVE_IRIS_STAGE3_LORA_EPOCH1',
          'join_basis':'EXACT_COMPILER_OVERLOAD_SINK_PARAMETER_AST_AND_CODEQL_FLOW_TERMINAL',
          'sink_argument_and_path_binding':'PROVEN','model_qualified_vulnerability':False}
        row['exact_argument_binding']={k:v for k,v in x.items() if k!='project'}
        row['model_qualified_dataflow_path']=True
        row['ai_validation']={'verdict':'API_ROLE_SINK_ONLY','api_role':'sink','parse_status':'ACCEPTED'}
        row['score']=asdict(scorer.score_finding(row))
        row['scoring_policy']='FROZEN_SAST_V22_EXACT_MODEL_SINK_ARGUMENT_PATH'
        row['vulnerability_confirmed']=False
        links.append({'finding_id':row['id'],'case_key':x['case_key'],
                      'path_index':x['path_index'],'argument_index':x['argument_index']})
    records.sort(key=lambda x:(-x['score']['final_score'],x['origin'],x['id']))
    report={'status':'PHASE6B_NEW_SCAN_EVIDENCE_REPORT','project':project,'findings':records,
       'summary':{'retained':len(records),'opengrep':len(og.get('results',[])),'codeql':len(original),
                  'exact_model_links':len(links),'codeql_codeflows':sum(bool(x.get('codeFlows')) for x in original)},
       'score_semantics':'REVIEW_PRIORITY_NOT_VULNERABILITY_PROBABILITY',
       'independent_gold':False,'new_scan':True,'vulnerability_confirmed':False,
       'model_xss_gate_granted':False,'model_links':links}
    save(run/'result.json',report)
    s=fuse.make_sarif(records,project)
    for entry in s['runs']:
        entry['properties'].update(new_scan_executed=True,full_project_new_java_zip=True,
            codeql_build_mode='none',native_stage3_attempted=bool(model_sinks),
            vulnerability_confirmed=False)
        belonging=[r for r in records if r['origin']==entry['properties']['original_engine']]
        for f,r in zip(entry['results'],belonging):
            f['properties']['model_qualified_dataflow_path']=bool(r.get('model_qualified_dataflow_path'))
            f['properties']['exact_argument_binding']=r.get('exact_argument_binding')
    save(run/'report.sarif',s)
    return report

def run(job,*,native=True,codeql_enabled=True,max_total=8):
    """One worker. Partial failures preserve earlier genuine evidence and are labelled."""
    job=Path(job).resolve(strict=True)
    demand(job.is_dir() and job.name.startswith('fp6b_'),'INVALID_JOB_FOLDER')
    archive=job/'input.zip'
    demand(archive.is_file() and not archive.is_symlink(),'INPUT_ARCHIVE_MISSING')
    statefile=job/'status.json'
    entry=read(statefile,65536)
    demand(entry.get('status')=='STARTING','JOB_ALREADY_STARTED_OR_INVALID')
    project=entry['project'];started=time.monotonic()
    summary={'project':project,'job_id':entry['id'],'new_upload_sha256':sha(archive),
      'opengrep':'NOT_RUN','codeql_db':'NOT_RUN','codeql_security':'NOT_RUN',
      'api_inventory':'NOT_RUN','native_lora':'NOT_RUN','exact_binding':'NOT_RUN',
      'score':'NOT_RUN','new_scan':True,'codeql_build_mode':'none',
      'maven_gradle_javac_executed_by_runner':False,'codeql_db_created_from_this_zip':False,
      'no_cloud_llm':True,'independent_gold':False,'limitations':[]}
    data=None;sarif={'runs':[]};source=None;before=None;stage='ZIP_INTAKE'
    env=runtime_env(job)
    def update(new_stage,status='RUNNING',err=None):
        nonlocal stage
        stage=new_stage
        if STOP and status=='RUNNING':raise ScanStopped('STOP_REQUESTED')
        current={'id':entry['id'],'project':project,'status':status,'stage':new_stage,
              'created_at':entry['created_at'],'elapsed_s':round(time.monotonic()-started,1),
              'summary':summary,'error':err,'run_id':entry['id']}
        save(statefile,current)
        print('FULLPROJECT_STAGE='+new_stage,flush=True)
    try:
        update('ZIP_INTAKE')
        source,metadata=extract_zip(archive,job/'unpacked')
        before=source_fingerprint(source)
        summary.update(input=metadata,source_hash_sha256=before['source_hash'],java_count=before['files'])
        demand(before['files']>0,'NO_JAVA_FILES')
        tools=toolchain(job)
        version=run_cmd([tools['codeql'],'version'],job/'logs'/'CODEQL_VERSION.log',45,env)
        demand(version['returncode']==0 and '2.25.6' in (job/'logs'/'CODEQL_VERSION.log').read_text(errors='replace'),
               'CODEQL_2_25_6_REQUIRED')
        update('OPENGREP_SCAN')
        ogfile=job/'opengrep_fullproject.json'
        op=run_cmd([tools['opengrep'],'scan','--config',tools['rules'],'--json',
          '--output',ogfile,'--no-rewrite-rule-ids',source],job/'logs'/'OPENGREP.log',1200,env)
        demand(op['returncode']==0 and ogfile.is_file(),'OPENGREP_SCAN_FAILED')
        data=read(ogfile)
        demand(isinstance(data.get('results'),list) and not data.get('errors'),'OPENGREP_INCOMPLETE_ERRORS')
        summary.update(opengrep='COMPLETE',opengrep_findings=len(data['results']),opengrep_seconds=op['seconds'],
                       opengrep_rules_sha256=sha(tools['rules']))
        if codeql_enabled:
            try:
                demand(shutil.disk_usage(job).free>=3*1024**3,'FREE_DISK_BELOW_3_GIB_FOR_CODEQL')
                update('CODEQL_DATABASE_NONE')
                db=job/'database'
                result=run_cmd([tools['codeql'],'database','create',db,'--language=java','--build-mode=none',
                  '--source-root='+str(source),'--threads=2','--ram=3072'],job/'logs'/'CODEQL_DATABASE.log',2400,env,cwd=job)
                demand(result['returncode']==0 and (db/'db-java').is_dir(),'CODEQL_DATABASE_CREATE_FAILED')
                summary['codeql_db']='COMPLETE_NO_BUILD'
                summary['codeql_db_created_from_this_zip']=True
                update('CODEQL_SECURITY_EXTENDED')
                qlsarif=job/'CODEQL_SECURITY_EXTENDED.sarif'
                q=run_cmd([tools['codeql'],'database','analyze',db,SUITE,'--format=sarif-latest',
                    '--output='+str(qlsarif),'--threads=2','--ram=3072'],job/'logs'/'CODEQL_SECURITY.log',2400,env)
                demand(q['returncode']==0 and qlsarif.is_file(),'CODEQL_SECURITY_FAILED')
                sarif=read(qlsarif)
                demand(sarif.get('version')=='2.1.0' and isinstance(sarif.get('runs'),list),'CODEQL_SARIF_SCHEMA')
                ql_findings=sum(len(x.get('results',[])) for x in sarif['runs'])
                summary.update(codeql_security='COMPLETE',codeql_findings=ql_findings,
                    codeql_codeflows=sum(bool(x.get('codeFlows')) for r in sarif['runs'] for x in r.get('results',[])))
                try:
                    update('CODEQL_COMPILER_API_INVENTORY')
                    packs,size=pin_packs(job)
                    bridge=import_verified('phase4_bridge')
                    lock=Path.home()/'iris/src/queries/codeql-pack.lock.yml'
                    demand(lock.is_file(),'HISTORICAL_CODEQL_LOCK_MISSING')
                    qp,query=make_query_pack(job,tools['codeql'],lock,'ApiInventory',QL_INVENTORY)
                    inventory_csv=run_query(tools['codeql'],db,qp,query,packs,job,'ApiInventory',env)
                    allcalls=bridge.read_inventory(inventory_csv)
                    summary.update(api_inventory='COMPLETE',compiler_calls=len(allcalls))
                    points=bridge.sarif_positions(qlsarif)
                    selected,counts=bridge.rank_and_select(allcalls,points,max_per_cwe=2,max_total=max_total)
                    summary['modelable_distinct_apis']=counts
                    summary['candidates_selected']=len(selected)
                    if selected:
                        update('CODEQL_COMPILER_PARAMETERS')
                        qp,query=make_query_pack(job,tools['codeql'],lock,'SelectedApiParameters',bridge.query_for_rows(selected))
                        params_csv=run_query(tools['codeql'],db,qp,query,packs,job,'SelectedApiParameters',env)
                        enriched=bridge.read_enriched(params_csv)
                        good,rejected=bridge.merge_identity(selected,enriched)
                        save(job/'COMPILER_IDENTITIES.json',good)
                        summary.update(parameters_verified=len(good),parameters_rejected=len(rejected))
                        if good and native:
                            try:
                                update('NATIVE_IRIS_STAGE3_LORA_EPOCH1')
                                reference=Path.home()/'migration/ntk_fastscan_dev_20261021/engine_reference'
                                work=Path.home()/'migration/ntk_stage3_verified_v5_work'
                                native_result=bridge.native_infer(cases=bridge.native_case_aggregate({project:good}),run=job,
                                    reference=reference,repo=Path.home()/'iris',work=work,
                                    downloads=Path('/mnt/c/Users/HP/Downloads'),host_python=Path(os.environ.get('NTK_IRIS_PYTHON',sys.executable)))
                                summary.update(native_lora=native_result['status'],native_requests=native_result['new_native_requests'],
                                    native_accepted=native_result['accepted'],native_abstain=native_result['abstain'])
                            except (Exception,KeyboardInterrupt) as e:
                                summary.update(native_lora='ERROR_NOT_FAKED',native_error=str(e)[:260])
                        else:
                            summary['native_lora']='SKIPPED_NO_ELIGIBLE_OR_DISABLED'
                        if summary['native_lora']=='NATIVE_STAGE3_EPOCH1_COMPLETED':
                            try:
                                update('CODEQL_EXACT_SINK_ARGUMENTS')
                                exact=import_verified('phase51_exact_binding')
                                audit=read(job/'NATIVE_EPOCH1_AUDIT.json',16*1024**2)
                                trace=job/'private_native/epoch_1/native_trace.jsonl'
                                cold={r['case_key']:r for r in (json.loads(l) for l in trace.read_text('utf-8').splitlines() if l.strip()) if r['phase']=='cold'}
                                bykey={r['case_key']:r for r in audit['details']}
                                sinks=[]
                                for x in good:
                                    c=x['candidate'];key=exact.native_key(c)
                                    a=bykey.get(key);raw=cold.get(key)
                                    if a is None or raw is None or a['status']!='ACCEPTED' or a['role']!='sink':continue
                                    label=raw.get('label') or {};args=label.get('sink_args') or []
                                    if label.get('type')!='sink' or 'this' in args or not args:continue
                                    if any(label.get(k)!=c[k] for k in ('package','class','method','signature')):continue
                                    sinks.append({'project':project,'case_key':key,'cwe':c['cwe'],
                                        'package':c['package'],'clazz':c['class'],'method':c['method'],
                                        'compiler_signature':c['compiler_signature'],'sink_args':tuple(args),'origin':x['origin']})
                                summary['native_accepted_sink_apis']=len(sinks)
                                if sinks:
                                    qp,query=make_query_pack(job,tools['codeql'],lock,'ExactSinkArguments',exact.emit_query(sinks))
                                    args_csv=run_query(tools['codeql'],db,qp,query,packs,job,'ExactSinkArguments',env)
                                    argument_rows=exact.read_args(args_csv)
                                    summary.update(exact_binding='QUERY_COMPLETE',argument_ast_rows=len(argument_rows))
                                    model_sinks=sinks
                                else:summary['exact_binding']='SKIPPED_NO_ACCEPTED_SINK'
                            except (Exception,KeyboardInterrupt) as e:
                                summary.update(exact_binding='ERROR_NOT_FAKED',exact_error=str(e)[:260])
                    else:
                        summary.update(native_lora='SKIPPED_NO_MODELED_API',exact_binding='SKIPPED_NO_MODELED_API')
                except (Exception,KeyboardInterrupt) as e:
                    summary.update(api_inventory='ERROR_NOT_FAKED',api_error=str(e)[:260])
            except (Exception,KeyboardInterrupt) as e:
                summary.update(codeql_error=str(e)[:260],codeql_security='ERROR_OR_INCOMPLETE' if summary['codeql_security']=='NOT_RUN' else summary['codeql_security'],
                               codeql_db='ERROR_OR_INCOMPLETE' if summary['codeql_db']=='NOT_RUN' else summary['codeql_db'])
        model_sinks=locals().get('model_sinks',[])
        argument_rows=locals().get('argument_rows',[])
        update('FROZEN_SAST_V22_FUSION')
        fuse=import_verified('fuse_phase5')
        scorer=fuse.load_scorer(tools['scorer'])
        report=score_and_export(job,source,data,sarif,model_sinks,argument_rows,project,scorer)
        summary.update(score='COMPLETE',exact_model_links=report['summary']['exact_model_links'],findings_retained=report['summary']['retained'])
        ready_static=(summary['codeql_security']=='COMPLETE' and summary['opengrep']=='COMPLETE'
            and summary['api_inventory']=='COMPLETE')
        model_state=summary['native_lora']
        acceptable=(model_state=='NATIVE_STAGE3_EPOCH1_COMPLETED' or
            model_state in ('SKIPPED_NO_MODELED_API','SKIPPED_NO_ELIGIBLE_OR_DISABLED'))
        state='COMPLETE' if ready_static and acceptable else 'PARTIAL'
        summary['overall_mode']='NEW_PROJECT_NATIVE_STAGE3_EXECUTED_NO_GOLD_CONFIRMATION' if (summary.get('native_lora')=='NATIVE_STAGE3_EPOCH1_COMPLETED' and
                summary['codeql_security']=='COMPLETE') else 'NEW_PROJECT_STATIC_WITH_MODEL_STAGE_UNAVAILABLE_OR_UNSUPPORTED'
        summary['limitations'].append('Java CodeQL no-build extraction: may miss library or generated-code flows; no Maven/Gradle executed')
        if summary.get('exact_model_links',0)==0:summary['limitations'].append('No model-qualified sink argument dataflow; findings retain neutral model priority')
        demand(source_fingerprint(source)==before,'JAVA_SOURCE_CHANGED_BY_SCAN')
        summary['source_unchanged']=True
        if STOP:
            raise ScanStopped('STOP_REQUESTED_BEFORE_FINAL_REPORT')
        summary['duration_s']=round(time.monotonic()-started,2)
        save(job/'SCAN_SUMMARY.json',summary)
        manifest={n:sha(job/n) for n in ('SCAN_SUMMARY.json','result.json','report.sarif','opengrep_fullproject.json') if (job/n).is_file()}
        save(job/'RESULT_MANIFEST.json',manifest)
        update('REPORT_READY',state)
        print('FULLPROJECT_STATUS='+state+'; OPENGREP='+summary['opengrep']+'; CODEQL='+summary['codeql_security']+
              '; NATIVE='+summary['native_lora']+'; EXACT_LINKS='+str(summary['exact_model_links']),flush=True)
        return state
    except (Exception,KeyboardInterrupt) as e:
        kind='STOPPED' if STOP or isinstance(e,ScanStopped) else 'BLOCKED'
        summary['error']=str(e)[:500]
        summary['duration_s']=round(time.monotonic()-started,2)
        save(job/'SCAN_SUMMARY.json',summary)
        update(stage,kind,str(e)[:350])
        print('FULLPROJECT_STATUS='+kind+'; BLOCKER='+str(e)[:240],flush=True)
        return kind

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--job',type=Path,required=True)
    p.add_argument('--no-codeql',action='store_true')
    p.add_argument('--no-native',action='store_true')
    p.add_argument('--max-candidates',type=int,default=8)
    a=p.parse_args()
    demand(1<=a.max_candidates<=16,'INVALID_CANDIDATE_BUDGET')
    signal.signal(signal.SIGTERM,_interrupt)
    signal.signal(signal.SIGINT,_interrupt)
    result=run(a.job,native=not a.no_native,codeql_enabled=not a.no_codeql,max_total=a.max_candidates)
    return 0 if result in ('COMPLETE','PARTIAL') else 2

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:
        print('FULLPROJECT_FATAL='+str(e)[:300],file=sys.stderr)
        sys.exit(2)
