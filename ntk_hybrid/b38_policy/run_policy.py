#!/usr/bin/env python3
"""C4 compiler-certified encoding review; DPA fresh mixed-evidence four-CWE integration."""
from __future__ import annotations
import argparse
from copy import deepcopy
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import time
import traceback
import uuid
import zipfile
from bootstrap import ROOT,ENGINE
from ntk_b33.common import COMMIT,Blocker,digest,sha_file,write_json
from ntk_b33.patcher import apply
from vendor_batch33 import frozen_state,snapshot_from_git
from b34_helpers import extract_b33,B33_NAME,local_pack_copy
from ntk_b34.toolchain import select_toolchain
from ntk_b34.pack_resolution import verify_and_options
from ntk_b34.core import read_arguments,load_scorer
from run_batch37a import ensure_safe_input,validate_local_assets,command
from ntk_b38.profiles import (PHASE_CWES,SOURCE_POLICY,POLICY,POLICY_SHA,
    select_candidates,adjudicate,manual_labels)
from ntk_b38.core import read_calls,emit_flow,parse_flows,calibrated_fusion,to_sarif
from ntk_b38.scanner import scan

from c4.policy import (tagged,tag_paths,bind_ast,assess_paths,policy_fusion,check_policy_fixture,
  to_sarif,ORIGIN,MODEL,POLICY as C4_POLICY,POLICY_SHA as C4_SHA)
from c4.gates import require_gate,issue_gate
PHASES={'C4':['79'],'DPA':['22','78','79','89']}


def implementation_sha():
 paths=[p for p in ROOT.rglob('*') if p.is_file() and
        (p.suffix in ('.py','.ql','.qll','.template','.yml','.sh','.js','.html','.css','.java') or p in (ROOT/'samples/MANIFEST.json',ROOT/'POLICY_SAMPLES.json')) and
        '__pycache__' not in p.parts]
 return digest({str(p.relative_to(ROOT)):sha_file(p) for p in sorted(paths)})


def fixture_for(archive_sha):
 rows=[dict(v,phase=k) for k,v in json.loads((ROOT/'POLICY_SAMPLES.json').read_text()).items() if v['sha256']==archive_sha]
 if len(rows)!=1:return None
 f=rows[0];f['files']=f['java_hashes'];allfiles=set(f['files'])
 f['expectations']={c:{p:{'expected_flow':p in vals and vals[p]['expected_flow']} for p in allfiles} for c,vals in f.get('model_expectations',{}).items()}
 f['expectations']['79']={p:{'expected_flow':p in f['expectations79'] and f['expectations79'][p]['raw_policy_flow']} for p in allfiles}
 f['scanner_expectations']={c:list(v) for c,v in f.get('model_expectations',{}).items()};f['scanner_expectations']['79']=list(f['expectations79'])
 return f


def check_cases(flows,expectations):
 observed={p:any(f['location']['uri']==p for f in flows) for p in expectations}
 unexpected=sorted({f['location']['uri'] for f in flows}-set(expectations))
 return {'expected':{p:r['expected_flow'] for p,r in expectations.items()},'observed':observed,
         'unexpected_path_files':unexpected,
         'match':not unexpected and all(observed[p]==r['expected_flow'] for p,r in expectations.items()),
         'unit':'FILE_PRESENCE_OF_CWE_QUALIFIED_PATH_NOT_RAW_FINDING_COUNT',
         'not_independent_gold':True}



def verify_fixture_scanner(og,fixture,target,cwes):
 if fixture is None:return {'scope':'NO_KNOWN_EXPECTATIONS_FOR_OPERATOR_PROJECT'}
 from ntk_b34.core import normalized_uri
 proof={}
 for c in cwes:
  if c not in fixture['expectations']:continue
  counts={}
  for row in og['results']:
   if row['cwe']==c:
    uri=normalized_uri(row['path'],target);counts[uri]=counts.get(uri,0)+1
  # Scanner call presence is not the same contract as CWE-qualified dataflow.
  # D evaluates every CWE on all 16 files, but each callsite rule is expected
  # only on its own four API-using files (positive and control alike).
  expected=set(fixture.get('scanner_expectations',{}).get(c,fixture['expectations'][c]))
  positives={p for p,r in fixture['expectations'][c].items() if r['expected_flow']}
  if not expected.issubset(fixture['expectations'][c]) or not positives.issubset(expected):
   raise Blocker('SCANNER_COVERAGE_CONTRACT_INCONSISTENT_CWE_'+c)
  proof[c]={'expected_files':sorted(expected),'observed_counts':counts,'match':set(counts)==expected}
  if not proof[c]['match']:raise Blocker('OPENGREP_FIXTURE_COVERAGE_MISMATCH_CWE_'+c)
 return proof


def pack(run,downloads,summary):
 excluded_roots={'database','snapshot','codeql-cache','query-compilation-cache','b33_evidence','uploaded_project',
  'encoding_compiler','classes','javac_preflight','javac_codeql','toolchain_recovery','cache'}
 included=[];excluded=[]
 for p in sorted(run.rglob('*')):
  if not p.is_file() or p.is_symlink():continue
  rel=p.relative_to(run)
  if (rel.parts[0] in excluded_roots or '.cache' in rel.parts or '.config' in rel.parts or '.tmp' in rel.parts or '.state' in rel.parts or '.semgrep' in rel.parts or
      p.suffix in ('.so','.pyc') or p.stat().st_size>32*1024*1024):
   excluded.append({'path':str(rel),'bytes':p.stat().st_size})
  elif rel.name not in ('OUTPUT_MANIFEST.json','EXCLUDED_FILES.json'):included.append(p)
 write_json(run/'EXCLUDED_FILES.json',excluded);included.append(run/'EXCLUDED_FILES.json')
 manifest=run/'OUTPUT_MANIFEST.json';write_json(manifest,{str(p.relative_to(run)):sha_file(p) for p in included})
 included.append(manifest)
 out=downloads/(run.name+'_result.zip')
 if out.exists():raise Blocker('REFUSE_EVIDENCE_OVERWRITE')
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for p in included:z.write(p,str(p.relative_to(run)))
 (downloads/(out.name+'.sha256')).write_text(sha_file(out)+'  '+out.name+'\n')
 return out,manifest


def parser():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--phase',choices=list(PHASES),required=True)
 p.add_argument('--arm',choices=['epoch_1','epoch_2','both'],default='epoch_1')
 p.add_argument('--project-zip',type=Path)
 p.add_argument('--work',type=Path,default=Path.home()/'migration/ntk_stage3_verified_v5_work')
 p.add_argument('--repo',type=Path,default=Path.home()/'iris')
 p.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
 # No diagnostic-only bypass; policy receipt is a different, explicit contract.
 return p


def main(argv=None):
 from ntk_b38.processes import install_cleanup_handler
 install_cleanup_handler()
 args=parser().parse_args(argv)
 sample_spec=json.loads((ROOT/'POLICY_SAMPLES.json').read_text())[args.phase]
 project=(args.project_zip or ROOT/sample_spec['archive']).resolve()
 cw=PHASES[args.phase];arms=['epoch_1','epoch_2'] if args.arm=='both' else [args.arm]
 args.work=args.work.resolve();args.repo=args.repo.resolve();args.downloads=args.downloads.resolve()
 if args.work==args.repo or args.repo in args.work.parents:
  raise Blocker('WORK_CANNOT_BE_INSIDE_FROZEN_REPOSITORY')
 args.work.mkdir(parents=True,exist_ok=True)
 # Shared between CLI and B38 web. B37 remains separate; do not run a B37 GPU scan concurrently.
 lock=(args.work/'batch38_gpu_scan.lock').open('a+')
 try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:raise Blocker('ANOTHER_B38_SCAN_IS_RUNNING')
 run=args.work/'batch38_policy_runs'/('batch38'+args.phase.lower()+'_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:6])
 run.mkdir(parents=True,exist_ok=False)
 before=None;start=time.monotonic();impl=implementation_sha();fixture=None
 s={'status':'RUNNING','revision':'B38_C4_DPA_COMPILER_ENCODING_AND_MIXED_EVIDENCE_V1','phase':args.phase,'cwes':cw,'arms':{},'diagnostics':{},
    'implementation_sha256':impl,'policy_sha256':POLICY_SHA,'diagnostic_only':False,'evidence_mode':'CODEQL_CONTEXTUAL_POLICY_ASSISTED' if args.phase=='C4' else 'MIXED_MODEL_DERIVED_AND_CONTEXTUAL_POLICY',
    'model_derived_xss_gate':'NOT_GRANTED','old_gate_D':'UNCHANGED_NOT_GRANTED','c4_policy_sha256':C4_SHA,
    'scope':'JDK21_ONLY_MAX24_JAVA_NOT_GENERAL_PROJECT_COVERAGE',
    'codeql_dataflow':'NOT_EXECUTED','source_policies':{c:SOURCE_POLICY[c] for c in cw},
    'source_discovered_by_llm':False,'transfers':'DECLARED_JDK_MODELS_NOT_LEARNED_PROPAGATOR_LABELS',
    'training':'NOT_EXECUTED','model_inference':'NOT_EXECUTED','Stage4':'NOT_EXECUTED','full_SAPipeline_run':'NOT_EXECUTED',
    'independent_gold':False,'run_dir':str(run)}
 def event(stage,detail=''):
  s['current_stage']=stage;write_json(run/'PROGRESS.json',s)
  print('B38_STAGE='+stage+(' '+detail if detail else ''),flush=True)
 def run_ql(codeql,qp,db,path,out,opts,resources):
  out.mkdir(parents=True,exist_ok=True)
  command([codeql,'query','compile','--check-only',path,*opts,*resources],out/'compile.log',cwd=run,timeout=900)
  command([codeql,'database','run-queries',db,path,*opts,*resources,'--no-default-compilation-cache',
           '--compilation-cache='+str(run/'query-compilation-cache')],out/'run.log',cwd=run,timeout=1800)
  sarif=out/'codeql.sarif'
  command([codeql,'database','interpret-results',db,path,'--format=sarifv2.1.0','--output='+str(sarif),
           '--max-paths=4',*opts],out/'interpret.log',cwd=run,timeout=600)
  b=list((db/'results').rglob(path.stem+'.bqrs'))
  if len(b)!=1:raise Blocker('REAL_BQRS_NOT_UNIQUE: '+path.name)
  shutil.copy2(b[0],out/'flow.bqrs')
  return json.loads(sarif.read_text())
 try:
  if not args.downloads.is_dir():raise Blocker('DOWNLOADS_DIRECTORY_MISSING')
  before=frozen_state(args.repo);write_json(run/'FROZEN_BEFORE.json',before)
  if before['head']!=COMMIT or before['status_porcelain']:raise Blocker('FROZEN_REPOSITORY_CHANGED')
  capacity=shutil.disk_usage(run)
  write_json(run/'STORAGE_PREFLIGHT.json',{'free_bytes':capacity.free,'minimum_free_bytes':4*1024**3,
    'note':'Per-run minimum, not an estimate of total A-D storage; no automatic deletion.'})
  if capacity.free<4*1024**3:raise Blocker('LESS_THAN_4_GIB_FREE_IN_WORK_FILESYSTEM')
  # D combines four CWEs only after the three separate fixed-fixture gates for the same arm.
  if args.phase=='DPA':
   event('VERIFY_PREVIOUS_GATES')
   require_gate(args.work,'C4','none',impl)
  event('ZIP_INTAKE');target=run/'uploaded_project';inp=ensure_safe_input(project,target)
  write_json(run/'UPLOADED_INPUT_PROVENANCE.json',inp);s['input_sha256']=inp['archive_sha256']
  fixture=fixture_for(inp['archive_sha256'])
  if fixture and inp['java_source_hashes']!=fixture['files']:raise Blocker('KNOWN_FIXTURE_SOURCE_HASHES_DRIFT')
  s['fixture']='PINNED_DEVELOPMENT_FIXTURE' if fixture else 'OPERATOR_PROJECT_NOT_GOLD'
  write_json(run/'C4_POLICY.json',C4_POLICY)
  mlpy=args.work/'.ntk_v5_lora_venv/bin/python'
  if not mlpy.is_file():raise Blocker('PINNED_ML_PYTHON_MISSING')
  event('OPENGREP_REAL');og=scan(run,target,cw,mlpy)
  s['opengrep_count']=len(og['results'])
  write_json(run/'OPENGREP_FIXTURE_COVERAGE.json',verify_fixture_scanner(og,fixture,target,cw))
  event('VERIFY_MODELS_AND_FROZEN_SCORER')
  old=run/'b33_evidence';b33=extract_b33(args.downloads/B33_NAME,old)
  cfgs=validate_local_assets(args.repo,old,run)
  if before!=json.loads((old/'FROZEN_BEFORE.json').read_text()):raise Blocker('FROZEN_STATE_DIFFERS_FROM_B33')
  snapshot=run/'snapshot';snapshot_from_git(args.repo,snapshot);patch=apply(snapshot,ENGINE)
  (run/'STAGE3_PATCH.diff').write_text(patch.pop('diff'));write_json(run/'STAGE3_PATCH_PROOF.json',patch)
  shutil.copy2(old/'inputs/runtime_protocol.json',run/'runtime_protocol.json')
  scorer_path=snapshot/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py'
  scorer=load_scorer(scorer_path);shutil.copy2(scorer_path,run/'SCORER_FROZEN.py')
  event('CODEQL_TOOLCHAIN_AND_PACKS')
  chosen=select_toolchain(args.repo/'codeql/codeql',args.work,args.downloads,run,allow_download=False)
  codeql=chosen.executable;cache=run/'codeql-cache'
  packs=local_pack_copy(args.repo,cache/'packages');write_json(run/'QLPACK_MANIFEST.json',packs)
  additional,resolution=verify_and_options(packs,ENGINE/'B34R2_OBSERVED_QLPACK_PINS.json',run=run,common_caches=cache)
  write_json(run/'CODEQL_PACK_RESOLUTION_PROOF.json',resolution)
  opts=[*additional,'--common-caches='+str(cache)];res=['--threads=1','--ram=3072']
  qp=run/'queries';shutil.copytree(ROOT/'queries',qp)
  shutil.copy2(snapshot/'src/queries/codeql-pack.lock.yml',qp/'codeql-pack.lock.yml')
  command([codeql,'pack','resolve-dependencies','--mode=verify',*opts,qp],run/'PACK_RESOLVE.log',cwd=run,timeout=180)
  event('QL_COMPILER_PREFLIGHT')
  template=(qp/'Flow.template').read_text()
  for c in cw:
   (qp/('Sources_'+c+'.ql')).write_text((qp/'Source.template').read_text().replace('__CWE__',c))
   preview,_=emit_flow(template,[],[],c,arms[0],'compile');(qp/('Compile_'+c+'.ql')).write_text(preview)
  # Explicit HTTP context inventory is audited independently of the returned flow.
  ct=(qp/'ApiCalls.ql').read_text().replace('ntkRelevant(m)','ntkRelevant(m) and ntkSinkContext(call, "79")')
  (qp/'HttpContexts.ql').write_text(ct.replace('api-calls','http-contexts'))
  for path in sorted(qp.glob('*.ql')):
   command([codeql,'query','compile','--check-only',path,*opts,*res],run/('COMPILE_'+path.stem+'.log'),cwd=run,timeout=900)
  event('JAVA_COMPILATION')
  version=command(['javac','-version'],run/'JAVAC_VERSION.log',cwd=run,timeout=30)
  if not re.search(r'\b21\.',version):raise Blocker('PINNED_JDK21_REQUIRED')
  command([mlpy,'-B',ENGINE/'build_jdk_only.py',target,run/'javac_preflight'],run/'JAVAC_PREFLIGHT.log',cwd=run,timeout=180)
  event('JAVAC_ENCODING_AND_OUTPUT_CONTEXT_PROOF')
  write_json(run/'ENCODING_TOOL_PROVENANCE.json',{'java_source_sha256':sha_file(ROOT/'trusted/NtkEncodingAudit.java'),'policy_sha256':C4_SHA,'compiler_interface':'JDK21_JAVAC_TREES','uploaded_classes_executed':False})
  astclasses=run/'encoding_compiler';astclasses.mkdir()
  command([mlpy,'-B',ROOT/'java_clean.py','javac','-proc:none','--release','21','-d',astclasses,ROOT/'trusted/NtkEncodingAudit.java'],run/'ENCODING_COMPILER_BUILD.log',cwd=run,timeout=180)
  rawast=command([mlpy,'-B',ROOT/'java_clean.py','java','-Xmx768m','--add-modules','jdk.compiler','-cp',astclasses,'NtkEncodingAudit',target],run/'ENCODING_COMPILER_RUN.log',cwd=run,timeout=180)
  ast=json.loads(rawast);write_json(run/'ENCODING_COMPILER_RAW.json',ast)
  event('CODEQL_NEW_DATABASE')
  db=run/'database';builder=' '.join(shlex.quote(str(x)) for x in [mlpy,'-B',ENGINE/'build_jdk_only.py',target,run/'javac_codeql'])
  command([codeql,'database','create',db,'--language=java','--source-root='+str(target),'--command='+builder,
    '--no-pre-finalize','--common-caches='+str(cache),*chosen.database_options,*res],run/'DATABASE_CREATE.log',cwd=run,timeout=1800)
  if {str(p.relative_to(target)):sha_file(p) for p in sorted(target.rglob('*.java'))}!=inp['java_source_hashes']:raise Blocker('UPLOADED_JAVA_CHANGED_DURING_ANALYSIS')
  if not (db/'db-java').is_dir() or not (db/'src.zip').is_file():raise Blocker('NEW_DATABASE_EVIDENCE_MISSING')
  write_json(run/'DATABASE_PROOF.json',{'created_in_this_run':True,'new_project_sha256':inp['archive_sha256'],
    'db_path':str(db),'db_metadata_sha256':sha_file(db/'codeql-database.yml'),'src_zip_sha256':sha_file(db/'src.zip'),
    'build':'TRUSTED_JAVAC_PROC_NONE_NO_PROJECT_BUILD_SCRIPTS','xml_pre_finalize':'SKIPPED_JAVA_ONLY',
    'java_application_executed':False})
  event('EXTRACT_COMPILER_IDENTITIES')
  for name in ['ApiCalls','ArgumentSpans','HttpContexts',*['Sources_'+c for c in cw]]:
   command([codeql,'query','run',qp/(name+'.ql'),'--database='+str(db),'--output='+str(run/(name+'.bqrs')),
    *opts,*res,'--no-default-compilation-cache','--compilation-cache='+str(run/'query-compilation-cache')],
    run/(name+'_QUERY.log'),cwd=run,timeout=1800)
   command([codeql,'bqrs','decode',run/(name+'.bqrs'),'--format=csv','--output='+str(run/(name+'.csv'))],
     run/(name+'_DECODE.log'),cwd=run,timeout=180)
  allcases,calls=read_calls(run/'ApiCalls.csv',target);arguments=read_arguments(run/'ArgumentSpans.csv',target)
  calls=tagged(calls)
  contexts=tagged(read_calls(run/'HttpContexts.csv',target)[1],'79')
  cases={c:select_candidates(allcases,c) for c in cw}
  sources={c:tagged(read_calls(run/('Sources_'+c+'.csv'),target)[1],c) for c in cw}
  flattened=[x for c in cw for x in cases[c]]
  if len(flattened)>100:raise Blocker('CWE_API_REQUEST_LIMIT_100')
  write_json(run/'CANDIDATES_BY_CWE.json',cases);write_json(run/'ALL_CALLS.json',calls)
  write_json(run/'ARGUMENTS.json',arguments);write_json(run/'HTTP_CONTEXT_CALLS.json',contexts)
  write_json(run/'SOURCES_BY_CWE.json',sources);write_json(run/'SEMANTIC_POLICY.json',POLICY)
  astproof=bind_ast(ast,calls,inp['java_source_hashes']);write_json(run/'ENCODING_COMPILER_BOUND.json',astproof)
  policy_raw=[];policy_qualified=[];policy_assessments=[]
  event('CONTEXTUAL_POLICY_AND_SEPARATE_MODEL_DIAGNOSTICS')
  # 22/78/89 diagnostics are not model results. 79 executes a distinct declared policy
  # whose guarded evidence is scored with NEUTRAL AI, never counted as LLM paths.
  for c in cw:
   out=run/('context_policy' if c=='79' else 'diagnostic')/('cwe-'+c)
   q,proof=emit_flow(template,cases[c],manual_labels(cases[c],c),c,arms[0],'diagnostic')
   if c=='79':
    q=q.replace('-diagnostic-', '-context-policy-')
    for binding in proof:binding['label_origin']=ORIGIN;binding['policy_sha256']=C4_SHA
   qfile=qp/(('ContextPolicy_' if c=='79' else 'Diagnostic_')+c+'.ql');qfile.write_text(q)
   sarif=run_ql(codeql,qp,db,qfile,out,opts,res)
   s['codeql_dataflow']='REAL_CONTEXT_OR_DIAGNOSTIC_QUERY_EXECUTED_NOT_YET_MODEL_ACCEPTED'
   flows=tag_paths(parse_flows(sarif,target,calls,arguments,proof,sources[c],c,contexts),c)
   write_json(out/('DECLARED_POLICY_BINDINGS.json' if c=='79' else 'MANUAL_DIAGNOSTIC_BINDINGS.json'),proof);write_json(out/'PATHS.json',flows)
   if c=='79':
    # The existing contextual policy defines this new branch, not the failed LLM labels.
    policy_raw=tag_paths(flows,'79')
    for f in policy_raw:f.update(input_project_sha256=inp['archive_sha256'],database_created_in_this_run=True,sink_origin=ORIGIN)
    policy_qualified,policy_assessments=assess_paths(policy_raw,astproof)
    po=run/'policy79';po.mkdir(exist_ok=True)
    write_json(po/'RAW_PATHS.json',policy_raw);write_json(po/'QUALIFIED_PATHS.json',policy_qualified)
    write_json(po/'ASSESSMENTS.json',policy_assessments)
    write_json(po/'PROVENANCE.json',{'origin':ORIGIN,'new_query_executed':True,'query_sha256':sha_file(qfile),
      'bqrs_sha256':sha_file(out/'flow.bqrs'),'sarif_sha256':sha_file(out/'codeql.sarif'),
      'policy_sha256':C4_SHA,'raw_model_labels_modified':False,'not_model_derived':True})
    if fixture:
     s['policy_fixture_check']=check_policy_fixture(policy_raw,policy_qualified,astproof,fixture['expectations79'])
     write_json(po/'FIXTURE_CHECK.json',s['policy_fixture_check'])
   result={'cwe':c,'flow_count':len(flows),'label_origin':ORIGIN if c=='79' else 'MANUAL_DIAGNOSTIC_ONLY_NOT_LLM_NOT_SCORED'}
   if fixture and c in fixture['expectations']:
    result['fixture_check']=check_cases(flows,fixture['expectations'][c])
    s['diagnostics'][c]=result;write_json(out/'SUMMARY.json',result)
    if not result['fixture_check']['match']:raise Blocker('CODEQL_DIAGNOSTIC_MISMATCH_BEFORE_GPU_CWE_'+c)
   else:s['diagnostics'][c]=result;write_json(out/'SUMMARY.json',result)
  if args.phase=='C4':
   fused=policy_fusion(og,policy_raw,policy_qualified,policy_assessments,astproof,calls,target,scorer,[])
   write_json(run/'analysis/policy/FUSED_FINDINGS.json',fused)
   write_json(run/'analysis/policy/FUSED_FINDINGS.sarif',to_sarif(fused))
   s['policy_counts']={'raw_paths':len(policy_raw),'qualified_paths':len(policy_qualified),'retained_opengrep':sum(x['origin']=='OPENGREP' for x in fused)}
   s['status']='B38_C4_POLICY_SCOPED_COMPLETE' if fixture and s['policy_fixture_check']['match'] else 'B38_POLICY_NEEDS_REVIEW'
   s['codeql_dataflow']='REAL_CODEQL_CONTEXTUAL_POLICY_NOT_LLM'

  else:
   common=dict(cfgs['epoch_1'],snapshot=str(snapshot),frozen_root=str(args.repo),ml_python=str(mlpy),
               protocol_path=str(run/'runtime_protocol.json'),cases=flattened)
   importcfg=run/'IMPORT_CONFIG.json';write_json(importcfg,common)
   host=None
   candidates=list(dict.fromkeys([os.environ.get('NTK_IRIS_PYTHON',''),b33.get('iris_host_python',''),str(mlpy)]))
   for i,candidate in enumerate(candidates):
    if not candidate or not Path(candidate).is_file():continue
    try:
     command([candidate,'-B',ENGINE/'run_native37.py',importcfg,'--import-only'],run/('IRIS_IMPORT_'+str(i)+'.log'),cwd=snapshot,timeout=180)
     host=candidate;break
    except Blocker:continue
   if not host:raise Blocker('CANNOT_IMPORT_REAL_IRIS')
   s['iris_host_python']=host
   for arm in arms:
    event('LIVE_LOCAL_IRIS_STAGE3',arm)
    cfg=dict(common,arm=arm,output_dir=str(run/'live'/arm),cache_dir=str(run/'cache'/arm),
     adapter_dir=cfgs[arm]['adapter_dir'],adapter_sha256=cfgs[arm]['adapter_sha256'],
     adapter_config_sha256=cfgs[arm]['adapter_config_sha256'])
    cp=run/('CONFIG_'+arm+'.json');write_json(cp,cfg)
    command([host,'-B','-u',ENGINE/'run_native37.py',cp],run/('LIVE_'+arm+'.log'),cwd=snapshot,timeout=7200)
    lr=run/'live'/arm;stage3=json.loads((lr/'SUMMARY.json').read_text())
    if stage3['cold_live_responses']!=len(flattened) or stage3['warm_exact_cache_hits']!=len(flattened):
     raise Blocker('LIVE_MODEL_OR_EXACT_CACHE_COVERAGE_INCOMPLETE')
    tracefile=lr/'native_trace.jsonl';trace=[json.loads(x) for x in tracefile.read_text().splitlines() if x.strip()] if tracefile.exists() else []
    s['model_inference']='FRESH_LOCAL_IRIS_STAGE3'
    result={'stage3':stage3,'cwes':{}};full=[];allflows=[]
    for c in cw:
     event('LIVE_CODEQL_AND_SCORING',arm+' CWE-'+c)
     # Empty selected candidates yield no API predictions, never hardcoded sinks.
     labelpath=lr/'cold'/('cwe-'+c)/'llm_labelled_sink_apis.json'
     labels=json.loads(labelpath.read_text()) if cases[c] else []
     eligible,decisions=adjudicate(cases[c],labels,c)
     text,proof=emit_flow(template,cases[c],eligible,c,arm)
     qfile=qp/('Live_'+c+'_'+arm+'.ql');qfile.write_text(text)
     out=run/'analysis'/arm/('cwe-'+c)
     sarif=run_ql(codeql,qp,db,qfile,out,opts,res)
     flows=tag_paths(parse_flows(sarif,target,calls,arguments,proof,sources[c],c,contexts),c)
     for f in flows:f.update(input_project_sha256=inp['archive_sha256'],database_created_in_this_run=True)
     model_flows=deepcopy(flows)
     for f in model_flows:f['evidence_origin']=MODEL
     if c=='79':
      write_json(out/'MODEL_ONLY_PATHS_NOT_POLICY.json',model_flows)
      fused=policy_fusion(og,policy_raw,policy_qualified,policy_assessments,astproof,calls,target,scorer,trace)
      flows=deepcopy(policy_qualified)
     else:
      fused=calibrated_fusion(og,flows,trace,calls,target,scorer,c,decisions)
      for finding in fused:
       finding['evidence_origin']=MODEL;finding['sink_origin']='LOCAL_LIVE_STAGE3'
       if finding.get('callsite'):finding['callsite']['cwe']=c

     write_json(out/'RAW_SINK_LABELS.json',labels);write_json(out/'SEMANTIC_DECISIONS.json',decisions)
     write_json(out/'SINK_BINDINGS.json',proof);write_json(out/'VERIFIED_PATHS.json',flows)
     write_json(out/'FUSED_FINDINGS.json',fused);write_json(out/'FUSED_FINDINGS.sarif',to_sarif(fused))
     cold=[x for x in trace if x['phase']=='cold' and x['candidate']['cwe']==c]
     r={'flow_count':len(flows),'candidate_count':len(cases[c]),'source_count':len(sources[c]),
        'accepted':sum(x['status']=='ACCEPTED' for x in cold),'abstain':sum(x['status']=='ABSTAIN' for x in cold),
        'opengrep_preserved':sum(x['origin']=='OPENGREP' for x in fused),'additional_codeql':sum(x['origin'] in ('CODEQL_ADDITIONAL','CODEQL_POLICY_ADDITIONAL') for x in fused),
        'no_path_means_safe':False,'source_policy':SOURCE_POLICY[c]}
     r['evidence_origin']=ORIGIN if c=='79' else MODEL
     r['model_only_flow_count']=len(model_flows)
     if c=='79':
      r['raw_policy_flow_count']=len(policy_raw);r['not_model_derived']=True
      if fixture:r['fixture_check']=s['policy_fixture_check']
     elif fixture and c in fixture['expectations']:r['fixture_check']=check_cases(flows,fixture['expectations'][c])
     result['cwes'][c]=r;full.extend(fused);allflows.extend(flows)
    if len({r['id'] for r in full})!=len(full):raise Blocker('DUPLICATE_MERGED_FINDING_ID')
    if sum(r['origin']=='OPENGREP' for r in full)!=len(og['results']):raise Blocker('AGGREGATE_OPENGREP_FINDINGS_LOST')
    write_json(run/'analysis'/arm/'FUSED_FINDINGS.json',full)
    write_json(run/'analysis'/arm/'FUSED_FINDINGS.sarif',to_sarif(full))
    write_json(run/'analysis'/arm/'VERIFIED_PATHS.json',allflows)
    s['arms'][arm]=result;s['codeql_dataflow']='REAL_FRESH_MIXED_MODEL_22_78_89_POLICY_79_QUERIES_EXECUTED'
    write_json(run/'PROGRESS.json',s)
   if fixture and all(c in fixture['expectations'] for c in cw):
    ok=all(r['fixture_check']['match'] for a in s['arms'].values() for r in a['cwes'].values())
    s['status']='B38_DPA_POLICY_SCOPED_COMPLETE' if ok else 'B38_POLICY_NEEDS_REVIEW'
   else:s['status']='B38_POLICY_ANALYSIS_COMPLETE_NOT_A_SAFETY_VERDICT'
 except Exception as exc:
  s['status']='B38_BLOCKED';s['blocker']=str(exc);(run/'FAILURE.txt').write_text(traceback.format_exc())
 finally:
  try:
   after=frozen_state(args.repo);write_json(run/'FROZEN_AFTER.json',after)
   s['frozen_unchanged']=before is not None and before==after
   if not s['frozen_unchanged']:s['status']='B38_BLOCKED';s['blocker']='FROZEN_REPOSITORY_STATE_CHANGED_OR_UNAVAILABLE'
  except Exception as e:s['frozen_unchanged']=False;s['frozen_error']=str(e);s['status']='B38_BLOCKED'
  s['wall_time_s']=time.monotonic()-start;s['current_stage']='FINISHED'
  write_json(run/'00_SUMMARY.json',s);write_json(run/'PROGRESS.json',s)
  if args.downloads.is_dir():
   out,manifest=pack(run,args.downloads,s)
   if s['status'] in ('B38_C4_POLICY_SCOPED_COMPLETE','B38_DPA_POLICY_SCOPED_COMPLETE') and fixture and fixture['phase']==args.phase:
    for arm in (['none'] if args.phase=='C4' else arms):issue_gate(args.work,args.phase,arm,impl,run,manifest)
   print('\n===== BATCH 38'+args.phase+' RESULT =====',flush=True)
   for k,v in [('STATUS',s['status']),('EVIDENCE_MODE',s['evidence_mode']),('MODEL_XSS_GATE',s['model_derived_xss_gate']),('OLD_GATE_D',s['old_gate_D']),('CODEQL_DATAFLOW',s['codeql_dataflow']),('FROZEN_REPO_UNCHANGED',s['frozen_unchanged']),
     ('RUN_DIR',run),('OUTPUT_ZIP',out),('OUTPUT_SHA256',sha_file(out))]:print(str(k)+'='+str(v),flush=True)
   if 'blocker' in s:print('BLOCKER='+s['blocker'],flush=True)
  else:print('RUN_DIR='+str(run),flush=True)
  fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
 return 2 if s['status']=='B38_BLOCKED' else 3 if s['status']=='B38_POLICY_NEEDS_REVIEW' else 0

if __name__=='__main__':
 try:sys.exit(main())
 except Blocker as e:print('B38_STARTUP_BLOCKED='+str(e),flush=True);sys.exit(2)
