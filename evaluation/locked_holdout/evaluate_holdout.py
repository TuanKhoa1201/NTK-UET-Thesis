#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, math, os, re, zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from metric_core import detection, ranking

ARMS=('opengrep_only','base','epoch_1','epoch_2'); CWES=('22','78','79','89')
POLICY='CODEQL_CONTEXTUAL_POLICY_ASSISTED'; MODEL='MODEL_DERIVED'

def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def digest(x):return hashlib.sha256(canonical(x).encode()).hexdigest()
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def require(v,msg):
 if not v:raise RuntimeError(msg)
def readj(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def writej(path,obj):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def zipmap(path):
 with zipfile.ZipFile(path) as z:
  require(z.testzip() is None,'ZIP_CRC');return {n:z.read(n) for n in z.namelist() if not n.endswith('/')}
def verify_sums(m):
 lines=m['SHA256SUMS'].decode().splitlines()
 for line in lines:
  if not line.strip():continue
  h,n=line.split(None,1);n=n.strip().lstrip('*')
  require(n in m and hashlib.sha256(m[n]).hexdigest()==h,'RESULT_MANIFEST:'+n)
def normalize(reports,units,input_sha):
 uni={(u['uri'],u['cwe']):u for u in units}; require(len(uni)==len(units),'DUPLICATE_UNITS')
 normalized={};lineage={}
 for arm in ARMS:
  rep=reports[arm];require(rep.get('arm')==arm and rep.get('input_sha256')==input_sha,'RESULT_IDENTITY:'+arm)
  rows={u['unit_id']:{'unit_id':u['unit_id'],'uri':u['uri'],'cwe':u['cwe'],'finding_count':0,'opengrep_count':0,
    'score':None,'qualified_model':False,'qualified_policy':False,'qualified_paths':set(),'raw_policy_paths':set()} for u in units}
  ids=set();raw={}
  for f in rep.get('findings',[]):
   require(f.get('id') not in ids,'DUPLICATE_FINDING');ids.add(f.get('id'))
   require(f.get('retained') is True and f.get('vulnerability_confirmed') is False,'SAFETY_FLAGS')
   loc=f.get('location',{});key=(loc.get('uri'),f.get('cwe'));require(key in uni,'UNMAPPED_FINDING:'+repr(key))
   row=rows[uni[key]['unit_id']];score=f.get('score',{}).get('final_score')
   require(type(score) in (int,float) and math.isfinite(score) and 0<=score<=100,'SCORE')
   row['finding_count']+=1;row['score']=score if row['score'] is None else max(row['score'],score)
   linked=f.get('linked_codeql_flow_ids',[]);flow=f.get('dataflow',[])
   require(isinstance(linked,list) and isinstance(flow,list) and bool(linked)==bool(flow),'LINK_FLOW')
   if f.get('origin')=='OPENGREP':
    require(isinstance(f.get('original_opengrep'),dict),'RAW_OPENGREP_MISSING');row['opengrep_count']+=1;raw[f['id']]=digest(f['original_opengrep'])
   if arm=='opengrep_only':require(not linked and f.get('model_observation') is None,'BASELINE_FLOW_OR_MODEL')
   elif f.get('cwe')=='79':
    require(f.get('evidence_origin')==POLICY,'XSS_ORIGIN')
    row['raw_policy_paths'].update(f.get('raw_policy_flow_ids',[]))
    if linked:
     require(f.get('evidence_status')=='POLICY_QUALIFIED_UNENCODED_HTML_PATH','XSS_QUAL_STATUS');row['qualified_policy']=True
   else:
    require(f.get('evidence_origin')==MODEL,'MODEL_ORIGIN')
    if linked:
     obs=f.get('model_observation');require(obs and obs.get('status')=='ACCEPTED' and obs.get('label',{}).get('type')=='sink','MODEL_FLOW_NO_ACCEPTED_SINK')
     require(f.get('evidence_status')=='CODEQL_CWE_'+f['cwe']+'_QUALIFIED_PATH','MODEL_QUAL_STATUS');row['qualified_model']=True
   row['qualified_paths'].update(linked)
  for r in rows.values():
   r['raw_opengrep']=r['opengrep_count']>0;r['any_reported_alert']=r['finding_count']>0
   r['qualified_evidence']=r['qualified_model'] or r['qualified_policy'];r['qualified_paths']=len(r['qualified_paths']);r['raw_policy_paths']=len(r['raw_policy_paths'])
  normalized[arm]=sorted(rows.values(),key=lambda r:r['unit_id']);lineage[arm]=raw
 require(all(lineage[a]==lineage['opengrep_only'] for a in ARMS),'RAW_OPENGREP_NOT_IDENTICAL')
 pv=[]
 for arm in ARMS[1:]:
  pv.append([{k:r[k] for k in ('unit_id','score','qualified_policy','raw_policy_paths','qualified_paths')} for r in normalized[arm] if r['cwe']=='79'])
 require(all(x==pv[0] for x in pv),'POLICY79_NOT_SHARED')
 return normalized

def main():
 p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--workspace',type=Path,required=True);p.add_argument('--result-zip',type=Path,required=True);p.add_argument('--downloads',type=Path,required=True)
 a=p.parse_args();ws=a.workspace.resolve();rz=a.result_zip.resolve();down=a.downloads.resolve();work=a.work.resolve()
 lock=readj(ws/'HOLDOUT_LOCK.json');lock_sha=sha(ws/'HOLDOUT_LOCK.json');input_sha=lock['project_zip_sha256']
 require(lock['predictions_exposed_before_lock'] is False and lock['independent_human_gold'] is False,'LOCK_SCOPE')
 m=zipmap(rz);verify_sums(m);res=json.loads(m['00_RESULT.json'])
 require(res['status']=='B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE' and res['input_sha256']==input_sha,'BACKEND_RESULT_OR_INPUT')
 require(res['completed_arms']==list(ARMS),'ARMS')
 name=rz.name;mobj=re.fullmatch(r'(b39b4_\d{8}T\d{6}Z_[0-9a-f]{8})_result(?: \(\d+\))?\.zip',name)
 require(mobj is not None,'RESULT_FILENAME');runid=mobj.group(1)
 rt=datetime.strptime(runid.split('_')[1],'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
 lt=datetime.fromisoformat(lock['locked_at'].replace('Z','+00:00'));require(rt>=lt,'PREDICTION_RUN_PREDATES_LABEL_LOCK')
 run=work/'batch39b4_hybrid_runs'/runid;private=run/'private';require(private.is_dir(),'LOCAL_BACKEND_RUN_MISSING')
 pm=json.loads(m['PRIVATE_RESULT_MANIFEST.json']);reports={};verified=[]
 for arm in ARMS:
  for leaf in ('result.json','report.sarif'):
   rel=f'analysis/{arm}/{leaf}';path=private/rel;require(path.is_file() and rel in pm and sha(path)==pm[rel],'PRIVATE_EXPORT_SHA:'+rel);verified.append(rel)
  reports[arm]=readj(private/f'analysis/{arm}/result.json')
 vectors=normalize(reports,lock['units'],input_sha)
 labels={u['unit_id']:u for u in lock['units']}
 protocol={'schema':'NTK_B39B7_PRE_PREDICTION_HOLDOUT_EVAL_V1','unit':'TESTCASE_TARGET_CWE','ranking_score':'MAX_FROZEN_FINAL_SCORE_PER_UNIT',
  'selectors':['raw_opengrep','any_reported_alert','qualified_evidence'],'ranking_k':[1,3,5,10],
  'score_threshold_tuning':'NOT_PERFORMED','cwe79_policy_is_lora_gain':False,'independent_human_gold':False,
  'pre_prediction_locked':True,'authorship':'AI_ASSISTED_OPERATOR_APPROVED_BEFORE_PREDICTIONS'}
 metrics={'schema':protocol['schema'],'scope':lock['scope'],'pre_prediction_locked':True,'independent_human_gold':False,
  'truth_counts':lock['truth_counts'],'units':len(lock['units']),'arms':{},'contribution_caveat':'CWE79_POLICY_IS_NOT_LORA_GAIN; OPENGREP_TO_HYBRID_IS_NOT_ADAPTER_ONLY'}
 for arm,rows in vectors.items():
  scopes={}
  for scope in ('all',*CWES):
   sub=rows if scope=='all' else [r for r in rows if r['cwe']==scope]
   det={}
   for selector in protocol['selectors']:
    det[selector]={'status':'NOT_APPLICABLE_CODEQL_NOT_RUN','metrics':None} if arm=='opengrep_only' and selector=='qualified_evidence' else detection(sub,labels,selector)
   scopes[scope]={'detection':det,'ranking':ranking(sub,labels,protocol['ranking_k'])}
  metrics['arms'][arm]={'scopes':scopes}
 outid='b39b7_eval_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+os.urandom(4).hex();outdir=work/'batch39b7_holdout_eval'/outid;outdir.mkdir(parents=True,exist_ok=False)
 public_lock={k:v for k,v in lock.items() if k!='reviewer'}
 result={'status':'B39B7_PRE_PREDICTION_HOLDOUT_METRICS_COMPUTED','blockers':0,'holdout_lock_sha256':lock_sha,'backend_result_sha256':sha(rz),
  'backend_run_id':runid,'input_sha256':input_sha,'units':24,'truth_counts':lock['truth_counts'],'exports_verified':len(verified),
  'new_gpu_inference_by_evaluator':False,'new_codeql_by_evaluator':False,'independent_human_gold':False,'pre_prediction_locked':True}
 writej(outdir/'00_RESULT.json',result);writej(outdir/'EVAL_PROTOCOL.json',protocol);writej(outdir/'METRICS.json',metrics);writej(outdir/'EVALUATION_VECTORS.json',vectors);writej(outdir/'HOLDOUT_LOCK_PUBLIC.json',public_lock)
 writej(outdir/'BACKEND_LINK.json',{'result_zip':str(rz),'result_sha256':sha(rz),'run_id':runid,'private_exports_verified':verified})
 files=[p for p in sorted(outdir.iterdir()) if p.is_file()]; sums=''.join(sha(p)+'  '+p.name+'\n' for p in files);(outdir/'SHA256SUMS').write_text(sums)
 outzip=down/(outid+'_result.zip')
 with zipfile.ZipFile(outzip,'w',compression=zipfile.ZIP_DEFLATED) as z:
  for pth in sorted(outdir.iterdir()):
   if pth.is_file():z.write(pth,pth.name)
 outsha=sha(outzip);(down/(outzip.name+'.sha256')).write_text(outsha+'  '+outzip.name+'\n')
 print('\n===== B39B.7 HOLDOUT EVALUATION RESULT =====')
 print('STATUS='+result['status']);print('BLOCKERS=0');print('PRE_PREDICTION_LOCKED=True');print('INDEPENDENT_HUMAN_GOLD=False')
 print('UNITS=24');print('TRUTH_COUNTS='+json.dumps(lock['truth_counts'],sort_keys=True,separators=(',',':')))
 print('BACKEND_RUN_ID='+runid);print('ORIGINAL_EXPORTS_VERIFIED=8');print('OUTPUT_ZIP='+str(outzip));print('OUTPUT_SHA256='+outsha)
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:
  print('STATUS=B39B7_EVALUATION_BLOCKED');print('BLOCKER='+str(e));raise
