#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys, uuid, zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

CONFIRM='DONG_Y_KHOA_HOLDOUT_TRUOC_DU_DOAN'

def canonical(x):
    return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def digest(x): return hashlib.sha256(canonical(x).encode()).hexdigest()
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def write_json(path,obj):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.tmp.'+str(os.getpid()))
    tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    os.replace(tmp,path)
def safe_zip(zpath):
    with zipfile.ZipFile(zpath) as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise SystemExit('BLOCKED:DUPLICATE_ZIP_MEMBER')
        for n in names:
            p=PurePosixPath(n)
            if p.is_absolute() or '..' in p.parts:raise SystemExit('BLOCKED:UNSAFE_ZIP_MEMBER:'+n)
        bad=z.testzip()
        if bad:raise SystemExit('BLOCKED:ZIP_CRC:'+bad)
        return {n:z.read(n) for n in names if not n.endswith('/')}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--work',type=Path,required=True)
    p.add_argument('--downloads',type=Path,required=True)
    p.add_argument('--reviewer',required=True)
    p.add_argument('--package-root',type=Path,required=True)
    a=p.parse_args()
    root=a.package_root.resolve(); work=a.work.expanduser().resolve(); down=a.downloads.resolve()
    if not work.is_dir() or not down.is_dir():raise SystemExit('BLOCKED:WORK_OR_DOWNLOADS_MISSING')
    if not a.reviewer.strip():raise SystemExit('BLOCKED:REVIEWER_EMPTY')
    pins=json.loads((root/'PINS.json').read_text())
    proposals=json.loads((root/'HOLDOUT_PROPOSALS.json').read_text())
    sample=root/'samples/B39B7_HOLDOUT_JDK.zip'
    if sha(sample)!=pins['holdout_zip_sha256']:raise SystemExit('BLOCKED:HOLDOUT_ZIP_SHA')
    members=safe_zip(sample)
    java={k:v for k,v in members.items() if k.endswith('.java')}
    if len(java)!=24:raise SystemExit('BLOCKED:HOLDOUT_FILE_COUNT')
    by_uri={x['uri']:x for x in proposals}
    if set(by_uri)!=set(java):raise SystemExit('BLOCKED:PROPOSAL_URI_SET')
    for uri,raw in java.items():
        if hashlib.sha256(raw).hexdigest()!=by_uri[uri]['source_sha256']:raise SystemExit('BLOCKED:SOURCE_SHA:'+uri)
    counts=Counter(x['truth'] for x in proposals)
    if counts!=Counter({'POSITIVE':12,'NEGATIVE':12}):raise SystemExit('BLOCKED:TRUTH_BALANCE')
    print('===== B39B7 HOLDOUT PREVIEW =====')
    print('Scope: 24 JDK-only Java testcases, 6 per CWE, balanced 12 POSITIVE / 12 NEGATIVE.')
    print('Labels are AI-assisted and operator-approved, locked BEFORE predictions.')
    print('This is NOT independent human gold and was authored after prior system behavior was observed.')
    for cwe in ('22','78','79','89'):
        xs=[x for x in proposals if x['cwe']==cwe]
        print('CWE-'+cwe+': '+', '.join(PurePosixPath(x['uri']).name+'='+x['truth'] for x in xs))
    print('PROJECT_ZIP_SHA256='+pins['holdout_zip_sha256'])
    print('PROPOSAL_SHA256='+digest(proposals))
    print('Review full rationales in HOLDOUT_PROPOSALS.json before approval if desired.')
    ans=input('Type '+CONFIRM+' to lock all labels before prediction, otherwise cancel: ').strip()
    if ans!=CONFIRM:
        print('STATUS=B39B7_HOLDOUT_NOT_LOCKED')
        return 3
    now=datetime.now(timezone.utc); rid='b39b7_holdout_'+now.strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    ws=work/'batch39b7_holdout'/rid; ws.mkdir(parents=True,exist_ok=False)
    private=ws/'private'; private.mkdir()
    local_zip=private/'B39B7_HOLDOUT_JDK.zip'; shutil.copy2(sample,local_zip)
    input_sha=sha(local_zip)
    units=[]
    for x in proposals:
        u={k:x[k] for k in ('uri','cwe','truth','source_sha256','source_line_count','evidence_lines','rationale','assumptions')}
        u.update(input_sha256=input_sha, unit_id=digest({'input_sha256':input_sha,'uri':x['uri'],'cwe':x['cwe']}),
                 reviewer=a.reviewer.strip(), review_mode='AI_ASSISTED_OPERATOR_APPROVED_PRE_PREDICTION',
                 independent_human_gold=False, predictions_exposed_before_lock=False)
        units.append(u)
    lock={
      'schema':'NTK_B39B7_PRE_PREDICTION_HOLDOUT_LOCK_V1','locked_at':now.isoformat().replace('+00:00','Z'),
      'scope':'PRE_PREDICTION_LOCKED_SYNTHETIC_HOLDOUT_NOT_INDEPENDENT_HUMAN_GOLD',
      'reviewer':a.reviewer.strip(),'review_mode':'AI_ASSISTED_OPERATOR_APPROVED_PRE_PREDICTION',
      'independent_human_gold':False,'predictions_exposed_before_lock':False,'quality_threshold_tuning_permitted':False,
      'project_zip_sha256':input_sha,'units':sorted(units,key=lambda x:x['unit_id']),
      'truth_counts':dict(sorted(Counter(x['truth'] for x in units).items())),
      'proposal_sha256':digest(proposals),'package_holdout_sha256':pins['holdout_zip_sha256']}
    write_json(ws/'HOLDOUT_LOCK.json',lock)
    lock_sha=sha(ws/'HOLDOUT_LOCK.json')
    (ws/'HOLDOUT_LOCK.json.sha256').write_text(lock_sha+'  HOLDOUT_LOCK.json\n')
    outzip=down/(rid+'.zip'); shutil.copy2(local_zip,outzip)
    out_sha=sha(outzip); (down/(outzip.name+'.sha256')).write_text(out_sha+'  '+outzip.name+'\n')
    pointer=work/'NTK_B39B7_HOLDOUT_WORKSPACE.txt'; pointer.write_text(str(ws)+'\n')
    write_json(ws/'PRE_PREDICTION_LOCK_PROOF.json',{
      'status':'B39B7_HOLDOUT_LOCKED_BEFORE_PREDICTION','workspace':str(ws),'lock_sha256':lock_sha,
      'project_zip':str(outzip),'project_zip_sha256':out_sha,'predictions_executed':False,'new_gpu_inference':False,
      'new_codeql_database':False,'independent_human_gold':False})
    print('\n===== B39B.7 PRE-PREDICTION LOCK RESULT =====')
    print('STATUS=B39B7_HOLDOUT_LOCKED_BEFORE_PREDICTION')
    print('UNITS=24')
    print('TRUTH_COUNTS='+json.dumps(lock['truth_counts'],sort_keys=True,separators=(',',':')))
    print('HOLDOUT_LOCK_SHA256='+lock_sha)
    print('PROJECT_ZIP='+str(outzip))
    print('PROJECT_SHA256='+out_sha)
    print('WORKSPACE='+str(ws))
    print('PREDICTIONS_EXECUTED=False')
    print('INDEPENDENT_HUMAN_GOLD=False')
    return 0
if __name__=='__main__': raise SystemExit(main())
