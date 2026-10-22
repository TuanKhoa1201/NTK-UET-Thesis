#!/usr/bin/env python3
"""NTK full-project Phase5: verified reuse, honest conservative evidence fusion.

No CodeQL/Java/OpenGrep/GPU execution; never modifies frozen inputs.
CodeQL path evidence is independent; a nearby LoRA label is not a path proof.
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
import sys
import uuid
from urllib.parse import unquote, urlsplit

P2_ID='fullproj_20261021T105909Z_94f48df6'
P2_SHA='ddccc3558d3584b4405f71f861060ed9fe9c8bde2e577fda147e81b1afe81cf4'
P3_ID='fullproj3_20261021T111518Z_1d5bdb66'
P3_SHA='c34b4a6d2d2ff8b2a44c5094fa6bf277cdccb267f4292ed0e6499be744cfc29d'
P31_ID='fullproj31_20261021T114118Z_3502ed0e'
P31_SHA='444482111e5b228385027dfe7923b257943a7af8583131b5364069638e230fdf'
P4_ID='fullproj4_20261021T164458Z_8d498c38'
P4_SHA='965210997af2a2eab3adb54480c90bddc7674ad8ac4df5118f1bbc27ab289f17'
SCORER_SHA='c1b9cbf071739ca6d96062032867835dbf4db185f4e0ac1e2d609bd319e0de7e'
PROJECTS=('spark_CVE-2016-9177_vuln','webgoat_sql_CVE-2026-0006_1.0')
EXPECTED={PROJECTS[0]:{'opengrep':1,'codeql':17},PROJECTS[1]:{'opengrep':18,'codeql':57}}
IDENTITY=('package','class','method','signature')
ROLES={'source','sink','none','taint-propagator','ABSTAIN'}
HEX=re.compile(r'^[0-9a-f]{64}$')
CWE_PATTERN=re.compile(r'(?i)\bcwe[-_/ ]?0*(\d{1,5})\b')

class FusionError(RuntimeError):pass

def need(test,reason):
    if not test: raise FusionError(reason)

def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
def digest(v):return sha_bytes(canonical(v).encode())

def checked_json(path,expected=None,size=160*1024**2):
    path=Path(path)
    need(path.is_file() and not path.is_symlink(),'REQUIRED_FILE_MISSING_OR_SYMLINK:'+path.name)
    need(path.stat().st_size<=size,'INPUT_TOO_LARGE:'+path.name)
    if expected:need(sha(path)==expected,'INPUT_HASH_MISMATCH:'+path.name)
    return json.loads(path.read_text(encoding='utf-8'))

def verify_manifest(root,name,expected):
    root=Path(root)
    need(root.is_dir() and not root.is_symlink(),'RUN_DIRECTORY_MISSING_OR_SYMLINK:'+str(root))
    lines=(root/'SHA256SUMS').read_text(encoding='ascii').splitlines()
    rec=[x for x in lines if re.fullmatch(r'[0-9a-f]{64}  '+re.escape(name),x)]
    need(len(rec)==1 and rec[0].split('  ')[0]==expected,'MANIFEST_MISMATCH:'+name)
    return checked_json(root/name,expected)

def source_inventory(root):
    skip={'.git','target','build','.gradle','.idea','node_modules','.venv','__pycache__','out'}
    need(root.is_dir() and not root.is_symlink(),'SOURCE_TREE_NOT_FOUND')
    java=[]
    for base,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in skip and not (Path(base)/d).is_symlink())
        java.extend(Path(base)/f for f in files if f.endswith('.java') and
                    not (Path(base)/f).is_symlink() and (Path(base)/f).is_file())
    java.sort(key=lambda x:x.relative_to(root).as_posix())
    h=hashlib.sha256()
    for file in java:
        name=file.relative_to(root).as_posix().encode('utf-8')
        h.update(len(name).to_bytes(4,'big'))
        h.update(name)
        h.update(bytes.fromhex(sha(file)))
    return {'files':len(java),'source_hash':h.hexdigest()}

def api_key(c):return digest([str(c['cwe']),[c[k] for k in IDENTITY]])

def model_evidence(p4,root):
    n=p4['native']
    need(p4['status']=='PHASE4_NATIVE_LORA_E1_COMPLETE' and
         n['status']=='NATIVE_STAGE3_EPOCH1_COMPLETED' and
         n['model_arm']=='epoch_1' and
         n.get('new_training') is False and p4.get('security_suite_rerun') is False,
         'PHASE4_NATIVE_MODEL_STATUS_INVALID')
    audit=checked_json(root/'NATIVE_EPOCH1_AUDIT.json',n['native_audit_sha256'])
    details=audit.get('details')
    need(isinstance(details,list) and len(details)==n['new_native_requests'], 'NATIVE_AUDIT_COUNT_MISMATCH')
    found={}
    for item in details:
        key=item['case_key']
        need(key not in found,'MODEL_CASE_KEY_DUPLICATE')
        need(item['status'] in ('ACCEPTED','ABSTAIN') and item['role'] in ROLES,
             'MODEL_STRICT_ROLE_SCHEMA')
        need((item['role']=='ABSTAIN')==(item['status']=='ABSTAIN'),'MODEL_ROLE_ABSTAIN_MISMATCH')
        found[key]=item
    out={};linked=[]
    for project in PROJECTS:
        p=root/project/'COMPILER_IDENTITIES.json'
        if p.is_file():
            rows=checked_json(p)
            need(isinstance(rows,list),'COMPILER_IDENTITIES_SCHEMA')
            for row in rows:
                c=row['candidate'];origin=row['origin'];key=api_key(c)
                need(key in found,'COMPILER_IDENTITY_NOT_IN_NATIVE_TRACE')
                need(c['cwe'] in ('22','78','89'),'MODEL_XSS_OR_UNKNOWN_CWE_FORBIDDEN')
                need(origin['line']>0 and origin['column']>0,'BAD_COMPILER_LOCATION')
                linked.append({'project':project,'case_key':key,
                               'identity':{k:c[k] for k in (*IDENTITY,'cwe')},
                               'origin':{'uri':origin['uri'],'line':origin['line'],
                                         'column':origin['column'],'rank_reason':origin['rank_reason']},
                               'role':found[key]['role'],'status':found[key]['status'],
                               'reason':found[key]['reason'],
                               'llm_evidence_origin':'LOCAL_NATIVE_IRIS_STAGE3_LORA_EPOCH1',
                               'candidate_is_not_a_vulnerability':True})
        else:
            need(p4['projects'][project]['identity_enrichment']['status']=='NO_MODELED_API_CANDIDATES',
                 'MISSING_COMPILER_IDENTITIES:'+project)
    need(len({r['case_key'] for r in linked})==len(found),'NATIVE_IDENTITY_COVERAGE_MISMATCH')
    # Duplicate model identity may occur in multiple projects; case key can repeat in linked records.
    need(set(r['case_key'] for r in linked)==set(found),'MODEL_IDENTITY_SET_MISMATCH')
    for row in linked:out.setdefault(row['project'],[]).append(row)
    return out,audit,linked

def cwes_from(v):
    if isinstance(v,str):return [f'CWE-{int(m)}' for m in CWE_PATTERN.findall(v)]
    if isinstance(v,(list,tuple)):
        result=[]
        for x in v:result.extend(cwes_from(x))
        return sorted(set(result),key=lambda s:int(s[4:]))
    return []

def choose_cwe(tags):
    return next((x for x in ('CWE-22','CWE-78','CWE-79','CWE-89') if x in tags),tags[0] if tags else None)

def normal_uri(uri,source_root):
    if not isinstance(uri,str) or not uri:return None
    raw=uri.replace('\\','/')
    if raw.startswith('file:'):
        s=urlsplit(raw)
        if s.scheme!='file' or s.netloc not in ('','localhost'):return None
        raw=unquote(s.path)
    else:
        s=urlsplit(raw)
        if s.scheme:return None
        raw=unquote(s.path)
    root=Path(source_root).resolve()
    p=Path(raw)
    if p.is_absolute():
        try:relative=p.resolve(strict=False).relative_to(root)
        except ValueError:return None
    else:
        relative=PurePosixPath(raw)
        if '..' in relative.parts or ':' in raw or relative.is_absolute():return None
        # Drop harmless leading './' without resolving outside the source root.
    parts=tuple(relative.parts)
    if not parts or '..' in parts:return None
    return PurePosixPath(*parts).as_posix()

def physical_loc(loc,source_root):
    p=loc.get('physicalLocation',loc)
    if not isinstance(p,dict):return None
    uri=normal_uri((p.get('artifactLocation') or {}).get('uri'),source_root)
    reg=p.get('region') or {}
    ln=reg.get('startLine');col=reg.get('startColumn')
    if uri is None or type(ln) is not int or ln<1:return None
    if col is not None and (type(col) is not int or col<1):return None
    return {'uri':uri,'line':ln,'column':col}

def codeql_flows(item,source_root):
    valid=[]
    for flow in item.get('codeFlows',[]):
        for tf in flow.get('threadFlows',[]):
            pts=[]
            for step in tf.get('locations',[]):
                loc=physical_loc(step.get('location',{}),source_root)
                if loc is not None:pts.append(loc)
            if len(pts)>=2:
                valid.append(pts)
    valid.sort(key=lambda x:-len(x))
    return valid

def exact_model_annotation(project,cwe,loc,proven,*,terminal=False):
    # Exact compiler callsite position plus correct CWE. Not proof of tainted argument.
    if loc is None or loc.get('column') is None:return None
    hits=[x for x in proven.get(project,[]) if 'CWE-'+x['identity']['cwe']==cwe and
          x['origin']['uri']==loc['uri'] and x['origin']['line']==loc['line'] and
          x['origin']['column']==loc['column']]
    if len(hits)!=1:return None
    x=hits[0]
    return {'case_key':x['case_key'],'status':x['status'],'role':x['role'],
            'origin':'LOCAL_NATIVE_IRIS_STAGE3_LORA_EPOCH1',
            'join_basis':'EXACT_CWE_SOURCE_FILE_LINE_COLUMN_AND_COMPILER_IDENTITY',
            'codeql_path_terminal':terminal,
            'sink_argument_and_path_binding':'NOT_PROVEN',
            'model_qualified_vulnerability':False}

def score_inputs_for_opengrep(item,source_root,project,i,models):
    extra=item.get('extra') or {};meta=extra.get('metadata') or {}
    tags=cwes_from(meta.get('cwe',[]))
    loc=physical_loc({'physicalLocation':{'artifactLocation':{'uri':item.get('path')},
         'region':{'startLine':(item.get('start') or {}).get('line',0),
                   'startColumn':(item.get('start') or {}).get('col')}}},source_root)
    cwe=choose_cwe(tags)
    annotation=exact_model_annotation(project,cwe,loc,models) if cwe else None
    return {'id':digest(['OPENGREP',project,i,item.get('check_id')]),'origin':'OPENGREP','project':project,
            'rule_id':str(item.get('check_id','UNKNOWN')),'cwe':cwe,'cwe_all':tags,
            'severity':str(extra.get('severity','UNKNOWN')).upper(),
            'message':str(extra.get('message','OpenGrep finding'))[:2000],
            'location':loc,'metadata':{'cwe':[cwe] if cwe else [],'confidence':meta.get('confidence','UNKNOWN')},
            'dataflow':[], 'model_annotation':annotation,
            'raw_source_index':i,'model_qualified_vulnerability':False,
            'codeql_cross_tool_join':'NOT_PROVEN', 'retained':True, 'vulnerability_confirmed':False}

def score_inputs_for_codeql(item,rule,source_root,project,i,models):
    rprops=rule.get('properties') or {};tags=cwes_from(rprops.get('tags',[]))
    tags=sorted(set(tags+cwes_from(item.get('ruleId',''))),key=lambda s:int(s[4:]))
    cwe=choose_cwe(tags)
    originloc=physical_loc(((item.get('locations') or [{}])[0]),source_root)
    flows=codeql_flows(item,source_root)
    terminal=flows[0][-1] if flows else None
    annotation=exact_model_annotation(project,cwe,terminal,models,terminal=True) if cwe and flows else None
    dataflow=[]
    if flows:
        chosen=flows[0]
        dataflow=[dict(type='source' if j==0 else 'sink' if j==len(chosen)-1 else 'intermediate',
                       **pos) for j,pos in enumerate(chosen)]
    level=str(item.get('level',rule.get('defaultConfiguration',{}).get('level','warning'))).lower()
    sev={'error':'ERROR','warning':'WARNING','note':'INFO','none':'UNKNOWN'}.get(level,'UNKNOWN')
    prec=rprops.get('precision','UNKNOWN')
    msg=item.get('message') or {}
    return {'id':digest(['CODEQL',project,i,item.get('ruleId')]),'origin':'CODEQL_SECURITY_EXTENDED',
            'project':project,'rule_id':str(item.get('ruleId','UNKNOWN')),
            'cwe':cwe,'cwe_all':tags,'severity':sev,
            'message':str(msg.get('text','CodeQL Security Extended finding'))[:2000],
            'location':originloc,'metadata':{'cwe':[cwe] if cwe else [],'confidence':prec},
            'dataflow':dataflow,'codeql_codeflows_present':bool(item.get('codeFlows')),
            'codeql_trace_locations_verified':bool(flows),
            'codeql_path_count':len(flows),'model_annotation':annotation,
            'model_qualified_vulnerability':False,'sink_argument_and_model_flow_join':'NOT_PROVEN',
            'raw_source_index':i,'retained':True,'vulnerability_confirmed':False}

def score_record(rec,scorer):
    # Model annotation is auxiliary unless exact *sink argument* join is proven.
    # Phase 4 has no proof of SARIF terminal to the same compiler argument.
    # Keep V2.2 AI neutral, document why; never claim that this is a full model-qualified path.
    from dataclasses import asdict
    rec['score']=asdict(scorer.score_finding(rec))
    need(rec['score']['ai_confidence_score']==0.5 and rec['score']['penalty_factor']==1.0,
         'MODEL_NOT_NEUTRAL_WHEN_ARGUMENT_UNPROVEN')
    rec['scoring_policy']='FROZEN_V2_2_NEUTRAL_AI_UNTIL_EXACT_ARGUMENT_PROOF'
    return rec

def load_scorer(path,expected=SCORER_SHA):
    path=Path(path)
    need(path.is_file() and not path.is_symlink(),'FROZEN_SCORER_NOT_FOUND')
    need(sha(path)==expected,'FROZEN_SCORER_SHA256_MISMATCH')
    name='ntk_frozen_sast_v22_scoring'
    spec=importlib.util.spec_from_file_location(name,str(path))
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module.SASTScoringEngine()

def make_sarif(rows,project):
    groups=[]
    for origin in ('OPENGREP','CODEQL_SECURITY_EXTENDED'):
        own=[r for r in rows if r['origin']==origin]
        rules={r['rule_id'] for r in own}
        sr=[]
        for x in own:
            loc=x['location']; locations=[]
            if loc:
                region={'startLine':loc['line']}
                if loc['column'] is not None:region['startColumn']=loc['column']
                locations=[{'physicalLocation':{'artifactLocation':{'uri':loc['uri']},'region':region}}]
            p={'project':project,'origin':origin,'cwe':x['cwe'],'all_cwes':x['cwe_all'],
               'evidence_status':'CODEQL_PATH' if x['dataflow'] else 'REVIEW_ONLY',
               'sast_priority_score':x['score']['final_score'],
               'sast_risk_level':x['score']['risk_level'],
               'model_annotation':x['model_annotation'],
               'model_qualified_vulnerability':False,'vulnerability_confirmed':False}
            e={'ruleId':x['rule_id'],'level':{'ERROR':'error','WARNING':'warning','INFO':'note'}.get(x['severity'],'warning'),
               'message':{'text':x['message']},'locations':locations,'properties':p}
            if x['dataflow']:
                trace=[]
                for pos in x['dataflow']:
                    rg={'startLine':pos['line']}
                    if pos['column'] is not None:rg['startColumn']=pos['column']
                    trace.append({'location':{'physicalLocation':{'artifactLocation':{'uri':pos['uri']},'region':rg}}})
                e['codeFlows']=[{'threadFlows':[{'locations':trace}]}]
            sr.append(e)
        groups.append({'tool':{'driver':{'name':'NTK FullProject Phase5 '+origin,
                           'rules':[{'id':rule} for rule in sorted(rules)]}},
                       'results':sr,'properties':{'project':project,'original_engine':origin,
                       'new_scan_executed':False,'model_role_annotation_not_sufficient_to_confirm_vulnerability':True}})
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':groups}

def write_new_json(path,data):
    with path.open('x',encoding='utf-8') as f:
        json.dump(data,f,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)
        f.write('\n')
    path.chmod(0o600)

def write_report(p2dir,p3dir,p31dir,p4dir,outbase,root,*,dry=False,scorer=None):
    p2=verify_manifest(p2dir,'FULLPROJECT_PHASE2_RESULT.json',P2_SHA)
    p3=verify_manifest(p3dir,'FULLPROJECT_PHASE3_RESULT.json',P3_SHA)
    p31=verify_manifest(p31dir,'FULLPROJECT_PHASE31_RESULT.json',P31_SHA)
    p4=verify_manifest(p4dir,'FULLPROJECT_PHASE4_RESULT.json',P4_SHA)
    need(p31['security_extended_reused_without_execution'] is True and
         p31['model_stage3_executed'] is False,'PHASE31_REUSE_CONTRACT')
    need(p4['phase31_sha256']==P31_SHA,'PHASE4_PHASE31_LINK_MISMATCH')
    models,audit,all_annotations=model_evidence(p4,p4dir)
    project2={x['project']:x for x in p2['project_rows']}
    project3={x['project']:x for x in p3['project_rows']}
    need(all(p in project2 and p in project3 and p in p4['projects'] for p in PROJECTS),'PROJECT_SET_MISSING')
    inputs={}; totals={'opengrep':0,'codeql':0,'codeql_codeflows_present':0,
            'codeql_path_locations_parsed':0,'model_accepted':0,'model_abstain':0}
    for project in PROJECTS:
        p2row=project2[project];p3row=project3[project]
        need(p2row['source_unchanged'] is True and p2row['opengrep']['status']=='COMPLETE',
             'PHASE2_INCOMPLETE:'+project)
        need(p3row['codeql_security']['status']=='COMPLETE' and p3row['source_java_unchanged'] is True,
             'PHASE3_INCOMPLETE:'+project)
        need(p4['projects'][project]['source_and_db_metadata_unchanged'] is True,
             'PHASE4_INPUTS_MUTATED:'+project)
        need(p2row['source']['source_hash']==p3row['source_hash_sha256'] and
             p2row['source']['files']==p3row['source_java_count'],
             'PHASE2_PHASE3_SOURCE_HASH_MISMATCH')
        source=root/'data/project-sources'/project
        need(source_inventory(source)=={'source_hash':p2row['source']['source_hash'],
             'files':p2row['source']['files']},'SOURCE_CHANGED_SINCE_SECURITY_SCAN:'+project)
        opath=p2dir/project/'opengrep_fullproject.json'
        og=checked_json(opath,p2row['opengrep']['json_sha256'])
        need(isinstance(og['results'],list) and len(og['results'])==EXPECTED[project]['opengrep'],
             'OPENGREP_COUNT_PARITY:'+project)
        spath=p3dir/project/'CODEQL_SECURITY_EXTENDED.sarif'
        sj=checked_json(spath,p3row['codeql_security']['sarif_sha256'])
        need(sj['version']=='2.1.0','CODEQL_SARIF_VERSION')
        count=sum(len(run.get('results',[])) for run in sj.get('runs',[]))
        need(count==EXPECTED[project]['codeql'],'CODEQL_FINDING_COUNT_PARITY:'+project)
        codeql_paths_in_sarif=sum(bool(item.get('codeFlows')) for run in sj['runs']
                                  for item in run.get('results',[]))
        need(codeql_paths_in_sarif==p3row['codeql_security']['results_with_codeflows'],
             'CODEQL_CODEFLOW_COUNT_DRIFT:'+project)
        needs=[]
        for i,raw in enumerate(og['results']):
            needs.append(score_inputs_for_opengrep(raw,source,project,i,models))
        idx=0
        for run in sj['runs']:
            rules={x['id']:x for x in (run.get('tool') or {}).get('driver',{}).get('rules',[])}
            for item in run.get('results',[]):
                needs.append(score_inputs_for_codeql(item,rules.get(item.get('ruleId'),{}),source,project,idx,models))
                idx+=1
        inputs[project]=needs
        totals['opengrep']+=len(og['results']);totals['codeql']+=count
        totals['codeql_codeflows_present']+=codeql_paths_in_sarif
        totals['codeql_path_locations_parsed']+=sum(
            f['codeql_trace_locations_verified'] for f in needs if f['origin']=='CODEQL_SECURITY_EXTENDED')
    totals['model_accepted']=sum(x['status']=='ACCEPTED' for x in all_annotations)
    totals['model_abstain']=sum(x['status']=='ABSTAIN' for x in all_annotations)
    need(totals['opengrep']==sum(v['opengrep'] for v in EXPECTED.values()) and
         totals['codeql']==sum(v['codeql'] for v in EXPECTED.values()),
         'INPUT_TOTAL_COUNTS_NOT_HISTORICAL')
    if dry:
        return {'status':'VERIFIED_INPUTS_READY_FOR_SCORING','totals':totals,'model_cases':len(all_annotations)}
    need(scorer is not None,'VERIFIED_FROZEN_SCORER_REQUIRED')
    outbase=Path(outbase).expanduser().resolve(strict=False)
    need(not outbase.is_relative_to(root.resolve()) and not outbase.is_relative_to(p4dir.resolve()),
         'FUSION_OUTPUT_INSIDE_FROZEN_INPUT')
    outbase.mkdir(parents=True,exist_ok=True,mode=0o700)
    run=outbase/('fullproj5_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    run.mkdir(mode=0o700)
    all_sums=[];manifest={'status':'PHASE5_CONSERVATIVE_EVIDENCE_FUSION_COMPLETE',
       'input_runs':{'phase2':str(p2dir),'phase3':str(p3dir),'phase31':str(p31dir),'phase4':str(p4dir)},
       'input_result_sha256':{'phase2':P2_SHA,'phase3':P3_SHA,'phase31':P31_SHA,'phase4':P4_SHA},
       'scorer_sha256':SCORER_SHA,'model_role_linking':'EXACT_CWE_COMPILER_CALLSITE_POSITION_ONLY',
       'model_qualified_dataflow_paths':0,'vulnerabilities_confirmed':0,
       'priority_is_not_probability_or_cvss':True,'ground_truth_validation':False,
       'cold_full_project_scan_this_step':False,'open_grep_codeql_gpu_executed_this_step':False,
       'website_8770_integration':'NOT_YET', 'project_rows':[]}
    for project,records in inputs.items():
        rows=[score_record(r,scorer) for r in records]
        rows.sort(key=lambda r:(-r['score']['final_score'],r['origin'],r['id']))
        obj={'project':project,'status':'PHASE5_STATIC_FINDINGS_SCORED_MODEL_API_SIDECARE_ONLY',
             'findings':rows,'model_api_annotations':models.get(project,[]),
             'source_results':{'opengrep_reused':EXPECTED[project]['opengrep'],
                               'codeql_reused':EXPECTED[project]['codeql']},
             'vulnerability_confirmed':False,
             'score_semantics':'REVIEW_PRIORITY_NOT_PROBABILITY',
             'model_qualified_dataflow_paths':0}
        folder=run/project;folder.mkdir(mode=0o700)
        result_path=folder/'result.json';sarif_path=folder/'report.sarif'
        write_new_json(result_path,obj)
        write_new_json(sarif_path,make_sarif(rows,project))
        need(sum(len(r['results']) for r in checked_json(sarif_path)['runs'])==len(rows),
             'PHASE5_JSON_SARIF_COUNT_MISMATCH')
        for file in (result_path,sarif_path):all_sums.append((str(file.relative_to(run)),sha(file)))
        per={'project':project,'opengrep_findings':EXPECTED[project]['opengrep'],
             'codeql_findings':EXPECTED[project]['codeql'],'total_engine_findings':len(rows),
             'codeql_codeflows_present':sum(x.get('codeql_codeflows_present',False) for x in rows if x['origin']=='CODEQL_SECURITY_EXTENDED'),
             'codeql_verified_trace_locations':sum(x['codeql_trace_locations_verified'] for x in rows if x['origin']=='CODEQL_SECURITY_EXTENDED'),
             'model_api_annotations':len(models.get(project,[])),
             'exact_location_links':sum(bool(x.get('model_annotation')) for x in rows),
             'model_qualified_dataflow_paths':0,'scoring':'FROZEN_V2_2_REVIEW_PRIORITY'}
        manifest['project_rows'].append(per)
        print('PROJECT='+project,flush=True)
        print('  OPENGREP='+str(per['opengrep_findings'])+' CODEQL='+str(per['codeql_findings'])+
              ' MODEL_API='+str(per['model_api_annotations']),flush=True)
        print('  CODEQL_CODEFLOWS_PRESENT='+str(per['codeql_codeflows_present'])+
              ' PARSED_TRACE_LOCATIONS='+str(per['codeql_verified_trace_locations'])+
              ' EXACT_API_ENDPOINT_LINKS='+str(per['exact_location_links'])+' QUALIFIED_MODEL_PATHS=0',flush=True)
        # Echo labels below only when useful to compare with the frozen historical run.
        # Original one-line print replaced by the block above.
    write_new_json(run/'FULLPROJECT_PHASE5_RESULT.json',manifest)
    all_sums.append(('FULLPROJECT_PHASE5_RESULT.json',sha(run/'FULLPROJECT_PHASE5_RESULT.json')))
    (run/'SHA256SUMS').write_text(''.join(f'{h}  {name}\n' for name,h in sorted(all_sums)),encoding='ascii')
    print('===== PHASE5 SUMMARY =====',flush=True)
    print('PHASE5_RUN_DIR='+str(run),flush=True)
    print('STATUS='+manifest['status'],flush=True)
    print('OPENGREP_REUSED='+str(totals['opengrep'])+' CODEQL_REUSED='+str(totals['codeql']),flush=True)
    print('NATIVE_MODEL_ANNOTATIONS='+str(len(all_annotations))+' ACCEPTED='+str(totals['model_accepted'])+
          ' ABSTAIN='+str(totals['model_abstain']),flush=True)
    print('SCORER=FROZEN_SAST_V2_2',flush=True)
    print('FRESH_SCANS_OR_INFERENCE=NO',flush=True)
    print('FULL_PROJECT_WEB_SCAN_READY=NO',flush=True)
    return {'run_dir':str(run),'status':manifest['status'],'totals':totals}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    home=Path.home()
    parser.add_argument('--root',type=Path,default=home/'iris')
    parser.add_argument('--phase2',type=Path,default=home/'migration/ntk_fullproject_phase2_runs'/P2_ID)
    parser.add_argument('--phase3',type=Path,default=home/'migration/ntk_fullproject_phase3_runs'/P3_ID)
    parser.add_argument('--phase31',type=Path,default=home/'migration/ntk_fullproject_phase31_runs'/P31_ID)
    parser.add_argument('--phase4',type=Path,default=home/'migration/ntk_fullproject_phase4_runs'/P4_ID)
    parser.add_argument('--output-base',type=Path,default=home/'migration/ntk_fullproject_phase5_runs')
    parser.add_argument('--verify-only',action='store_true')
    a=parser.parse_args(argv)
    kw={'p2dir':a.phase2.resolve(strict=True),'p3dir':a.phase3.resolve(strict=True),
        'p31dir':a.phase31.resolve(strict=True),'p4dir':a.phase4.resolve(strict=True),
        'outbase':a.output_base,'root':a.root.resolve(strict=True)}
    p4=verify_manifest(kw['p4dir'],'FULLPROJECT_PHASE4_RESULT.json',P4_SHA)
    scorefile=kw['p4dir']/'private_native/snapshot/simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py'
    if a.verify_only:
        print(write_report(**kw,dry=True))
    else:
        scorer=load_scorer(scorefile)
        write_report(**kw,scorer=scorer)
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (FusionError,KeyError,ValueError,TypeError,FileNotFoundError,PermissionError) as e:
        print('PHASE5_BLOCKER='+type(e).__name__+':'+str(e)[:700],file=sys.stderr)
        sys.exit(2)
