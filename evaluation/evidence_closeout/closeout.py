#!/usr/bin/env python3
"""NTK B39B.8: offline, fail-closed evidence reconciliation and scope-qualified closeout.

This tool does not run models, scanners, Java code, Git operations, or modify
production artifacts. Metadata-only mode is exclusively an authoring dry-run.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ARMS = ("opengrep_only", "base", "epoch_1", "epoch_2")
CWES = ("22", "78", "79", "89")
KEYS = ("tp", "fp", "fn", "tn")
K_VALUES = (1, 3, 5, 10)
EVAL_SHA = "8d95a918da2f4601415a12eba0ea9dc7e93a28c8e4a107a53e2ed4ec01dbc0fd"
BACKEND_SHA = "560020e7a5d78e0b2b8500652eaf951e835b758fdcd3c596374c72a2a2e59bf2"
SOURCE_SHA = "6e968d05c11073a71a218950c80250ad10ed59a97d8ac04faa354746a489c15a"
LOCK_SHA = "5bccf51fcc98611abde6c01049816a9d02681b89d52f1befacced6a51387597d"
RUN_ID = "b39b4_20261020T100814Z_63d29938"
FROZEN_GIT = "9f8f1a7977423edabc262a06b39ce39965f58df8"
FROZEN_IRIS = "51c2aafaf2746a6246ab057752791cc397c272d4"
FROZEN_SCORER_SHA = "c1b9cbf071739ca6d96062032867835dbf4db185f4e0ac1e2d609bd319e0de7e"
EVAL_STATUS = "B39B7_PRE_PREDICTION_HOLDOUT_METRICS_COMPUTED"
BACKEND_STATUS = "B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE"
FINAL_STATUS = "B39B8_TECHNICAL_EVIDENCE_CLOSED_WITH_DECLARED_LIMITATIONS"

class Blocked(Exception):
    pass

def require(ok: bool, reason: str):
    if not ok:
        raise Blocked(reason)

def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def canonical_bytes(obj) -> bytes:
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')

def digest(obj) -> str:
    return sha_bytes(canonical_bytes(obj))

def read_json(p: Path):
    require(p.is_file() and not p.is_symlink(), 'REQUIRED_JSON_MISSING_OR_SYMLINK:'+str(p))
    return json.loads(p.read_text(encoding='utf-8'))

def parse_json(b: bytes):
    return json.loads(b.decode('utf-8'))

def put_json(p: Path, data):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n', encoding='utf-8')

def validate_zip_path(name: str):
    p=PurePosixPath(name)
    require(name and '\\' not in name and not name.startswith('/') and not name.startswith('~')
            and ':' not in name and all(x not in ('..','.') for x in p.parts), 'UNSAFE_ZIP_PATH')
    return name

def read_zip(path: Path, *, max_total: int=100_000_000):
    require(path.is_file() and not path.is_symlink(),'ZIP_MISSING_OR_SYMLINK:'+str(path))
    files={};total=0
    with zipfile.ZipFile(path,'r') as z:
        require(z.testzip() is None, 'ZIP_CRC_FAIL:'+str(path))
        infos=z.infolist()
        require(len(infos)<5000,'ZIP_MEMBER_LIMIT')
        for inf in infos:
            validate_zip_path(inf.filename)
            require((inf.external_attr >> 16) & 0o170000 != 0o120000,'ZIP_SYMLINK')
            if inf.is_dir():continue
            require(inf.filename not in files, 'ZIP_DUPLICATE_FILE')
            total+=inf.file_size
            require(total<=max_total,'ZIP_UNCOMPRESSED_LIMIT')
            files[inf.filename]=z.read(inf)
    return files

def verify_manifest(m):
    require('SHA256SUMS' in m, 'MISSING_SHA_MANIFEST')
    listed=set()
    for line in m['SHA256SUMS'].decode('utf-8').splitlines():
        if not line.strip():continue
        match=re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)',line)
        require(match is not None, 'MALFORMED_SHA_MANIFEST')
        h,name=match.groups();validate_zip_path(name)
        require(name not in listed and name in m,'MANIFEST_MISSING_OR_DUPLICATED:'+name)
        require(sha_bytes(m[name])==h,'MANIFEST_HASH_MISMATCH:'+name)
        listed.add(name)
    require(set(m)-{'SHA256SUMS'}==listed,'MANIFEST_NOT_EXHAUSTIVE')
    return len(listed)

def check_source_zip(path: Path, lock):
    require(sha_file(path)==SOURCE_SHA, 'SOURCE_ZIP_SHA_MISMATCH')
    data=read_zip(path,max_total=2_000_000)
    units=lock['units']
    require(len(units)==24 and len(data)==24,'SOURCE_OR_UNIT_COUNT')
    seen=set();by_cwe=Counter();by_truth=Counter()
    for unit in units:
        uri=validate_zip_path(unit['uri']);uid=unit['unit_id']
        require(uri in data and uri.endswith('.java'),'SOURCE_URI_UNKNOWN:'+uri)
        require(uid not in seen,'DUPLICATE_UNIT_ID');seen.add(uid)
        require(sha_bytes(data[uri])==unit['source_sha256'],'UNIT_SOURCE_SHA:'+uri)
        require(unit['cwe'] in CWES and unit['truth'] in ('POSITIVE','NEGATIVE'),'UNIT_CWE_OR_LABEL')
        require(unit['input_sha256']==SOURCE_SHA,'UNIT_INPUT_SHA')
        require(unit.get('independent_human_gold') is False,'FALSE_GOLD_CLAIM')
        by_cwe[unit['cwe']]+=1;by_truth[unit['truth']]+=1
        require(len(data[uri].decode('utf-8').splitlines())==unit['source_line_count'],'UNIT_LINE_COUNT:'+uri)
    require(all(by_cwe[c]==6 for c in CWES),'CWE_SUPPORT_NOT_SIX')
    require(by_truth==Counter({'POSITIVE':12,'NEGATIVE':12}),'HOLDOUT_TRUTH_BALANCE')
    return {'source_file_sha256_verified':len(data),'unit_count':len(units),'by_cwe':dict(sorted(by_cwe.items())),
            'truth_counts':dict(sorted(by_truth.items()))}

def confusion(rows, labels, key):
    c=dict(tp=0,fp=0,fn=0,tn=0)
    for r in rows:
        require(type(r.get(key)) is bool, 'SELECTOR_NOT_BOOL:'+key)
        y=labels[r['unit_id']]['truth'];pred=r[key]
        c[('tp' if pred else 'fn') if y=='POSITIVE' else ('fp' if pred else 'tn')]+=1
    tp,fp,fn,tn=tuple(c[x] for x in KEYS)
    div=lambda a,b:a/b if b else None
    return {**c,'precision':div(tp,tp+fp),'recall':div(tp,tp+fn),
            'f1':div(2*tp,2*tp+fp+fn),'specificity':div(tn,tn+fp),
            'positive_support':tp+fn,'negative_support':tn+fp}

def ranking(rows, labels):
    # Independent arithmetic replay using frozen score and tie grouping; no refitting.
    retrieved=sorted([r for r in rows if r['any_reported_alert']],key=lambda r:(-r['score'],r['unit_id']))
    total=sum(u['truth']=='POSITIVE' for u in labels.values() if u['unit_id'] in {r['unit_id'] for r in rows})
    truth=[int(labels[r['unit_id']]['truth']=='POSITIVE') for r in retrieved]
    hits=0;ap_sum=0.0
    for i,y in enumerate(truth,1):
        hits+=y
        if y:ap_sum+=hits/i
    expected=[];pos_before=0;exp_ap_sum=0.;off=0;groups=[]
    while off<len(retrieved):
        end=off+1
        while end<len(retrieved) and retrieved[end]['score']==retrieved[off]['score']:end+=1
        n=end-off;m=sum(truth[off:end]);p=m/n
        expected.extend([p]*n)
        for j in range(1,n+1):
            second=(j-1)*m*(m-1)/(n*(n-1)) if n>1 else 0.
            exp_ap_sum+=((pos_before+1)*p+second)/(off+j)
        groups.append((off,n,m));pos_before+=m;off=end
    top={}
    for k in K_VALUES:
        if k>len(retrieved):
            top[str(k)]={'status':'INSUFFICIENT_RETRIEVED_K','retrieved':len(retrieved),'metrics':None}
            continue
        n_hit=sum(truth[:k]);e_hit=sum(expected[:k]);lo=hi=0
        for off,n,m in groups:
            n_take=max(0,min(n,k-off))
            if n_take:
                lo+=max(0,n_take-(n-m));hi+=min(n_take,m)
        ideal=sum(1/math.log2(i+2) for i in range(min(k,total)))
        dcg=sum(y/math.log2(i+2) for i,y in enumerate(truth[:k]))
        e_dcg=sum(y/math.log2(i+2) for i,y in enumerate(expected[:k]))
        top[str(k)]={'status':'COMPUTED', 'precision':n_hit/k,
                     'recall':n_hit/total if total else None,
                     'ndcg_binary':dcg/ideal if ideal else None,
                     'tie_expected_precision':e_hit/k,
                     'tie_expected_recall':e_hit/total if total else None,
                     'tie_expected_ndcg_binary':e_dcg/ideal if ideal else None,
                     'within_tie_precision_min':lo/k,
                     'within_tie_precision_max':hi/k}
    return {'status':'COMPUTED','universe':len(rows),'retrieved':len(retrieved),
            'positive_support':total,'positive_not_retrieved':total-sum(truth),
            'ap_single_list_not_map':ap_sum/total if total else None,
            'tie_expected_ap':exp_ap_sum/total if total else None,
            'tie_groups_with_multiple_units':sum(n>1 for _,n,_ in groups),
            'top_k':top}

def numeric_equal(a,b,*,path='root'):
    if type(a) is type(b) and isinstance(a,(int,float)) and not isinstance(a,bool):
        require(math.isclose(a,b,rel_tol=0,abs_tol=1e-10), 'METRIC_MISMATCH:'+path)
    elif type(a) is not type(b):
        require(False,'METRIC_TYPE_MISMATCH:'+path)
    elif isinstance(a,dict):
        require(set(a)==set(b),'METRIC_KEYS_MISMATCH:'+path)
        for k in a:numeric_equal(a[k],b[k],path=path+'.'+str(k))
    elif isinstance(a,list):
        require(len(a)==len(b),'METRIC_LIST_LEN:'+path)
        for i,(x,y) in enumerate(zip(a,b)):numeric_equal(x,y,path=path+'.'+str(i))
    else:
        require(a==b,'METRIC_VALUE_MISMATCH:'+path)

def verify_vectors_and_metrics(ev):
    rows_all=parse_json(ev['EVALUATION_VECTORS.json'])
    metrics=parse_json(ev['METRICS.json'])
    lock=parse_json(ev['HOLDOUT_LOCK_PUBLIC.json'])
    labels={u['unit_id']:u for u in lock['units']}
    require(len(labels)==24,'LOCK_UNIQUE_UNITS')
    require(set(rows_all)==set(ARMS),'VECTOR_ARMS')
    require(metrics['units']==24 and metrics['truth_counts']=={'POSITIVE':12,'NEGATIVE':12},'METRIC_SCOPE')
    counts={};matrix={}
    base_ids=set(labels)
    for arm in ARMS:
        rows=rows_all[arm]
        require(len(rows)==24 and {r['unit_id'] for r in rows}==base_ids,'VECTOR_COVERAGE:'+arm)
        require(len({r['unit_id'] for r in rows})==24,'VECTOR_DUP_ID')
        for r in rows:
            u=labels[r['unit_id']]
            require(r['uri']==u['uri'] and r['cwe']==u['cwe'],'VECTOR_IDENTITY')
            require(type(r['score']) in (int,float) and math.isfinite(r['score']) and 0<=r['score']<=100,'VECTOR_SCORE')
            require(r['qualified_evidence']==(r['qualified_model'] or r['qualified_policy']),'VECTOR_QUAL_FLAG')
            require(not (r['qualified_policy'] and r['qualified_model']),'DOUBLE_ORIGIN')
            require(not(r['cwe']!='79' and r['qualified_policy']),'POLICY_CWE_MISMATCH')
            require(not(r['cwe']=='79' and r['qualified_model']),'XSS_MODEL_ONLY_MISATTRIBUTION')
            require(r['raw_opengrep'] and r['any_reported_alert'],'MISSING_RAW_OPENGREP_IN_HOLDOUT')
        counts[arm]={k:sum(bool(r[k]) for r in rows) for k in ('raw_opengrep','qualified_model','qualified_policy','qualified_evidence')}
        matrix[arm]={}
        for scope in ('all',*CWES):
            rr=rows if scope=='all' else [r for r in rows if r['cwe']==scope]
            require(len(rr)==(24 if scope=='all' else 6),'SCOPE_UNIT_COUNT')
            measured=metrics['arms'][arm]['scopes'][scope]
            for selector in ('raw_opengrep','any_reported_alert','qualified_evidence'):
                if arm=='opengrep_only' and selector=='qualified_evidence':
                    require(measured['detection'][selector]=={'status':'NOT_APPLICABLE_CODEQL_NOT_RUN','metrics':None},'OG_QUAL_NA')
                    continue
                calc=confusion(rr,labels,selector)
                numeric_equal(calc,measured['detection'][selector],path=f'{arm}.{scope}.{selector}')
                if scope=='all':matrix[arm][selector]=calc
            calc_rank=ranking(rr,labels)
            numeric_equal(calc_rank,measured['ranking'],path=f'{arm}.{scope}.ranking')
    require(rows_all['epoch_1']==rows_all['epoch_2'],'EPOCH1_EPOCH2_VECTORS_DIFFER')
    require(counts['base']['qualified_model']==0 and counts['base']['qualified_policy']==1,'BASE_EVIDENCE_ORIGIN')
    require(all(counts[a]['qualified_model']==12 and counts[a]['qualified_policy']==1 for a in ('epoch_1','epoch_2')),
            'LORA_EVIDENCE_ORIGIN')
    return {'vectors':rows_all,'lock':lock,'counts':counts,'confusion':matrix,
            'metric_scopes_replayed':len(ARMS)*5,'detection_cells_replayed':len(ARMS)*5*3-5,
            'ranking_scopes_replayed':len(ARMS)*5,
            'all_metric_values_consistent':True}

def file_based_diagnostic(vectors,lock):
    byid={u['unit_id']:u for u in lock['units']}
    e1=vectors['epoch_1'];errors=[];distro=Counter()
    case_hints={
        'PathAllowlisted.java':('CWE22_ALLOWLIST_RESTRICTION','A syntactic allowlist restricts input to a single basename; dataflow alone cannot prove traversal under the declared trusted-filesystem assumptions.'),
        'PathRootChecked.java':('CWE22_ROOT_CONTAINMENT','Path normalization and startsWith(root) provide scoped containment; symlinks/TOCTOU remain outside the locked trust assumptions.'),
        'CommandDataArgument.java':('CWE78_FIXED_EXECUTABLE_DATA_ARG','Untrusted input reaches a fixed trusted /usr/bin/printf argument but does not choose the executable or become a shell program.'),
        'HtmlQueryAttribute.java':('CWE79_ATTRIBUTE_CONTEXT_NOT_IN_POLICY','Decoded getQuery() data enters quoted HTML attribute; current qualified policy covers narrower HTML output contexts.'),
        'HtmlQueryScript.java':('CWE79_SCRIPT_CONTEXT_NOT_IN_POLICY','Decoded getQuery() data enters JavaScript string context; current policy does not establish escaping in this context.')
    }
    for row in e1:
        label=byid[row['unit_id']]['truth'];q=row['qualified_evidence']
        if (label=='NEGATIVE' and q) or (label=='POSITIVE' and not q):
            basename=Path(row['uri']).name
            require(basename in case_hints,'UNEXPECTED_QUALIFICATION_ERROR:'+basename)
            category,detail=case_hints[basename]
            kind='FALSE_POSITIVE' if label=='NEGATIVE' else 'FALSE_NEGATIVE'
            distro[kind]+=1
            errors.append({'unit_id':row['unit_id'],'file':basename,'cwe':row['cwe'],
                           'error':kind,'root_cause_status':'HYPOTHESIS_REQUIRES_FURTHER_PROOF',
                           'diagnostic_category':category,'interpretation':detail,
                           'score':row['score'],'model_derived':row['qualified_model'],
                           'policy_assisted':row['qualified_policy'],
                           'locked_truth':label,'source_sha256':byid[row['unit_id']]['source_sha256'],
                           'human_gold':False})
    require(distro==Counter({'FALSE_POSITIVE':3,'FALSE_NEGATIVE':2}),'UNEXPECTED_ERROR_COUNTS')
    require(set(e['file'] for e in errors)==set(case_hints),'ERROR_CASE_IDENTITY')
    errors.sort(key=lambda x:(x['error'],x['cwe'],x['file']))
    return {'scope':'OBSERVED_HOLDOUT_DIAGNOSTICS_NOT_NEW_MODEL_METRICS_NOT_PATCH_AUTHORIZATION',
            'evaluation_reused_without_relabeling':True,'root_causes_proven':False,
            'error_count':len(errors),'error_types':dict(sorted(distro.items())),
            'cases':errors,'recommended_development_tests':[
              {'cwe':'22','topic':'allowlisted basenames vs rooted path normalization and symbolic-link trust','separate_from_holdout':True},
              {'cwe':'78','topic':'fixed trusted executable + data-only argument vs shell -c','separate_from_holdout':True},
              {'cwe':'79','topic':'HTML text vs quoted attribute vs JS string context, decoded/raw URI semantics','separate_from_holdout':True}
            ]}

def reconstruct(private:Path, vectors, lock, pm, input_sha):
    units={(u['uri'],u['cwe']):u for u in lock['units']}
    baseline_raw=None;exports=[];checks=0;rows_by_arm={}
    for arm in ARMS:
        for leaf in ('result.json','report.sarif'):
            name=f'analysis/{arm}/{leaf}';p=private/name
            require(name in pm and p.is_file() and not p.is_symlink(),'PRIVATE_EXPORT_MISSING:'+name)
            require(sha_file(p)==pm[name],'PRIVATE_EXPORT_SHA:'+name)
            exports.append(name)
        report=read_json(private/f'analysis/{arm}/result.json')
        require(report['arm']==arm and report['input_sha256']==input_sha,'PRIVATE_RESULT_IDENTITY:'+arm)
        require(type(report.get('findings')) is list,'PRIVATE_FINDINGS_TYPE')
        uniq=set();raw={}
        rows={u['unit_id']:{'unit_id':u['unit_id'],'uri':u['uri'],'cwe':u['cwe'],'finding_count':0,
              'opengrep_count':0,'score':None,'qualified_model':False,'qualified_policy':False,
              'qualified_paths':set(),'raw_policy_paths':set()} for u in lock['units']}
        for f in report['findings']:
            require(f['id'] not in uniq,'FINDING_DUPLICATE_ID');uniq.add(f['id'])
            require(f['retained'] is True and f['vulnerability_confirmed'] is False,'FALSE_SAFETY_VERDICT')
            key=(f['location']['uri'],f['cwe']);require(key in units,'FINDING_OUTSIDE_LOCKED_UNIT')
            row=rows[units[key]['unit_id']];score=f['score']['final_score']
            require(type(score) in (int,float) and math.isfinite(score) and 0<=score<=100,'FINDING_SCORE')
            row['score']=max(row['score'],score) if row['score'] is not None else score
            row['finding_count']+=1
            linked=f.get('linked_codeql_flow_ids',[])
            dataflow=f.get('dataflow',[])
            require(isinstance(linked,list) and isinstance(dataflow,list) and bool(linked)==bool(dataflow),
                    'QUAL_FLOW_STATUS_MISMATCH')
            if f['origin']=='OPENGREP':
                row['opengrep_count']+=1
                require(isinstance(f.get('original_opengrep'),dict),'ORIGINAL_RAW_FINDING_ABSENT')
                raw[f['id']]=digest(f['original_opengrep'])
            if arm=='opengrep_only':
                require(not linked and f.get('model_observation') is None,'OG_ONLY_HAS_MODEL_OR_PATH')
            elif f['cwe']=='79':
                require(f.get('evidence_origin')=='CODEQL_CONTEXTUAL_POLICY_ASSISTED','XSS_EVIDENCE_ORIGIN')
                row['raw_policy_paths'].update(f.get('raw_policy_flow_ids',[]))
                if linked:
                    require(f.get('evidence_status')=='POLICY_QUALIFIED_UNENCODED_HTML_PATH','XSS_POLICY_STATUS')
                    require(f['score'].get('ai_confidence_score')==0.5,'XSS_POLICY_MUST_HAVE_NEUTRAL_AI')
                    row['qualified_policy']=True
            else:
                require(f.get('evidence_origin')=='MODEL_DERIVED','MODEL_EVIDENCE_ORIGIN')
                if linked:
                    obs=f.get('model_observation') or {}
                    require(obs.get('status')=='ACCEPTED' and (obs.get('label') or {}).get('type')=='sink',
                            'PATH_WITHOUT_ACCEPTED_MODEL_SINK')
                    row['qualified_model']=True
            row['qualified_paths'].update(linked)
        require(len(report['findings'])>=24,'RAW_OPENGREP_UNEXPECTEDLY_DROPPED')
        require(sum(f['origin']=='OPENGREP' for f in report['findings'])==24,'RAW_OPENGREP_DROPPED')
        if baseline_raw is None:baseline_raw=raw
        else:require(baseline_raw==raw,'ORIGINAL_OPENGREP_ALTERS_ACROSS_ARMS')
        for row in rows.values():
            row['raw_opengrep']=bool(row['opengrep_count']);row['any_reported_alert']=bool(row['finding_count'])
            row['qualified_evidence']=row['qualified_model'] or row['qualified_policy']
            row['qualified_paths']=len(row['qualified_paths']);row['raw_policy_paths']=len(row['raw_policy_paths'])
        observed={r['unit_id']:r for r in vectors[arm]}
        for row in rows.values():
            require(row==observed[row['unit_id']],'PRIVATE_EXPORT_VS_VECTOR_MISMATCH:'+arm+':'+row['uri'])
            checks+=1
        rows_by_arm[arm]=rows
    return {'exports_verified':len(exports),'exports':exports,'unit_rows_reconstructed':checks,
            'raw_opengrep_retained_all_arms':True,'orig_opengrep_byte_equivalence':True,
            'private_results_match_eval_vectors':True,'no_confirmed_vulnerability_claim':True}

def runtime_summary(bk):
    res=parse_json(bk['00_RESULT.json'])
    require(res['status']==BACKEND_STATUS and res['completed_arms']==list(ARMS),'BACKEND_STATUS')
    require(res['new_native_requests']==51 and res['warm_cache_hits']==51,'NATIVE_REQUEST_COUNTS')
    require(res['new_training'] is False and res['web_gate_changed_by_runner'] is False,'BACKEND_MUTATED')
    require(res['stage4']=='NOT_EXECUTED' and res['full_SAPipeline_run']=='NOT_EXECUTED','STAGE_SCOPE')
    require(parse_json(bk['BEFORE.json'])==parse_json(bk['AFTER.json']),'SOURCE_GATE_BEFORE_AFTER_DIFFER')
    before=parse_json(bk['BEFORE.json'])
    require(before['git']['github']['head']==FROZEN_GIT and before['git']['iris']['head']==FROZEN_IRIS,'FROZEN_COMMIT')
    require(before['git']['github']['status']=='' and before['git']['iris']['status']=='','DIRTY_FROZEN_REPOSITORY')
    protocol=parse_json(bk['RUN_PROTOCOL.json'])
    require(protocol['input_sha256']==SOURCE_SHA and protocol['arms']==list(ARMS),'RUN_PROTOCOL')
    require(protocol['database_count']==1 and protocol['quality_pass_threshold'] is None,'RUN_PROTOCOL_DATABASE_OR_THRESHOLD')
    require(protocol['scorer_sha256']==FROZEN_SCORER_SHA,'SCORER_NOT_PINNED')
    require(protocol['runtime']['web_gate_changed'] is False,'WEB_GATE_CHANGE')
    cmp=parse_json(bk['COMPARISON.json'])
    require(cmp['arms']['opengrep_only']['findings']==24,'OPENGREP_ONLY_FINDING_COUNT')
    for arm in ARMS:
        require(cmp['arms'][arm]['retained_opengrep']==24,'OPEN_GREP_LOST:'+arm)
    require(all(cmp['arms'][arm]['qualified_paths']==13 for arm in ('epoch_1','epoch_2')),'QUALIFIED_PATH_COUNT')
    require(cmp['arms']['base']['qualified_paths']==1,'BASE_POLICY_EVIDENCE')
    policy=parse_json(bk['POLICY79.json'])
    require(policy['origin']=='CODEQL_CONTEXTUAL_POLICY_ASSISTED' and policy['model_xss_gate_granted'] is False,'XSS_GATE')
    require(policy['computed_once_shared_by_three_arms'] is True,'POLICY_MUST_BE_SHARED')
    native={}
    for arm in ('base','epoch_1','epoch_2'):
        n=parse_json(bk['NATIVE_'+arm+'.json'])
        details=n['details'];require(len(details)==17 and n['candidates']==17 and n['cache_hits']==17,'NATIVE_DETAIL_COUNT')
        require(n['cleanup']['worker_still_running'] is False and n['cleanup']['worker_returncode']==0,'WORKER_CLEANUP')
        native[arm]={'requests':len(details),'accepted':n['accepted'],'abstain':n['abstain'],
                     'generation_seconds_sum':round(sum(row['generation_s'] for row in details),3),
                     'torch_allocator_peak_mib':round(max(row['peak_vram_allocated_bytes'] for row in details)/(1024*1024),2),
                     'cache_hits':n['cache_hits']}
    timings=parse_json(bk['COMMAND_TIMINGS.json'])
    require(len(timings)>0 and all(x['returncode']==0 and not x['timed_out'] and not x['still_running'] for x in timings),
            'COMMAND_PROCESS_FAILED_OR_RUNNING')
    return {'backend_status':res['status'],'backend_run_id':RUN_ID,'full_pipeline_stage4':'NOT_EXECUTED',
            'model_arms_native':native,'all_three_native_arms_sequential':True,
            'runtime_wall_seconds_total':res['elapsed_s'],
            'opengrep_seconds':parse_json(bk['SCANNER_PROOF.json'])['duration_s'],
            'command_records_zero_failure':len(timings),
            'new_codeql_databases':parse_json(bk['DATABASE_PROOF.json'])['count'],
            'opengrep_alerts_retained':24,'policy79_raw_paths':policy['raw_paths'],
            'policy79_qualified_paths':policy['qualified_paths'],
            'model_only_xss_proven_paths':0,
            'scorer_sha256':FROZEN_SCORER_SHA,'release_git_commit':FROZEN_GIT,
            'frozen_iris_commit':FROZEN_IRIS,
            'before_after_frozen_repo_gates_equal':True,
            'latency_caveat':'SHARED_EXTRACTION_NOT_3_INDEPENDENT_COLD_END_TO_END_RUNS',
            'vram_caveat':'TORCH_ALLOCATOR_PEAK_NOT_TOTAL_DEVICE_VRAM'}

def verify_archive_links(ev,bk,source,work,workspace,*,authoring_only=False):
    er=parse_json(ev['00_RESULT.json']);br=parse_json(bk['00_RESULT.json'])
    require(er['status']==EVAL_STATUS and er['blockers']==0,'EVALUATOR_RESULT')
    require(er['backend_run_id']==RUN_ID and er['backend_result_sha256']==BACKEND_SHA,'EVAL_BACKEND_LINK')
    require(er['input_sha256']==SOURCE_SHA and br['input_sha256']==SOURCE_SHA,'SOURCE_BINDING')
    require(er['holdout_lock_sha256']==LOCK_SHA,'HOLDOUT_LABEL_LOCK_HASH')
    require(er['units']==24 and er['truth_counts']=={'NEGATIVE':12,'POSITIVE':12},'TRUTH_COUNTS')
    require(er['pre_prediction_locked'] is True and er['independent_human_gold'] is False,'TRUTH_SCIENTIFIC_SCOPE')
    require(er['exports_verified']==8,'PRIVATE_EXPORT_CHECKCOUNT')
    public=parse_json(ev['HOLDOUT_LOCK_PUBLIC.json'])
    require(public['project_zip_sha256']==SOURCE_SHA and public['predictions_exposed_before_lock'] is False,'PRELOCK_PUBLIC')
    if not authoring_only:
        lock=read_json(workspace/'HOLDOUT_LOCK.json')
        require(sha_file(workspace/'HOLDOUT_LOCK.json')==LOCK_SHA,'PRIVATE_LOCK_SHA_CHANGED')
        require({k:v for k,v in lock.items() if k!='reviewer'}==public,'PRIVATE_PUBLIC_LOCK_DIFFERS')
        require(workspace.joinpath('PREDICTION_RUN_LINK.json').is_file(),'PREDICTION_RUN_LINK_MISSING')
        link=read_json(workspace/'PREDICTION_RUN_LINK.json')
        require(link['backend_result_sha256']==BACKEND_SHA,'WORKSPACE_BACKEND_SHA_DIFFERS')
        require(Path(link['backend_result_zip']).resolve()==source['backend_path'],'BACKEND_SAVED_FILE_NOT_SAME_LINK')
        require(link['holdout_lock_sha256']==LOCK_SHA,'WORKSPACE_LOCK_LINK_DIFFERS')
    lock_time=datetime.fromisoformat(public['locked_at'].replace('Z','+00:00'))
    run_time=datetime.strptime(RUN_ID.split('_')[1],'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    require(run_time>lock_time,'RUN_PREDATES_LABEL_LOCK')
    return public

def derive_next_actions():
    return {'classification':'TECHNICAL_FOLLOW_UP_REQUIRES_FRESH_DEVELOPMENT_FIXTURES_NOT_TEST_SET_TUNING',
            'not_completed_by_b39b8':['Independent multi-reviewer labels / external gold evaluation',
                                      'General-purpose Java/third-party frameworks',
                                      'Model-derived CWE-79 sink qualification',
                                      'Full legacy SAPipeline.run and Stage4',
                                      'Fresh-install reproducibility of the mixed Python environment'],
            'product_action':'Keep production epoch_1 website gate and frozen scorer unchanged',
            'research_scope':'24 AI-assisted synthetic samples authored with knowledge of earlier system behavior',
            'if_improving':'Create fresh development cases; version semantic policy; test new version there; retain B39B7 as analyzed holdout, not reused as validation of improvement',
            'advisor_status':'Technical prototype and pre-prediction synthetic comparison are ready to report, broader scientific generalization remains unverified'}

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--work',type=Path,required=True)
    ap.add_argument('--downloads',type=Path,required=True)
    ap.add_argument('--workspace',type=Path,required=True)
    ap.add_argument('--backend-zip',type=Path,required=True)
    ap.add_argument('--evaluation-zip',type=Path,required=True)
    ap.add_argument('--source-zip',type=Path,required=True)
    ap.add_argument('--metadata-only-authoring',action='store_true',help='Test-only; cannot close B39B')
    args=ap.parse_args(argv)
    paths={k:getattr(args,k).expanduser().resolve() for k in ('work','downloads','workspace','backend_zip','evaluation_zip','source_zip')}
    work=paths['work'];dl=paths['downloads'];ws=paths['workspace']
    require(work.is_dir() and dl.is_dir() and ws.is_dir(),'ROOT_OR_WORKSPACE_MISSING')
    require(sha_file(paths['backend_zip'])==BACKEND_SHA,'PINNED_BACKEND_SHA_MISMATCH')
    require(sha_file(paths['evaluation_zip'])==EVAL_SHA,'PINNED_EVALUATION_SHA_MISMATCH')
    print('B39B8_STAGE=PINNED_EVIDENCE_ZIPS_VERIFIED',flush=True)
    ev=read_zip(paths['evaluation_zip']);bk=read_zip(paths['backend_zip'])
    evchecks=verify_manifest(ev);bkchecks=verify_manifest(bk)
    require(evchecks==6 and bkchecks==27,'UNEXPECTED_ARCHIVE_MANIFEST_FILES')
    public=parse_json(ev['HOLDOUT_LOCK_PUBLIC.json'])
    source=check_source_zip(paths['source_zip'],public)
    print('B39B8_STAGE=LOCKED_SOURCES_AND_TIMELINE_VERIFIED',flush=True)
    public=verify_archive_links(ev,bk,dict(backend_path=paths['backend_zip']),work,ws,
                                authoring_only=args.metadata_only_authoring)
    metrics=verify_vectors_and_metrics(ev)
    print('B39B8_STAGE=ALL_20_SCOPES_DETECTION_AND_RANKING_RECALCULATED',flush=True)
    runtime=runtime_summary(bk)
    failures=file_based_diagnostic(metrics['vectors'],public)
    print('B39B8_STAGE=THREE_FP_TWO_FN_PRESERVED_AS_DIAGNOSTIC_LIMITATIONS',flush=True)
    private_checks={'verification_mode':'NOT_PERFORMED_AUTHORING_ONLY'}
    if not args.metadata_only_authoring:
        run_dir=work/'batch39b4_hybrid_runs'/RUN_ID
        require(run_dir.is_dir(),'LOCAL_BACKEND_RUN_DIRECTORY_MISSING')
        pm=parse_json(bk['PRIVATE_RESULT_MANIFEST.json'])
        private_checks=reconstruct(run_dir/'private',metrics['vectors'],public,pm,SOURCE_SHA)
        print('B39B8_STAGE=EIGHT_PRIVATE_EXPORTS_VERIFIED_AND_96_UNIT_ROWS_RECONSTRUCTED',flush=True)
    scope={'closure_scope':'B39B_RESEARCH_EVIDENCE_AND_SCOPED_PROTOTYPE_NOT_FULL_GENERAL_SAST',
           'independent_human_gold':False,'test_authorship':'AI_ASSISTED_OPERATOR_APPROVED_PRE_PREDICTION',
           'test_construction_informed_by_earlier_system_behavior':True,
           'holdout_was_not_used_for_threshold_tuning':True,
           'evaluation_outcome':{'epoch_1':{'tp':10,'fp':3,'fn':2,'tn':9},
                                 'epoch_2':{'tp':10,'fp':3,'fn':2,'tn':9},
                                 'base':{'tp':1,'fp':0,'fn':11,'tn':12}},
           'cwe79_model_sink_supported':False,'cwe79_policy_assisted':True,
           'stage4_and_SAPipeline_run_verified':False,'production_adapter_change':False,
           'production_scorer_change':False,'production_gate_change':False,
           'metric_value_is_not_a_risk_probability':True,
           'experimental_reproducibility_limit':'LOCKED_ENVIRONMENT_OBSERVED_NOT_CLEAN_INSTALL'}
    metrics_replay={'schema':'NTK_B39B8_OFFLINE_METRIC_RECONCILIATION_V1',
      'recomputed_scopes':metrics['metric_scopes_replayed'],
      'detection_cells_recomputed':metrics['detection_cells_replayed'],
      'ranking_scopes_recomputed':metrics['ranking_scopes_replayed'],
      'all_values_match_original_evaluator':metrics['all_metric_values_consistent'],
      'counts_by_arm':metrics['counts'],
      'global_confusion_by_arm':metrics['confusion'],
      'epoch1_epoch2_vectors_equal_on_this_holdout':True,
      'holdout_overfitting_or_independent_generalization_not_assessed':True,
      'input_eval_sha256':EVAL_SHA,'input_backend_sha256':BACKEND_SHA}
    provenance={'input_archives':{'B39B7_evaluation':{'sha256':EVAL_SHA,'manifest_entries':evchecks},
                                  'B39B4_backend':{'sha256':BACKEND_SHA,'manifest_entries':bkchecks}},
      'holdout_lock_sha256':LOCK_SHA,'project_java_zip_sha256':SOURCE_SHA,
      'source_verification':source,'private_export_checks':private_checks,
      'backend_run_id':RUN_ID,'pre_prediction_lock_timestamp':public['locked_at'],
      'privacy':'ONLY_HASHES_AGGREGATES_AND_ERROR_UNIT_IDS_EXPORTED_NO_JAVA_SOURCE_NO_RAW_PROMPTS_NO_WEIGHTS'}
    result={'status':FINAL_STATUS if not args.metadata_only_authoring else 'B39B8_METADATA_ONLY_AUTHORING_NOT_PRODUCTION_CLOSURE',
      'blockers':0,'source_files_verified':24,'unit_vectors_verified':96,
      'private_exports_verified':private_checks.get('exports_verified',0),
      'metric_scopes_recomputed':metrics['metric_scopes_replayed'],
      'false_positive_cases':3,'false_negative_cases':2,
      'independent_human_gold':False,'new_scans':False,'new_inference':False,'new_training':False,
      'git_mutations':False,'web_gate_mutations':False,'scorer_mutations':False,
      'holdout_metrics_recomputed_not_retrained':True,
      'closure_qualified':not args.metadata_only_authoring}
    folder=work/'batch39b8_closeout';folder.mkdir(exist_ok=True)
    lockfile=folder/'.closeout.lock'
    with lockfile.open('a+') as lf:
        fcntl.flock(lf,fcntl.LOCK_EX|fcntl.LOCK_NB)
        name='b39b8_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+os.urandom(4).hex()
        outdir=folder/name;outdir.mkdir(mode=0o700)
        for n,obj in [('00_RESULT.json',result),('INPUT_PROVENANCE.json',provenance),
                      ('QUALITY_REPLAY.json',metrics_replay),('FAILURE_REGISTER.json',failures),
                      ('RUNTIME_EVIDENCE.json',runtime),('SYSTEM_SCOPE_LOCK.json',scope),
                      ('NEXT_ACTIONS.json',derive_next_actions())]:
            put_json(outdir/n,obj)
        entries=sorted(p for p in outdir.iterdir() if p.is_file())
        (outdir/'SHA256SUMS').write_text(''.join(sha_file(p)+'  '+p.name+'\n' for p in entries),encoding='ascii')
        target=dl/(name+'_result.zip')
        require(not target.exists(),'OUTPUT_ALREADY_EXISTS')
        with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for p in sorted(outdir.iterdir()):
                if p.is_file():z.write(p,arcname=p.name)
        targetsha=sha_file(target)
        (dl/(target.name+'.sha256')).write_text(targetsha+'  '+target.name+'\n',encoding='ascii')
        fcntl.flock(lf,fcntl.LOCK_UN)
    print('\n===== B39B.8 TECHNICAL CLOSEOUT RESULT =====',flush=True)
    for k,v in [('STATUS',result['status']),('BLOCKERS',0),('SOURCE_FILES_VERIFIED',24),
                ('PRIVATE_EXPORTS_VERIFIED',result['private_exports_verified']),('METRIC_SCOPES_RECOMPUTED',20),
                ('KNOWN_FALSE_POSITIVES',3),('KNOWN_FALSE_NEGATIVES',2),('INDEPENDENT_HUMAN_GOLD',False),
                ('NEW_GPU_INFERENCE',False),('NEW_CODEQL_DATABASE',False),('WEB_GATE_CHANGED',False),
                ('OUTPUT_ZIP',target),('OUTPUT_SHA256',targetsha)]:
        print(str(k)+'='+str(v),flush=True)
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (Blocked,ValueError,KeyError,TypeError,zipfile.BadZipFile,OSError) as ex:
        print('STATUS=B39B8_BLOCKED',flush=True)
        print('BLOCKER='+str(ex),flush=True)
        raise SystemExit(2)
