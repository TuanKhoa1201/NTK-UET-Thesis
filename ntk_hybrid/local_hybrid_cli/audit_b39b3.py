#!/usr/bin/env python3
"""Audit exported evidence only; does not pretend to re-read excluded model/raw bytes."""
import argparse
from collections import Counter
import json
from pathlib import Path
import statistics
import sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ntk_core import loads, sha, require, verify_sums, zip_members, write_json
B3_NAME = 'b39b3_20261020T051708Z_d535d53e_result.zip'
B3_SHA = '26666def24a3ad71af54d520c9c3c9f9c425675865184a35c53ea2c22e2318ea'
B2_NAME = 'b39b2_20261020T045315Z_bf52f398_result.zip'
B2_SHA = '5ada3b025c9cf99d3e3f908e5767d9b867b818872f16b827bb936c2724c39585'
ARMS = ('base','epoch_1','epoch_2')
ROLES = ('none','sink','source','taint-propagator')

def archive(path, expected):
    raw = Path(path).read_bytes()
    require(sha(raw) == expected, 'INPUT_ZIP_SHA_MISMATCH:' + Path(path).name)
    members = zip_members(raw); n = verify_sums(members)
    return members,n

def metrics(rows, reported):
    require(len(rows) == reported['n'], 'METRIC_N')
    matrix = {r:{p:0 for p in (*ROLES,'ABSTAIN')} for r in ROLES}
    for r in rows:
        matrix[r['reference_role']][r['predicted_role']] += 1
        require(r['role_matches_weak_reference'] == (r['reference_role'] == r['predicted_role']), 'ROLE_MATCH_FLAG')
        require((r['status']=='ABSTAIN') == (r['predicted_role']=='ABSTAIN'), 'ABSTAIN_NOT_NONE')
    require(matrix == reported['confusion_matrix'], 'CONFUSION_MATRIX')
    fs=[]
    for role in ROLES:
        sup=sum(matrix[role].values());pred=sum(v[role] for v in matrix.values());tp=matrix[role][role]
        f=(2*tp/(sup+pred) if sup+pred else 0) if sup else None
        p=reported['per_role'][role]
        require((p['support'],p['predicted'],p['true_positive'])==(sup,pred,tp),'ROLE_COUNT')
        require(p['recall']==(tp/sup if sup else None) and p['f1']==f,'ROLE_F1_OR_RECALL')
        if f is not None:fs.append(f)
    require(abs(reported['macro_f1_supported_roles']-sum(fs)/len(fs))<1e-12,'MACRO_F1')
    require(reported['accepted']==sum(r['status']=='ACCEPTED' for r in rows),'ACCEPTED_COUNT')
    require(reported['abstain']==sum(r['status']=='ABSTAIN' for r in rows),'ABSTAIN_COUNT')
    require(reported['reason_counts']==dict(Counter(r['reason'] for r in rows)),'REASON_COUNTS')
    require(reported['sink_args_joint_correct']==sum(r['sink_args_joint_matches_weak_reference'] for r in rows),'SINK_ARGS_COUNT')
    require(reported['sink_denominator']==sum(r['reference_role']=='sink' for r in rows),'SINK_SUPPORT')

def audit(b3path, b2path=None):
    members,n=archive(b3path,B3_SHA)
    report=loads(members['00_RESULT.json'])
    require(report['status']=='B39B3_NATIVE_WEAK_VALIDATION_COMPLETE' and not report['blockers'],'B3_NOT_COMPLETE')
    require(members['BEFORE.json']==members['AFTER.json'],'BASELINE_CHANGED')
    require(report['real_requests']==411 and report['warm_cache_hits']==411,'REQUEST_COUNTS')
    token=loads(members['TOKENIZER_PREFLIGHT.json']);prompt=loads(members['PROMPT_PARITY.json'])
    require(token['n']==137 and token['maximum_input_tokens']<=token['token_limit'],'TOKEN_LIMIT')
    require(prompt['n']==137 and prompt['same_b28_prompt']==137 and prompt['changed_b28_prompt']==0,'PROMPT_PARITY')
    require(all(x['same_prompt_bytes'] and x['native_prompt_sha256']==x['b28_prompt_sha256'] for x in prompt['details']),'PROMPT_ITEM')
    reference={};out={};maps={};cache={}
    old=archive(b2path,B2_SHA)[0] if b2path else None
    for arm in ARMS:
        d=loads(members['NATIVE_'+arm+'.json']);rows=d['details'];m=d['measurements'];perf=d['performance']
        require(len(rows)==len(m)==137,'ARM_COUNT');metrics(rows,d['metrics'])
        for c in ('22','78','79','89'):metrics([x for x in rows if x['cwe']==c],d['per_cwe'][c])
        ids={x['sample_id_sha256'] for x in rows}; require(len(ids)==137,'DUPLICATE_ID')
        refs={x['sample_id_sha256']:(x['reference_role'],x['cwe'],x['prompt_sha256']) for x in rows}
        if reference:require(reference==refs,'CROSS_ARM_TARGET_OR_INPUT')
        reference=refs
        require(all(x['cache_hit'] is False for x in m),'COLD_CACHE')
        maps[arm]={x['sample_id_sha256']:x['input_token_ids_sha256'] for x in m};cache[arm]=d['cache_keys']
        w=d['worker'];require(w['arm']==arm and w['ready'] and w['trainable_parameters']==0 and not w['training_executed'],'WORKER')
        require(all(w['isolation'][f]=='DENIED_EPERM' for f in ('AF_INET','AF_INET6')),'WORKER_INET')
        require(d['native_method_invocations']==8 and d['cleanup']['worker_returncode']==0 and not d['cleanup']['worker_still_running'],'CLEANUP')
        require(perf['worker_generation_median_s']==statistics.median(x['generation_s'] for x in m),'MEDIAN')
        require(abs(perf['worker_generation_total_s']-sum(x['generation_s'] for x in m))<1e-9,'GENERATION_TOTAL')
        process=loads(members['PROCESS_'+arm+'.json'])['process']
        require(process['returncode']==0 and not process['still_running'] and not process['process_group_still_running'],'DRIVER_CLEANUP')
        delta=None
        if old:
            prev=loads(old['REPLAY_'+arm+'.json']);a={x['sample_id_sha256']:x for x in prev['details']}
            diff=[dict(sample_id_sha256=x['sample_id_sha256'],cwe=x['cwe'],old_role=a[x['sample_id_sha256']]['predicted_role'],new_role=x['predicted_role']) for x in rows if x['raw_sha256']!=a[x['sample_id_sha256']]['raw_sha256']]
            delta={'raw_response_hash_differences':len(diff),'role_differences':sum(x['old_role']!=x['new_role'] for x in diff),'details':diff,'old_macro_f1':prev['metrics']['macro_f1_four_roles'],
                   'interpretation':'RAW_BYTES_EXCLUDED_FROM_UPLOAD; DIFFERENCE_CAUSE_NOT_ESTABLISHED; PROMPTS_EQUAL'}
        out[arm]={'metrics':d['metrics'],'performance':perf,'historical_b28_delta':delta}
    require(maps['base']==maps['epoch_1']==maps['epoch_2'],'CROSS_ARM_TOKEN_IDS')
    require(all(len({cache[a][i] for a in ARMS})==3 for i in cache['base']),'CROSS_ARM_CACHE_NAMESPACE')
    planned={r['input_token_ids_sha256'] for r in token['rows']}
    require(planned==set(maps['base'].values()),'PREFLIGHT_TOKEN_SET')
    return {'status':'B39B3_EXPORTED_EVIDENCE_AUDITED','archive_sha256':B3_SHA,'sha_manifest_entries_verified':n,
        'crc':'PASS','n':137,'real_requests':411,'warm_cache_hits':411,'prompt_equal_to_b28_count':137,
        'maximum_input_tokens':token['maximum_input_tokens'],'elapsed_s_reported':report['elapsed_s'], 'per_arm':out,
        'scope':'RECOMPUTED_EXPORTED_ROW_METRICS_AND_MANIFESTS_NOT_RAW_RESPONSE_REEXECUTION',
        'independent_gold':False,'model_weights_or_private_raw_bytes_rehashed':False,'no_new_inference':True}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('b3',type=Path);p.add_argument('--b2',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();write_json(a.out,audit(a.b3,a.b2));print('AUDIT_COMPLETE='+str(a.out))
