"""Invariant checks for the four-arm hybrid CLI; not gold evaluation."""
from collections import Counter
from copy import deepcopy
import math
from pathlib import Path
import statistics
from ntk_core import Blocker, IDENTITY, CWES, digest, require, loads
from vendor.common import strict_label
ARMS=('base','epoch_1','epoch_2')
POLICY='CODEQL_CONTEXTUAL_POLICY_ASSISTED'
MODEL='MODEL_DERIVED'

def key(c):
    return digest([c['cwe'],[c[k] for k in IDENTITY]])

def native_inputs(cases):
    out=[]
    for c in cases:
        require(all(isinstance(c.get(k),str) and c[k] for k in (*IDENTITY,'compiler_signature','cwe','source_record_sha256')), 'COMPILER_CANDIDATE_MISSING_IDENTITY')
        require(c['cwe'] in CWES,'COMPILER_CWE')
        out.append({**{k:c[k] for k in (*IDENTITY,'cwe','source_record_sha256')},
                    'is_static':c.get('is_static'), 'receiver_policy':'HOLD_THIS_UNTIL_SEMANTIC_REVIEW'})
    require(len({key(c) for c in out})==len(out),'DUPLICATE_COMPILER_API_CWE')
    require(0<len(out)<=100,'COMPILER_REQUEST_BUDGET')
    return out

def trace_check(cases, trace, summary, arm, versions, token_proof):
    require(summary.get('status')=='B39B4_NATIVE_ARM_COMPLETE','NATIVE_DRIVER_NOT_COMPLETE')
    w=summary['worker'];require(w['arm']==arm and w['ready'] and w['versions']==versions,'WORKER_IDENTITY')
    require(w['trainable_parameters']==0 and not w['training_executed'],'INFERENCE_ONLY')
    require(all(w['isolation'][k]=='DENIED_EPERM' for k in ('AF_INET','AF_INET6')),'NATIVE_NETWORK')
    require(summary['cleanup']['worker_returncode']==0 and not summary['cleanup']['worker_still_running'],'NATIVE_CLEANUP')
    require(summary['native_method_invocations']==8,'NATIVE_INVOCATION_COUNT')
    require(w['tokenizer_chat_template_sha256']==token_proof['tokenizer_chat_template_sha256'],'TOKENIZER_TEMPLATE')
    inputs={key(c):c for c in cases};n=len(inputs);require(n==len(cases),'DUPLICATE_INPUT')
    require(len(trace)==n*2,'TRACE_COUNT')
    phases={}
    for phase in ('cold','warm'):
        rows=[x for x in trace if x['phase']==phase]
        phases[phase]={x['case_key']:x for x in rows}
        require(len(rows)==len(phases[phase])==n and set(phases[phase])==set(inputs),'TRACE_ID_SET')
    tokens={x['case_key']:x['input_token_ids_sha256'] for x in token_proof['rows']}
    require(set(tokens)==set(inputs),'TOKENIZER_CASE_SET')
    records=[]
    for ident,c in inputs.items():
        cold,warm=phases['cold'][ident],phases['warm'][ident]
        for x in (cold,warm):
            require(not x.get('infrastructure_failure') and isinstance(x.get('raw_completion'),str),'INFRASTRUCTURE_FAILURE')
            require(x['candidate']=={k:c[k] for k in (*IDENTITY,'cwe')},'TRACE_IDENTITY_CHANGED')
            require(x['source_record_sha256']==c['source_record_sha256'] and x['prompt_sha256']==digest(c['expected_messages']),'TRACE_PROVENANCE_CHANGED')
            verdict=strict_label(x['raw_completion'],c,c['cwe'])
            require(all(x[k]==verdict[k] for k in ('status','reason','label')),'STRICT_PARSER_MISMATCH')
        require(not cold['cache_hit'] and warm['cache_hit'],'CACHE_PHASE')
        require(all(cold[k]==warm[k] for k in ('raw_completion','label','status','reason','cache_key')),'WARM_CACHE_CHANGED')
        m=cold['worker'];require(m['input_token_ids_sha256']==tokens[ident],'INPUT_TOKEN_DRIFT')
        for k in ('generation_s','input_tokens','output_tokens','peak_vram_allocated_bytes','peak_vram_reserved_bytes'):
            require(type(m.get(k)) in (float,int) and math.isfinite(m[k]) and m[k]>=0,'INVALID_MEASUREMENT')
        records.append({'case_key':ident,'cwe':c['cwe'],'status':cold['status'],'reason':cold['reason'],
                        'role':cold['label']['type'] if cold['label'] else 'ABSTAIN',
                        'cache_key':cold['cache_key'],'prompt_sha256':cold['prompt_sha256'],**m})
    return {'arm':arm,'candidates':n,'new_requests':n,'cache_hits':n,
        'accepted':sum(x['status']=='ACCEPTED' for x in records),
        'abstain':sum(x['status']=='ABSTAIN' for x in records),
        'reasons':dict(Counter(x['reason'] for x in records)),'details':records,
        'worker':w,'cleanup':summary['cleanup'],'native_method_invocations':8,
        'performance':{'model_load_s':w['load_s'],'generation_median_s':statistics.median(x['generation_s'] for x in records),
                       'generation_total_s':sum(x['generation_s'] for x in records),
                       'peak_pytorch_allocated_bytes':max(x['peak_vram_allocated_bytes'] for x in records),
                       'peak_pytorch_reserved_bytes':max(x['peak_vram_reserved_bytes'] for x in records),
                       'scope':'ONE_NEW_WORKER_PER_ARM_NOT_OS_COLD; CACHE_LATENCY_AND_DEVICE_TOTAL_VRAM_NOT_MEASURED'}}

def scorer_fields(score):
    from dataclasses import asdict
    return asdict(score)

def verify_fusion(rows, og, scorer, mode):
    require(len({r['id'] for r in rows})==len(rows),'DUPLICATE_FUSED_ID')
    observed=[r for r in rows if r['origin']=='OPENGREP']
    require(len(observed)==len(og['results']),'RAW_OPENGREP_COUNT_LOST')
    by_id={r['id']:r for r in observed}
    for i,raw in enumerate(og['results']):
        r=by_id.get('opengrep:'+str(i))
        require(r is not None and r['original_opengrep']==raw,'RAW_OPENGREP_MODIFIED')
    for r in rows:
        require(r.get('retained') is True and r.get('vulnerability_confirmed') is False,'RETENTION_OR_CONFIRMATION_CHANGED')
        require(r['score']==scorer_fields(scorer.score_finding(deepcopy(r))),'SCORER_REPLAY_MISMATCH')
        v=r['score']['final_score'];require(type(v) in (float,int) and math.isfinite(v) and 0<=v<=100,'INVALID_SCORE')
        if mode=='opengrep_only':
            require(r['origin']=='OPENGREP' and not r['linked_codeql_flow_ids'] and not r['dataflow'],'BASELINE_HAS_FLOW')
            require(r['model_observation'] is None and r['score']['ai_confidence_score']==0.5,'BASELINE_MODEL_EVIDENCE')
        elif r['cwe']=='79':
            require(r['evidence_origin']==POLICY and r['score']['ai_confidence_score']==0.5,'XSS_POLICY_MISATTRIBUTED')
    return {'findings':len(rows),'retained_opengrep':len(observed),
        'scorer_replay_checked':len(rows),'per_cwe':{c:{'findings':sum(r['cwe']==c for r in rows),
          'opengrep_kept':sum(r['cwe']==c for r in observed),
          'score_values':sorted({r['score']['final_score'] for r in rows if r['cwe']==c})} for c in CWES}}

def results_view(rows, arm, input_sha):
    """Standalone machine-readable local result. No changes to legacy numeric scoring."""
    return {'mode':'B39B4_COMPARISON_CLI_NOT_DPA_WEB_GATE','arm':arm,'input_sha256':input_sha,
        'findings':rows,'priority_semantics':'REVIEW_PRIORITY_NOT_VULNERABILITY_PROBABILITY',
        'legacy_score_description_is_not_confirmation':True,
        'xss_evidence_origin':POLICY if arm!='opengrep_only' else 'OPENGREP_ONLY',
        'model_xss_gate_granted':False,'independent_gold':False,
        'display': [{'id':r['id'],'priority':r['score']['final_score'],
                      'priority_label':r['score']['risk_level']+' - REVIEW PRIORITY',
                      'confirmed':False} for r in sorted(rows,key=lambda r:(-r['score']['final_score'],r['id']))]}

def assert_comparison(summaries, traces, policy_hashes):
    require(set(summaries)=={'opengrep_only',*ARMS},'ARM_SET_INCOMPLETE')
    require(len({s['retained_opengrep'] for s in summaries.values()})==1,'CROSS_ARM_SCANNER_COUNT')
    require(len(set(policy_hashes.values()))==1,'POLICY79_NOT_SHARED_IDENTICAL')
    a={arm:{x['case_key']:x for x in traces[arm]['details']} for arm in ARMS}
    require(set(a['base'])==set(a['epoch_1'])==set(a['epoch_2']),'CROSS_ARM_CANDIDATES')
    for ident in a['base']:
        require(len({a[arm][ident]['input_token_ids_sha256'] for arm in ARMS})==1,'CROSS_ARM_TOKENS')
        require(len({a[arm][ident]['cache_key'] for arm in ARMS})==3,'CROSS_ARM_CACHE_COLLISION')
    return {'same_scanner_input':True,'same_candidate_input_tokens':True,'distinct_model_cache_namespaces':True,
        'same_policy79_paths':True,'new_native_requests':sum(x['new_requests'] for x in traces.values()),
        'warm_cache_hits':sum(x['cache_hits'] for x in traces.values()),
        'no_ground_truth_metrics_computed':True,'web_gate_promoted':False}

def sarif_view(exporter, rows, arm):
    data=exporter(rows)
    for run in data['runs']:
        run['tool']['driver']['name']='NTK B39B4 local four-arm comparison CLI'
        run['properties'].update(mode='OPENGREP_ONLY' if arm=='opengrep_only' else 'NATIVE_STAGE3_CODEQL_MIXED_EVIDENCE',
            arm=arm,model_xss_gate_granted=False,independent_gold=False,
            score_is_probability=False,legacy_score_description_is_not_confirmation=True)
        for item in run['results']:
            item['properties']['new_web_gate_granted']=False
            if arm=='opengrep_only':
                item['properties'].update(evidence_origin='OPENGREP_ONLY',sink_origin='NOT_APPLIED',
                    model_role_used_for_xss_score=False,source_policy_applied=False)
    return data
