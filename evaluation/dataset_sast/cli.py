#!/usr/bin/env python3
"""Offline saved-artifact dataset/SAST evaluator. No scan/train/model entrypoint."""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ntk_core import (Blocker, CWES, IDENTITY, canonical, convert_rows, digest, file_state,
    jsonl, loads, overlap, read_checked, require, safe_member, sha, stats, verify_sums,
    write_json, write_jsonl, zip_members)
from vendor.common import deny_inet
from eval_core import (ARMS, PROTOCOL, evaluate_vectors, initial_labels, normalize_reports,
                       unit_id, validate_labels, validate_units)

PINS = loads((ROOT/'PINS.json').read_bytes())


def now():
    return datetime.now(timezone.utc).isoformat()


def safe_under(root, relative):
    root = Path(root).resolve(strict=True)
    parts = safe_member(relative).parts
    dest = root
    for part in parts:
        dest = dest/part
        require(not dest.is_symlink(), 'SYMLINK_INPUT_REFUSED:'+str(relative))
    require(dest.resolve().is_relative_to(root), 'PATH_OUTSIDE_EXPECTED_ROOT')
    return dest


class Inputs:
    """Hash all files actually read and recheck them at action end; no tree-wide scan."""
    def __init__(self): self.files = {}
    def read(self, path, expected=None, limit=32*1024**2):
        path = Path(path)
        require(not path.is_symlink(), 'SYMLINK_INPUT_REFUSED:'+path.name)
        raw = read_checked(path, expected, limit=limit)
        record = {'sha256':sha(raw), 'size':len(raw)}
        key = str(path.absolute())
        require(key not in self.files or self.files[key] == record, 'INPUT_CHANGED_DURING_ACTION')
        self.files[key] = record
        return raw
    def verify(self):
        for path, rec in self.files.items():
            raw = read_checked(path, rec['sha256'])
            require(len(raw)==rec['size'], 'INPUT_SIZE_CHANGED')


def code_hashes():
    return {name:sha((ROOT/name).read_bytes()) for name in
            ('cli.py','eval_core.py','ntk_core.py','vendor/common.py','vendor/__init__.py','run.sh','PINS.json','UNITS.json')}


def release_state(work, inputs):
    result = {}
    for name, root, commit in [('iris', Path.home()/'iris', PINS['iris_commit']),
           ('github',Path.home()/'migration/ntk_github_publish_20261020',PINS['github_commit'])]:
        env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1')
        def get(*args):
            p = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),*args],
                env=env, capture_output=True, text=True, timeout=90)
            require(p.returncode==0, 'READ_ONLY_GIT_FAILED_'+name)
            return p.stdout.strip()
        head = get('rev-parse','HEAD'); status=get('status','--porcelain','--untracked-files=normal')
        require(head==commit and not status, 'FROZEN_GIT_DRIFT_'+name)
        result[name]={'head':head, 'status':status}
    gate_root = work/'batch38_policy_gates'
    result['gates']={p.name:sha(inputs.read(p)) for p in sorted(gate_root.glob('*.json'))}
    require('DPA_epoch_1.json' in result['gates'], 'EXISTING_DPA_GATE_MISSING')
    return result


def decode_audit(inputs, downloads, pins):
    receipt_raw = inputs.read(downloads/pins['receipt_name'], pins['receipt_sha256'])
    outer = zip_members(receipt_raw); count_outer = verify_sums(outer)
    receipt = loads(outer['WEB_JOB_RECEIPT.json'])
    require(receipt.get('status')=='B39B5_WEB_JOB_HTTP_CHAIN_VERIFIED' and not receipt.get('blockers'), 'WEB_RECEIPT_NOT_VERIFIED')
    require(receipt.get('run_id')==pins['run_id'] and receipt.get('input_sha256')==pins['input_sha256'], 'WRONG_WEB_RUN_OR_INPUT')
    backend_raw = outer['backend/'+pins['run_id']+'_result.zip']
    require(sha(backend_raw)==pins['backend_audit_sha256']==receipt['backend_audit_sha256'], 'BACKEND_AUDIT_SHA')
    backend = zip_members(backend_raw); count_inner=verify_sums(backend)
    state=loads(backend['00_RESULT.json'])
    require(state.get('status')=='B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE' and not state.get('blockers'), 'BACKEND_NOT_COMPLETE')
    require(state.get('completed_arms')==list(ARMS), 'BACKEND_MISSING_ARM')
    require(state.get('input_sha256')==pins['input_sha256'], 'BACKEND_INPUT_SHA')
    require(loads(backend['BEFORE.json'])==loads(backend['AFTER.json']), 'BACKEND_PARITY_FAILURE')
    return backend, {'receipt_sha256':sha(receipt_raw), 'backend_sha256':sha(backend_raw),
                     'receipt_manifest_entries':count_outer,'backend_manifest_entries':count_inner}


def audit_dataset(inputs, work, downloads, pins, native_cases):
    """Reuse locked B39B2 original train/dev bytes; does not recreate or relabel datasets."""
    archive = zip_members(inputs.read(downloads/pins['b2_name'],pins['b2_sha256']))
    verify_sums(archive); prior=loads(archive['DATA_LOCK.json'])
    require(loads(archive['00_RESULT.json'])['status']=='B39B2_DATA_LOCK_AND_LOCAL_ARMS_SMOKE_COMPLETE','B2_NOT_COMPLETE')
    folder=work/pins['b2_run_relative']/'private'
    parsed={}; calculations={}
    for split in ('train','validation'):
        name=split+'_original.jsonl'; expected=prior['private_artifact_hashes'][name]
        original=jsonl(inputs.read(safe_under(folder,name),expected))
        requests,targets=convert_rows(original)
        calculated=stats(requests,targets)
        require(calculated==prior[split], 'B2_DATA_SUMMARY_RECOMPUTATION_DRIFT_'+split)
        parsed[split]=(requests,targets); calculations[split]=calculated
    same=overlap(parsed['train'][0],parsed['validation'][0])
    require(same==prior['exact_overlap'],'B2_DATA_OVERLAP_RECOMPUTATION_DRIFT')
    def identity(c): return digest({k:c[k] for k in (*IDENTITY,'cwe')})
    run_keys={identity(c) for c in native_cases}
    require(len(run_keys)==len(native_cases),'DUPLICATE_NATIVE_CASES')
    native_prompt={digest(c['expected_messages']) for c in native_cases}
    checks={}
    for split,(requests,targets) in parsed.items():
        keys={identity(r['candidate']) for r in requests}
        prompts={r['prompt_sha256'] for r in requests}
        matrix={c:{role:sum(t['cwe']==c and t['label']['type']==role for t in targets)
                    for role in ('none','source','sink','taint-propagator')} for c in CWES}
        checks[split]={'cwe_role_including_zeros':matrix,
            'native_identity_cwe_overlap_count':len(keys & run_keys),
            'native_exact_prompt_overlap_count':len(prompts & native_prompt),
            'native_identity_overlap_hashes':sorted(keys & run_keys)}
    return {'schema':'NTK_B39B6_DATASET_QUALITY_V1', 'source':'B39B2_PINNED_ORIGINAL_WEAK_BYTES',
        'recomputed':calculations, 'train_validation_overlap':same, 'runtime_overlap':checks,
        'runtime_unique_api_cwe':len(native_cases),
        'limitations':['EXACT_MATCH_ONLY_NO_PROJECT_OR_NEAR_DUPLICATE_PROOF',
            'TRAIN_IDENTITY_DERIVED_FROM_STORED_WEAK_TARGET_NOT_REEXTRACTED_COMPILER_IDENTITY',
            'API_OVERLAP_IS_RECORDED_NOT_AUTOMATICALLY_A_PROJECT_LEAKAGE_VERDICT',
            'B39B4_FIXTURE_ALREADY_USED_FOR_DEVELOPMENT', 'NO_NEW_HUMAN_GOLD_CREATED'],
        'new_training':False, 'data_rows_removed_or_relabelled':0,
        'scorable_sink_recall_on_weak_validation':{c:calculations['validation']['cwe_role'].get(c+'|sink',0)>0 for c in CWES}}


def load_scorer(path, inputs):
    inputs.read(path,PINS['scorer_sha256'])
    module_name='ntk_b39b6_pinned_scorer'
    spec=importlib.util.spec_from_file_location(module_name,path)
    require(spec is not None and spec.loader is not None,'SCORER_IMPORT_SPEC')
    module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module
    spec.loader.exec_module(module)
    return module.SASTScoringEngine()


def validate_sarif(raw, result, arm):
    doc=loads(raw)
    require(doc.get('version')=='2.1.0' and isinstance(doc.get('runs'),list),'SARIF_SCHEMA')
    rows=[]
    for run in doc['runs']:
        require(run.get('properties',{}).get('arm')==arm,'SARIF_ARM_DRIFT')
        require(run['properties'].get('score_is_probability') is False, 'SARIF_SCORE_SEMANTICS')
        rows.extend(run['results'])
    byid={r.get('properties',{}).get('ntk_id'):r for r in rows}
    require(len(byid)==len(rows)==len(result['findings']) and set(byid)=={r['id'] for r in result['findings']},'SARIF_RESULT_ID_SET')
    for f in result['findings']:
        item=byid[f['id']]; props=item['properties']
        require(props.get('priority_score')==f['score'] and props.get('cwe')=='CWE-'+f['cwe'],'SARIF_SCORE_OR_CWE_MISMATCH')
        loc=item['locations'][0]['physicalLocation']
        require(loc['artifactLocation']['uri']==f['location']['uri'] and loc['region']['startLine']==f['location']['start_line'],'SARIF_LOCATION_MISMATCH')


def gather(work, downloads, workspace, scorer_path):
    """Complete prepare work. Public caller surrounds this with Git/gate parity checks."""
    inputs=Inputs();backend,audit=decode_audit(inputs,downloads,PINS)
    runroot=work/PINS['b4_run_relative']; privateroot=runroot/'private'
    private_manifest=loads(backend['PRIVATE_RESULT_MANIFEST.json'])
    source_raw=inputs.read(safe_under(privateroot,'project.zip'), PINS['input_sha256'],16*1024**2)
    source_members=zip_members(source_raw,max_total=32*1024**2)
    unit_spec=loads((ROOT/'UNITS.json').read_bytes())
    require(unit_spec['input_sha256']==PINS['input_sha256'],'UNIT_SPEC_INPUT')
    source_files={k:sha(v) for k,v in source_members.items() if k.endswith('.java')}
    require(source_files=={u['uri']:u['source_sha256'] for u in unit_spec['units']},'SOURCE_SET_OR_HASH_MISMATCH')
    units=[]
    for u in unit_spec['units']:
        content=source_members[u['uri']].decode('utf-8')
        units.append({**u,'input_sha256':PINS['input_sha256'],
            'unit_id':unit_id(PINS['input_sha256'],u['uri'],u['cwe']),
            'source_line_count':len(content.splitlines()),'source_origin':'B39B4_SYNTHETIC_DEVELOPMENT_FIXTURE'})
    validate_units(units)
    reports={};exports={}
    for arm in ARMS:
        for leaf in ('result.json','report.sarif'):
            rel='analysis/'+arm+'/'+leaf
            require(rel in private_manifest,'PRIVATE_EXPORT_MANIFEST_MISSING')
            raw=inputs.read(safe_under(privateroot,rel),private_manifest[rel])
            exports[rel]=sha(raw)
            if leaf=='result.json': reports[arm]=loads(raw)
            else: validate_sarif(raw,reports[arm],arm)
    native_rel='live/base/effective_native_config.json'
    native=loads(inputs.read(safe_under(privateroot,native_rel),private_manifest[native_rel]))
    require(isinstance(native.get('cases'),list),'NATIVE_CASE_MANIFEST_MISSING')
    require(len(native['cases'])==loads(backend['NATIVE_base.json'])['candidates'], 'NATIVE_CANDIDATE_COUNT_MISMATCH')
    dataset=audit_dataset(inputs,work,downloads,PINS,native['cases'])
    scorer=load_scorer(scorer_path,inputs)
    vectors,sast_audit=normalize_reports(reports,units,PINS['input_sha256'],scorer)
    comparison=loads(backend['COMPARISON.json'])
    for arm in ARMS:
        require(sast_audit['arms'][arm]['findings']==comparison['arms'][arm]['findings'], 'STORED_FINDING_COUNT_MISMATCH')
        require(sast_audit['arms'][arm]['origins'].get('OPENGREP',0)==comparison['arms'][arm]['retained_opengrep'],'STORED_RAW_FINDING_COUNT_MISMATCH')
    apistats={a:{k:loads(backend['NATIVE_'+a+'.json'])[k] for k in ('candidates','accepted','abstain','reasons','new_requests','cache_hits')}
              for a in ARMS[1:]}
    # Normalized vectors contain no source, prompt or model response bodies.
    (workspace/'private').mkdir(exist_ok=True)
    (workspace/'private/review_sources.zip').write_bytes(source_raw)
    write_json(workspace/'private/units.json',units)
    write_json(workspace/'private/vectors.json',vectors)
    write_jsonl(workspace/'private/labels.draft.jsonl',initial_labels(units))
    write_json(workspace/'DATASET_QUALITY.json',dataset)
    write_json(workspace/'SAST_INPUT_AUDIT.json', {**sast_audit,'verified_original_exports':exports,
        'source_sha256':PINS['input_sha256'],'source_files':source_files,
        'exact_source_duplicates':len(source_files)-len(set(source_files.values())),
        'native_api_stats_from_saved_backend':apistats,
        'native_stats_not_case_level_confusion':True,
        'metadata_archive_audit':audit,'no_new_scans':True})
    write_json(workspace/'EVAL_PROTOCOL.json',PROTOCOL)
    write_json(workspace/'LABEL_REVIEW_STATUS.json',{'units':len(units),'binary_reviewed':0,'unknown':len(units),
        'quality_metrics':None,'reason':'EXPLICIT_LABEL_REVIEW_AND_LOCK_REQUIRED',
        'already_exposed_to_model_predictions':True,'independent_gold':False})
    inputs.verify()
    lock={'schema':'NTK_B39B6_WORKSPACE_V1','code':code_hashes(),
          'original_inputs':inputs.files,'files':{},'created_at':now(),
          'input_sha256':PINS['input_sha256'],'run_id':PINS['run_id'],
          'scope':PROTOCOL['scope'],'independent_gold':False}
    for name in ('private/review_sources.zip','private/units.json','private/vectors.json','EVAL_PROTOCOL.json',
                 'DATASET_QUALITY.json','SAST_INPUT_AUDIT.json','LABEL_REVIEW_STATUS.json'):
        lock['files'][name]=sha((workspace/name).read_bytes())
    write_json(workspace/'WORKSPACE_LOCK.json',lock)
    for action in ('review','lock','evaluate'):
        extra=' --reviewer "${NTK_REVIEWER:?Set NTK_REVIEWER to your name or identifier}"' if action=='review' else ''
        cmd='exec bash '+shlex.quote(str(ROOT/'run.sh'))+' '+action+' --workspace '+shlex.quote(str(workspace))+extra
        (workspace/(action+'.sh')).write_text('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n'+cmd+'\n')
    return {'units':len(units),'train_rows':dataset['recomputed']['train']['rows'],
        'validation_rows':dataset['recomputed']['validation']['rows'],
        'scorer_replayed':sum(v['scorer_replayed'] for v in sast_audit['arms'].values()),
        'verified_original_exports':len(exports)}


def workspace_load(path):
    path=Path(path).expanduser().resolve(strict=True)
    require(not path.is_symlink(),'WORKSPACE_SYMLINK')
    lock=loads(read_checked(path/'WORKSPACE_LOCK.json'))
    require(lock.get('schema')=='NTK_B39B6_WORKSPACE_V1' and lock.get('code')==code_hashes(),'WORKSPACE_CODE_DRIFT')
    require(lock.get('scope')==PROTOCOL['scope'] and lock.get('independent_gold') is False,'WORKSPACE_SCOPE_DRIFT')
    for rel, expected in lock['files'].items(): read_checked(safe_under(path,rel),expected)
    require(loads((path/'EVAL_PROTOCOL.json').read_bytes())==PROTOCOL,'PROTOCOL_CHANGED')
    for original, rec in lock['original_inputs'].items(): read_checked(original,rec['sha256'])
    units=loads((path/'private/units.json').read_bytes())
    vectors=loads((path/'private/vectors.json').read_bytes())
    return path, lock, units, vectors


def pack(directory, downloads, names):
    downloads.mkdir(parents=True,exist_ok=True)
    require(all(isinstance(n,str) and not n.startswith('private/') for n in names),'PRIVATE_ARCHIVE_EXPORT_FORBIDDEN')
    mapping={n:sha(read_checked(safe_under(directory,n))) for n in names}
    sums=''.join(h+'  '+n+'\n' for n,h in sorted(mapping.items()))
    (directory/'SHA256SUMS').write_text(sums,encoding='ascii')
    out=downloads/(directory.name+'_result.zip')
    with zipfile.ZipFile(out,'x',zipfile.ZIP_DEFLATED) as z:
        for n in sorted(names): z.write(directory/n,n)
        z.write(directory/'SHA256SUMS','SHA256SUMS')
    with zipfile.ZipFile(out) as z: require(z.testzip() is None,'OUTPUT_CRC_FAILED')
    h=sha(out.read_bytes())
    with (downloads/(out.name+'.sha256')).open('x') as f:f.write(h+'  '+out.name+'\n')
    return out,h


def run_prepare(args):
    work=args.work.expanduser().resolve(strict=True);downloads=args.downloads.expanduser().resolve(strict=True)
    runid='b39b6_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    workspace=work/'batch39b6_dataset_sast'/runid
    forbidden=[Path.home()/'iris',Path.home()/'migration/ntk_github_publish_20261020']
    require(not any(workspace.resolve().is_relative_to(p.resolve()) for p in forbidden),'WORKSPACE_IN_FROZEN_REPOSITORY')
    workspace.mkdir(parents=True,exist_ok=False)
    result={'status':'B39B6_BLOCKED','blockers':[],'new_inference':False,'new_codeql':False,
            'new_training':False,'independent_gold':False,'labelled_ground_truth_metrics':False,'workspace':str(workspace)}
    before=None;inputs=Inputs()
    try:
        print('B39B6_STAGE=OFFLINE_AND_RELEASE_PARITY',flush=True)
        write_json(workspace/'NETWORK.json',deny_inet())
        before=release_state(work,inputs);write_json(workspace/'BEFORE.json',before)
        print('B39B6_STAGE=READ_PINNED_DATA_AND_SAVED_FOUR_ARM_RESULTS',flush=True)
        facts=gather(work,downloads,workspace,Path.home()/'iris/simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py')
        result.update(facts)
        result['status']='B39B6_PREPARED_REQUIRES_LABEL_REVIEW'
    except (Exception,KeyboardInterrupt) as exc:
        result['blockers'].append(type(exc).__name__+': '+str(exc)[:800])
    finally:
        try:
            after=release_state(work,Inputs());write_json(workspace/'AFTER.json',after)
            inputs.verify();require(before is not None and before==after,'FINAL_RELEASE_PARITY_FAILED')
        except Exception as exc:result['blockers'].append(type(exc).__name__+': '+str(exc)[:500])
        if result['blockers']:result['status']='B39B6_BLOCKED'
        write_json(workspace/'00_RESULT.json',result)
        # Strict explicit allowlist: neither original source nor review rationale is exported.
        names=[p.name for p in workspace.iterdir() if p.is_file() and p.name in
               {'00_RESULT.json','NETWORK.json','BEFORE.json','AFTER.json','DATASET_QUALITY.json',
                'SAST_INPUT_AUDIT.json','LABEL_REVIEW_STATUS.json','EVAL_PROTOCOL.json','WORKSPACE_LOCK.json'}]
        out,h=pack(workspace,downloads,names)
        print('\n===== B39B.6 RESULT =====',flush=True)
        for k,v in [('STATUS',result['status']),('BLOCKERS',len(result['blockers'])),('CASE_CWE_UNITS',result.get('units')),
                ('TRAIN_ROWS',result.get('train_rows')),('VALIDATION_ROWS',result.get('validation_rows')),
                ('ORIGINAL_EXPORTS_VERIFIED',result.get('verified_original_exports')),('SCORER_REPLAYED',result.get('scorer_replayed')),
                ('GROUND_TRUTH_METRICS','WITHHELD_UNTIL_REVIEW_AND_LOCK'),('NEW_GPU_INFERENCE',False),('NEW_CODEQL_SCAN',False),
                ('EVAL_WORKSPACE',workspace),('REVIEW_SCRIPT',workspace/'review.sh'),('OUTPUT_ZIP',out),('OUTPUT_SHA256',h)]:
            print(str(k)+'='+str(v),flush=True)
        for e in result['blockers']:print('BLOCKER='+e,flush=True)
    return 2 if result['blockers'] else 0


def atomic_draft(path,labels):
    tmp=path.with_name(path.name+'.tmp.'+uuid.uuid4().hex)
    tmp.write_text(''.join(canonical(x)+'\n' for x in labels),encoding='utf-8')
    os.replace(tmp,path)


def run_review(args):
    deny_inet()
    workspace,lock,units,vectors=workspace_load(args.workspace)
    require(not (workspace/'LABEL_LOCK.json').exists(),'LABELS_ALREADY_LOCKED_CREATE_NEW_WORKSPACE_FOR_REVISION')
    require(sys.stdin.isatty(),'INTERACTIVE_REVIEW_REQUIRES_TERMINAL')
    reviewer=args.reviewer.strip()
    require(bool(reviewer) and len(reviewer)<=200,'REVIEWER_ID_REQUIRED')
    draft=workspace/'private/labels.draft.jsonl'
    labels=jsonl(read_checked(draft));current=validate_labels(units,labels)
    sources=zip_members(read_checked(workspace/'private/review_sources.zip'))
    unitmap={u['unit_id']:u for u in units}
    print('Development review only. Predictions were already observed. No independent gold claim.')
    print('POSITIVE = target-CWE flaw under stated assumptions; NEGATIVE = target-CWE absent under them.')
    print('Use UNKNOWN when uncertain. Neither no path nor ABSTAIN is a label. No model scores are shown here.')
    for ordinal,label in enumerate(labels,1):
        if label['review_status']=='REVIEWED':continue
        u=unitmap[label['unit_id']]
        print('\n[%d/%d] CWE-%s %s\nunit=%s'%(ordinal,len(labels),u['cwe'],u['uri'],u['unit_id']))
        text=sources[u['uri']].decode('utf-8')
        for i,line in enumerate(text.splitlines(),1):
            safe=''.join(c if c=='\t' or ord(c)>=32 and ord(c)!=127 else '?' for c in line)
            print('%4d | %s'%(i,safe))
        while True:
            answer=input('Label [p=POSITIVE, n=NEGATIVE, u=UNKNOWN, q=save and quit]: ').strip().lower()
            if answer=='q':print('DRAFT_SAVED='+str(draft));return 0
            if answer in ('p','n','u'):break
        reason=input('Reason from source, not from predictions: ').strip()
        assumptions=input('Threat model / environment assumptions (or why unresolved): ').strip()
        lines=input('Evidence line numbers, comma separated: ').strip()
        try: numbers=sorted(set(int(x.strip()) for x in lines.split(',') if x.strip()))
        except ValueError:raise Blocker('INVALID_LINE_LIST_RESTART_REVIEW_TO_RESUME') from None
        update={**label,'truth':{'p':'POSITIVE','n':'NEGATIVE','u':'UNKNOWN'}[answer],
            'review_status':'REVIEWED','reviewer':reviewer,'reviewed_at':now(),'rationale':reason,
            'assumptions':assumptions,'evidence_lines':numbers}
        candidate=[update if x['unit_id']==label['unit_id'] else x for x in labels]
        validate_labels(units,candidate)
        labels=candidate;atomic_draft(draft,labels)
    print('REVIEW_COMPLETE_NOT_YET_LOCKED=True')
    print('NEXT_LOCK_COMMAND=bash '+shlex.quote(str(workspace/'lock.sh')))
    return 0


def run_lock(args):
    deny_inet()
    workspace,lock,units,vectors=workspace_load(args.workspace)
    require(not (workspace/'LABEL_LOCK.json').exists(),'LABEL_LOCK_ALREADY_EXISTS_NOT_OVERWRITTEN')
    raw=read_checked(workspace/'private/labels.draft.jsonl')
    labels=jsonl(raw);validate_labels(units,labels,for_lock=True)
    canonical_bytes=(''.join(canonical(x)+'\n' for x in sorted(labels,key=lambda x:x['unit_id']))).encode('utf-8')
    with (workspace/'private/labels.locked.jsonl').open('xb') as f:f.write(canonical_bytes)
    binding={'schema':'NTK_B39B6_LABEL_LOCK_V1','created_at':now(),'scope':PROTOCOL['scope'],
        'labels_sha256':sha(canonical_bytes),'draft_sha256':sha(raw),
        'workspace_lock_sha256':sha((workspace/'WORKSPACE_LOCK.json').read_bytes()),
        'protocol_sha256':digest(PROTOCOL),'code':code_hashes(),'independent_gold':False,
        'truth_counts':dict(Counter(x['truth'] for x in labels)),
        'review_assertions_are_user_supplied_not_an_independent_reviewer_attestation':True}
    write_json(workspace/'LABEL_LOCK.json',binding)
    print('STATUS=B39B6_DEVELOPMENT_LABELS_LOCKED')
    print('LABEL_LOCK_SHA256='+sha((workspace/'LABEL_LOCK.json').read_bytes()))
    print('TRUTH_COUNTS='+canonical(binding['truth_counts']))
    print('NEXT_EVALUATE_COMMAND=bash '+shlex.quote(str(workspace/'evaluate.sh')))
    return 0


def run_evaluate(args):
    deny_inet()
    workspace,wlock,units,vectors=workspace_load(args.workspace)
    lockraw=read_checked(workspace/'LABEL_LOCK.json');lock=loads(lockraw)
    require(lock.get('schema')=='NTK_B39B6_LABEL_LOCK_V1' and lock['code']==code_hashes() and
       lock['scope']==PROTOCOL['scope'] and lock['independent_gold'] is False,'LABEL_LOCK_SCHEMA_OR_SCOPE')
    require(sha((workspace/'WORKSPACE_LOCK.json').read_bytes())==lock['workspace_lock_sha256'] and
            digest(PROTOCOL)==lock['protocol_sha256'],'LABEL_BINDING_DRIFT')
    read_checked(workspace/'private/labels.draft.jsonl',lock['draft_sha256'])
    raw=read_checked(workspace/'private/labels.locked.jsonl',lock['labels_sha256'])
    labels=jsonl(raw)
    metrics=evaluate_vectors(vectors,units,labels,PROTOCOL)
    runid='b39b6_eval_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    output=workspace/runid;output.mkdir(exist_ok=False)
    write_json(output/'METRICS.json',metrics)
    # Enough anonymous vectors for independent metric replay; no code text or model completions.
    byid={l['unit_id']:l for l in labels}
    exported={arm:[{k:r[k] for k in ('unit_id','cwe','score','raw_opengrep','any_reported_alert',
                  'qualified_evidence','qualified_model','qualified_policy') }|{'truth':byid[r['unit_id']]['truth']}
                  for r in rows] for arm,rows in vectors.items()}
    write_json(output/'EVALUATION_VECTORS.json',exported)
    write_json(output/'EVAL_PROTOCOL.json',PROTOCOL)
    write_json(output/'LABEL_LOCK_PROOF.json',lock)
    # Explicitly do not assert quality or acceptance based on numeric outcomes.
    status='B39B6_DEVELOPMENT_METRICS_COMPUTED' if metrics['truth_counts'].get('UNKNOWN',0)==0 else 'B39B6_PARTIAL_METRICS_UNKNOWN_PRESERVED'
    write_json(output/'00_RESULT.json',{'status':status,'blockers':[], 'workspace':str(workspace),
        'label_lock_sha256':sha(lockraw),'truth_counts':metrics['truth_counts'],'independent_gold':False,
        'new_training':False,'new_inference':False,'new_codeql':False,'scorer_or_threshold_changed':False,
        'quality_threshold_applied':None})
    workspace_load(workspace)
    downloads=args.downloads.expanduser().resolve(strict=True)
    out,h=pack(output,downloads,[p.name for p in output.iterdir() if p.is_file()])
    print('\n===== B39B.6 EVALUATION RESULT =====')
    for k,v in [('STATUS',status),('BLOCKERS',0),('INDEPENDENT_GOLD',False),('OUTPUT_ZIP',out),('OUTPUT_SHA256',h)]:print(str(k)+'='+str(v))
    return 0


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    s=p.add_subparsers(dest='action',required=True)
    d=Path('/mnt/c/Users/HP/Downloads');w=Path.home()/'migration/ntk_stage3_verified_v5_work'
    pr=s.add_parser('prepare');pr.add_argument('--work',type=Path,default=w);pr.add_argument('--downloads',type=Path,default=d)
    for action in ('review','lock','evaluate'):
        sub=s.add_parser(action);sub.add_argument('--workspace',type=Path,required=True)
        if action=='review':sub.add_argument('--reviewer',required=True)
        if action=='evaluate':sub.add_argument('--downloads',type=Path,default=d)
    a=p.parse_args()
    return {'prepare':run_prepare,'review':run_review,'lock':run_lock,'evaluate':run_evaluate}[a.action](a)


if __name__=='__main__':
    try: sys.exit(main())
    except (Exception,KeyboardInterrupt) as exc:
        print('B39B6_BLOCKED='+type(exc).__name__+': '+str(exc),flush=True)
        sys.exit(2)
