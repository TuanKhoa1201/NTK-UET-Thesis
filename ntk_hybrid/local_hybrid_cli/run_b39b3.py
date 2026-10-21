#!/usr/bin/env python3
"""Complete native IRIS Stage 3 batch evaluation on the already locked weak validation.
No new gold, training, database, web gate, scanner rules, or scorer changes.
"""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ntk_core import (Blocker, CWES, IDENTITY, canonical, convert_rows, digest, evaluate,
    file_state, jsonl, loads, read_checked, require, safe_member, sha, stats,
    verify_sums, write_json, write_jsonl, zip_members)
from ntk_runtime import offline_env
from run_b39b2 import PINS, baseline, make_runtime_configs, pack
from vendor.common import ADAPTER_SHA, ADAPTER_CONFIG_SHA, deny_inet
B2_NAME = 'b39b2_20261020T045315Z_bf52f398_result.zip'
B2_SHA = '5ada3b025c9cf99d3e3f908e5767d9b867b818872f16b827bb936c2724c39585'
B2_RUN = 'batch39b2_data_runtime/b39b2_20261020T045315Z_bf52f398'
ARMS = ('base', 'epoch_1', 'epoch_2')


def native_key(case):
    return digest([case['cwe'], [case[k] for k in IDENTITY]])


def load_data(work, downloads, states):
    members = zip_members(read_checked(downloads/B2_NAME, B2_SHA, states=states))
    verified = verify_sums(members)
    old = loads(members['00_RESULT.json'])
    require(old['status'] == 'B39B2_DATA_LOCK_AND_LOCAL_ARMS_SMOKE_COMPLETE' and not old['blockers'],
            'B39B2_NOT_SUCCESSFUL')
    require(loads(members['BEFORE.json']) == loads(members['AFTER.json']), 'B2_REPORTED_BASELINE_DRIFT')
    lock = loads(members['DATA_LOCK.json'])
    require(lock['scope'] == 'PINNED_B28_WEAK_TRAIN_AND_DEV_NOT_GOLD', 'B2_LABEL_AUTHORITY_CHANGED')
    private = work/B2_RUN/'private'
    saved = {}
    for name in ('validation_original.jsonl', 'validation.requests.jsonl', 'validation.targets.jsonl'):
        saved[name] = read_checked(private/name, lock['private_artifact_hashes'][name], states=states)
    requests, targets = convert_rows(jsonl(saved['validation_original.jsonl']))
    require(requests == jsonl(saved['validation.requests.jsonl']) and targets == jsonl(saved['validation.targets.jsonl']),
            'B2_REQUEST_TARGET_RECONSTRUCTION_MISMATCH')
    require(len(requests) == 137 and stats(requests, targets) == lock['validation'], 'B2_VALIDATION_STATS_DRIFT')
    require(len({native_key(r['candidate']) for r in requests}) == len(requests), 'DUPLICATE_NATIVE_CANDIDATE')
    raw_cases = [{**r['candidate'], 'source_record_sha256': r['source_record_sha256']} for r in requests]
    return requests, targets, raw_cases, members, lock, verified


def unpack_snapshot(data, snapshot):
    require(len(data) <= 256*1024**2, 'GIT_ARCHIVE_SIZE_LIMIT')
    snapshot.mkdir(exist_ok=False)
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        entries = archive.getmembers()
        require(len(entries) <= 20000, 'GIT_ARCHIVE_ENTRY_LIMIT')
        names = set()
        for item in entries:
            name = item.name.rstrip('/')
            safe_member(name)
            require(name not in names, 'DUPLICATE_GIT_ARCHIVE_PATH')
            names.add(name)
            path = snapshot/name
            require(path.resolve().is_relative_to(snapshot.resolve()), 'GIT_PATH_ESCAPE')
            if item.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                total += item.size
                require(total <= 256*1024**2, 'GIT_ARCHIVE_EXPANDED_LIMIT')
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                path.chmod(item.mode & 0o777)
                files[name] = sha(path.read_bytes())
            elif item.issym():
                target = (path.parent/item.linkname).resolve()
                require(target.is_relative_to(snapshot.resolve()), 'EXTERNAL_GIT_SYMLINK')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(item.linkname)
            else:
                raise Blocker('UNSUPPORTED_GIT_ARCHIVE_ENTRY')
    require('src/iris.py' in files, 'SNAPSHOT_IRIS_MISSING')
    return {'source': 'GIT_ARCHIVE_FROZEN_COMMIT', 'commit': PINS['iris_commit'],
            'regular_file_count': len(files), 'regular_files_fingerprint': digest(files),
            'unpacked_bytes': total, 'symlinks': len([x for x in entries if x.issym()])}


def run_child(argv, log, cwd, timeout, trace=None, progress_label=''):
    started = time.monotonic()
    result = {'timeout_s': timeout, 'escalations': [], 'returncode': None,
              'process_group_owned': True, 'timed_out': False}
    pending = None
    with Path(log).open('xb') as out:
        p = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=offline_env(), close_fds=True,
                             stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        result['pid'] = p.pid
        last = -1
        try:
            while p.poll() is None:
                if time.monotonic()-started > timeout:
                    result['timed_out'] = True
                    raise Blocker('NATIVE_CHILD_TIMEOUT')
                if trace is not None and trace.is_file():
                    # Observations are rewritten by the frozen provider. Empty/partial reads are ignored.
                    count = trace.read_bytes().count(b'\n')
                    if count >= last+10 or count in (137,274):
                        if count != last:
                            print('B39B3_PROGRESS=' + progress_label + ' trace_rows=' + str(count), flush=True)
                            last = count
                time.sleep(0.25)
            result['returncode'] = p.returncode
        except BaseException as e:
            pending = e
        finally:
            def group_alive():
                p.poll()
                try:
                    os.killpg(p.pid, 0)
                    return True
                except ProcessLookupError:
                    return False
            if group_alive():
                for sig, grace in ((signal.SIGTERM,20), (signal.SIGKILL,5)):
                    if not group_alive():
                        break
                    result['escalations'].append(sig.name)
                    try:
                        os.killpg(p.pid, sig)
                    except ProcessLookupError:
                        break
                    until = time.monotonic() + grace
                    while group_alive() and time.monotonic() < until:
                        time.sleep(0.1)
            result['process_group_still_running'] = group_alive()
            result['returncode'] = p.poll()
            result['still_running'] = p.poll() is None
            result['elapsed_s'] = time.monotonic()-started
    # Persist metadata even if interrupted. Logs remain private.
    write_json(Path(log).with_suffix('.process.json'), result)
    if pending is not None:
        raise pending
    require(not result['still_running'] and not result['process_group_still_running'], 'NATIVE_DRIVER_NOT_STOPPED')
    return result


def build_requests(old_requests, native_cases):
    by_key = {native_key(c): c for c in native_cases}
    require(len(by_key) == len(native_cases) == len(old_requests), 'NATIVE_INPUT_COUNT')
    requests, changed = [], []
    for r in old_requests:
        case = by_key.get(native_key(r['candidate']))
        require(case is not None, 'NATIVE_INPUT_NOT_IN_VALIDATION')
        messages = case['expected_messages']
        require(len(messages) == 2 and [x['role'] for x in messages] == ['system','user'], 'NATIVE_TARGET_LEAK')
        require(all(set(x) == {'role','content'} and type(x['content']) is str for x in messages), 'NATIVE_MESSAGE_SCHEMA')
        prompt = digest(messages)
        requests.append({**r, 'messages': messages, 'prompt_sha256': prompt})
        changed.append({'sample_id_sha256': digest(r['id']), 'cwe': r['cwe'],
                        'b28_prompt_sha256': r['prompt_sha256'], 'native_prompt_sha256': prompt,
                        'same_prompt_bytes': messages == r['messages']})
    return requests, {'n': len(requests), 'same_b28_prompt': sum(x['same_prompt_bytes'] for x in changed),
        'changed_b28_prompt': sum(not x['same_prompt_bytes'] for x in changed),
        'policy': 'USE_FROZEN_NATIVE_PROMPT_NO_REPAIR_NO_TARGET_TEXT',
        'historical_metrics_comparison': 'PROMPT_SHIFT_POSSIBLE_NOT_IDENTICAL_PROTOCOL_CLAIM',
        'details': changed}


def summarize_trace(requests, targets, trace, summary, expected_runtime):
    require(summary.get('status') == 'B39B3_NATIVE_ARM_COMPLETE', 'NATIVE_ARM_NOT_COMPLETE')
    worker = summary['worker']
    require(worker['versions'] == expected_runtime and worker['arm'] == summary['arm'], 'NATIVE_WORKER_VERSION_OR_ARM')
    require(worker['ready'] is True and worker['training_executed'] is False and worker['trainable_parameters'] == 0,
            'NATIVE_WORKER_NOT_INFERENCE_ONLY')
    require(all(worker['isolation'][f] == 'DENIED_EPERM' for f in ('AF_INET','AF_INET6')), 'WORKER_NETWORK_NOT_DENIED')
    require(summary['native_method_invocations'] == 8, 'NATIVE_INVOCATION_COUNT')
    require(summary['cleanup']['worker_returncode'] == 0 and summary['cleanup']['worker_still_running'] is False,
            'NATIVE_CLEANUP_FAILED')
    req = {native_key(r['candidate']): r for r in requests}
    phases = {}
    for mode in ('cold','warm'):
        rows = [x for x in trace if x['phase'] == mode]
        phases[mode] = {x['case_key']: x for x in rows}
        require(len(phases[mode]) == len(rows) == len(req) and set(phases[mode]) == set(req),
                'NATIVE_TRACE_ID_COVERAGE_' + mode)
    require(len(trace) == len(req)*2, 'EXTRA_NATIVE_TRACE_PHASES')
    predictions, measurements, cache_keys = [], [], {}
    for key, r in req.items():
        cold, warm = phases['cold'][key], phases['warm'][key]
        for x in (cold,warm):
            require(not x.get('infrastructure_failure') and isinstance(x.get('raw_completion'),str), 'NATIVE_INFRASTRUCTURE_FAILURE')
            require(x['prompt_sha256'] == r['prompt_sha256'], 'TRACE_PROMPT_DIFFERS_FROM_PLAN')
            require(x['source_record_sha256'] == r['source_record_sha256'], 'TRACE_SOURCE_RECORD_CHANGED')
            require(x['candidate'] == {k:r['candidate'][k] for k in (*IDENTITY,'cwe')}, 'TRACE_CANDIDATE_CHANGED')
        require(cold['cache_hit'] is False and warm['cache_hit'] is True, 'CACHE_PHASE_MISMATCH')
        require(cold['raw_completion'] == warm['raw_completion'] and cold['label'] == warm['label'] and
                cold['status'] == warm['status'] and cold['reason'] == warm['reason'] and cold['cache_key'] == warm['cache_key'],
                'CACHE_RESULT_DRIFT')
        reply = cold['worker']
        require(isinstance(reply,dict) and re.fullmatch('[a-f0-9]{64}',reply['input_token_ids_sha256']), 'INPUT_TOKEN_PROOF')
        for k in ('generation_s','input_tokens','output_tokens','peak_vram_allocated_bytes','peak_vram_reserved_bytes'):
            require(type(reply.get(k)) in (int,float) and math.isfinite(reply[k]) and reply[k] >= 0, 'INVALID_MEASUREMENT_'+k)
        predictions.append({'id': r['id'], 'cwe':r['cwe'], 'raw':cold['raw_completion']})
        measurements.append({'sample_id_sha256':digest(r['id']), 'cwe':r['cwe'], **reply,
                             'cache_hit':False,'transport_wall_s':cold['latency_s']})
        cache_keys[digest(r['id'])] = cold['cache_key']
    metric, details = evaluate(requests, targets, predictions)
    for d,r in zip(details,requests):
        row = phases['cold'][native_key(r['candidate'])]
        require(d['status'] == row['status'] and d['reason'] == row['reason'], 'EVALUATOR_NATIVE_PARSER_DIVERGENCE')
    per_cwe = {}
    for c in CWES:
        ids = {canonical(r['id']) for r in requests if r['cwe'] == c}
        if ids:
            per_cwe[c] = evaluate([r for r in requests if canonical(r['id']) in ids],
                [t for t in targets if canonical(t['id']) in ids],
                [p for p in predictions if canonical(p['id']) in ids])[0]
    gens = [x['generation_s'] for x in measurements]
    perf = {'n_live_requests':len(gens), 'model_load_s':worker['load_s'],
            'worker_generation_total_s':sum(gens), 'worker_generation_median_s':statistics.median(gens),
            'worker_generation_min_s':min(gens), 'worker_generation_max_s':max(gens),
            'peak_pytorch_allocated_bytes':max(x['peak_vram_allocated_bytes'] for x in measurements),
            'peak_pytorch_reserved_bytes':max(x['peak_vram_reserved_bytes'] for x in measurements),
            'warm_cache_hit_count':len(requests), 'cache_hit_latency_benchmark':'NOT_MEASURED_FROZEN_PROVIDER_REPORTS_PLACEHOLDER_ZERO',
            'load_condition':'NEW_WORKER_NOT_OS_PAGE_CACHE_COLD',
            'generation_scope':'TOKENIZE_GENERATE_DECODE_NOT_KERNEL_ONLY',
            'gpu_total_vram':'NOT_MEASURED', 'repeats':1}
    return {'arm': summary['arm'], 'metrics':metric, 'per_cwe':per_cwe, 'details':details,
            'measurements':measurements, 'performance':perf, 'worker':worker,
            'cleanup':summary['cleanup'], 'cache_keys':cache_keys,
            'native_method_invocations':8, 'raw_completion_exported':False,
            'label_authority':'WEAK_DEV_NOT_GOLD', 'new_inference':True}, predictions


def cross_arm(arms):
    require(set(arms) == set(ARMS), 'THREE_ARMS_REQUIRED')
    templates = {x['worker']['tokenizer_chat_template_sha256'] for x in arms.values()}
    require(len(templates) == 1, 'TOKENIZER_DIFFERS_ACROSS_ARMS')
    inputs = {a:{r['sample_id_sha256']:r['input_token_ids_sha256'] for r in v['measurements']} for a,v in arms.items()}
    require(inputs['base'] == inputs['epoch_1'] == inputs['epoch_2'], 'NATIVE_TOKEN_INPUTS_DIFFER_ACROSS_ARMS')
    for sample in inputs['base']:
        require(len({v['cache_keys'][sample] for v in arms.values()}) == 3, 'CROSS_ARM_CACHE_NAMESPACE_COLLISION')
    return {'same_tokenized_inputs':True,'same_chat_template':True,'distinct_arm_cache_keys':True,
            'n_inputs':len(inputs['base']),'real_requests':sum(v['metrics']['n'] for v in arms.values()),
            'warm_cache_hits':sum(v['metrics']['n'] for v in arms.values())}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work',type=Path,default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    p.add_argument('--repo',type=Path,default=Path.home()/'iris')
    p.add_argument('--github',type=Path,default=Path.home()/'migration/ntk_github_publish_20261020')
    p.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
    p.add_argument('--host-python',type=Path,required=True)
    p.add_argument('--run-native',action='store_true',help='Explicitly execute all 137 x 3 real native requests')
    a=p.parse_args(argv)
    for key in ('work','repo','github','downloads'):
        setattr(a,key,getattr(a,key).expanduser().resolve())
    require(a.work.is_dir() and a.downloads.is_dir(),'WORK_OR_DOWNLOADS_MISSING')
    require(not a.work.is_relative_to(a.repo) and not a.work.is_relative_to(a.github),'OUTPUT_IN_PROTECTED_REPO')
    require(a.host_python.is_file() and os.access(a.host_python,os.X_OK),'HOST_PYTHON_MISSING')
    run=a.work/'batch39b3_native_validation'/('b39b3_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True,exist_ok=False); os.chmod(run,0o700)
    private=run/'private'; private.mkdir()
    states={};before=None; locks=[]; arms={};began=time.monotonic()
    result={'status':'B39B3_BLOCKED','blockers':[],'run_name':run.name,'new_training':'NOT_EXECUTED',
            'new_codeql_database':'NOT_EXECUTED','new_opengrep_scan':'NOT_EXECUTED','web_gate_changed_by_runner':False,
            'independent_gold':False,'native_stage3_method':'NOT_EXECUTED','model_inference':'NOT_EXECUTED',
            'stage4':'NOT_EXECUTED','full_SAPipeline_run':'NOT_EXECUTED','completed_arms':[]}
    def event(s):print('B39B3_STAGE='+s,flush=True)
    def interrupt(signum,frame):raise KeyboardInterrupt('INTERRUPTED')
    signal.signal(signal.SIGTERM,interrupt)
    try:
        event('VERIFY_B39B2_LOCK_AND_RELEASE')
        write_json(run/'NETWORK.json',deny_inet())
        before=baseline(a.work,a.repo,a.github,states);write_json(run/'BEFORE.json',before)
        requests,targets,cases,b2,lock,count=load_data(a.work,a.downloads,states)
        require(before==loads(b2['BEFORE.json']),'RELEASE_BASELINE_DIFFERS_FROM_B39B2')
        write_json(run/'INPUT_PROVENANCE.json',{'b2_zip_sha256':B2_SHA,'b2_manifest_entries':count,
            'validation_sha256':lock['validation_sha256'],'n':len(requests), 'validation_stats':lock['validation'],
            'exact_overlap':lock['exact_overlap'],'train_reference_contract_failures_kept':lock['train']['reference_contract_failures_kept'],
            'warnings':['WEAK_DEV_ALREADY_USED_NOT_GOLD','NO_VALIDATION_SINK_CWE78_CWE79','EIGHT_TRAIN_RECEIVER_TARGETS_NOT_NATIVE_ACCEPTED_NOT_MODIFIED'],
            'candidate_origin':'STORED_WEAK_REFERENCE_IDENTITY_NOT_NEW_COMPILER_RESOLUTION'})
        engine=Path((a.work/'NTK_BATCH38_POLICY_TOOL_PATH.txt').read_text().strip()).resolve()/'engine'
        require(shutil.disk_usage(run).free >= 2*1024**3,'LESS_THAN_2_GIB_FREE')
        event('ISOLATED_FROZEN_IRIS_SNAPSHOT')
        child=subprocess.run(['git','-C',str(a.repo),'archive','--format=tar',PINS['iris_commit']],
                             capture_output=True,timeout=120,env=offline_env())
        require(child.returncode==0,'GIT_ARCHIVE_FAILED')
        snapshot=private/'snapshot'
        write_json(run/'SNAPSHOT.json',unpack_snapshot(child.stdout,snapshot))
        b33=zip_members(read_checked(a.downloads/PINS['b33_name'],PINS['b33_sha256'],states=states))
        protocol=b33['inputs/runtime_protocol.json']; (private/'runtime_protocol.json').write_bytes(protocol)
        prepdir=private/'prepare';prepdir.mkdir()
        cfg={'snapshot':str(snapshot),'engine':str(engine),'protocol_path':str(private/'runtime_protocol.json'),
             'prepare_dir':str(prepdir),'raw_cases':cases}
        cfgpath=private/'prepare_config.json';write_json(cfgpath,cfg)
        event('REAL_IRIS_IMPORT_AND_NATIVE_PROMPT_PREFLIGHT_NO_GPU')
        childres=run_child([a.host_python,'-I','-B','-u',ROOT/'native_driver.py','prepare',cfgpath],
                           prepdir/'driver.log',private,180)
        dr=loads((prepdir/'DRIVER_RESULT.json').read_bytes()) if (prepdir/'DRIVER_RESULT.json').is_file() else {}
        write_json(run/'PREFLIGHT_RESULT.json',{'process':childres,'driver':dr})
        require(childres['returncode']==0 and dr.get('status')=='NATIVE_IMPORT_AND_INPUT_PREPARE_COMPLETE',
                'NATIVE_PREPARE_FAILED:'+str(dr.get('blocker','see private/prepare/driver.log')))
        prepared=loads((prepdir/'PREPARED.json').read_bytes())
        native_cases=loads((prepdir/'NATIVE_INPUTS.json').read_bytes())
        native_requests,prompt_proof=build_requests(requests,native_cases)
        write_json(run/'PROMPT_PARITY.json',prompt_proof)
        patch=loads((prepdir/'PATCH_PROOF.json').read_bytes())
        write_json(run/'PATCH_PROOF_PUBLIC.json',{k:v for k,v in patch.items() if k!='native_system_prompt'})
        require(patch['stage4_and_get_model_body_unchanged'] is True,'UNEXPECTED_PATCH_SCOPE')
        write_jsonl(private/'native.requests.jsonl',native_requests)
        write_jsonl(private/'validation.targets.jsonl',targets)
        # No numeric pass threshold on model quality; invalid answers remain ABSTAIN.
        write_json(run/'EVALUATION_PROTOCOL.json',{'status':'LOCKED_BEFORE_NEW_INFERENCE','n':137,'arms':list(ARMS),
            'input_ids_sha256':digest([r['id'] for r in native_requests]),'case_inputs_sha256':prepared['case_inputs_sha256'],
            'targets_sha256':sha((private/'validation.targets.jsonl').read_bytes()),
            'runtime_generation':loads(b2['RUNTIME_CONFIG_PROVENANCE.json'])['generation'],
            'runtime_versions':PINS['runtime_versions'],'adapter_sha256':ADAPTER_SHA,
            'native_module_sha256':prepared['source_sha256'],
            'parser': 'ntk-strict-six-fields-v33.1','evaluator_sha256':sha((ROOT/'ntk_core.py').read_bytes()),
            'driver_sha256':sha((ROOT/'native_driver.py').read_bytes()),'zero_support_recall':'NULL',
            'sink_args':'EXACT_LIST_MATCH','invalid_output':'ABSTAIN_NOT_NONE','label_authority':'WEAK_DEV_NOT_GOLD',
            'selection_rule':'ALL_137_LOCKED_VALIDATION_ROWS_NO_EXCLUSIONS', 'quality_threshold':'NONE_NOT_A_MODEL_ACCEPTANCE_GATE',
            'native_method':'SAPipeline.query_gpt_for_api_src_tp_sink_batched', 'policy_source':'FROZEN_NATIVE_IRIS_PROTOCOL_FROM_B33'})
        if a.run_native:
            event('VERIFY_MODELS_AND_PINNED_GENERATION')
            assets=private/'runtime_assets';assets.mkdir()
            configs=make_runtime_configs(a.work,a.downloads,assets,states)
            runtime_proof=loads((assets/'RUNTIME_CONFIG_PROVENANCE.json').read_bytes())
            runtime_proof.update(scope='NATIVE_IMPORTED_STAGE3_WITH_FROZEN_B33_PROVIDER_AND_WORKER',
                                 cache='FRESH_PER_ARM_COLD_LIVE_THEN_WARM_CACHE',
                                 original_asset_check_proof_sha256=sha((assets/'RUNTIME_CONFIG_PROVENANCE.json').read_bytes()))
            write_json(run/'RUNTIME_CONFIG_PROVENANCE.json',runtime_proof)
            require(runtime_proof['generation']==loads(b2['RUNTIME_CONFIG_PROVENANCE.json'])['generation'],
                    'GENERATION_DIFFERS_FROM_LOCKED_B39B2')
            token_cfg=private/'tokenizer_config.json'
            write_json(token_cfg,{**configs['base'],'cases':native_cases})
            event('ALL_137_NATIVE_PROMPTS_CPU_TOKENIZER_PREFLIGHT')
            tres=run_child([a.work/'.ntk_v5_lora_venv/bin/python','-I','-B',ROOT/'tokenizer_preflight.py',
                           token_cfg,run/'TOKENIZER_PREFLIGHT.json'],private/'tokenizer.log',private,180)
            require(tres['returncode']==0,'TOKENIZER_PREFLIGHT_FAILED_SEE_PRIVATE_TOKENIZER_LOG')
            token_proof=loads((run/'TOKENIZER_PREFLIGHT.json').read_bytes())
            require(token_proof['status']=='TOKENIZER_CPU_PREFLIGHT_COMPLETE' and token_proof['n']==137,
                    'TOKENIZER_PREFLIGHT_INCOMPLETE')

            for name in ('batch38_gpu_scan.lock','batch39b2_gpu.lock','batch39b3_gpu.lock'):
                f=(a.work/name).open('a+');locks.append(f)
                try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise Blocker('ANOTHER_SCAN_HOLDS_'+name) from None
            probe=subprocess.run(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'],
                                  capture_output=True,text=True,timeout=30,env=offline_env())
            require(probe.returncode==0 and not probe.stdout.strip(),'GPU_NOT_IDLE_OR_PROBE_FAILED')
            write_json(run/'GPU_PREFLIGHT.json',{'returncode':0,'compute_processes':0})
            result['model_inference']='ATTEMPTED_REAL_NATIVE_LOCAL_GPU'
            result['native_stage3_method']='ATTEMPTING_REAL_NATIVE_STAGE3'
            for arm in ARMS:
                event('NATIVE_STAGE3_'+arm.upper()+'_137_LIVE_AND_137_CACHE')
                folder=private/arm;folder.mkdir()
                config={**cfg,**configs[arm], 'cases':native_cases,'preparation_proof':prepared,
                    'output_dir':str(folder),'cache_dir':str(folder/'cache'),'cache_mode':'readwrite',
                    'frozen_root':str(a.repo),'ml_python':str(a.work/'.ntk_v5_lora_venv/bin/python'),
                    'adapter_sha256':None if arm=='base' else ADAPTER_SHA[arm],
                    'adapter_config_sha256':None if arm=='base' else ADAPTER_CONFIG_SHA,
                    'request_timeout_s':configs[arm]['generation']['generation_timeout_s']+30,'load_timeout_s':300}
                path=folder/'config.json';write_json(path,config)
                res=run_child([a.host_python,'-I','-B','-u',ROOT/'native_driver.py','run',path],folder/'driver.log',
                    folder,3600,folder/'native_trace.jsonl',arm)
                summary=loads((folder/'DRIVER_RESULT.json').read_bytes()) if (folder/'DRIVER_RESULT.json').is_file() else {}
                write_json(run/('PROCESS_'+arm+'.json'),{'process':res,'driver':summary})
                require(res['returncode']==0 and summary.get('status')=='B39B3_NATIVE_ARM_COMPLETE',
                        'NATIVE_ARM_FAILED_'+arm+':'+str(summary.get('blocker','see private driver.log')))
                trace=jsonl((folder/'native_trace.jsonl').read_bytes())
                armres,preds=summarize_trace(native_requests,targets,trace,summary,configs[arm]['runtime_versions'])
                planned_tokens={r['case_key']:r['input_token_ids_sha256'] for r in token_proof['rows']}
                id_to_case={digest(r['id']):native_key(r['candidate']) for r in native_requests}
                require(armres['worker']['tokenizer_chat_template_sha256']==token_proof['tokenizer_chat_template_sha256'],
                        'WORKER_TEMPLATE_DIFFERS_FROM_CPU_PREFLIGHT')
                for measurement in armres['measurements']:
                    require(measurement['input_token_ids_sha256']==planned_tokens[id_to_case[measurement['sample_id_sha256']]],
                            'WORKER_TOKENS_DIFFER_FROM_CPU_PREFLIGHT')
                arms[arm]=armres;write_json(run/('NATIVE_'+arm+'.json'),armres)
                write_jsonl(folder/'predictions_id_joined.jsonl',preds)
                result['completed_arms'].append(arm)
            parity=cross_arm(arms)
            write_json(run/'COMPARISON.json',{'parity':parity,'per_arm':{a:{k:v[k] for k in ('metrics','per_cwe','performance')} for a,v in arms.items()},
                'old_b28_replay_metrics':loads(b2['REPLAY_SUMMARY.json'])['arms'],
                'historical_comparison_scope':'B28_STORED_PROMPT_VS_NATIVE_RUNTIME_PROMPT_MEASURED_IN_PROMPT_PARITY',
                'no_new_gold':True,'no_web_model_promotion':True})
            result.update(status='B39B3_NATIVE_WEAK_VALIDATION_COMPLETE',native_stage3_method='EXECUTED',
                model_inference='REAL_LOCAL_GPU_411_REQUESTS',real_requests=parity['real_requests'],
                warm_cache_hits=parity['warm_cache_hits'],native_method_invocations=24)
        else:
            result['status']='B39B3_NATIVE_PREFLIGHT_COMPLETE_NO_INFERENCE'
    except (Exception,KeyboardInterrupt) as e:
        result['status']='B39B3_BLOCKED';result['blockers'].append(type(e).__name__+': '+str(e)[:1000])
    finally:
        for f in reversed(locks):f.close()
        event('FINAL_RELEASE_AND_INPUT_PARITY')
        try:
            after=baseline(a.work,a.repo,a.github,{})
            write_json(run/'AFTER.json',after)
            require(before is not None and after==before,'RELEASE_OR_GATE_CHANGED')
            for path,old in states.items():require(file_state(path)==old,'HASHED_INPUT_CHANGED:'+Path(path).name)
            result['input_files_checked_unchanged']=len(states)
        except Exception as e:
            result['status']='B39B3_BLOCKED';result['blockers'].append(type(e).__name__+': '+str(e)[:1000])
        result['elapsed_s']=round(time.monotonic()-began,3)
        # Evidence for completed/partial private artifacts without exporting their content.
        records={str(f.relative_to(private)):sha(f.read_bytes()) for f in private.rglob('*')
                 if f.is_file() and 'snapshot' not in f.relative_to(private).parts and f.stat().st_size<64*1024**2}
        write_json(run/'PRIVATE_MANIFEST.json',records)
        write_json(run/'EXPORT_POLICY.json',{'raw_prompt':False,'raw_response':False,'dataset':False,'source':False,
            'weights':False,'private_dir':'RETAINED_LOCAL_NOT_EXPORTED','metadata_publication':'NOT_APPROVED'})
        write_json(run/'00_RESULT.json',result)
        out,h=pack(run,a.downloads)
        print('\n===== B39B.3 RESULT =====',flush=True)
        for k,v in [('STATUS',result['status']),('BLOCKERS',len(result['blockers'])),('COMPLETED_ARMS',','.join(result['completed_arms'])),
            ('NATIVE_STAGE3_METHOD',result['native_stage3_method']),('MODEL_INFERENCE',result['model_inference']),
            ('NEW_TRAINING',result['new_training']),('NEW_CODEQL_DATABASE',result['new_codeql_database']),
            ('INDEPENDENT_GOLD',False),('WEB_GATE_CHANGED_BY_RUNNER',False),('RUN_DIR',run),('OUTPUT_ZIP',out),('OUTPUT_SHA256',h)]:
            print(k+'='+str(v),flush=True)
        for b in result['blockers']:print('BLOCKER='+b,flush=True)
    return 2 if result['blockers'] else 0


if __name__=='__main__':
    sys.exit(main())
