#!/usr/bin/env python3
"""B39B2: lock known B28 data, build evaluator, optionally smoke Base/E1/E2 locally.
This is a separate research/development component, not a new DPA web gate or gold test.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
import zipfile
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ntk_core import (Blocker, CWES, IDENTITY, PARSER, canonical, convert_rows, digest, evaluate,
    file_state, hash_checked, jsonl, loads, overlap, read_checked, require, select_smoke, sha,
    stats, verify_sums, write_json, write_jsonl, zip_members, safe_member)
from ntk_runtime import Worker, offline_env
from vendor.common import ADAPTER_SHA, ADAPTER_CONFIG_SHA, deny_inet
PINS = loads((ROOT/'PINS.json').read_bytes())


def git_state(repo, github):
    out = {}
    for name, path, expected in [('iris', repo, PINS['iris_commit']), ('github', github, PINS['github_commit'])]:
        def run(args):
            p = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True,
                               env=offline_env(), timeout=60)
            require(p.returncode == 0, 'GIT_READ_FAILED_' + name)
            return p.stdout.strip()
        head = run(['rev-parse', 'HEAD'])
        status = run(['status', '--porcelain', '--untracked-files=normal'])
        require(head == expected and not status, 'GIT_BASELINE_DRIFT_' + name)
        out[name] = {'head': head, 'status': status}
    return out


def baseline(work, repo, github, states):
    result = {'git': git_state(repo, github)}
    pointer = read_checked(work/'NTK_BATCH38_POLICY_TOOL_PATH.txt', limit=4096, states=states).decode().strip()
    p = Path(pointer).expanduser().resolve()
    require(p.is_dir(), 'B38_SOURCE_POINTER_MISSING')
    for name, directory in [('P', p), ('G', github/'ntk_hybrid/b38_policy')]:
        sums = read_checked(directory/'SHA256SUMS', PINS['source_manifest_sha256'], states=states)
        for line in sums.decode().splitlines():
            h, rel = line.split(None, 1)
            rel = rel.lstrip('*')
            safe_member(rel)
            require(re.fullmatch(r'[a-f0-9]{64}', h) is not None, 'SOURCE_MANIFEST_FORMAT')
            read_checked(directory/rel, h, limit=64*1024**2, states=states)
        for filename, expected in PINS['vendor'].items():
            original = read_checked(directory/'engine/ntk_b33'/filename, expected['sha256'], states=states)
            vendor = read_checked(ROOT/'vendor'/filename, expected['sha256'], states=states)
            require(original == vendor, 'VENDORED_RUNTIME_NOT_RELEASE_BYTES')
        result[name + '_manifest_sha256'] = sha(sums)
    result['gates'] = {}
    for f in sorted((work/'batch38_policy_gates').glob('*.json')):
        result['gates'][f.name] = sha(read_checked(f, states=states))
    require('DPA_epoch_1.json' in result['gates'], 'EXPECTED_EXISTING_DPA_GATE_MISSING')
    return result


def prepare_data(work, downloads, run, states):
    bm = zip_members(read_checked(downloads/PINS['b1_name'], PINS['b1_sha256'], states=states))
    verified = verify_sums(bm)
    b1 = loads(bm['00_RESULT.json'])
    require(b1['status'] == 'B39B1_DISCOVERY_COMPLETE_REVIEW_REQUIRED' and not b1['blockers'], 'B1_NOT_ACCEPTED')
    # Exact lineage; no recursive filesystem discovery and no selection by row count.
    names = list(PINS['b28_members'])
    b28 = zip_members(read_checked(work/PINS['b28_relative'], PINS['b28_sha256'], states=states), names)
    for name, pin in PINS['b28_members'].items():
        require(sha(b28[name]) == pin['sha256'], 'B28_MEMBER_DRIFT:' + name)
    b27 = zip_members(read_checked(work/PINS['b27_relative'], PINS['b27_sha256'], states=states),
                      list(PINS['b27_members']))
    for name, h in PINS['b27_members'].items():
        require(sha(b27[name]) == h, 'B27_MEMBER_DRIFT:' + name)
    train_name, val_name = 'dataset/01_TRAIN_SILVER_WEAK_950.jsonl', 'dataset/02_VALIDATION_WEAK_DISJOINT.jsonl'
    manifest = loads(b28['ml/training_manifest.json'])
    job = loads(b28['03_TRAIN_JOB.json'])
    status = loads(b28['05_TRAINING_PROCESS_STATUS.json'])
    require(status.get('rc') == 0 and status.get('training_attempted') is True, 'B28_TRAINING_STATUS_NOT_SUCCESS')
    require(manifest.get('train_sha256') == sha(b28[train_name]), 'B28_TRAIN_MANIFEST_LINK_FAILED')
    require(manifest.get('dev_sha256') == sha(b28[val_name]), 'B28_DEV_MANIFEST_LINK_FAILED')
    require(manifest.get('config') == job.get('config'), 'B28_CONFIG_LINK_FAILED')
    for k, name in [('train', train_name), ('dev', val_name)]:
        require(Path(job[k]).resolve() == (work/PINS['b28_relative'].removesuffix('.zip')/name).resolve(),
                'B28_JOB_' + k.upper() + '_PATH_MISMATCH')
    protocol = read_checked(Path(job['protocol']), manifest.get('protocol_sha256'), states=states)
    train_raw, val_raw = jsonl(b28[train_name]), jsonl(b28[val_name])
    train, train_targets = convert_rows(train_raw)
    val, val_targets = convert_rows(val_raw)
    require(len(train) == 950 and len(val) == 137, 'PINNED_DATA_COUNT_MISMATCH')
    ov = overlap(train, val)
    require(ov['id_overlap'] == 0 and ov['identity_cwe_overlap'] == 0, 'EXACT_TRAIN_VALIDATION_OVERLAP')
    old_train, old_train_t = convert_rows(jsonl(b27['1_train_SILVER_WEAK_NOT_GOLD.jsonl']))
    old_val, old_val_t = convert_rows(jsonl(b27['1_validation_SILVER_WEAK_NOT_GOLD.jsonl']))
    def signatures(reqs, targets):
        return {canonical(r['id']): {'cwe': r['cwe'], 'label': t['label']} for r, t in zip(reqs, targets)}
    oldt, newt = signatures(old_train, old_train_t), signatures(train, train_targets)
    oldv, newv = signatures(old_val, old_val_t), signatures(val, val_targets)
    require(oldt == newt, 'B27_B28_TRAIN_TARGET_LINEAGE_MISMATCH')
    require(set(newv).issubset(oldv) and all(oldv[k] == v for k, v in newv.items()), 'VALIDATION_TARGET_LINEAGE_MISMATCH')
    removed = set(oldv) - set(newv)
    require(len(oldv) == 138 and len(removed) == 1, 'VALIDATION_EXCLUSION_DELTA_MISMATCH')
    prep = loads(b28['dataset/05_PREPARATION_AND_LEAKAGE.json'])
    exclusion = jsonl(b28['dataset/03_VALIDATION_EXCLUDED_LEAKAGE.jsonl'])
    # Preserve the original exclusion reason and evidence. Do not invent family-mapping semantics.
    claimed = prep.get('validation_ids_excluded_for_reference_protection')
    require(isinstance(claimed, list) and {canonical(x) for x in claimed} == removed,
            'HISTORICAL_EXCLUSION_ID_LIST_MISMATCH')
    require(prep.get('raw_validation') == 138 and prep.get('validation_scored_after_family_guard') == 137,
            'HISTORICAL_VALIDATION_DENOMINATOR_MISMATCH')
    private = run/'private'
    private.mkdir(exist_ok=True)
    # Exact original training dataset retained by path, never rewritten in its original location.
    (private/'train_original.jsonl').write_bytes(b28[train_name])
    (private/'validation_original.jsonl').write_bytes(b28[val_name])
    write_jsonl(private/'train.requests.jsonl', train)
    write_jsonl(private/'train.targets.jsonl', train_targets)
    write_jsonl(private/'validation.requests.jsonl', val)
    write_jsonl(private/'validation.targets.jsonl', val_targets)
    write_json(private/'historical_exclusion.json', {'preparation': prep, 'excluded_records': exclusion})
    selected = select_smoke(val)
    write_jsonl(private/'smoke.requests.jsonl', selected)
    target_map = {canonical(t['id']): t for t in val_targets}
    smoke_targets = [target_map[canonical(r['id'])] for r in selected]
    write_jsonl(private/'smoke.targets.jsonl', smoke_targets)
    lock = {'scope': 'PINNED_B28_WEAK_TRAIN_AND_DEV_NOT_GOLD', 'b1_manifest_entries_verified': verified,
        'b28_archive_sha256': PINS['b28_sha256'], 'b27_archive_sha256': PINS['b27_sha256'],
        'train_sha256': sha(b28[train_name]), 'validation_sha256': sha(b28[val_name]),
        'historical_protocol_sha256': sha(protocol), 'historical_config': manifest['config'],
        'train': stats(train, train_targets), 'validation': stats(val, val_targets), 'exact_overlap': ov,
        'validation_138_to_137': {'removed': 1, 'removed_id_sha256': [digest(loads(k)) for k in sorted(removed)],
            'evidence': 'B27_B28_ID_TARGET_CROSSWALK_AND_B28_REFERENCE_PROTECTION_EXCLUSION_LIST',
            'family_reason': 'REPORTED_BY_PINNED_B28_PREPARATION_NOT_REPROVEN_FROM_REFERENCE_200'},
        'gold_created': False, 'independent_review': False, 'original_files_modified': False,
        'prompt_policy': 'SAVED_B28_SYSTEM_USER_BYTES_UNCHANGED_ASSISTANT_TARGET_NOT_SENT',
        'identity_origin': 'STORED_WEAK_LABEL_IDENTITY_NOT_NEW_COMPILER_RESOLUTION',
        'smoke_selection': {'method': 'LOWEST_PROMPT_SHA256_PER_CWE_THEN_ID_NO_LABEL_BASED_SELECTION',
            'requests': [{'id_sha256': digest(r['id']), 'cwe': r['cwe'], 'prompt_sha256': r['prompt_sha256']} for r in selected]},
        'private_artifact_hashes': {f.name: sha(f.read_bytes()) for f in sorted(private.iterdir()) if f.is_file()}}
    write_json(run/'DATA_LOCK.json', lock)
    replay = {'scope': 'B28_HISTORICAL_RAW_OUTPUT_REPARSED_WITH_B33_PARSER_NOT_NEW_INFERENCE', 'arms': {}}
    for arm in ('base', 'epoch_1', 'epoch_2'):
        preds = jsonl(b28['ml/' + arm + '_predictions.jsonl'])
        metric, details = evaluate(val, val_targets, preds)
        replay['arms'][arm] = metric
        write_json(run/('REPLAY_' + arm + '.json'), {'metrics': metric, 'details': details,
            'source_predictions_sha256': sha(b28['ml/' + arm + '_predictions.jsonl']),
            'new_inference': False, 'original_metrics_overwritten': False})
    write_json(run/'REPLAY_SUMMARY.json', replay)
    return selected, smoke_targets, lock


def make_runtime_configs(work, downloads, run, states):
    raw = read_checked(downloads/PINS['b33_name'], PINS['b33_sha256'], states=states)
    members = zip_members(raw)
    require('OUTPUT_MANIFEST.json' in members, 'B33_MANIFEST_MISSING')
    man = loads(members['OUTPUT_MANIFEST.json'])
    require(isinstance(man, dict), 'B33_MANIFEST_SCHEMA')
    for name, h in man.items():
        safe_member(name)
        require(name in members and sha(members[name]) == h, 'B33_MEMBER_SHA_MISMATCH:' + name)
    old = {arm: loads(members['CONFIG_' + arm + '.json']) for arm in ('epoch_1', 'epoch_2')}
    for key in ('base_dir', 'base_fingerprint', 'generation', 'runtime_versions'):
        require(old['epoch_1'][key] == old['epoch_2'][key], 'B33_ARMS_DIFFER_' + key)
    require(old['epoch_1']['runtime_versions'] == PINS['runtime_versions'], 'B33_VERSION_PINS_MISMATCH')
    require(old['epoch_1']['base_fingerprint'] == PINS['base_fingerprint'], 'B33_BASE_FINGERPRINT_MISMATCH')
    expected = loads(members['inputs/BASE_MANIFEST.json'])['files']
    require(isinstance(expected, dict), 'BASE_MANIFEST_SCHEMA')
    base = Path(old['epoch_1']['base_dir']).resolve()
    require(digest(expected) == PINS['base_fingerprint'], 'BASE_MANIFEST_FINGERPRINT')
    observed_names = {str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}
    require(observed_names == set(expected), 'BASE_FILE_SET_CHANGED')
    for name, h in expected.items():
        safe_member(name)
        hash_checked(base/name, h, states)
    for arm, cfg in old.items():
        ad = Path(cfg['adapter_dir'])
        hash_checked(ad/'adapter_model.safetensors', ADAPTER_SHA[arm], states)
        hash_checked(ad/'adapter_config.json', ADAPTER_CONFIG_SHA, states)
    configs = {}
    for arm in ('base', 'epoch_1', 'epoch_2'):
        src = old['epoch_1'] if arm == 'base' else old[arm]
        # Intentionally do not pass cases, target labels, cached outputs or B33 output paths.
        cfg = {k: src[k] for k in ('base_dir', 'base_fingerprint', 'generation', 'runtime_versions')}
        cfg.update(arm=arm, adapter_dir=None if arm == 'base' else src['adapter_dir'])
        gen = cfg['generation']
        require(set(('seed', 'max_input_tokens', 'max_new_tokens', 'attention', 'generation_timeout_s')).issubset(gen),
                'B33_GENERATION_CONFIG_INCOMPLETE')
        require(type(gen['max_new_tokens']) is int and 0 < gen['max_new_tokens'] <= 1024,
                'GENERATION_BUDGET_GUARD')
        require(type(gen['generation_timeout_s']) in (int, float) and 0 < gen['generation_timeout_s'] <= 600,
                'GENERATION_TIMEOUT_GUARD')
        configs[arm] = cfg
    write_json(run/'RUNTIME_CONFIG_PROVENANCE.json', {'b33_archive_sha256': PINS['b33_sha256'],
        'base_fingerprint': PINS['base_fingerprint'], 'adapter_sha256': ADAPTER_SHA,
        'runtime_versions': PINS['runtime_versions'], 'generation': configs['base']['generation'],
        'worker_sha256': PINS['vendor']['worker.py']['sha256'],
        'parser_sha256': PINS['vendor']['common.py']['sha256'], 'parser': PARSER,
        'scope': 'REUSES_FROZEN_B33_WORKER_AND_PARSER_NOT_NATIVE_SAPIPELINE_METHOD',
        'cache': 'NO_PROVIDER_CACHE_USED', 'web_gate_changed': False})
    return configs


def smoke(configs, selected, targets, work, run, events):
    # Shared B38 scan lock, plus our own; do not run a B37 scan simultaneously.
    locks = []
    try:
        for name in ('batch38_gpu_scan.lock', 'batch39b2_gpu.lock'):
            f = (work/name).open('a+')
            locks.append(f)
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocker('ANOTHER_SCAN_HOLDS_' + name) from None
        ml = work/'.ntk_v5_lora_venv/bin/python'
        require(ml.is_file() and os.access(ml, os.X_OK), 'ML_PYTHON_MISSING')
        gpu = shutil.which('nvidia-smi')
        require(gpu is not None, 'NVIDIA_SMI_MISSING')
        probe = subprocess.run([gpu, '--query-compute-apps=pid,process_name', '--format=csv,noheader'],
            capture_output=True, text=True, timeout=30, env=offline_env())
        require(probe.returncode == 0, 'GPU_IDLE_PROBE_FAILED')
        require(not probe.stdout.strip(), 'GPU_COMPUTE_PROCESS_ALREADY_RUNNING')
        write_json(run/'GPU_IDLE.json', {'returncode': 0, 'compute_process_lines': 0,
            'scope': 'NVIDIA_SMI_COMPUTE_QUERY_NOT_GLOBAL_PROCESS_MONITOR'})
        input_ids, templates, results = {}, set(), {}
        for arm in ('base', 'epoch_1', 'epoch_2'):
            events('REAL_LOCAL_WORKER_' + arm.upper())
            folder = run/'private'/arm
            folder.mkdir()
            cfgpath = folder/'worker_config.json'
            write_json(cfgpath, configs[arm])
            # The worker installs seccomp before importing any ML packages.
            w = Worker([ml, '-I', '-B', '-u', ROOT/'vendor/worker.py', cfgpath], folder/'stderr.log', folder)
            predictions, measurements = [], []
            arm_meta = {'arm': arm, 'cache_used': False, 'requests_planned': len(selected)}
            try:
                hello = w.read(300)
                write_json(folder/'hello.json', hello)
                require(hello.get('ready') is True, 'WORKER_NOT_READY_' + arm + '_' + str(hello.get('error_kind', 'UNKNOWN')))
                require(hello.get('versions') == configs[arm]['runtime_versions'] and hello.get('arm') == arm,
                        'WORKER_IDENTITY_OR_VERSIONS_DRIFT')
                require(hello.get('trainable_parameters') == 0 and hello.get('training_executed') is False,
                        'WORKER_NOT_INFERENCE_ONLY')
                require(all(hello.get('isolation', {}).get(k) == 'DENIED_EPERM' for k in ('AF_INET', 'AF_INET6')),
                        'WORKER_NETWORK_ISOLATION_NOT_PROVEN')
                templates.add(hello['tokenizer_chat_template_sha256'])
                require(len(templates) == 1, 'TOKENIZER_TEMPLATE_DIFFERS_BETWEEN_ARMS')
                arm_meta.update(hello=hello)
                for index, request in enumerate(selected, 1):
                    print('B39B2_REQUEST=' + arm + ' ' + str(index) + '/' + str(len(selected)) + ' CWE-' + request['cwe'], flush=True)
                    began = time.monotonic()
                    reply = w.request(request['messages'], configs[arm]['generation']['generation_timeout_s'] + 30)
                    write_json(folder/('reply_' + str(index) + '.json'), reply)
                    require(reply.get('ok') is True and isinstance(reply.get('raw'), str),
                            'MODEL_INFRASTRUCTURE_ERROR_' + arm + '_' + str(reply.get('error_kind', 'UNKNOWN')))
                    ident = canonical(request['id'])
                    actual_tokens = reply.get('input_token_ids_sha256')
                    require(isinstance(actual_tokens, str) and re.fullmatch(r'[0-9a-f]{64}', actual_tokens) is not None,
                            'INPUT_TOKEN_HASH_MISSING')
                    if ident in input_ids:
                        require(input_ids[ident] == actual_tokens, 'INPUT_TOKENS_DIFFER_BETWEEN_ARMS')
                    input_ids[ident] = actual_tokens
                    predictions.append({'id': request['id'], 'cwe': request['cwe'], 'raw': reply['raw']})
                    measurement = {k: v for k, v in reply.items() if k not in ('raw', 'ok')}
                    measurement.update(sample_id_sha256=digest(request['id']), cwe=request['cwe'],
                        client_request_wall_s=time.monotonic()-began, is_first_request=index == 1,
                        cache_hit=False, raw_sha256=sha(reply['raw'].encode()))
                    measurements.append(measurement)
                write_jsonl(folder/'predictions.jsonl', predictions)
                metric, details = evaluate(selected, targets, predictions)
                # Four input smoke is too small for model quality claims; only show transport/contracts.
                arm_meta.update(requests_completed=len(predictions), accepted=metric['accepted'],
                    abstain=metric['abstain'], reasons=metric['reason_counts'], measurements=measurements,
                    reference_quality='WEAK_DEV_SMOKE_NOT_QUALITY_BENCHMARK', details=details)
            finally:
                arm_meta['cleanup'] = w.close()
                write_json(run/('SMOKE_' + arm + '.json'), arm_meta)
            require(not arm_meta['cleanup']['still_running'] and arm_meta['cleanup']['returncode'] == 0,
                    'MODEL_WORKER_STOP_FAILED_' + arm)
            results[arm] = arm_meta
        return {'arms': {a: {k: x[k] for k in ('requests_completed', 'accepted', 'abstain', 'cleanup')} for a, x in results.items()},
                'requests_completed': sum(x['requests_completed'] for x in results.values()),
                'same_tokenized_inputs_across_arms': True, 'same_chat_template_across_arms': True,
                'new_training': False, 'model_inference': 'REAL_LOCAL_GPU',
                'native_stage3_method': 'NOT_EXECUTED_WORKER_INTERFACE_ONLY',
                'codeql': 'NOT_EXECUTED', 'opengrep': 'NOT_EXECUTED', 'web_gate_modified': False,
                'quality_benchmark': False, 'independent_gold': False}
    finally:
        for f in reversed(locks):
            f.close()


def pack(run, downloads):
    files = [f for f in sorted(run.iterdir()) if f.is_file() and f.suffix == '.json']
    sums = ''.join(sha(f.read_bytes()) + '  ' + f.name + '\n' for f in files)
    (run/'SHA256SUMS').write_text(sums, encoding='ascii')
    out = downloads/(run.name + '_result.zip')
    with zipfile.ZipFile(out, 'x', zipfile.ZIP_DEFLATED) as z:
        for f in files + [run/'SHA256SUMS']:
            z.write(f, f.name)
    h = sha(out.read_bytes())
    with Path(str(out)+'.sha256').open('x', encoding='ascii') as f:
        f.write(h + '  ' + out.name + '\n')
    return out, h


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work', type=Path, default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    ap.add_argument('--repo', type=Path, default=Path.home()/'iris')
    ap.add_argument('--github', type=Path, default=Path.home()/'migration/ntk_github_publish_20261020')
    ap.add_argument('--downloads', type=Path, default=Path('/mnt/c/Users/HP/Downloads'))
    ap.add_argument('--smoke', action='store_true', help='Run 4 real requests x 3 arms after CPU preparation')
    a = ap.parse_args()
    for key in ('work', 'repo', 'github', 'downloads'):
        setattr(a, key, getattr(a, key).expanduser().resolve())
    require(a.work.is_dir() and a.downloads.is_dir(), 'WORK_OR_DOWNLOADS_MISSING')
    require(a.repo != a.work and a.repo not in a.work.parents and a.github not in a.work.parents,
            'OUTPUT_CANNOT_BE_INSIDE_FROZEN_OR_PUBLISH_REPOSITORY')
    run = a.work/'batch39b2_data_runtime'/('b39b2_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:8])
    run.mkdir(parents=True, exist_ok=False)
    os.chmod(run, 0o700)
    states, before = {}, None
    result = {'status': 'B39B2_BLOCKED', 'blockers': [], 'new_training': 'NOT_EXECUTED',
        'new_codeql_database': 'NOT_EXECUTED', 'new_opengrep_scan': 'NOT_EXECUTED',
        'native_stage3_method': 'NOT_EXECUTED', 'independent_gold': False,
        'model_inference': 'NOT_EXECUTED', 'mode': 'DATA_LOCK_AND_12_REQUEST_SMOKE' if a.smoke else 'DATA_LOCK_ONLY',
        'steps_completed': [], 'run_name': run.name}
    began = time.monotonic()
    def event(name):
        print('B39B2_STAGE=' + name, flush=True)
    def stop_signal(signum, frame):
        raise KeyboardInterrupt('INTERRUPTED')
    signal.signal(signal.SIGTERM, stop_signal)
    try:
        event('NETWORK_AND_RELEASE_PARITY')
        isolation = deny_inet()
        write_json(run/'NETWORK.json', isolation)
        before = baseline(a.work, a.repo, a.github, states)
        write_json(run/'BEFORE.json', before)
        result['steps_completed'].append('RELEASE_PARITY')
        event('PINNED_DATASET_LOCK_AND_CPU_EVALUATOR')
        selected, targets, lock = prepare_data(a.work, a.downloads, run, states)
        result['steps_completed'].append('WEAK_DATA_LOCK_AND_HISTORICAL_REPLAY')
        result['train_rows'], result['validation_rows'] = lock['train']['rows'], lock['validation']['rows']
        if a.smoke:
            event('VERIFY_LOCAL_MODEL_ASSETS')
            configs = make_runtime_configs(a.work, a.downloads, run, states)
            result['model_inference'] = 'ATTEMPTING_REAL_LOCAL_WORKERS'
            result['smoke'] = smoke(configs, selected, targets, a.work, run, event)
            result['model_inference'] = 'REAL_LOCAL_GPU_12_REQUESTS'
            result['steps_completed'].append('BASE_EPOCH1_EPOCH2_REAL_WORKER_SMOKE')
            result['status'] = 'B39B2_DATA_LOCK_AND_LOCAL_ARMS_SMOKE_COMPLETE'
        else:
            result['status'] = 'B39B2_WEAK_DATA_LOCK_AND_EVALUATOR_READY'
    except (Exception, KeyboardInterrupt) as e:
        result['blockers'].append(type(e).__name__ + ': ' + str(e))
        result['status'] = 'B39B2_BLOCKED'
    finally:
        event('FINAL_INPUT_AND_RELEASE_PARITY')
        try:
            after = baseline(a.work, a.repo, a.github, {})
            write_json(run/'AFTER.json', after)
            require(before is not None and before == after, 'RELEASE_OR_GATE_CHANGED')
            for path, old in states.items():
                require(file_state(path) == old, 'HASHED_INPUT_CHANGED_AT_FINISH:' + Path(path).name)
            result['input_files_checked_unchanged'] = len(states)
        except Exception as e:
            result['blockers'].append(type(e).__name__ + ': ' + str(e))
            result['status'] = 'B39B2_BLOCKED'
        result['elapsed_s'] = round(time.monotonic()-began, 3)
        write_json(run/'EXPORT_POLICY.json', {'includes_raw_datasets': False, 'includes_prompt_or_completion_text': False,
            'includes_weights': False, 'private_runtime_files_remain_local': True,
            'includes_aggregate_weak_labels_and_identity_hashes': True, 'new_training': False,
            'public_github_approved': False, 'old_attempts_preserved': True,
            'scope': 'DEVELOPMENT_RUNTIME_COMPONENT_NOT_DPA_GATE_OR_GOLD_ACCEPTANCE'})
        write_json(run/'00_RESULT.json', result)
        out, h = pack(run, a.downloads)
        print('\n===== B39B.2 RESULT =====', flush=True)
        for key, value in [('STATUS', result['status']), ('BLOCKERS', len(result['blockers'])),
            ('TRAIN_ROWS', result.get('train_rows', 'UNVERIFIED')), ('VALIDATION_ROWS', result.get('validation_rows', 'UNVERIFIED')),
            ('MODEL_INFERENCE', result['model_inference']), ('NEW_TRAINING', 'NOT_EXECUTED'),
            ('NEW_CODEQL_DATABASE', 'NOT_EXECUTED'), ('WEB_GATE_CHANGED_BY_RUNNER', False),
            ('RUN_DIR', run), ('OUTPUT_ZIP', out), ('OUTPUT_SHA256', h)]:
            print(str(key) + '=' + str(value), flush=True)
        for b in result['blockers']:
            print('BLOCKER=' + b, flush=True)
    return 2 if result['blockers'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print('B39B2_EARLY_BLOCKED=' + type(e).__name__ + ':' + str(e), flush=True)
        sys.exit(2)
