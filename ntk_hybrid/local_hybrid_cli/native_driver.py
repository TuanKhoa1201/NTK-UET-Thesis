#!/usr/bin/env python3
"""B39B3 native IRIS driver. All model transport remains in the frozen B33 provider.
Prepare imports the complete patched module without executing Stage 3/model calls.
Run calls the actual imported Stage 3 method; no full constructor, DB, or Stage 4.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import signal
import sys
import time
import traceback
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ntk_core import (CWES, IDENTITY, canonical, digest, loads, normalize_cwe, require,
                      sha, write_json)
from vendor.common import deny_inet


def routes_for(queries):
    out = {}
    for cwe in CWES:
        matches = []
        for name, query in queries.items():
            if not isinstance(query, dict) or 'cwe_id' not in query or 'prompts' not in query:
                continue
            try:
                found = normalize_cwe(query['cwe_id'])
            except Exception:
                continue
            if found == cwe:
                matches.append((name, query))
        preferred = [x for x in matches if x[0] == 'cwe-%03d' % int(cwe)]
        if preferred:
            matches = preferred
        require(bool(matches) and len({digest(x[1]['prompts']) for x in matches}) == 1,
                'NATIVE_CWE_ROUTE_AMBIGUOUS_' + cwe)
        out[cwe] = sorted(matches, key=lambda x: x[0])[0]
    return out


def prepare_cases(cases, system, user_template, routes):
    result, keys = [], set()
    allowed = set(IDENTITY) | {'cwe', 'is_static', 'receiver_policy', 'source_record_sha256'}
    for case in cases:
        require(set(case) == allowed, 'CASE_FIELDS_NOT_LABEL_FREE')
        require(case['cwe'] in CWES, 'CASE_CWE')
        require(all(type(case[k]) is str for k in IDENTITY), 'CASE_IDENTITY_SCHEMA')
        key = digest([case['cwe'], [case[k] for k in IDENTITY]])
        require(key not in keys, 'DUPLICATE_NATIVE_CASE_KEY')
        keys.add(key)
        query = routes[case['cwe']][1]
        user = user_template.format(cwe_description=query['prompts']['desc'],
            cwe_id=query['cwe_id'], cwe_long_description=query['prompts']['long_desc'],
            cwe_examples=json.dumps(query['prompts']['examples'], indent=2),
            methods=','.join(case[k] for k in IDENTITY))
        result.append({**case, 'expected_messages': [
            {'role': 'system', 'content': system}, {'role': 'user', 'content': user}]})
    return result


def execute(cfg, phase):
    isolation = deny_inet()
    snapshot, engine = Path(cfg['snapshot']).resolve(), Path(cfg['engine']).resolve()
    sys.path[:0] = [str(engine), str(snapshot), str(snapshot/'src')]
    from ntk_b33.patcher import apply, native_system_prompt
    from run_native37 import assert_protocol, new_stage3_pipeline
    if phase == 'prepare':
        patch = apply(snapshot, engine)
        (Path(cfg['prepare_dir'])/'STAGE3_PATCH.diff').write_text(patch.pop('diff'), encoding='utf-8')
        # Prompt/source text stays local; public proof contains hashes only.
        write_json(Path(cfg['prepare_dir'])/'PATCH_PROOF.json', patch)
    import src.iris as iris
    from src.ntk_stage3_native.provider import NativeProvider
    source_file = Path(inspect.getfile(iris.SAPipeline)).resolve()
    require(source_file == snapshot/'src/iris.py', 'IMPORTED_WRONG_NATIVE_IRIS')
    require(Path(inspect.getfile(NativeProvider)).resolve() == snapshot/'src/ntk_stage3_native/provider.py',
            'IMPORTED_WRONG_NATIVE_PROVIDER')
    source_sha = sha(source_file.read_bytes())
    method_sha = digest(inspect.getsource(iris.SAPipeline.query_gpt_for_api_src_tp_sink_batched))
    system = native_system_prompt(source_file.read_text(encoding='utf-8'))
    protocol = loads(Path(cfg['protocol_path']).read_bytes())
    routes = routes_for(iris.QUERIES)
    for _, query in routes.values():
        assert_protocol(protocol, system, iris.API_LABELLING_USER_PROMPT, query)
    cases = prepare_cases(cfg['raw_cases'], system, iris.API_LABELLING_USER_PROMPT, routes)
    proof = {'source_sha256': source_sha, 'native_method_sha256': method_sha,
             'case_inputs_sha256': digest(cases), 'native_system_sha256': digest(system),
             'user_template_sha256': digest(iris.API_LABELLING_USER_PROMPT),
             'route_hashes': {c: digest(q) for c, (_, q) in routes.items()},
             'candidates': len(cases), 'isolation': isolation,
             'scope': 'FULL_IMPORTED_IRIS_MODULE_STAGE3_ONLY_NOT_FULL_SAPIPELINE',
             'candidate_origin': 'B28_WEAK_DATASET_NOT_NEW_COMPILER_DATABASE'}
    if phase == 'prepare':
        write_json(Path(cfg['prepare_dir'])/'NATIVE_INPUTS.json', cases)
        write_json(Path(cfg['prepare_dir'])/'PREPARED.json', proof)
        return {'status': 'NATIVE_IMPORT_AND_INPUT_PREPARE_COMPLETE', 'proof': proof,
                'model_inference': 'NOT_EXECUTED', 'native_stage3_calls': 0}
    require(proof == cfg['preparation_proof'], 'PREPARATION_OR_IMPORT_DRIFT')
    require(cases == cfg['cases'], 'NATIVE_PROMPTS_CHANGED_AFTER_PREPARE')
    effective = {**cfg, 'cases': cases, 'native_system_prompt': system, 'protocol_parity_verified': True}
    effective.pop('raw_cases', None)
    write_json(Path(cfg['output_dir'])/'effective_native_config.json', effective)
    provider = NativeProvider(effective)
    success = False
    cleanup, worker_process = None, None
    began = time.monotonic()
    try:
        for mode in ('cold', 'warm'):
            provider.phase = mode
            for cwe, (name, query) in routes.items():
                print('NATIVE_STAGE3=' + cfg['arm'] + ':' + mode + ':CWE-' + cwe, flush=True)
                pipeline = new_stage3_pipeline(iris.SAPipeline, effective, cwe, name, query, mode)
                pipeline.project_name = 'ntk-b39b3-weak-api-validation-not-a-codeql-project'
                pipeline.run_id = 'b39b3-' + cfg['arm'] + '-' + mode
                pipeline._ntk_stage3_provider = provider
                # Complete imported method. No AST extraction and no stand-in algorithm.
                pipeline.query_gpt_for_api_src_tp_sink_batched()
                require(not Path(pipeline.api_labels_cache_path).exists(), 'LEGACY_CACHE_WRITTEN')
        success = True
    finally:
        worker_process = provider.process
        provider.close()
        cleanup = {'worker_pid': worker_process.pid if worker_process else None,
                   'worker_returncode': worker_process.poll() if worker_process else None,
                   'worker_still_running': worker_process is not None and worker_process.poll() is None,
                   'own_worker_only': True}
        write_json(Path(cfg['output_dir'])/'CLEANUP.json', cleanup)
    require(success and cleanup['worker_returncode'] == 0 and not cleanup['worker_still_running'],
            'NATIVE_WORKER_FAILED_OR_NOT_STOPPED')
    cold = [x for x in provider.observations if x['phase'] == 'cold']
    warm = [x for x in provider.observations if x['phase'] == 'warm']
    require(len(cold) == len(cases) == len(warm), 'NATIVE_CANDIDATE_COVERAGE')
    require(all(not x['cache_hit'] for x in cold) and all(x['cache_hit'] for x in warm), 'CACHE_PHASE_CONTRACT')
    require([x['raw_completion'] for x in cold] == [x['raw_completion'] for x in warm], 'WARM_RAW_DRIFT')
    require(provider.native_invocations == len(CWES)*2, 'NATIVE_METHOD_INVOCATION_COUNT')
    require(sha(source_file.read_bytes()) == source_sha, 'SNAPSHOT_SOURCE_CHANGED_DURING_NATIVE_RUN')
    return {'status': 'B39B3_NATIVE_ARM_COMPLETE', 'arm': cfg['arm'],
            'cold_live_responses': len(cold), 'warm_cache_hits': len(warm),
            'native_method_invocations': provider.native_invocations,
            'worker': provider.worker_meta, 'cleanup': cleanup, 'proof': proof,
            'elapsed_s': time.monotonic()-began, 'native_stage3_method': 'EXECUTED',
            'stage4': 'NOT_EXECUTED', 'full_SAPipeline_run': 'NOT_EXECUTED',
            'codeql_database': 'NOT_EXECUTED', 'independent_gold': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=['prepare', 'run'])
    p.add_argument('config', type=Path)
    a = p.parse_args()
    cfg = loads(a.config.read_bytes())
    def interrupt(signum, frame):
        raise KeyboardInterrupt('SIGNAL_' + str(signum))
    signal.signal(signal.SIGTERM, interrupt)
    folder = Path(cfg['prepare_dir'] if a.phase == 'prepare' else cfg['output_dir'])
    try:
        result = execute(cfg, a.phase)
        code = 0
    except (Exception, KeyboardInterrupt) as e:
        traceback.print_exc()
        result = {'status': 'B39B3_NATIVE_DRIVER_BLOCKED', 'error_type': type(e).__name__,
                  'blocker': str(e)[:800], 'phase': a.phase}
        code = 2
    write_json(folder/'DRIVER_RESULT.json', result)
    return code


if __name__ == '__main__':
    sys.exit(main())
