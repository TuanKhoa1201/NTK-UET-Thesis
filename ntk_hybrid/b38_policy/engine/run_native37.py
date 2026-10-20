#!/usr/bin/env python3
"""Import the complete patched IRIS module and run its actual Stage 3 labelling method.
Does not extract/exec AST methods and does not fabricate a CodeQL database.
"""
from __future__ import annotations
import csv
import inspect
import json
import os
from pathlib import Path
import sys
import traceback
from ntk_b33.common import Blocker, IDENTITY, canonical, deny_inet, digest, normalize_cwe, walk, write_json


class Log:
    def info(self, message, **kwargs):
        print(message, flush=True)
    def error(self, message, **kwargs):
        print('ERROR: ' + str(message), flush=True)
    def print(self, message='', **kwargs):
        print(message, flush=True)


def assert_protocol(protocol, system, user_template, query):
    values = list(walk(protocol))
    if system not in values:
        raise Blocker('LOCKED_SYSTEM_PROMPT_DIFFERS_FROM_NATIVE_IRIS')
    if user_template not in values:
        raise Blocker('LOCKED_USER_TEMPLATE_DIFFERS_FROM_NATIVE_IRIS')
    prompts = query['prompts']
    for key in ('desc', 'long_desc'):
        if prompts[key] not in values:
            raise Blocker('LOCKED_CWE_CONTEXT_MISSING_OR_DIFFERENT: ' + key)
    expected = canonical(prompts['examples'])
    examples_match = False
    for val in values:
        if isinstance(val, (list, dict)) and canonical(val) == expected:
            examples_match = True
        elif isinstance(val, str):
            try:
                if canonical(json.loads(val)) == expected:
                    examples_match = True
            except (ValueError, TypeError):
                pass
    if not examples_match:
        raise Blocker('LOCKED_CWE_EXAMPLES_MISSING_OR_DIFFERENT')


def new_stage3_pipeline(cls, cfg, cwe, query_name, query, phase):
    # Explicit Stage 3-only constructor. Full __init__ requires a real DB and CVE metadata;
    # do not fake those to claim end-to-end execution.
    p = cls.__new__(cls)
    p.project_name = 'ntk-b37-uploaded-jdk-only-java'
    p.query = query_name
    p.cwe_id = query['cwe_id']
    p.run_id = 'b34-' + cfg['arm'] + '-' + phase
    p.llm = 'ntk-peft-stage3-local'
    p.label_api_batch_size = 1
    p.label_func_param_batch_size = 1
    p.num_threads = 1
    p.seed = cfg['generation']['seed']
    p.project_logger = Log()
    p.skip_huge_project = False
    p.skip_huge_project_num_apis_threshold = 3000
    p.overwrite = False
    p.overwrite_labelled_apis = False
    p.overwrite_llm_cache = False
    p.test_run = False
    p.no_logger = False
    p.model = None
    root = Path(cfg['output_dir']) / phase / ('cwe-' + cwe)
    root.mkdir(parents=True, exist_ok=False)
    p.candidate_apis_csv_path = str(root / 'candidate_apis.csv')
    p.label_api_log_path = str(root / 'logs')
    Path(p.label_api_log_path).mkdir()
    for attr, filename in (
        ('llm_labelled_source_apis_path', 'llm_labelled_source_apis.json'),
        ('llm_labelled_sink_apis_path', 'llm_labelled_sink_apis.json'),
        ('llm_labelled_taint_prop_apis_path', 'llm_labelled_taint_prop_apis.json')):
        setattr(p, attr, str(root / filename))
    p.api_labels_cache_path = str(root / 'legacy_cache_MUST_NOT_EXIST.json')
    with open(p.candidate_apis_csv_path, 'w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(('package', 'clazz', 'func', 'full_signature'))
        for row in cfg['cases']:
            if row['cwe'] == cwe:
                writer.writerow([row[k] for k in IDENTITY])
    return p


def main(config_path):
    cfg = json.loads(Path(config_path).read_text(encoding='utf-8'))
    snapshot = Path(cfg['snapshot']).resolve()
    isolation = deny_inet()  # Before IRIS imports; child worker inherits this restriction.
    sys.path[:0] = [str(snapshot), str(snapshot / 'src')]
    import src.iris as iris
    from src.ntk_stage3_native.provider import NativeProvider
    source_file = Path(inspect.getfile(iris.SAPipeline)).resolve()
    if source_file != snapshot / 'src/iris.py':
        raise Blocker('IMPORTED_WRONG_IRIS_MODULE: ' + str(source_file))
    if '--import-only' in sys.argv:
        print(json.dumps({'import_ok': True, 'source_file': str(source_file), 'isolation': isolation}))
        return
    protocol = json.loads(Path(cfg['protocol_path']).read_text(encoding='utf-8'))
    routes = {}
    for cwe in sorted({row['cwe'] for row in cfg['cases']}):
        matches = []
        for key, value in iris.QUERIES.items():
            if not isinstance(value, dict) or 'cwe_id' not in value or 'prompts' not in value:
                continue
            try:
                if normalize_cwe(value['cwe_id']) == cwe:
                    matches.append((key, value))
            except Blocker:
                continue
        preferred = [item for item in matches if item[0] == 'cwe-%03d' % int(cwe)]
        if preferred:
            matches = preferred
        if not matches or len({digest(q['prompts']) for _, q in matches}) != 1:
            raise Blocker('AMBIGUOUS_NATIVE_CWE_ROUTE: ' + cwe)
        key, query = sorted(matches, key=lambda pair: pair[0])[0]
        assert_protocol(protocol, cfg['native_system_prompt'], iris.API_LABELLING_USER_PROMPT, query)
        routes[cwe] = (key, query)
        for case in cfg['cases']:
            if case['cwe'] != cwe:
                continue
            user = iris.API_LABELLING_USER_PROMPT.format(
                cwe_description=query['prompts']['desc'], cwe_id=query['cwe_id'],
                cwe_long_description=query['prompts']['long_desc'],
                cwe_examples=json.dumps(query['prompts']['examples'], indent=2),
                methods=','.join(case[k] for k in IDENTITY),
            )
            case['expected_messages'] = [{'role': 'system', 'content': cfg['native_system_prompt']},
                                         {'role': 'user', 'content': user}]
            if (case.get('historical_b32_messages') is not None and
                    case['historical_b32_messages'] != case['expected_messages']):
                raise Blocker('HISTORICAL_B32_REQUEST_MESSAGES_DIFFER_FROM_NATIVE_RUNTIME')
    cfg['protocol_parity_verified'] = True
    write_json(Path(cfg['output_dir']) / 'effective_native_config.json', cfg)
    provider = NativeProvider(cfg)
    stage4_test = False
    try:
        for phase in ('cold', 'warm'):
            provider.phase = phase
            for cwe, (key, query) in routes.items():
                pipeline = new_stage3_pipeline(iris.SAPipeline, cfg, cwe, key, query, phase)
                pipeline._ntk_stage3_provider = provider
                if not stage4_test:
                    class Sentinel:
                        calls = 0
                        def predict(self, prompt, **kwargs):
                            self.calls += 1
                            return 'stage4-test-sentinel-not-a-model-verdict'
                    sentinel = Sentinel()
                    pipeline.model = sentinel
                    response, hit, cache_key = pipeline._stage4_predict_with_exact_cache([], 'initial')
                    if sentinel.calls != 1 or response != 'stage4-test-sentinel-not-a-model-verdict':
                        raise Blocker('STAGE4_PROVIDER_ISOLATION_REGRESSION')
                    if provider.observations or provider.process is not None:
                        raise Blocker('STAGE4_TOUCHED_STAGE3_PROVIDER')
                    pipeline.model = None
                    stage4_test = True
                # This is the actual complete method on the imported original SAPipeline class.
                pipeline.query_gpt_for_api_src_tp_sink_batched()
                if Path(pipeline.api_labels_cache_path).exists():
                    raise Blocker('LEGACY_NONE_CACHE_WAS_WRITTEN')
        expected = len(cfg['cases'])
        cold = [x for x in provider.observations if x['phase'] == 'cold']
        warm = [x for x in provider.observations if x['phase'] == 'warm']
        if len(cold) != expected or len(warm) != expected:
            raise Blocker('INCOMPLETE_NATIVE_CANDIDATE_COVERAGE')
        if any(x['cache_hit'] for x in cold) or not all(x['cache_hit'] for x in warm):
            raise Blocker('COLD_LIVE_OR_WARM_CACHE_PROOF_FAILED')
        if [x['raw_completion'] for x in cold] != [x['raw_completion'] for x in warm]:
            raise Blocker('CACHE_RESPONSE_DRIFT')
        summary = {
            'status': 'NATIVE_STAGE3_ARM_COMPLETE', 'arm': cfg['arm'],
            'scope': 'COMPLETE_IMPORTED_STAGE3_API_LABELLING_METHOD_NOT_FULL_SAPIPELINE_RUN',
            'source_file': str(source_file), 'isolation': isolation,
            'candidates': expected, 'cold_live_responses': len(cold), 'warm_exact_cache_hits': len(warm),
            'native_method_invocations': provider.native_invocations,
            'strict_accepted': sum(x['status'] == 'ACCEPTED' for x in cold),
            'abstain': sum(x['status'] == 'ABSTAIN' for x in cold),
            'abstain_reasons': {r: sum(x['reason'] == r for x in cold)
                                for r in sorted({x['reason'] for x in cold if x['status'] == 'ABSTAIN'})},
            'role_counts': {role: sum(x['label'] is not None and x['label']['type'] == role for x in cold)
                            for role in ('source', 'sink', 'taint-propagator', 'none')},
            'stage4_dispatch_isolation_test': stage4_test,
            'worker': provider.worker_meta, 'training_executed': False,
            'codeql_dataflow': 'NOT_EXECUTED', 'independent_gold': False,
        }
        write_json(Path(cfg['output_dir']) / 'SUMMARY.json', summary)
        print('ARM_SUMMARY=' + json.dumps(summary), flush=True)
    finally:
        provider.close()


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception:
        traceback.print_exc()
        sys.exit(2)
