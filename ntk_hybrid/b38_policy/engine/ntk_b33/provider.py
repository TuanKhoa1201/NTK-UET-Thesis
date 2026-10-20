from __future__ import annotations
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from .common import Blocker, PARSER, IDENTITY, canonical, digest, normalize_cwe, strict_label, write_json


class NativeProvider:
    """Stage 3 only. Uses a local child process, never IRIS.get_model or any daemon."""
    def __init__(self, config: dict):
        self.config = config
        self.process = None
        self.pending = None
        self.observations = []
        self.phase = 'cold'
        self.worker_meta = None
        self.last_transport = None
        self.cache_hits = 0
        self.cache_misses = 0
        self.native_invocations = 0
        self.index = {}
        for row in config['cases']:
            key = self.case_key(row['cwe'], [row[k] for k in IDENTITY])
            if key in self.index:
                raise Blocker('Duplicate candidate in configured request set')
            self.index[key] = row
        self.output = Path(config['output_dir'])
        self.output.mkdir(parents=True, exist_ok=True)
        self.stderr_handle = None

    @staticmethod
    def from_config(path: str):
        return NativeProvider(json.loads(Path(path).read_text(encoding='utf-8')))

    @staticmethod
    def case_key(cwe, identity):
        return digest([normalize_cwe(cwe), list(identity)])

    def begin(self, pipeline):
        if pipeline.test_run:
            raise Blocker('Native live acceptance requires test_run=False')
        if not self.config.get('protocol_parity_verified'):
            raise Blocker('LOCKED_PROTOCOL_PARITY_NOT_VERIFIED')
        forbidden = Path(self.config['frozen_root']).resolve()
        for attr in ('label_api_log_path', 'llm_labelled_source_apis_path',
                     'llm_labelled_sink_apis_path', 'llm_labelled_taint_prop_apis_path'):
            path = Path(getattr(pipeline, attr)).resolve()
            if path == forbidden or forbidden in path.parents:
                raise Blocker('REFUSE_WRITE_TO_FROZEN_REPOSITORY: ' + str(path))
        self.segment_start = len(self.observations)
        self.native_invocations += 1

    def prepare(self, identity, cwe, messages):
        key = self.case_key(cwe, identity)
        case = self.index.get(key)
        if case is None:
            raise Blocker('CANDIDATE_NOT_IN_PROVENANCE_MANIFEST')
        if messages != case['expected_messages']:
            raise Blocker('NATIVE_PROMPT_PARITY_MISMATCH for ' + key)
        self.pending = (key, case, messages)

    def start_worker(self):
        if self.process is not None:
            return
        from . import worker
        cfg = self.output / 'worker_config.json'
        write_json(cfg, self.config)
        env = dict(os.environ, HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',
                   HF_HUB_DISABLE_TELEMETRY='1', DO_NOT_TRACK='1', WANDB_DISABLED='true',
                   TOKENIZERS_PARALLELISM='false', PYTHONDONTWRITEBYTECODE='1')
        self.stderr_handle = open(self.output / 'worker_stderr.log', 'a', encoding='utf-8')
        self.process = subprocess.Popen(
            [self.config['ml_python'], '-B', '-u', str(Path(worker.__file__)), str(cfg)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr_handle,
            text=True, bufsize=1, env=env, close_fds=True,
        )
        hello = self.read_worker(float(self.config.get('load_timeout_s', 300)))
        if not hello.get('ready'):
            self.close()
            raise Blocker('WORKER_NOT_READY: ' + repr(hello))
        self.worker_meta = hello

    def read_worker(self, timeout_s):
        ready, _, _ = select.select([self.process.stdout], [], [], timeout_s)
        if not ready:
            self.close()
            raise Blocker('MODEL_WORKER_TIMEOUT')
        line = self.process.stdout.readline()
        if not line:
            code = self.process.poll()
            self.close()
            raise Blocker('MODEL_WORKER_EXITED: ' + str(code))
        try:
            return json.loads(line)
        except ValueError as exc:
            raise Blocker('WORKER_PROTOCOL_INVALID: ' + repr(line[:200])) from exc

    def predict_cached(self, messages, cwe):
        if self.pending is None:
            raise Blocker('Stage3 dispatcher called without a native prepared candidate')
        case_key, case, expected = self.pending
        if expected != messages or normalize_cwe(cwe) != case['cwe']:
            raise Blocker('REQUEST_CONTEXT_CHANGED_AFTER_PREPARATION')
        request = {
            'stage': 'IRIS_STAGE3_API_LABELLING', 'parser_version': PARSER,
            'base_fingerprint': self.config['base_fingerprint'],
            'adapter_sha256': self.config.get('adapter_sha256'),
            'adapter_config_sha256': self.config.get('adapter_config_sha256'),
            'runtime_versions': self.config['runtime_versions'],
            'generation': self.config['generation'], 'cwe': normalize_cwe(cwe),
            'messages': messages, 'receiver_policy': case.get('receiver_policy'),
            'case_key': case_key,
        }
        cache_key = digest(request)
        cache_path = Path(self.config['cache_dir']) / cache_key[:2] / (cache_key + '.json')
        if self.config.get('cache_mode') == 'readwrite' and cache_path.is_file():
            try:
                cached = json.loads(cache_path.read_text(encoding='utf-8'))
                if (cached['request'] == request and isinstance(cached['raw'], str)
                        and cached['response_sha256'] == digest(cached['raw'])):
                    self.cache_hits += 1
                    self.last_transport = dict(cache_key=cache_key, cache_hit=True,
                                               latency_s=0, worker=None)
                    return cached['raw'], True, cache_key
            except (ValueError, OSError, KeyError, TypeError):
                pass
        self.cache_misses += 1
        started = time.monotonic()
        try:
            self.start_worker()
            self.process.stdin.write(json.dumps({'messages': messages}) + '\n')
            self.process.stdin.flush()
            reply = self.read_worker(float(self.config.get('request_timeout_s', 180)))
            if not reply.get('ok'):
                raise Blocker('MODEL_RUNTIME_ERROR: ' + canonical(reply))
            raw = reply['raw']
            if not isinstance(raw, str):
                raise Blocker('MODEL_RAW_NOT_TEXT')
        except Exception as exc:
            self.observations.append({
                'case_key': case_key, 'phase': self.phase, 'candidate': {k: case.get(k) for k in (*IDENTITY, 'cwe')},
                'status': 'ABSTAIN', 'reason': str(exc), 'label': None,
                'infrastructure_failure': True, 'raw_completion': None,
            })
            self.flush_trace()
            raise  # Do not turn an infrastructure failure into a successful all-abstain run.
        self.last_transport = dict(cache_key=cache_key, cache_hit=False,
                                   latency_s=time.monotonic() - started,
                                   worker={k: v for k, v in reply.items() if k not in ('raw', 'ok')})
        if self.config.get('cache_mode') == 'readwrite':
            write_json(cache_path, {'request': request, 'raw': raw, 'response_sha256': digest(raw)})
        return raw, False, cache_key

    def validate_response(self, raw, cwe):
        case_key, case, messages = self.pending
        verdict = strict_label(raw, case, cwe, receiver_approved=False)
        entry = dict(verdict, case_key=case_key, phase=self.phase,
                     candidate={k: case.get(k) for k in (*IDENTITY, 'cwe')},
                     raw_completion=raw, prompt_sha256=digest(messages),
                     source_record_sha256=case['source_record_sha256'],
                     parser_version=PARSER, **(self.last_transport or {}))
        self.observations.append(entry)
        self.flush_trace()
        return [verdict['label']] if verdict['status'] == 'ACCEPTED' else []

    def flush_trace(self):
        path = self.output / 'native_trace.jsonl'
        path.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in self.observations),
                        encoding='utf-8')

    def finish(self, pipeline):
        current = self.observations[self.segment_start:]
        for role, attr in (
            ('source', 'llm_labelled_source_apis_path'), ('sink', 'llm_labelled_sink_apis_path'),
            ('taint-propagator', 'llm_labelled_taint_prop_apis_path')):
            expected = [row['label'] for row in current
                        if row['status'] == 'ACCEPTED' and row['label']['type'] == role]
            actual = json.loads(Path(getattr(pipeline, attr)).read_text(encoding='utf-8'))
            if sorted(map(canonical, actual)) != sorted(map(canonical, expected)):
                raise Blocker('NATIVE_LABEL_ARTIFACT_DIVERGED_FROM_STRICT_VERDICTS: ' + role)
        write_json(Path(pipeline.label_api_log_path) / 'ntk_stage3_provenance.json', {
            'scope': 'ACTUAL_IMPORTED_SAPIPELINE_STAGE3_METHOD',
            'phase': self.phase, 'cwe': str(pipeline.cwe_id),
            'observations': current, 'codeql_dataflow': 'NOT_EXECUTED',
            'labels_semantically_gold': False,
        })

    def close(self):
        if self.process is not None:
            process, self.process = self.process, None
            try:
                if process.stdin:
                    process.stdin.close()
                process.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                process.kill()
                process.wait()
            if process.stdout:
                process.stdout.close()
        if self.stderr_handle is not None:
            self.stderr_handle.close()
            self.stderr_handle = None
