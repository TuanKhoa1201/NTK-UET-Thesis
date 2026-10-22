"""Independent, pinned Fast E1 bridge for the single-port NTK web UI.

Never mutates the frozen Workbench, scores, LoRA weights or prior runs.
The Fast runner is experimental; evidence is verified locally before presentation.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import threading
import time
from pathlib import Path

RUN_ID = re.compile(r'ntkfast_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\Z')
JOB_ID = re.compile(r'[0-9a-f]{20}\Z')
RUNNER_SHA = '4ccc5dae1083085412bf5900bd1b89d72d8a453f07d85fece431d8515530c82c'  # verified legacy base
ORIGINAL_SHA = 'b74075eb834ef563af235c183f82d7ba855adf36dd4d9198b85e63d08e274e1e'
SUCCESS = {'NTK_FASTSCAN_EPOCH1_COMPLETE', 'NTK_FASTSCAN_RAW_ONLY_NO_CANDIDATES'}
ALLOWED_ARMS = ('opengrep_only', 'epoch_1')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_fast_runner(runner, module, cfg):
    """Reconstruct expected byte-pinned v2.3 runner from unchanged v2.2 source.

    The website's SHA256SUMS pins the transformation implementation.
    A local manifest alone is never allowed to authorize different Python code.
    """
    from fastscan_v23_patch import BASE_SHA, RESEARCH_SHA, upgrade_bytes
    p = Path(runner).expanduser()
    if p.name != 'run_fastscan.py' or p.is_symlink() or not p.is_file():
        raise ValueError('FAST_RUNNER_UNEXPECTED_PATH')
    p = p.resolve()
    parent = p.parent
    if parent.name != 'engine_candidate_v23' or parent.is_symlink():
        raise ValueError('FAST_RUNNER_NOT_SEPARATE_V23_CANDIDATE')
    dev = parent.parent
    old = dev / 'engine_candidate'
    ref = dev / 'engine_reference'
    if old.is_symlink() or not old.is_dir() or ref.is_symlink() or not ref.is_dir():
        raise ValueError('FAST_ORIGINAL_REFERENCE_MISSING')
    old_raw = module.read(old / 'run_fastscan.py', 2 * 1024 * 1024)
    if digest(old_raw) != BASE_SHA:
        raise ValueError('FAST_V22_SUCCESSFUL_RUNNER_DRIFT')
    expected = upgrade_bytes(old_raw)
    actual = module.read(p, 2 * 1024 * 1024)
    if actual != expected:
        raise ValueError('FAST_V23_RUNNER_NOT_DETERMINISTIC_PINNED_BYTES')
    for candidate in (parent, old, ref):
        if module.verify_engine(candidate) != cfg['engine_manifest_sha256']:
            raise ValueError('FAST_FROZEN_ENGINE_MANIFEST_DRIFT')
    pinned = module.read(old / 'run_hybrid.py', 2 * 1024 * 1024)
    if digest(pinned) != RESEARCH_SHA or pinned != module.read(parent / 'run_hybrid.py',2*1024*1024) or pinned != module.read(ref / 'run_hybrid.py',2*1024*1024):
        raise ValueError('FAST_RESEARCH_RUNNER_DRIFT')
    report = dev / 'FASTSCAN_PATCH_REPORT_V23.json'
    proof = module.loads(module.read(report, 1 * 1024 * 1024))
    if (proof.get('status') != 'NTK_FAST_E1_V23_CPU_PATCH_VERIFIED' or
        proof.get('source_runner_sha256') != BASE_SHA or
        proof.get('patched_runner_sha256') != digest(expected) or
        proof.get('research_runner_sha256') != RESEARCH_SHA or
        proof.get('frozen_sources_modified') is not False):
        raise ValueError('FAST_V23_PATCH_PROOF_DRIFT')
    return p


class FastBridge:
    def __init__(self, ui_state, runner, workbench, engine, allow_scan=False):
        self.workbench = workbench
        self.engine = engine
        self.cfg = engine.cfg
        self.runner = verify_fast_runner(runner, workbench, self.cfg)
        self.root = Path(ui_state).expanduser().resolve() / 'fast_jobs'
        if self.root.is_symlink():
            raise RuntimeError('FAST_STATE_SYMLINK')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.runroot = Path(self.cfg['work']).resolve() / 'ntk_fastscan_runs'
        self.allow_scan = bool(allow_scan)
        self.lock = threading.RLock()
        self.active = None
        self.process = None
        self.thread = None
        self.stopping = False
        for path in sorted(self.root.glob('*/job.json')):
            if not JOB_ID.fullmatch(path.parent.name) or path.is_symlink():
                continue
            job = self.workbench.loads(self.workbench.read(path, 1024 * 1024))
            if job.get('status') in ('RUNNING', 'STARTING', 'STOPPING'):
                job.update(status='INTERRUPTED_UNCONFIRMED', stage='SERVER_RESTART_NO_AUTOMATIC_RESUME')
                self._write_job(path.parent.name, job)

    def _folder(self, jid):
        if not isinstance(jid, str) or not JOB_ID.fullmatch(jid):
            raise ValueError('FAST_JOB_ID_INVALID')
        target = self.root / jid
        if target.is_symlink():
            raise ValueError('FAST_JOB_SYMLINK')
        return target

    def _write_job(self, jid, item):
        self.workbench.write_json(self._folder(jid) / 'job.json', item)

    def job(self, jid):
        return self.workbench.loads(self.workbench.read(self._folder(jid) / 'job.json', 1024 * 1024))

    def jobs(self):
        out = []
        for p in sorted(self.root.glob('*/job.json'), reverse=True):
            if JOB_ID.fullmatch(p.parent.name) and not p.is_symlink():
                try: out.append(self.job(p.parent.name))
                except (ValueError, OSError): pass
        return out

    def update(self, jid, **updates):
        with self.lock:
            job = self.job(jid)
            job.update(updates, updated_at=time.time())
            self._write_job(jid, job)
            return job

    def _new(self, project, proof, *, imported=False):
        jid = secrets.token_hex(10)
        folder = self._folder(jid)
        folder.mkdir(mode=0o700, exist_ok=False)
        self._write_job(jid, {'id': jid, 'status': 'STARTING' if not imported else 'COMPLETE',
                              'stage': 'EXPLICIT_OPERATOR_REQUEST' if not imported else 'IMPORTED_COMPLETED_LOCAL_RESULT',
                              'input_sha256': proof['sha256'], 'created_at': time.time(),
                              'mode': 'fast', 'imported_prior_cli': imported, 'project': project[:100]})
        return jid

    def submit(self, blob, name):
        if not self.allow_scan or not self.engine.enable_scan:
            raise ValueError('FAST_SCAN_DISABLED')
        proof = self.workbench.validate_upload(blob)
        with self.lock, self.engine.mutex:
            if self.active is not None or self.engine.active is not None or self.stopping or self.engine.stopping:
                raise ValueError('ANOTHER_LOCAL_JOB_IS_ACTIVE')
            self.workbench.release_state(self.cfg)
            if self.workbench.verify_engine(self.cfg['engine']) != self.cfg['engine_manifest_sha256']:
                raise ValueError('FROZEN_ENGINE_DRIFT')
            verify_fast_runner(self.runner, self.workbench, self.cfg)
            jid = self._new(name, proof)
            self.workbench.write_json(self._folder(jid) / 'INTAKE.json', proof, exclusive=True)
            with (self._folder(jid) / 'input.zip').open('xb') as f:
                f.write(blob)
            self.active = jid
            self.thread = threading.Thread(target=self.run_job, args=(jid,), daemon=True)
            self.thread.start()
            return jid

    def import_existing(self, run, project):
        """Explicitly import a previously completed CLI run, never call inference."""
        path = Path(run).expanduser()
        if path.is_symlink() or not path.is_dir():
            raise ValueError('FAST_IMPORT_NOT_DIRECTORY')
        path = path.resolve()
        if not RUN_ID.fullmatch(path.name) or path.parent != self.runroot:
            raise ValueError('FAST_IMPORT_OUTSIDE_PINNED_RUNROOT')
        run_id = path.name
        doc = self._verify_run(run_id)
        for job in self.jobs():
            if job.get('run_id') == run_id and job.get('status') == 'COMPLETE':
                return job['id']
        with self.lock:
            if self.active or self.engine.active:
                raise ValueError('CANNOT_IMPORT_WHILE_SCANNING')
            jid = self._new(project, {'sha256': doc['summary']['input_sha256']}, imported=True)
            self.update(jid, run_id=run_id, elapsed_s=doc['summary']['elapsed_s'], backend_returncode=0)
            return jid

    def run_job(self, jid):
        folder = self._folder(jid)
        log = folder / 'engine.log'
        p = None
        started = time.monotonic()
        try:
            cfg = self.cfg
            old_runs = {d.name for d in self.runroot.iterdir() if d.is_dir()} if self.runroot.exists() else set()
            argv = [cfg['host_python'], '-I', '-B', '-u', str(self.runner), '--run-hybrid',
                    '--host-python', cfg['host_python'], '--work', cfg['work'], '--repo', cfg['repo'],
                    '--github', cfg['github'], '--downloads', cfg['downloads'], '--project-zip', str(folder / 'input.zip')]
            self.workbench.write_json(folder / 'COMMAND.json', {'argv': argv,
                'runner_sha256': digest(self.workbench.read(self.runner,2*1024*1024)), 'mode': 'EPOCH1_ADAPTIVE_EXPERIMENTAL',
                'consented_local_execution': True}, exclusive=True)
            with log.open('xb') as output:
                p = subprocess.Popen(argv, cwd=self.runner.parent, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT,
                                     env=self.workbench.offline_env(), start_new_session=True, close_fds=True)
                with self.lock:
                    self.process = p
                    self.update(jid, status='RUNNING', pid=p.pid)
                offset, carry, stage, stop_sent = 0, '', '', False
                while p.poll() is None:
                    with log.open('rb') as f:
                        f.seek(offset)
                        part = f.read(256 * 1024)
                        offset = f.tell()
                    carry += part.decode('utf-8', errors='replace')
                    lines = carry.split('\n')
                    carry = lines.pop()[-4096:]
                    for line in lines:
                        if line.startswith('B39B4_STAGE='):
                            stage = line.split('=', 1)[1][:160]
                    self.update(jid, stage=stage or 'STARTING_BACKEND', elapsed_s=round(time.monotonic()-started, 1))
                    if time.monotonic()-started > 7200 and not stop_sent:
                        p.send_signal(signal.SIGTERM)
                        stop_sent = True
                        self.update(jid, status='STOPPING', stage='TWO_HOUR_DEADLINE_STOP_REQUESTED')
                    time.sleep(1)
            text = self.workbench.read(log, 16 * 1024 * 1024).decode('utf-8', errors='replace')
            vals = {}
            for line in text.splitlines():
                if line.startswith(('RUN_DIR=', 'OUTPUT_ZIP=', 'OUTPUT_SHA256=', 'STATUS=', 'BLOCKER=')) and '=' in line:
                    k, v = line.split('=', 1)
                    vals[k] = v
            if p.returncode != 0 or vals.get('STATUS') not in SUCCESS:
                raise RuntimeError(('BACKEND_NOT_COMPLETE_EXIT_'+str(p.returncode)+': '+vals.get('BLOCKER', 'CHECK_LOCAL_ENGINE_LOG'))[:450])
            rid = Path(vals['RUN_DIR']).name
            if not RUN_ID.fullmatch(rid) or Path(vals['RUN_DIR']).resolve() != self.runroot / rid or rid in old_runs:
                raise ValueError('FAST_RUN_PROVENANCE_FAILED')
            validated = self._verify_run(rid, expected_sha=vals['OUTPUT_SHA256'])
            if validated['summary']['input_sha256'] != self.job(jid)['input_sha256']:
                raise ValueError('FAST_RESULT_INPUT_MISMATCH')
            if Path(vals['OUTPUT_ZIP']).resolve() != Path(cfg['downloads']).resolve() / (rid + '_result.zip'):
                raise ValueError('FAST_OUTPUT_ZIP_PATH_DRIFT')
            self.update(jid, status='COMPLETE', stage='RESULT_VERIFIED_AND_REGISTERED', run_id=rid,
                        elapsed_s=round(time.monotonic()-started,1), backend_returncode=p.returncode)
        except Exception as exc:
            self.update(jid, status='BLOCKED', stage='CHECK_LOCAL_ENGINE_LOG', error=str(exc)[:450],
                        elapsed_s=round(time.monotonic()-started,1), backend_returncode=p.poll() if p else None)
        finally:
            if p is not None and p.poll() is None:
                try: p.send_signal(signal.SIGTERM)
                except ProcessLookupError: pass
                try: p.wait(timeout=120)
                except subprocess.TimeoutExpired: pass
            with self.lock:
                if p is None or p.poll() is not None:
                    self.process = None
                    self.active = None
                else:
                    self.process = p
                    self.update(jid, status='STOP_UNCONFIRMED', stage='INSPECT_OWN_PROCESS_NO_BROAD_KILL')

    def _verify_run(self, rid, expected_sha=None):
        if not isinstance(rid,str) or not RUN_ID.fullmatch(rid):
            raise ValueError('FAST_RUN_ID_INVALID')
        rd = self.runroot / rid
        if rd.is_symlink() or not rd.is_dir():
            raise ValueError('FAST_RUN_NOT_FOUND')
        zp = Path(self.cfg['downloads']) / (rid + '_result.zip')
        raw = self.workbench.read(zp, 64 * 1024 * 1024)
        actual_sha = digest(raw)
        if expected_sha and actual_sha != expected_sha:
            raise ValueError('FAST_ARCHIVE_SHA_CHANGED')
        sha_sidecar = Path(str(zp)+'.sha256')
        sidecar = self.workbench.read(sha_sidecar, 4096).decode('ascii').strip()
        if sidecar != actual_sha+'  '+zp.name:
            raise ValueError('FAST_ARCHIVE_SIDECAR_MISMATCH')
        entries = self.workbench.archive(raw, actual_sha)
        required = ('00_RESULT.json','COMPARISON.json','PROFILE_DISCOVERY.json',
                    'PRIVATE_RESULT_MANIFEST.json','BEFORE.json','AFTER.json','RUN_PROTOCOL.json')
        # The RAW_ONLY branch has no RUN_PROTOCOL (model not prepared).
        for key in required:
            if key not in entries and key != 'RUN_PROTOCOL.json':
                raise ValueError('FAST_MISSING_METADATA:'+key)
        data = self.workbench.loads(entries['00_RESULT.json'])
        if data['status'] not in SUCCESS or data.get('blockers') or data.get('new_training') is not False:
            raise ValueError('FAST_NOT_VERIFIED_COMPLETE')
        if data.get('independent_gold') is not False or data.get('model_xss_gate_granted') is not False:
            raise ValueError('FAST_SCOPE_DRIFT')
        if entries['BEFORE.json'] != entries['AFTER.json']:
            raise ValueError('FAST_FROZEN_RELEASE_CHANGED')
        if not re.fullmatch(r'[0-9a-f]{64}', data.get('input_sha256','')):
            raise ValueError('FAST_INPUT_SHA')
        for key in required:
            if key in entries and self.workbench.read(rd / key, 32 * 1024 * 1024) != entries[key]:
                raise ValueError('FAST_LOCAL_METADATA_DRIFT:'+key)
        comp = self.workbench.loads(entries['COMPARISON.json'])
        profile = self.workbench.loads(entries['PROFILE_DISCOVERY.json'])
        # V2.3 provenance is optional for imported V2.2 runs. If provided,
        # its claims must be internally consistent, pinned and byte-identical.
        if 'FAST_SOURCE_ABSENCE_PROOF.json' in entries:
            from fastscan_v23_patch import POLICY_PINS
            proof_bytes=entries['FAST_SOURCE_ABSENCE_PROOF.json']
            if self.workbench.read(rd / 'FAST_SOURCE_ABSENCE_PROOF.json',2*1024*1024)!=proof_bytes:
                raise ValueError('FAST_SOURCE_PROOF_LOCAL_MISMATCH')
            sp=self.workbench.loads(proof_bytes)
            active=set(profile.get('active_cwes',[]))
            claimed=sp.get('skipped_source_queries',[])
            expected_skipped=sorted(active & {'22','78','89'}) if sp.get('env_source_proven_absent') is True else []
            if sorted(claimed)!=expected_skipped or len(claimed)!=len(set(claimed)):
                raise ValueError('FAST_SOURCE_SKIP_PROVENANCE_CONFLICT')
            if sp.get('no_source_is_not_safe') is not True:
                raise ValueError('FAST_SOURCE_PROOF_SAFETY_SEMANTICS')
            if sp.get('env_source_proven_absent') is True and (sp.get('query_pins_verified') is not True or
                    sp.get('query_sha256')!=POLICY_PINS or
                    not isinstance(sp.get('source_sha256'),dict) or
                    len(sp.get('source_sha256'))!=sp.get('verified_java_files')):
                raise ValueError('FAST_SOURCE_PINNED_PROOF_INVALID')
        manifest = self.workbench.loads(entries['PRIVATE_RESULT_MANIFEST.json'])
        arms = tuple(comp['arms'])
        want = ('opengrep_only', 'epoch_1') if data['status']=='NTK_FASTSCAN_EPOCH1_COMPLETE' else ('opengrep_only',)
        if set(arms) != set(want) or data['completed_arms'] != list(want):
            raise ValueError('FAST_ARMS_STATUS_MISMATCH')
        if profile.get('no_candidates_is_not_safe') is not True or set(profile.get('active_cwes',[])+profile.get('no_candidates_cwes',[])) != {'22','78','79','89'}:
            raise ValueError('FAST_PROFILE_DISCOVERY_SCOPE')
        if data['status']=='NTK_FASTSCAN_EPOCH1_COMPLETE' and sum(profile['candidates'].values())!=data['new_native_requests']:
            raise ValueError('FAST_NATIVE_REQUEST_COUNT')
        if data['status']=='NTK_FASTSCAN_RAW_ONLY_NO_CANDIDATES' and sum(profile['candidates'].values())!=0:
            raise ValueError('FAST_RAW_ONLY_CANDIDATE_CONFLICT')
        verified_files={}
        for arm in want:
            for leaf in ('result.json','report.sarif'):
                relative='analysis/'+arm+'/'+leaf
                if relative not in manifest:
                    raise ValueError('FAST_PRIVATE_FILE_NOT_IN_MANIFEST')
                p = rd / 'private' / relative
                b = self.workbench.read(p, 32 * 1024 * 1024)
                if digest(b) != manifest[relative]:
                    raise ValueError('FAST_PRIVATE_RESULT_HASH_DRIFT')
                verified_files[(arm,leaf)] = b
            report = self.workbench.loads(verified_files[(arm,'result.json')])
            self.workbench.verify_report(report, comp['arms'][arm], arm, data['input_sha256'])
            sarif = self.workbench.loads(verified_files[(arm,'report.sarif')])
            if sarif.get('version') != '2.1.0' or sum(len(z.get('results',[])) for z in sarif.get('runs',[])) != len(report['findings']):
                raise ValueError('FAST_SARIF_FINDINGS_COUNT')
        native={}
        if 'epoch_1' in want:
            native_record = self.workbench.loads(entries['NATIVE_epoch_1.json'])
            if native_record.get('new_requests') != data['new_native_requests']:
                raise ValueError('FAST_NATIVE_SUMMARY_DRIFT')
            native['epoch_1'] = {k:v for k,v in native_record.items() if k in ('accepted','abstain','candidates','reasons','performance')}
        return {'summary':data,'comparison':comp,'native':native,
                'profile_discovery':profile, 'registration':{'run_id':rid,'input_sha256':data['input_sha256'],
                'audit_sha256':actual_sha,'origin':'EXPERIMENTAL_FAST_E1_LOCAL'},
                'mode':'FAST_E1_COMPLETED_PRIOR_CLI_OR_NEW_WEB_NOT_RESEARCH_FOUR_ARM'}

    def overview(self, rid):
        return self._verify_run(rid)

    def file(self, rid, arm, leaf):
        if arm not in ALLOWED_ARMS or leaf not in ('result.json', 'report.sarif'):
            raise ValueError('FAST_ARM_OR_FILE_NOT_ALLOWED')
        facts = self._verify_run(rid)
        if arm not in facts['comparison']['arms']:
            raise ValueError('FAST_ARM_NOT_EXECUTED')
        path = self.runroot / rid / 'private' / 'analysis' / arm / leaf
        return self.workbench.read(path, 32 * 1024 * 1024)

    def evidence(self, rid):
        self._verify_run(rid)
        return self.workbench.read(Path(self.cfg['downloads']) / (rid + '_result.zip'), 64 * 1024 * 1024)

    def view(self, rid, arm):
        facts = self._verify_run(rid)
        if arm not in facts['comparison']['arms']:
            raise ValueError('FAST_ARM_NOT_EXECUTED')
        raw = self.file(rid, arm, 'result.json')
        report = self.workbench.loads(raw)
        out = []
        for x in report['findings']:
            model = x.get('model_observation') or {}
            label = model.get('label') or {}
            call = x.get('callsite') or {}
            out.append({'id': x['id'], 'cwe': x['cwe'], 'location': x['location'],
                'rule_id': x['rule_id'], 'origin': x['origin'],
                'score': {k:v for k,v in x['score'].items() if k!='risk_description'},
                'evidence_status':x['evidence_status'], 'evidence_origin':x.get('evidence_origin', 'OPENGREP_ONLY'),
                'confirmed':False, 'retained':True,
                'callsite':{k:call[k] for k in ('package','class','method','signature','compiler_signature') if k in call},
                'model':{'status':model.get('status','NOT_APPLIED'), 'role':label.get('type'), 'reason':model.get('reason')},
                'dataflow':[{k:n[k] for k in ('uri','start_line','start_column','type') if k in n}
                            for n in x.get('dataflow',[])],
                'raw_policy_path_count':len(x.get('raw_policy_flow_ids',[])),
                'encoding_assessments':[a.get('status','UNKNOWN') for a in x.get('sanitizer_assessments',[])]})
        return {'run_id':rid,'arm':arm,'input_sha256':report['input_sha256'],'findings':out,
                'scope':'READ_ONLY_SANITIZED_VIEW; NO_RAW_PROMPTS_OR_MODEL_COMPLETIONS',
                'independent_gold':False,'score_is_probability':False,'original_result_sha256':digest(raw)}

    def request_stop(self, jid):
        with self.lock:
            if jid != self.active or self.process is None or self.process.poll() is not None:
                raise ValueError('NO_OWN_ACTIVE_FASTSCAN')
            self.process.send_signal(signal.SIGTERM)
            self.update(jid,status='STOPPING',stage='OWN_FAST_RUNNER_SIGTERM_REQUESTED')

    def close(self):
        with self.lock:
            self.stopping=True
            thread=self.thread
            proc=self.process
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        if thread and thread.is_alive():
            thread.join(timeout=120)
        if thread and thread.is_alive():
            raise RuntimeError('FAST_RUNNER_STILL_ACTIVE_NO_BROAD_KILL')
