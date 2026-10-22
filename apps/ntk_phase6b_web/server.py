#!/usr/bin/env python3
"""Single-port localhost NTK SAST UI, using the installed verified Workbench engine.

No second HTTP service is required. No changes to the frozen IRIS tree, model
weights, production gate, pinned scoring source, or existing research artifacts.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, unquote
# The launch script uses Python -I; explicitly import only this bundled module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dataset_io import create_xlsx, parse_jsonl, parse_csv, parse_xlsx
from fast_bridge import FastBridge, RUN_ID as FAST_RUN_RE, ALLOWED_ARMS as FAST_ARMS
from fullproject_view import FullProjectView, PROJECTS as FULLPROJECT_NAMES
from fullproject_live import LiveJobs
from fullproject_pipeline import MAX_ZIP

HERE = Path(__file__).resolve().parent
MAX_DATASET = 16 * 1024 * 1024
MAX_UPLOAD = 16 * 1024 * 1024
JOB_ID = re.compile(r'[0-9a-f]{20}\Z')
RUN_ID = re.compile(r'b39b4_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\Z')
ARMS = ('opengrep_only', 'base', 'epoch_1', 'epoch_2')
LOCAL_DATASET_NAMES = {
    'train': '01_TRAIN_SILVER_WEAK_950.jsonl',
    'validation': '02_VALIDATION_WEAK_DISJOINT.jsonl',
}
EXPECTED_COUNTS = {'train': 950, 'validation': 137}


def enc(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read_restricted(path, maximum=MAX_DATASET):
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise ValueError('Tệp dữ liệu không tồn tại hoặc là đường dẫn liên kết.')
    before = p.stat()
    if before.st_size <= 0 or before.st_size > maximum or not stat.S_ISREG(before.st_mode):
        raise ValueError('Kích thước tệp dữ liệu không hợp lệ.')
    with p.open('rb') as f:
        raw = f.read(maximum + 1)
    after = p.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) or len(raw) != before.st_size:
        raise ValueError('Tệp dữ liệu bị thay đổi trong khi đang đọc.')
    return raw


def find_local_datasets(workroot):
    """Look only under known data-lock workspaces, never follow symlinks."""
    w = Path(workroot)
    roots = [p for p in [w / 'batch39b2_data_runtime', w / 'batch39b1_discovery',
                         w / 'batch39b6_dataset_sast'] if p.is_dir() and not p.is_symlink()]
    if not roots and w.is_dir():
        roots = [w]
    found = {'train': [], 'validation': []}
    max_dirs = 3500
    visited = 0
    for root in roots:
        for base, ds, files in os.walk(root, followlinks=False):
            visited += 1
            if visited > max_dirs:
                return found
            relative = len(Path(base).relative_to(root).parts)
            ds[:] = [] if relative >= 7 else [d for d in ds if not d.startswith('.') and
                    not (Path(base) / d).is_symlink() and d not in ('__pycache__', 'node_modules', '.git')]
            for split, name in LOCAL_DATASET_NAMES.items():
                if name in files:
                    p = Path(base) / name
                    if not p.is_symlink():
                        found[split].append(p)
    return found


class DatasetCatalog:
    def __init__(self, workroot, train=None, validation=None):
        self.data = {}
        self.errors = {}
        candidates = find_local_datasets(workroot) if not (train and validation) else {}
        for split, manual in (('train', train), ('validation', validation)):
            options = [Path(manual).expanduser()] if manual else candidates.get(split, [])
            if not options:
                self.errors[split] = 'Chưa tìm thấy tệp dữ liệu gốc trên máy.'
                continue
            # Multiple byte-distinct candidates cannot be silently declared the training input.
            try:
                hashes = {file_sha(p) for p in options if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_DATASET}
                if len(hashes) != 1:
                    raise ValueError('Có nhiều bản dữ liệu khác nhau; hãy chỉ định đường dẫn dữ liệu đã khóa.')
                raw = read_restricted(options[0])
                dataset = parse_jsonl(raw)
                if dataset['count'] != EXPECTED_COUNTS[split]:
                    raise ValueError(f'Số bản ghi {dataset["count"]} không khớp bộ dữ liệu {EXPECTED_COUNTS[split]} mẫu.')
                dataset['sha256'] = hashlib.sha256(raw).hexdigest()
                dataset['source'] = 'LOCAL_TRAINING_DATA'
                dataset['filename'] = options[0].name
                self.data[split] = dataset
            except (ValueError, OSError, UnicodeError) as exc:
                self.errors[split] = str(exc)

    def info(self):
        return {k: {'available': k in self.data,
                    'count': self.data[k]['count'] if k in self.data else 0,
                    'sha256': self.data[k]['sha256'] if k in self.data else None,
                    'message': self.errors.get(k, 'Sẵn sàng xem dữ liệu đã sử dụng huấn luyện.')}
                for k in EXPECTED_COUNTS}

    def get(self, split):
        if split not in self.data:
            raise ValueError(self.errors.get(split, 'Không có bộ dữ liệu được chọn.'))
        return self.data[split]


class SessionCatalog:
    """Only tracks jobs launched in this UI. Clearing never deletes engine evidence."""
    def __init__(self, base):
        self.lock = threading.RLock()
        self.home = Path(base).expanduser()
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        self.path = self.home / 'local_scan_registry.json'
        if self.path.exists() and not self.path.is_symlink():
            try:
                doc = json.loads(read_restricted(self.path, 2 * 1024 * 1024))
                jobs = doc.get('jobs', [])
                if not isinstance(jobs, list) or len(jobs) > 500:
                    raise ValueError('Bad registry')
                self.jobs = [j for j in jobs if isinstance(j, dict) and JOB_ID.fullmatch(j.get('id', ''))]
            except (ValueError, OSError, json.JSONDecodeError):
                raise RuntimeError('Không thể xác minh danh mục quét cá nhân. Không ghi đè dữ liệu hiện có.')
        else:
            self.jobs = []

    def save(self):
        raw = enc({'version': 1, 'jobs': self.jobs})
        temp = self.home / ('.registry-' + secrets.token_hex(8))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            os.replace(temp, self.path)
        finally:
            if temp.exists():
                temp.unlink()

    def add(self, jid, name, mode='deep'):
        if not JOB_ID.fullmatch(jid):
            raise ValueError('Mã tác vụ không hợp lệ.')
        label = Path(name.replace('\\', '/')).name.strip()[:100] or 'Dự án Java'
        with self.lock:
            if mode not in ('deep','fast'):
                raise ValueError('INVALID_SCAN_MODE')
            self.jobs.append({'id': jid, 'project': label, 'mode': mode,
                              'created_at': int(time.time())})
            self.save()

    def job_ids(self):
        with self.lock:
            return {j['id'] for j in self.jobs}

    def job_mode(self, jid):
        with self.lock:
            for j in self.jobs:
                if j['id'] == jid:
                    return j.get('mode', 'deep')
        return None

    def run_items(self, engine, fast=None):
        with self.lock:
            entries=list(self.jobs)
        visible=[]
        for entry in reversed(entries):
            try:
                is_fast=entry.get('mode')=='fast'
                if is_fast and fast is None:
                    continue
                backend=fast if is_fast else engine
                j=backend.job(entry['id'])
                rid=j.get('run_id','')
                if j.get('status') != 'COMPLETE':
                    continue
                if is_fast:
                    if not FAST_RUN_RE.fullmatch(rid):continue
                    detail=fast.overview(rid)
                else:
                    if not RUN_ID.fullmatch(rid):continue
                    detail=engine.store.overview(rid)
                visible.append({'run_id':rid,'status':j['status'],
                    'project':entry['project'], 'created_at':entry['created_at'],
                    'raw_opengrep_findings':detail['summary']['raw_opengrep_findings'],
                    'mode':'fast' if is_fast else 'deep',
                    'imported_prior_cli':bool(j.get('imported_prior_cli',False))})
            except (OSError,ValueError,KeyError,RuntimeError,TypeError):
                continue
        return visible

    def allowed_run(self,engine,rid,fast=None):
        return any(v['run_id']==rid for v in self.run_items(engine,fast))

    def jobs_list(self,engine,fast=None):
        with self.lock:
            entries=list(reversed(self.jobs))
        visible=[]
        for entry in entries:
            try:
                kind=entry.get('mode','deep')
                if kind=='fast' and fast is None:
                    continue
                backend=fast if kind=='fast' else engine
                item=backend.job(entry['id'])
                visible.append({**item,'project':entry['project'],'mode':kind})
            except (OSError,ValueError,KeyError,RuntimeError,TypeError):
                pass
        return visible

    def clear(self,engine,fast=None):
        with self.lock:
            if engine.active is not None or (fast is not None and fast.active is not None) or any(
                 j.get('status') in ('STARTING','RUNNING','STOPPING') for j in self.jobs_list(engine,fast)):
                raise ValueError('Không thể xóa hiển thị khi tác vụ phân tích chưa kết thúc.')
            self.jobs=[]
            self.save()
        return {'cleared':True,'verified_evidence_preserved':True}


def load_verified_engine(workbench_dir, enabled):
    directory = Path(workbench_dir).expanduser().resolve()
    for name in ('workbench.py', 'store.py', 'INSTALL.json', 'SHA256SUMS', 'serve.sh'):
        if not (directory / name).is_file():
            raise RuntimeError('Thiếu thành phần Workbench đã cài: ' + name)
    import importlib.util
    # Reuse source integrity check from the original serve.sh, not a patched engine copy.
    checksum = subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=directory,
                              capture_output=True, text=True, timeout=120)
    if checksum.returncode != 0:
        raise RuntimeError('Kiểm tra SHA256SUMS của Workbench không đạt. Dừng để bảo vệ baseline.')
    install = json.loads(read_restricted(directory / 'INSTALL.json', 2 * 1024 * 1024))
    if os.path.abspath(sys.executable) != os.path.abspath(install['host_python']):
        raise RuntimeError('Hãy dùng Python của môi trường conda iris (NTK_IRIS_PYTHON) đã ghi trong INSTALL.json.')
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location('ntk_local_verified_engine', directory / 'workbench.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Không nạp được Workbench.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = Path(install['state']).resolve()
    cfg = module.loads(module.read(state / 'config.json'))
    module.release_state(cfg)
    if module.verify_engine(cfg['engine']) != cfg['engine_manifest_sha256']:
        raise RuntimeError('Mã nguồn scanner đã thay đổi so với manifest đã khóa.')
    return module, module.App(state, 8770, enable_scan=enabled), state


class App(BaseHTTPRequestHandler):
    server_version = 'NTKSAST/2.0'

    def log_message(self, fmt, *args):
        pass  # No filenames, source, tokens, request bodies or query strings in server logs.

    def allowed(self):
        port = str(self.server.server_port)
        hosts = ('127.0.0.1:' + port, 'localhost:' + port)
        return (self.headers.get('Host') in hosts
                and self.headers.get('Origin') in (None, *(f'http://{x}' for x in hosts))
                and self.headers.get('Sec-Fetch-Site') != 'cross-site')

    def reply(self, status, obj, mime='application/json; charset=utf-8', filename=None):
        raw = enc(obj) if isinstance(obj, (dict, list)) else obj.encode('utf-8') if isinstance(obj, str) else obj
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if filename:
            self.send_header('Content-Disposition', 'attachment; filename="' + filename + '"')
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def fail(self, code, reason):
        self.reply(code, {'error': str(reason)[:400]})

    def get_body(self, limit):
        field = self.headers.get('Content-Length', '')
        if not field.isdecimal() or not 0 < int(field) <= limit or self.headers.get('Transfer-Encoding'):
            raise ValueError('Kích thước yêu cầu không hợp lệ hoặc vượt giới hạn.')
        data = self.rfile.read(int(field))
        if len(data) != int(field):
            raise ValueError('Dữ liệu gửi đến không đầy đủ.')
        return data

    def post_allowed(self):
        return self.allowed() and secrets.compare_digest(self.headers.get('X-NTK-CSRF', ''), self.server.token)

    def do_GET(self):
        if not self.allowed():
            return self.fail(403, 'INVALID_HOST_OR_ORIGIN')
        path = urlsplit(self.path).path
        engine = self.server.engine
        reg = self.server.registry
        try:
            if path == '/':
                content = (HERE / 'web/index.html').read_text(encoding='utf-8')
                return self.reply(200, content.replace('__NTK_LOCAL_CSRF__', self.server.token), 'text/html; charset=utf-8')
            if path in ('/fullproject-live-ui.js', '/fullproject-live-ui.css'):
                name = path[1:]
                mime = 'text/javascript; charset=utf-8' if name.endswith('.js') else 'text/css; charset=utf-8'
                return self.reply(200, (HERE / name).read_bytes(), mime)
            if path in ('/fullproject-ui.js', '/fullproject-ui.css'):
                name = path[1:]
                mime = 'text/javascript; charset=utf-8' if name.endswith('.js') else 'text/css; charset=utf-8'
                return self.reply(200, (HERE / name).read_bytes(), mime)
            if path in ('/app.js', '/style.css'):
                name, mime = ('app.js', 'text/javascript; charset=utf-8') if path.endswith('.js') else ('style.css', 'text/css; charset=utf-8')
                return self.reply(200, (HERE / 'web' / name).read_bytes(), mime)
            if path == '/api/fullproject/live/jobs':
                return self.reply(200, self.server.live.jobs())
            live_match = re.fullmatch(r'/api/fullproject/live/jobs/(fp6b_[0-9a-f]{20})(?:/(result\.json|report\.sarif|SCAN_SUMMARY\.json|RESULT_MANIFEST\.json))?', path)
            if live_match:
                jid, leaf=live_match.groups()
                if leaf is None:return self.reply(200,self.server.live.job(jid))
                mime='application/json; charset=utf-8' if leaf != 'report.sarif' else 'application/sarif+json'
                return self.reply(200,self.server.live.artifact(jid,leaf),mime,'NTK_Phase6B_'+leaf)
            if path == '/api/fullproject':
                if self.server.fullproject is None: return self.fail(404, 'FULLPROJECT_PHASE51_NOT_CONFIGURED')
                return self.reply(200, self.server.fullproject.listing())
            full_match = re.fullmatch(r'/api/fullproject/([A-Za-z0-9._-]+)(?:/(result|result\.json|report\.sarif))?', path)
            if full_match:
                if self.server.fullproject is None: return self.fail(404, 'FULLPROJECT_PHASE51_NOT_CONFIGURED')
                proj, leaf = full_match.groups()
                if proj not in FULLPROJECT_NAMES: return self.fail(404, 'UNKNOWN_FULLPROJECT')
                if leaf is None or leaf == 'result':
                    return self.reply(200, self.server.fullproject.detail(proj))
                return self.reply(200, self.server.fullproject.file(proj, leaf),
                    'application/json; charset=utf-8', 'NTK_FullProject_' + proj + '_' + leaf)
            if path == '/api/connect':
                return self.reply(200, {'connected': True,
                    'backend': {'scan_enabled': engine.enable_scan,
                                'fullproject_new_scan_available':self.server.live.enabled,
                                'fast_available': self.server.fast is not None,
                                'fullproject_phase51_import_available': self.server.fullproject is not None,
                                'registered_runs': len(reg.run_items(engine,self.server.fast))},
                    'single_port': True, 'local_only': True})
            if path == '/api/dataset/info':
                return self.reply(200, self.server.datasets.info())
            if path in ('/api/dataset/train', '/api/dataset/validation'):
                return self.reply(200, self.server.datasets.get(path.split('/')[-1]))
            if path == '/api/runs':
                return self.reply(200, reg.run_items(engine,self.server.fast))
            if path == '/api/jobs':
                return self.reply(200, reg.jobs_list(engine,self.server.fast))
            if path == '/api/sample':
                sample = Path(engine.cfg['engine']) / 'samples' / 'B39B4_JDK_INTEGRATION.zip'
                return self.reply(200, self.server.workbench.read(sample), 'application/zip', 'NTK_Java_Example.zip')
            match = re.fullmatch(r'/api/jobs/([0-9a-f]{20})', path)
            if match and match.group(1) in reg.job_ids():
                jid=match.group(1)
                backend=self.server.fast if reg.job_mode(jid)=='fast' else engine
                if backend is None: return self.fail(404,'FAST_BACKEND_NOT_CONFIGURED')
                return self.reply(200, backend.job(jid))
            match_fast=re.fullmatch(r'/api/runs/(ntkfast_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8})(?:/(.*))?',path)
            if match_fast:
                rid,suffix=match_fast.groups()
                fast=self.server.fast
                if fast is None or not reg.allowed_run(engine,rid,fast):
                    return self.fail(404,'Không tìm thấy dự án trong lịch sử của giao diện.')
                if suffix is None:
                    return self.reply(200,fast.overview(rid))
                if suffix=='evidence.zip':
                    return self.reply(200,fast.evidence(rid),'application/zip','NTK_FastScan_evidence.zip')
                if suffix in FAST_ARMS:
                    return self.reply(200,fast.view(rid,suffix))
                f=re.fullmatch(r'(opengrep_only|epoch_1)/(result\.json|report\.sarif)',suffix)
                if f:
                    return self.reply(200,fast.file(rid,f.group(1),f.group(2)),
                                      'application/json; charset=utf-8', 'NTK_FastScan_'+f.group(1)+'_'+f.group(2))
                return self.fail(404,'NOT_FOUND')
            match = re.fullmatch(r'/api/runs/(b39b4_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8})(?:/(.*))?', path)
            if match:
                rid, suffix = match.groups()
                if not reg.allowed_run(engine, rid):
                    return self.fail(404, 'Không tìm thấy dự án trong lịch sử của giao diện.')
                if suffix is None:
                    return self.reply(200, engine.store.overview(rid))
                if suffix == 'evidence.zip':
                    raw, _ = engine.store.evidence(rid)
                    return self.reply(200, raw, 'application/zip', 'NTK_analysis_receipt.zip')
                if suffix in ARMS:
                    return self.reply(200, engine.store.view(rid, suffix))
                p = re.fullmatch(r'(opengrep_only|base|epoch_1|epoch_2)/(result\.json|report\.sarif)', suffix)
                if p:
                    leaf = p.group(2)
                    return self.reply(200, engine.store.full_file(rid, p.group(1), leaf),
                                      'application/json; charset=utf-8', 'NTK_' + p.group(1) + '_' + leaf)
            return self.fail(404, 'NOT_FOUND')
        except (OSError, KeyError, ValueError, RuntimeError, TypeError) as e:
            return self.fail(409, e)

    def do_POST(self):
        if not self.post_allowed():
            return self.fail(403, 'CSRF_OR_ORIGIN_INVALID')
        path = urlsplit(self.path).path
        engine = self.server.engine
        try:
            if path == '/api/fullproject/live/jobs':
                if not engine.enable_scan:return self.fail(403,'SCAN_DISABLED')
                if self.headers.get('X-NTK-Consent') != 'TRUSTED_FULLPROJECT_ZIP_NO_BUILD':return self.fail(403,'PROJECT_SCAN_CONSENT_REQUIRED')
                if self.headers.get('Content-Type','').split(';')[0] != 'application/zip':return self.fail(415,'ZIP_MIME_REQUIRED')
                if engine.active is not None or (self.server.fast is not None and self.server.fast.active is not None):
                    return self.fail(409,'ANOTHER_LOCAL_SCAN_ACTIVE')
                name=unquote(self.headers.get('X-NTK-Project-Name','project.zip'))
                data=self.get_body(MAX_ZIP)
                return self.reply(202,self.server.live.submit(data,name))
            stop_live=re.fullmatch(r'/api/fullproject/live/jobs/(fp6b_[0-9a-f]{20})/stop',path)
            if stop_live:return self.reply(202,self.server.live.stop(stop_live.group(1)))
            if path == '/api/dataset/parse':
                data = self.get_body(MAX_DATASET)
                ext = self.headers.get('X-NTK-Format', '').lower()
                funcs = {'jsonl': parse_jsonl, 'csv': parse_csv, 'tsv': lambda x: parse_csv(x, '\t'), 'xlsx': parse_xlsx}
                if ext not in funcs:
                    return self.fail(415, 'Hãy chọn tệp JSONL, CSV, TSV hoặc XLSX.')
                return self.reply(200, funcs[ext](data))
            if path == '/api/dataset/export':
                data = json.loads(self.get_body(MAX_DATASET))
                content = create_xlsx(data.get('columns'), data.get('rows'), data.get('sheet', 'Dataset'))
                return self.reply(200, content, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'NTK_dataset.xlsx')
            if path == '/api/session/clear':
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self.fail(415, 'INVALID_CONTENT_TYPE')
                body = json.loads(self.get_body(1024))
                if body != {'confirm': 'HIDE_LOCAL_UI_SCAN_HISTORY'}:
                    return self.fail(400, 'CONFIRMATION_REQUIRED')
                return self.reply(200, self.server.registry.clear(engine,self.server.fast))
            if path == '/api/jobs':
                if self.server.live.is_busy():return self.fail(409,'FULLPROJECT_SCAN_ACTIVE')
                if not engine.enable_scan:
                    return self.fail(403, 'SCAN_DISABLED_RESTART_WITH_ENABLE_SCAN')
                mode=self.headers.get('X-NTK-Scan-Mode','deep')
                if mode not in ('deep','fast'):
                    return self.fail(400,'SCAN_MODE_INVALID')
                consent=('TRUSTED_JDK_ONLY_RUN_FAST_E1' if mode=='fast' else 'TRUSTED_JDK_ONLY_RUN_ALL_FOUR_ARMS')
                if self.headers.get('X-NTK-Consent') != consent:
                    return self.fail(403,'SOURCE_CONSENT_REQUIRED')
                if mode=='fast' and self.server.fast is None:
                    return self.fail(409,'FAST_RUNNER_NOT_CONFIGURED')
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/zip':
                    return self.fail(415, 'APPLICATION_ZIP_REQUIRED')
                name = unquote(self.headers.get('X-NTK-Project-Name', 'Dự án Java'))
                data = self.get_body(MAX_UPLOAD)
                fast=self.server.fast
                if mode=='fast':
                    jid=fast.submit(data,name)
                else:
                    if fast is not None:
                        with fast.lock:
                            if fast.active is not None:
                                raise ValueError('ANOTHER_LOCAL_JOB_IS_ACTIVE')
                            jid=engine.submit(data)
                    else:
                        jid=engine.submit(data)
                self.server.registry.add(jid,name,mode)
                return self.reply(202,{'job_id':jid,'mode':mode})
            p = re.fullmatch(r'/api/jobs/([0-9a-f]{20})/stop', path)
            if p:
                jid = p.group(1)
                if jid not in self.server.registry.job_ids():
                    return self.fail(404, 'JOB_NOT_FOUND')
                mode=self.server.registry.job_mode(jid)
                if mode=='fast' and self.server.fast is not None:
                    self.server.fast.request_stop(jid)
                else:
                    engine.request_stop(jid)
                return self.reply(202,{'status':'STOP_REQUESTED_NOT_YET_STOPPED'})
            return self.fail(404, 'NOT_FOUND')
        except (OSError, KeyError, ValueError, RuntimeError, TypeError, json.JSONDecodeError) as e:
            return self.fail(409, e)


def create_server(engine, workbench, datasets, registry, port=8770, fast=None, fullproject=None, live=None):
    if port != 0 and (not 1024 <= port <= 65535 or port in (8765, 8766, 8767)):
        raise ValueError('Cổng giao diện không hợp lệ.')
    httpd = ThreadingHTTPServer(('127.0.0.1', port), App)
    httpd.daemon_threads = True
    httpd.token = secrets.token_urlsafe(32)
    httpd.engine = engine
    httpd.workbench = workbench
    httpd.registry = registry
    httpd.datasets = datasets
    httpd.fast = fast
    httpd.fullproject = fullproject
    httpd.live = live
    return httpd


def main():
    p = argparse.ArgumentParser(description='NTK SAST - Web phân tích mã nguồn Java trên một cổng localhost')
    p.add_argument('--port', type=int, default=8770)
    p.add_argument('--enable-scan', action='store_true', help='Cho phép quét Java sau khi người dùng xác nhận.')
    p.add_argument('--workbench', default=str(Path.home() / 'migration/ntk_stage3_verified_v5_work/b39b5_tools_ajmVZQl0'))
    p.add_argument('--train-file', type=Path)
    p.add_argument('--validation-file', type=Path)
    p.add_argument('--ui-state', type=Path, default=Path.home() / '.local/share/ntk-sast-ui')
    p.add_argument('--fast-runner', type=Path, help='Đường dẫn runner FastScan độc lập đã ghim SHA')
    p.add_argument('--fullproject-phase51', type=Path, help='Nạp báo cáo Phase 5.1 đã nghiệm thu, CHỈ ĐỌC; không tạo lượt scan mới')
    p.add_argument('--fullproject-live-root', type=Path, default=Path.home()/'migration/ntk_fullproject_web_runs_phase6b')
    p.add_argument('--import-fast-run', type=Path, help='Nạp một lần lượt quét FastScan CLI đã hoàn thành, không chạy lại')
    p.add_argument('--import-name', default='Dự án GitHub đã phân tích trước')
    args = p.parse_args()
    if not (1024 <= args.port <= 65535) or args.port in (8765, 8766, 8767):
        p.error('Port 8770 is recommended (do not override existing system ports).')
    # The original workbench uses 8767 by default; change the in-process HTTP port only.
    module, engine, state = load_verified_engine(args.workbench, args.enable_scan)
    engine.port = args.port
    state_lock = (state / 'server.lock').open('a+')
    try:
        try:
            fcntl.flock(state_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Workbench khác đang dùng trạng thái này. Dừng server 8767/8770 cũ bằng Ctrl+C, không xóa server.lock.')
        catalog = DatasetCatalog(engine.cfg['work'], args.train_file, args.validation_file)
        registry = SessionCatalog(args.ui_state)
        if args.import_fast_run and not args.fast_runner:
            raise ValueError('IMPORT_REQUIRES_FAST_RUNNER')
        fast = FastBridge(args.ui_state,args.fast_runner,module,engine,args.enable_scan) if args.fast_runner else None
        if args.import_fast_run:
            jid=fast.import_existing(args.import_fast_run,args.import_name)
            if jid not in registry.job_ids():
                registry.add(jid,args.import_name,'fast')
        fullproject = FullProjectView(args.fullproject_phase51) if args.fullproject_phase51 else None
        live=LiveJobs(args.fullproject_live_root,HERE/'fullproject_pipeline.py',sys.executable,enabled=args.enable_scan)
        httpd = create_server(engine, module, catalog, registry, args.port, fast=fast, fullproject=fullproject, live=live)
        def signal_stop(signum, frame):
            raise KeyboardInterrupt('SIGNAL_' + str(signum))
        signal.signal(signal.SIGTERM, signal_stop)
        try:
            print('NTK_WEB=http://127.0.0.1:' + str(args.port), flush=True)
            print('ONE_PORT=True; SCAN_ENABLED=' + str(args.enable_scan), flush=True)
            print('FAST_E1_AVAILABLE='+str(fast is not None),flush=True)
            print('FULLPROJECT_PHASE51_IMPORT='+('VERIFIED_READ_ONLY' if fullproject else 'DISABLED'),flush=True)
            print('FULLPROJECT_NEW_ZIP_SCAN=ENABLED_CODEQL_JAVA_NO_BUILD',flush=True)
            print('FULLPROJECT_NATIVE_STAGE3=ATTEMPTED_IF_SUPPORTED_API_AND_GPU_AVAILABLE',flush=True)
            print('FAST_E1_IS_EXPERIMENTAL_NOT_120S_VERIFIED=True',flush=True)
            print('DATASET_TRAIN=' + ('950' if 'train' in catalog.data else 'NOT_FOUND'), flush=True)
            print('DATASET_VALIDATION=' + ('137' if 'validation' in catalog.data else 'NOT_FOUND'), flush=True)
            print('UI_SCAN_HISTORY_ISOLATED=True; FROZEN_ARTIFACTS_UNCHANGED=True', flush=True)
            httpd.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            live.close()
            if fast is not None:
                fast.close()
            engine.close()
    finally:
        state_lock.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as e:
        print('NTK_START_BLOCKED=' + str(e), file=sys.stderr, flush=True)
        sys.exit(2)
