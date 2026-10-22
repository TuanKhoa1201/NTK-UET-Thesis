"""Phase6B localhost asynchronous job manager, separate from legacy workbench.

Full-project jobs never enter the Phase6A imported prior-evidence registry.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from fullproject_pipeline import MAX_ZIP, zip_inventory, read, sha

ID=re.compile(r'fp6b_[0-9a-f]{20}\Z')
TERMINAL={'COMPLETE','PARTIAL','BLOCKED','STOPPED','INTERRUPTED_UNCONFIRMED'}
RUNNING={'STARTING','RUNNING','STOPPING'}

class LiveError(ValueError):pass

class LiveJobs:
    def __init__(self,root,runner,python,*,enabled=True):
        self.root=Path(root).expanduser().resolve()
        self.runner=Path(runner).resolve(strict=True)
        self.python=str(python)
        self.enabled=bool(enabled)
        self.lock=threading.RLock()
        self.process=None
        self.active=None
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        os.chmod(self.root,0o700)
        # Previous runs survive restart. A vanished worker must not masquerade as successful.
        for p in self.root.glob('fp6b_*'):
            if not p.is_dir() or p.is_symlink() or not ID.fullmatch(p.name):continue
            s=p/'status.json'
            if not s.is_file() or s.is_symlink():continue
            try:
                row=read(s,65536)
                if row.get('status') in RUNNING:
                    row['status']='INTERRUPTED_UNCONFIRMED'
                    row['error']='Server restarted before final worker receipt'
                    from fullproject_pipeline import save
                    save(s,row)
            except (ValueError,OSError,json.JSONDecodeError):pass

    def is_busy(self):
        with self.lock:
            return self.active is not None and self.process is not None and self.process.poll() is None

    def _folder(self,jid):
        if not ID.fullmatch(str(jid)):raise LiveError('INVALID_FULLPROJECT_JOB_ID')
        path=self.root/jid
        if not path.is_dir() or path.is_symlink():raise LiveError('FULLPROJECT_JOB_NOT_FOUND')
        return path

    def submit(self,data,name):
        if not self.enabled:raise LiveError('FULLPROJECT_SCANS_DISABLED')
        if not isinstance(data,bytes) or not 0<len(data)<=MAX_ZIP:raise LiveError('ZIP_UPLOAD_LIMIT_64_MIB')
        label=Path(str(name).replace('\\','/')).name[:100] or 'github-project.zip'
        if not label.lower().endswith('.zip'):raise LiveError('FULLPROJECT_ZIP_REQUIRED')
        with self.lock:
            if self.is_busy():raise LiveError('ANOTHER_FULLPROJECT_SCAN_ACTIVE')
            jid='fp6b_'+secrets.token_hex(10)
            folder=self.root/jid
            folder.mkdir(mode=0o700)
            try:
                src=folder/'input.zip'
                with src.open('xb') as f:f.write(data)
                src.chmod(0o600)
                manifest,_=zip_inventory(src)
                if manifest['java_files_zip']>15000:raise LiveError('JAVA_FILE_LIMIT')
                from fullproject_pipeline import save
                status={'id':jid,'project':label,'created_at':int(time.time()),
                        'status':'STARTING','stage':'ZIP_INTAKE','elapsed_s':0,
                        'new_scan':True,'input_sha256':sha(src)}
                save(folder/'status.json',status)
                output=(folder/'worker.log').open('xb')
                try:
                    p=subprocess.Popen([self.python,'-I','-B','-u',str(self.runner),'--job',str(folder)],
                       cwd=folder,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,
                       env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1',
                            'CODEQL_TELEMETRY_DISABLE':'1','GIT_TERMINAL_PROMPT':'0'},
                       close_fds=True,start_new_session=True)
                finally:output.close()
                self.active=jid;self.process=p
                return {'job_id':jid,'mode':'fullproject','status':'STARTING',
                        'source_java_entries':manifest['java_files_zip'],
                        'entry_count':manifest['members'],
                        'codeql_build_mode':'none','new_scan':True}
            except Exception:
                # No unknown deletion. Only the newly allocated folder can be removed.
                import shutil
                if self.active!=jid and folder.is_dir() and not folder.is_symlink():shutil.rmtree(folder)
                raise

    def job(self,jid):
        folder=self._folder(jid)
        state=read(folder/'status.json',65536)
        if state.get('id')!=jid:raise LiveError('JOB_STATUS_ID_MISMATCH')
        if state.get('status') in RUNNING and self.active==jid and self.process is not None and self.process.poll() is not None:
            from fullproject_pipeline import save
            state['status']='INTERRUPTED_UNCONFIRMED'
            state['error']='Worker exited without a verified terminal report'
            save(folder/'status.json',state)
            with self.lock:
                self.active=None;self.process=None
        return state

    def jobs(self):
        found=[]
        for path in sorted(self.root.glob('fp6b_*'),key=lambda x:x.name,reverse=True)[:100]:
            if path.is_dir() and not path.is_symlink() and ID.fullmatch(path.name):
                try:found.append(self.job(path.name))
                except (OSError,ValueError,json.JSONDecodeError):continue
        return found

    def stop(self,jid):
        with self.lock:
            state=self.job(jid)
            if state.get('status') not in RUNNING:raise LiveError('JOB_NOT_RUNNING')
            if self.active!=jid or self.process is None or self.process.poll() is not None:
                raise LiveError('NO_OWNED_ACTIVE_WORKER')
            from fullproject_pipeline import save
            state['status']='STOPPING'
            state['stage']='STOP_REQUESTED'
            save(self._folder(jid)/'status.json',state)
            try:os.killpg(self.process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            return {'status':'STOP_REQUESTED_NOT_YET_CONFIRMED'}

    def artifact(self,jid,name):
        if name not in ('result.json','report.sarif','SCAN_SUMMARY.json','RESULT_MANIFEST.json'):
            raise LiveError('ARTIFACT_NOT_ALLOWED')
        state=self.job(jid)
        if state.get('status') not in ('COMPLETE','PARTIAL'):
            raise LiveError('RESULT_NOT_READY')
        folder=self._folder(jid)
        manifest=read(folder/'RESULT_MANIFEST.json',65536)
        import hashlib
        leaf=folder/name
        if name=='RESULT_MANIFEST.json':
            for filename,expected in manifest.items():
                if filename not in ('result.json','report.sarif','SCAN_SUMMARY.json','opengrep_fullproject.json'):
                    raise LiveError('RESULT_MANIFEST_CONTAINS_UNEXPECTED_FILE')
                target=folder/filename
                if not target.is_file() or target.is_symlink() or sha(target)!=expected:
                    raise LiveError('RESULT_MANIFEST_VERIFICATION_FAILED')
        else:
            if name not in manifest or not leaf.is_file() or leaf.is_symlink():
                raise LiveError('VERIFIED_ARTIFACT_NOT_FOUND')
            if sha(leaf)!=manifest[name]:raise LiveError('RESULT_ARTIFACT_SHA256_DRIFT')
        if not leaf.is_file() or leaf.is_symlink() or leaf.stat().st_size>50*1024**2:
            raise LiveError('ARTIFACT_RESPONSE_TOO_LARGE_OR_UNSAFE')
        return leaf.read_bytes()

    def close(self):
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                try:os.killpg(self.process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    try:os.killpg(self.process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    self.process.wait(timeout=5)
            self.process=None;self.active=None
