#!/usr/bin/env python3
"""Local persistent workbench. Read-only by default; explicit opt-in for NEW B4 scans."""
from __future__ import annotations
import argparse, fcntl, io, json, os, secrets, signal, socket, stat, subprocess, sys, threading, time, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from store import *


def offline_env():
    e=dict(os.environ)
    for k in ('PYTHONPATH','PYTHONHOME'):e.pop(k,None)
    e.update(PYTHONDONTWRITEBYTECODE='1',GIT_OPTIONAL_LOCKS='0',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1',WANDB_DISABLED='true',CODEQL_TELEMETRY_DISABLE='1',TOKENIZERS_PARALLELISM='false')
    return e

def verify_engine(root):
    root=Path(root);manifest=read(root/'SHA256SUMS');records={}
    for line in manifest.decode('ascii').splitlines():
        need(bool(re.fullmatch(r'[0-9a-f]{64}  .+',line)),'ENGINE_MANIFEST_LINE')
        h,n=line.split('  ',1);need(n not in records,'ENGINE_MANIFEST_DUPLICATE');records[n]=h
    for n,h in records.items():need(sha(read(under(root,n)))==h,'ENGINE_SOURCE_DRIFT:'+n)
    return sha(manifest)

def release_state(config):
    work=Path(config['work']);source=Path((work/'NTK_BATCH38_POLICY_TOOL_PATH.txt').read_text().strip()).resolve()
    expected=config['baseline'];out={'git':{},'gates':{}}
    for k,repo in (('iris',Path(config['repo'])),('github',Path(config['github']))):
        def git(*args):
            p=subprocess.run(['git','-C',str(repo),*args],capture_output=True,text=True,timeout=60,env=offline_env())
            need(p.returncode==0,'GIT_READ_FAILED');return p.stdout.strip()
        out['git'][k]={'head':git('rev-parse','HEAD'),'status':git('status','--porcelain')}
        need(out['git'][k]==expected['git'][k],'GIT_BASELINE_CHANGED:'+k)
    for label,root in (('P',source),('G',Path(config['github'])/'ntk_hybrid/b38_policy')):
        b=read(root/'SHA256SUMS');h=sha(b);need(h==expected[label+'_manifest_sha256'],'SOURCE_MANIFEST_CHANGED')
        out[label+'_manifest_sha256']=h
        for line in b.decode('ascii').splitlines():
            h,n=line.split('  ',1);need(sha(read(under(root,n)))==h,'RELEASE_SOURCE_CHANGED:'+n)
    gd=work/'batch38_policy_gates'
    out['gates']={p.name:sha(read(p)) for p in sorted(gd.glob('*.json'))}
    need(out['gates']==expected['gates'],'EXISTING_GATES_CHANGED')
    return out

def validate_upload(blob):
    need(0<len(blob)<=16*1024**2,'UPLOAD_SIZE_LIMIT_16_MIB')
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            info=z.infolist();need(len(info)<=256,'ZIP_ENTRY_LIMIT');seen=set();java=0;total=0
            for i in info:
                name=i.filename;safe_name(name);k=name.casefold();need(k not in seen,'DUPLICATE_ZIP_PATH');seen.add(k)
                mode=stat.S_IFMT(i.external_attr>>16)
                need(mode in (0,stat.S_IFREG,stat.S_IFDIR) and not i.flag_bits&1,'ZIP_SPECIAL_OR_ENCRYPTED')
                if i.is_dir():continue
                need(name.endswith('.java'),'JAVA_ONLY_NO_BUILD_SCRIPTS_OR_BINARIES')
                java+=1;total+=i.file_size;need(i.file_size<=2*1024**2 and total<=16*1024**2,'JAVA_SIZE_LIMIT')
                z.read(i)  # CRC, bounded above; no extraction or compilation here.
            need(1<=java<=24,'JDK_ONLY_1_TO_24_JAVA')
    except zipfile.BadZipFile:raise Blocked('INVALID_PROJECT_ZIP') from None
    return {'sha256':sha(blob),'java_files':java,'bytes':len(blob),'label':'OPERATOR_TRUSTED_INPUT_NOT_GOLD'}

class App:
    def __init__(self,state,port,enable_scan=False):
        self.state=Path(state).resolve();self.cfg=loads(read(self.state/'config.json'))
        self.store=Store(self.state,self.cfg['work']);self.port=port;self.enable_scan=enable_scan
        self.csrf=secrets.token_urlsafe(32);self.mutex=threading.RLock();self.active=None;self.process=None;self.thread=None;self.stopping=False
        self.jobs_dir=self.state/'jobs';self.jobs_dir.mkdir(exist_ok=True)
        # Never attach to, signal, resume or declare success for a PID from a prior server.
        for p in sorted(self.jobs_dir.glob('*/job.json')):
            old=loads(read(p))
            if old.get('status') in ('RUNNING','STARTING','STOPPING'):
                old.update(status='INTERRUPTED_UNCONFIRMED',stage='SERVER_RESTART_NO_AUTOMATIC_RESUME',previous_pid=old.pop('pid',None));write_json(p,old)
    def job(self,jid):
        need(bool(JOB_RE.fullmatch(jid)),'JOB_ID_INVALID');return loads(read(under(self.jobs_dir,jid+'/job.json')))
    def save_job(self,jid,**fields):
        with self.mutex:
            p=under(self.jobs_dir,jid+'/job.json');v=loads(read(p));v.update(fields,updated_at=time.time());write_json(p,v);return v
    def jobs(self):
        return [loads(read(p)) for p in sorted(self.jobs_dir.glob('*/job.json'),reverse=True)]
    def submit(self,blob):
        need(self.enable_scan,'SCAN_DISABLED_START_WITH_ENABLE_SCAN')
        proof=validate_upload(blob)
        with self.mutex:
            need(not self.stopping and self.active is None,'ANOTHER_LOCAL_JOB_IS_ACTIVE')
            release_state(self.cfg)
            need(verify_engine(self.cfg['engine'])==self.cfg['engine_manifest_sha256'],'ENGINE_MANIFEST_DRIFT')
            jid=secrets.token_hex(10);folder=self.jobs_dir/jid;folder.mkdir(mode=0o700)
            (folder/'input.zip').write_bytes(blob);write_json(folder/'INTAKE.json',proof,exclusive=True)
            write_json(folder/'job.json',{'id':jid,'status':'STARTING','stage':'EXPLICIT_OPERATOR_REQUEST','input_sha256':proof['sha256'],
                       'created_at':time.time(),'scope':'FOUR_ARM_CLI_NEW_SCAN_NOT_B38_DPA_GATE','new_scan_requested':True},exclusive=True)
            self.active=jid;self.thread=threading.Thread(target=self.run_job,args=(jid,),daemon=True);self.thread.start()
            return jid
    def run_job(self,jid):
        cfg=self.cfg;folder=self.jobs_dir/jid;log=folder/'engine.log';p=None
        old_runs={q.name for q in self.store.runroot.iterdir() if q.is_dir()} if self.store.runroot.exists() else set()
        try:
            argv=[cfg['host_python'],'-I','-B','-u',str(Path(cfg['engine'])/'run_hybrid.py'),'--run-hybrid',
                  '--host-python',cfg['host_python'],'--work',cfg['work'],'--repo',cfg['repo'],'--github',cfg['github'],
                  '--downloads',cfg['downloads'],'--project-zip',str(folder/'input.zip')]
            write_json(folder/'COMMAND.json',{'argv':argv,'backend_source':'BYTE_IDENTICAL_B39B4','new_gpu_and_codeql_requested':True},exclusive=True)
            with log.open('xb') as out:
                p=subprocess.Popen(argv,cwd=cfg['engine'],stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,
                                   env=offline_env(),start_new_session=True,close_fds=True)
                with self.mutex:
                    self.process=p;self.save_job(jid,status='RUNNING',pid=p.pid)
                    if self.stopping:p.send_signal(signal.SIGTERM)
                began=time.monotonic();offset=0;carry='';seen_stage='';stop_sent=False
                while p.poll() is None:
                    with log.open('rb') as f:f.seek(offset);part=f.read(256*1024);offset=f.tell()
                    carry+=part.decode('utf-8',errors='replace');lines=carry.split('\n');carry=lines.pop()[-4096:]
                    stages=[s[len('B39B4_STAGE='):] for s in lines if s.startswith('B39B4_STAGE=')]
                    if stages:seen_stage=stages[-1][:160]
                    self.save_job(jid,stage=seen_stage or 'STARTING_BACKEND',elapsed_s=round(time.monotonic()-began,1))
                    if time.monotonic()-began>4*3600 and not stop_sent:
                        p.send_signal(signal.SIGTERM);stop_sent=True;self.save_job(jid,status='STOPPING',stage='FOUR_HOUR_DEADLINE_STOP_REQUESTED')
                    time.sleep(1)
                # The original backend packages failure evidence too; do not equate an archive with success.
                text=read(log,limit=16*1024**2).decode('utf-8',errors='replace')
                values={}
                for line in text.splitlines():
                    if '=' in line:
                        k,v=line.split('=',1)
                        if k in ('RUN_DIR','OUTPUT_ZIP','OUTPUT_SHA256','STATUS'):values[k]=v
                need(p.returncode==0 and values.get('STATUS')=='B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE','BACKEND_NOT_COMPLETE_EXIT_'+str(p.returncode))
                rid=Path(values['RUN_DIR']).name;need(bool(RUN_RE.fullmatch(rid)),'BACKEND_RUN_ID')
                need(Path(values['RUN_DIR']).resolve()==self.store.runroot/rid,'BACKEND_RUN_PATH')
                need(rid not in old_runs,'BACKEND_RETURNED_OLD_RUN_NOT_THIS_JOB')
                zp=Path(cfg['downloads'])/(rid+'_result.zip')
                need(Path(values['OUTPUT_ZIP']).resolve()==zp.resolve(),'BACKEND_ZIP_PATH')
                metadata=archive(read(zp),values['OUTPUT_SHA256'])
                need(loads(metadata['00_RESULT.json'])['input_sha256']==self.job(jid)['input_sha256'],'BACKEND_INPUT_NOT_THIS_UPLOAD')
                with self.mutex:self.store.register(rid,zp,values['OUTPUT_SHA256'],'NEW_EXPLICIT_LOCAL_JOB')
                self.save_job(jid,status='COMPLETE',stage='RESULT_VERIFIED_AND_REGISTERED',run_id=rid,backend_returncode=p.returncode)
        except Exception as exc:
            self.save_job(jid,status='BLOCKED',stage='INSPECT_LOCAL_ENGINE_LOG',error=str(exc)[:600],backend_returncode=p.poll() if p else None)
        finally:
            if p is not None and p.poll() is None:
                try:p.send_signal(signal.SIGTERM)
                except ProcessLookupError:pass
                try:p.wait(timeout=120)
                except subprocess.TimeoutExpired:pass
            with self.mutex:
                if p is None or p.poll() is not None:self.process=None;self.active=None
                else:
                    self.process=p
                    self.save_job(jid,status='STOP_UNCONFIRMED',stage='INSPECT_OWN_BACKEND_NO_BROAD_KILL')
    def request_stop(self,jid):
        with self.mutex:
            need(self.active==jid and self.process is not None and self.process.poll() is None,'NO_OWN_RUNNING_JOB')
            # Signal only the owned runner. Its existing finally clauses stop its own child groups.
            self.process.send_signal(signal.SIGTERM);self.save_job(jid,status='STOPPING',stage='OWN_BACKEND_SIGTERM_REQUESTED')
    def close(self):
        with self.mutex:
            self.stopping=True;t=self.thread;p=self.process
            if p is not None and p.poll() is None:
                p.send_signal(signal.SIGTERM)
        if t and t.is_alive():t.join(timeout=120)
        need((not t or not t.is_alive()) and (p is None or p.poll() is not None),'BACKEND_CLEANUP_UNCONFIRMED_INSPECT_LOCAL_LOG_NO_BROAD_KILL')


def handler(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def setup(self):super().setup();self.connection.settimeout(30)
        def log_message(self,fmt,*args): pass # URLs/tokens/source bodies are not written to shared logs.
        def allowed(self):
            allowed=('127.0.0.1:'+str(app.port),'localhost:'+str(app.port))
            return self.headers.get('Host') in allowed and self.headers.get('Origin') in (None,*('http://'+x for x in allowed)) and self.headers.get('Sec-Fetch-Site')!='cross-site'
        def reply(self,code,body,ctype='application/json; charset=utf-8',filename=None):
            if isinstance(body,(dict,list)):body=canonical(body).encode()
            elif isinstance(body,str):body=body.encode()
            self.send_response(code);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
            self.end_headers();self.wfile.write(body)
        def do_GET(self):
            try:
                if not self.allowed():return self.reply(403,{'error':'INVALID_HOST_OR_ORIGIN'})
                path=urlsplit(self.path).path
                if path=='/':return self.reply(200,read(ROOT/'web/index.html').replace(b'__CSRF__',app.csrf.encode()),'text/html; charset=utf-8')
                if path in ('/app.js','/style.css'):return self.reply(200,read(ROOT/'web'/path[1:]),'text/javascript; charset=utf-8' if path.endswith('.js') else 'text/css; charset=utf-8')
                if path=='/api/health':return self.reply(200,{'mode':'B39B5_PERSISTENT_COMPARISON_WORKBENCH','scan_enabled':app.enable_scan,
                    'registered_runs':len(app.store.catalog),'active_job':app.active,'historical_results_are_not_new_scans':True,
                    'model_xss_gate_granted':False,'cwes':list(CWES),'arms':list(ARMS),'production_b38_8766_not_replaced':True})
                if path=='/api/runs':return self.reply(200,app.store.listing())
                if path=='/api/jobs':return self.reply(200,app.jobs())
                if path=='/api/sample':return self.reply(200,read(Path(app.cfg['engine'])/'samples/B39B4_JDK_INTEGRATION.zip'),'application/zip','B39B4_JDK_INTEGRATION.zip')
                if path.startswith('/api/jobs/'):
                    jid=path[len('/api/jobs/'):];return self.reply(200,app.job(jid))
                parts=path.strip('/').split('/')
                if len(parts)>=3 and parts[:2]==['api','runs']:
                    rid=parts[2]
                    if len(parts)==3:return self.reply(200,app.store.overview(rid))
                    if len(parts)==4 and parts[3]=='evidence.zip':
                        raw,_=app.store.evidence(rid);return self.reply(200,raw,'application/zip',rid+'_result.zip')
                    if len(parts)==4 and parts[3] in ARMS:return self.reply(200,app.store.view(rid,parts[3]))
                    if len(parts)==5 and parts[3] in ARMS and parts[4] in ('result.json','report.sarif'):
                        raw=app.store.full_file(rid,parts[3],parts[4]);return self.reply(200,raw,'application/json',rid+'_'+parts[3]+'_'+parts[4])
                return self.reply(404,{'error':'NOT_FOUND'})
            except (Blocked,OSError,ValueError,KeyError) as exc:self.reply(409,{'error':str(exc)[:600]})
        def do_POST(self):
            try:
                if not self.allowed():return self.reply(403,{'error':'INVALID_HOST_OR_ORIGIN'})
                if self.headers.get('X-NTK-CSRF')!=app.csrf:return self.reply(403,{'error':'CSRF_REQUIRED'})
                if not app.enable_scan:return self.reply(403,{'error':'SCAN_DISABLED_START_WITH_ENABLE_SCAN'})
                path=urlsplit(self.path).path
                if path=='/api/jobs':
                    need(self.headers.get('X-NTK-Consent')=='TRUSTED_JDK_ONLY_RUN_ALL_FOUR_ARMS','TRUSTED_INPUT_CONSENT_REQUIRED')
                    need(self.headers.get('Content-Type','').split(';')[0]=='application/zip','ZIP_CONTENT_TYPE_REQUIRED')
                    length=self.headers.get('Content-Length','');need(length.isdecimal() and 0<int(length)<=16*1024**2,'UPLOAD_SIZE_LIMIT_16_MIB')
                    need(not self.headers.get('Transfer-Encoding'),'CHUNKED_UPLOAD_NOT_SUPPORTED')
                    data=self.rfile.read(int(length));need(len(data)==int(length),'INCOMPLETE_UPLOAD')
                    return self.reply(202,{'job_id':app.submit(data)})
                m=re.fullmatch(r'/api/jobs/([0-9a-f]{20})/stop',path)
                if m:app.request_stop(m.group(1));return self.reply(202,{'status':'STOP_REQUESTED_NOT_YET_STOPPED'})
                self.reply(404,{'error':'NOT_FOUND'})
            except (Blocked,OSError,ValueError,KeyError) as exc:self.reply(409,{'error':str(exc)[:600]})
    return Handler

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--state',type=Path,required=True);ap.add_argument('--port',type=int,default=8767)
    ap.add_argument('--enable-scan',action='store_true');a=ap.parse_args(argv)
    need(1024<=a.port<=65535,'PORT_RANGE');need(a.port not in (8765,8766),'PRESERVE_EXISTING_WEBSITES')
    config=loads(read(a.state/'config.json'));release_state(config)
    need(verify_engine(config['engine'])==config['engine_manifest_sha256'],'ENGINE_CHANGED')
    lock=(a.state/'server.lock').open('a+')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise Blocked('THIS_WORKBENCH_STATE_ALREADY_SERVED') from None
    app=App(a.state,a.port,a.enable_scan);srv=None
    try:
        srv=ThreadingHTTPServer(('127.0.0.1',a.port),handler(app));srv.daemon_threads=True
        print('NTK_WORKBENCH=http://127.0.0.1:'+str(a.port),flush=True)
        print('SCAN_ENABLED='+str(a.enable_scan),flush=True)
        print('READING_HISTORY_DOES_NOT_RUN_MODELS_OR_CODEQL',flush=True)
        srv.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:pass
    finally:
        if srv:srv.server_close()
        app.close();lock.close()
    return 0
if __name__=='__main__':
    def interrupted(signum,frame):raise KeyboardInterrupt('SIGNAL_'+str(signum))
    signal.signal(signal.SIGTERM,interrupted)
    try:sys.exit(main())
    except Exception as e:print('WORKBENCH_BLOCKED='+str(e),flush=True);sys.exit(2)
