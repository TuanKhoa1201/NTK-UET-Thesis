#!/usr/bin/env python3
"""B38D: independent localhost UI on 8766. Requires audited D gate for each model."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import zipfile
from bootstrap import ROOT,ENGINE
from ntk_b33.common import Blocker,sha_file,write_json
from secure_intake import secure_unpack,IntakeError,MAX_ZIP
from run_batch38 import require_gate,implementation_sha


class App:
 def __init__(self,work,downloads,repo,port):
  self.work=work;self.downloads=downloads;self.repo=repo;self.port=port
  self.token=secrets.token_urlsafe(32);self.lock=threading.Lock();self.active=None
  self.jobs={};self.process=None;self.allowed=[];self.impl=implementation_sha()
  self.runtime=work/'batch38_web';self.runtime.mkdir(parents=True,exist_ok=True)
  for arm in ('epoch_1','epoch_2'):
   try:require_gate(work,'D',arm,self.impl);self.allowed.append(arm)
   except (Blocker,OSError,KeyError,ValueError):pass
  if not self.allowed:raise Blocker('NO_VALID_B38D_MODEL_GATE: run A/B/C/D before starting this UI')

 def snapshot(self,job):
  with self.lock:
   state=self.jobs.get(job)
   return json.loads(json.dumps(state)) if state else None

 def submit(self,blob,arm,cwe):
  if arm not in self.allowed:raise ValueError('MODEL_NOT_ACCEPTED_BY_D_GATE')
  if cwe not in ('all','22','78','79','89'):raise ValueError('INVALID_CWE')
  with self.lock:
   if self.active is not None:raise ValueError('ONE_SCAN_AT_A_TIME')
   job=secrets.token_hex(10);self.active=job
   self.jobs[job]={'id':job,'status':'RUNNING','stage':'ZIP_INTAKE','arm':arm,'cwe':cwe,
                   'input_sha256':hashlib.sha256(blob).hexdigest(),'mode':'REAL_NEW_INPUT_B38_SCOPED'}
  folder=self.runtime/job;folder.mkdir()
  try:
   proof=secure_unpack(blob,folder/'intake_check')
   if not 1<=len(list((folder/'intake_check').rglob('*.java')))<=24:raise ValueError('JDK_ONLY_MAX24_JAVA')
   (folder/'project.zip').write_bytes(blob);write_json(folder/'intake_proof.json',proof)
  except Exception:
   with self.lock:self.active=None;self.jobs[job]['status']='BLOCKED'
   raise
  thread=threading.Thread(target=self.run_job,args=(job,folder,arm,cwe),daemon=True);thread.start()
  return job

 def run_job(self,job,folder,arm,cwe):
  phase={'all':'D','22':'A','78':'B','79':'C','89':'SQL'}[cwe]
  try:
   # Input and asset directories differ. Downloads holds only this job's reports.
   out=folder/'downloads';out.mkdir()
   # The engine needs the immutable B33 evidence in its downloads directory.
   old=self.downloads/'batch33_20261018T144300Z_6460a4_result.zip'
   import shutil
   shutil.copy2(old,out/old.name)
   argv=[str(self.work/'.ntk_v5_lora_venv/bin/python'),'-B','-u',str(ROOT/'run_batch38.py'),
     '--phase',phase,'--arm',arm,'--project-zip',str(folder/'project.zip'),
     '--work',str(self.work),'--repo',str(self.repo),'--downloads',str(out)]
   log=folder/'engine.log'
   with log.open('wb') as f:
    p=subprocess.Popen(argv,stdout=f,stderr=subprocess.STDOUT,start_new_session=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
    self.process=p;began=time.monotonic()
    while p.poll() is None:
     lines=log.read_text(errors='replace').splitlines()
     stages=[x for x in lines if x.startswith('B38_STAGE=')]
     with self.lock:
      self.jobs[job]['stage']=stages[-1][10:] if stages else 'INITIALIZING_ENGINE'
      self.jobs[job]['elapsed_s']=round(time.monotonic()-began,1)
     if time.monotonic()-began>14400:
      p.terminate();p.wait(timeout=20);raise ValueError('SCAN_TIMEOUT')
     time.sleep(1)
   self.process=None
   archives=list(out.glob('batch38*_result.zip'))
   if len(archives)!=1:raise ValueError('ENGINE_DID_NOT_PRODUCE_UNIQUE_EVIDENCE_ZIP: see engine.log')
   with zipfile.ZipFile(archives[0]) as z:
    if z.testzip():raise ValueError('RESULT_ZIP_CRC_FAILURE')
    manifest=json.loads(z.read('OUTPUT_MANIFEST.json'))
    for name,h in manifest.items():
     if hashlib.sha256(z.read(name)).hexdigest()!=h:raise ValueError('EVIDENCE_HASH_FAILURE')
    s=json.loads(z.read('00_SUMMARY.json'))
    if s.get('input_sha256')!=self.jobs[job]['input_sha256'] or s.get('implementation_sha256')!=self.impl:
     raise ValueError('WRONG_INPUT_OR_ENGINE_PROVENANCE')
    summary={'summary':s,'job_id':job,'uploaded_sha256':s['input_sha256'],'arm':arm,'cwe_selection':cwe,
     'findings':[],'paths':[],'artifact_sha256':sha_file(archives[0]),
     'scope':'JDK_ONLY_DECLARED_SOURCES_NO_GENERAL_CWE_COVERAGE','training_executed':False}
    if s['status']!='B38_BLOCKED':
     db=json.loads(z.read('DATABASE_PROOF.json'))
     if not db.get('created_in_this_run') or db.get('new_project_sha256')!=s['input_sha256']:
      raise ValueError('DATABASE_NOT_FOR_THIS_UPLOAD')
     summary['findings']=json.loads(z.read('analysis/'+arm+'/FUSED_FINDINGS.json'))
     summary['paths']=json.loads(z.read('analysis/'+arm+'/VERIFIED_PATHS.json'))
     (folder/'report.sarif').write_bytes(z.read('analysis/'+arm+'/FUSED_FINDINGS.sarif'))
    write_json(folder/'result.json',summary)
   with self.lock:
    self.jobs[job].update(status='BLOCKED' if s['status']=='B38_BLOCKED' else
      'NEEDS_REVIEW' if s['status']=='B38_COMPLETED_NEEDS_REVIEW' else 'COMPLETE',
      stage='FINISHED',engine_status=s['status'],blocker=s.get('blocker'),evidence_file=str(archives[0]))
  except Exception as e:
   with self.lock:self.jobs[job].update(status='BLOCKED',stage='ERROR',blocker=str(e))
  finally:
   with self.lock:self.active=None

 def close(self):
  if self.process and self.process.poll() is None:
   self.process.terminate()
   try:self.process.wait(timeout=20)
   except subprocess.TimeoutExpired:self.process.kill();self.process.wait()


def handler(app):
 class Handler(BaseHTTPRequestHandler):
  def reply(self,code,body,ctype='application/json'):
   if isinstance(body,(dict,list)):body=json.dumps(body,ensure_ascii=False).encode()
   if isinstance(body,str):body=body.encode()
   self.send_response(code);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)))
   self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
   self.send_header('Referrer-Policy','no-referrer')
   self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
   self.end_headers();self.wfile.write(body)
  def valid_host(self):return self.headers.get('Host') in (f'127.0.0.1:{app.port}',f'localhost:{app.port}')
  def do_GET(self):
   if not self.valid_host():return self.reply(403,{'error':'INVALID_HOST'})
   path=urlsplit(self.path).path
   if path=='/':return self.reply(200,(ROOT/'web/index.html').read_text().replace('__CSRF__',app.token),'text/html; charset=utf-8')
   if path in ('/web/app.js','/web/style.css'):
    return self.reply(200,(ROOT/path[1:]).read_bytes(),'text/javascript; charset=utf-8' if path.endswith('.js') else 'text/css; charset=utf-8')
   if path=='/api/health':return self.reply(200,{'accepted_arms':app.allowed,'cwes':['22','78','79','89'],
     'engine_sha256':app.impl,'source_scope':'ENV_FOR_22_78_89_HTTP_URI_QUERY_FOR_79','general_coverage':False})
   sample=re.fullmatch(r'/api/sample/(A|B|C|D|SQL)',path)
   if sample:return self.reply(200,(ROOT/'samples'/('B38'+sample.group(1)+'_JAVA.zip')).read_bytes(),'application/zip')
   m=re.fullmatch(r'/api/jobs/([0-9a-f]{20})(?:/(result\.json|report\.sarif|evidence\.zip|engine\.log))?',path)
   if not m:return self.reply(404,{'error':'NOT_FOUND'})
   job,leaf=m.groups();state=app.snapshot(job)
   if state is None:return self.reply(404,{'error':'JOB_NOT_FOUND'})
   if leaf is None:return self.reply(200,state)
   if leaf=='evidence.zip':
    dest=Path(state.get('evidence_file','/nonexistent'))
   else:dest=app.runtime/job/leaf
   if not dest.is_file():return self.reply(409,{'error':'ARTIFACT_NOT_READY'})
   return self.reply(200,dest.read_bytes(),'application/zip' if leaf=='evidence.zip' else
     'application/sarif+json' if leaf=='report.sarif' else 'text/plain; charset=utf-8' if leaf=='engine.log' else 'application/json')
  def do_POST(self):
   if not self.valid_host() or self.headers.get('Origin') not in (None,f'http://127.0.0.1:{app.port}',f'http://localhost:{app.port}'):
    return self.reply(403,{'error':'INVALID_HOST_OR_ORIGIN'})
   if self.headers.get('X-NTK-CSRF')!=app.token:return self.reply(403,{'error':'CSRF_TOKEN_REQUIRED'})
   if urlsplit(self.path).path!='/api/jobs':return self.reply(404,{'error':'NOT_FOUND'})
   if self.headers.get('Content-Type','').split(';')[0]!='application/zip':return self.reply(415,{'error':'ZIP_REQUIRED'})
   n=self.headers.get('Content-Length','')
   if not n.isdecimal() or not 0<int(n)<=MAX_ZIP:return self.reply(413,{'error':'MAX16MIB'})
   self.connection.settimeout(30);blob=self.rfile.read(int(n))
   if len(blob)!=int(n):return self.reply(400,{'error':'TRUNCATED_BODY'})
   try:job=app.submit(blob,self.headers.get('X-NTK-Arm','epoch_1'),self.headers.get('X-NTK-CWE','all'))
   except (ValueError,IntakeError,OSError) as e:return self.reply(400,{'error':str(e)})
   return self.reply(202,{'job_id':job})
 return Handler


def main():
 p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True)
 p.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
 p.add_argument('--repo',type=Path,default=Path.home()/'iris');p.add_argument('--port',type=int,default=8766)
 a=p.parse_args()
 if not 1024<=a.port<=65535:raise Blocker('PORT_OUT_OF_RANGE')
 app=App(a.work.resolve(),a.downloads.resolve(),a.repo.resolve(),a.port)
 srv=ThreadingHTTPServer(('127.0.0.1',a.port),handler(app));srv.daemon_threads=True
 print('B38D_LOCAL_WEB=http://127.0.0.1:'+str(a.port),flush=True)
 print('CWE profiles validated on development fixtures only. Original B37 web remains on 8765.',flush=True)
 try:srv.serve_forever(poll_interval=0.2)
 except KeyboardInterrupt:pass
 finally:app.close();srv.server_close()

if __name__=='__main__':
 try:main()
 except Blocker as e:print('B38D_WEB_BLOCKED='+str(e),flush=True);sys.exit(2)
