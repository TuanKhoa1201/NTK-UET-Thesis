"""HTTP tests use patched gate metadata, not a real B38 approval."""
import hashlib
import http.client
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bootstrap import ROOT,ENGINE
from ntk_b33.common import Blocker
from secure_intake import secure_unpack,IntakeError
import web_server38 as web

class IntakeTests(unittest.TestCase):
 def test_all_sample_inputs_pass_existing_intake(self):
  for n in ('A','B','C','D','SQL'):
   with tempfile.TemporaryDirectory() as d:
    proof=secure_unpack((ROOT/'samples'/('B38'+n+'_JAVA.zip')).read_bytes(),Path(d)/'src')
    self.assertEqual(len(list((Path(d)/'src').rglob('*.java'))),16 if n=='D' else 4)
 def test_zip_traversal_rejected(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:z.writestr('../outside.java','class X {}')
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(IntakeError):secure_unpack(b.getvalue(),Path(d)/'src')
 def test_symlink_rejected(self):
  b=io.BytesIO();info=zipfile.ZipInfo('Evil.java');info.external_attr=0o120777<<16
  with zipfile.ZipFile(b,'w') as z:z.writestr(info,'/etc/passwd')
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(IntakeError):secure_unpack(b.getvalue(),Path(d)/'src')
 def test_real_child_socket_denial(self):
  code='''import sys,socket,json
sys.path.insert(0,sys.argv[1])
from offline_common import deny_inet
proof=deny_inet()
for family in (socket.AF_INET,socket.AF_INET6):
 try:
  s=socket.socket(family,socket.SOCK_STREAM)
  raise RuntimeError("socket was not denied")
 except PermissionError:pass
print(json.dumps(proof))
'''
  proc=subprocess.run([sys.executable,'-B','-c',code,str(ENGINE)],capture_output=True,text=True,timeout=15)
  self.assertEqual(proc.returncode,0,proc.stderr)
  self.assertEqual(json.loads(proc.stdout)['AF_INET'],'DENIED_EPERM')

class HTTPTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.work=Path(self.tmp.name)
  def gate(w,phase,arm,impl):
   if arm!='epoch_1':raise Blocker('not tested in fake fixture')
   return {'unit_test_only':True}
  with patch.object(web,'require_gate',side_effect=gate):self.app=web.App(self.work,self.work,self.work/'repo',8766)
  self.server=ThreadingHTTPServer(('127.0.0.1',0),web.handler(self.app))
  self.app.port=self.server.server_address[1]
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def tearDown(self):
  self.server.shutdown();self.server.server_close();self.thread.join();self.app.close();self.tmp.cleanup()
 def req(self,method,path,body=None,headers=None):
  conn=http.client.HTTPConnection('127.0.0.1',self.app.port,timeout=10)
  conn.request(method,path,body=body,headers=headers or {});r=conn.getresponse();data=r.read();status=r.status;hdr=dict(r.getheaders());conn.close();return status,hdr,data
 def test_health_requires_gate_but_not_gold(self):
  status,_,body=self.req('GET','/api/health');self.assertEqual(status,200)
  data=json.loads(body);self.assertEqual(data['accepted_arms'],['epoch_1']);self.assertFalse(data['general_coverage'])
 def test_html_local_assets_and_security_headers(self):
  status,h,body=self.req('GET','/');self.assertEqual(status,200)
  self.assertNotIn(b'__CSRF__',body);self.assertEqual(h['X-Content-Type-Options'],'nosniff')
  self.assertIn("frame-ancestors 'none'",h['Content-Security-Policy'])
  self.assertNotIn(b'https://cdn.',body)
 def test_host_rebinding_denied(self):
  status,_,_=self.req('GET','/',headers={'Host':'attacker.invalid'});self.assertEqual(status,403)
 def test_csrf_rejected(self):
  status,_,_=self.req('POST','/api/jobs',body=b'x',headers={'Content-Type':'application/zip'});self.assertEqual(status,403)
 def test_origin_rejected(self):
  status,_,_=self.req('POST','/api/jobs',body=b'x',headers={'Origin':'https://attacker.invalid','X-NTK-CSRF':self.app.token});self.assertEqual(status,403)
 def test_nonzip_rejected(self):
  status,_,_=self.req('POST','/api/jobs',body=b'x',headers={'Content-Type':'text/plain','X-NTK-CSRF':self.app.token});self.assertEqual(status,415)
 def test_sample_download_hash(self):
  status,_,body=self.req('GET','/api/sample/C');self.assertEqual(status,200)
  self.assertEqual(body,(ROOT/'samples/B38C_JAVA.zip').read_bytes())
 def test_upload_unknown_arm_rejected(self):
  data=(ROOT/'samples/B38A_JAVA.zip').read_bytes()
  status,_,body=self.req('POST','/api/jobs',body=data,headers={'Content-Type':'application/zip','X-NTK-CSRF':self.app.token,'X-NTK-Arm':'epoch_2'})
  self.assertEqual(status,400);self.assertIn(b'MODEL_NOT_ACCEPTED',body)
 def test_http_upload_hash_and_job_scope(self):
  blob=(ROOT/'samples/B38A_JAVA.zip').read_bytes()
  with patch.object(self.app,'run_job') as fake:
   status,_,body=self.req('POST','/api/jobs',body=blob,headers={'Content-Type':'application/zip','X-NTK-CSRF':self.app.token,'X-NTK-Arm':'epoch_1','X-NTK-CWE':'22'})
   self.assertEqual(status,202);job=json.loads(body)['job_id']
   status,_,body=self.req('GET','/api/jobs/'+job);state=json.loads(body)
   self.assertEqual(state['input_sha256'],hashlib.sha256(blob).hexdigest())
   self.assertEqual(state['cwe'],'22');self.assertEqual(state['status'],'RUNNING')
   status,_,_=self.req('GET','/api/jobs/'+job+'/report.sarif');self.assertEqual(status,409)
 def test_one_job_at_a_time(self):
  blob=(ROOT/'samples/B38A_JAVA.zip').read_bytes()
  with patch.object(self.app,'run_job'):
   self.app.submit(blob,'epoch_1','22')
   with self.assertRaises(ValueError):self.app.submit(blob,'epoch_1','22')
 def test_missing_gate_blocks_web_start(self):
  with self.assertRaises(Blocker):web.App(self.work/'other',self.work,self.work/'repo',8766)

if __name__=='__main__':unittest.main()
