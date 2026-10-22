"""CPU-only test of fast/deep routing. No engine, GPU, CodeQL, or scanner used."""
from __future__ import annotations
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
from test_app import FakeEngine

FRID='ntkfast_20261021T085514Z_e86a3942'
FJID='e'*20

class FakeFast:
    def __init__(self):
        self.active=None
        self.lock=threading.RLock()
        self._jobs={}
        self.seen=[]
    def job(self,jid):return self._jobs[jid]
    def submit(self,blob,name):
        self.seen.append((blob,name))
        self._jobs[FJID]={'id':FJID,'status':'COMPLETE','run_id':FRID,
                          'stage':'DONE','mode':'fast','imported_prior_cli':False}
        return FJID
    def overview(self,rid):
        assert rid==FRID
        return {'mode':'FAST_E1_COMPLETED_PRIOR_CLI_OR_NEW_WEB_NOT_RESEARCH_FOUR_ARM',
                'summary':{'elapsed_s':285,'raw_opengrep_findings':2,'input_sha256':'a'*64},
                'profile_discovery':{'active_cwes':['78','89'],'no_candidates_cwes':['22','79'],
                                     'no_candidates_is_not_safe':True},
                'comparison':{'arms':{'opengrep_only':{'retained_opengrep':2},'epoch_1':{'retained_opengrep':2}}},
                'native':{'epoch_1':{'accepted':1,'abstain':1}}}
    def view(self,rid,arm):
        assert arm in ('epoch_1','opengrep_only')
        return {'run_id':rid,'arm':arm,'findings':[{'id':'test','score':{'final_score':51},'cwe':'89'}]}
    def evidence(self,rid):return b'PK-FAKE-BYTES'
    def file(self,rid,arm,leaf):
        assert arm in ('epoch_1','opengrep_only')
        return b'{}'
    def request_stop(self,jid):raise ValueError('NOT_ACTIVE')

class FastWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.eng=FakeEngine()
        self.fast=FakeFast()
        self.reg=server.SessionCatalog(Path(self.tmp.name)/'ui')
        self.web=server.create_server(self.eng,object(),server.DatasetCatalog(self.tmp.name),self.reg,0,self.fast)
        self.web.token='test-token'
        self.thread=threading.Thread(target=self.web.serve_forever,daemon=True)
        self.thread.start()
        self.base='http://127.0.0.1:'+str(self.web.server_port)
    def tearDown(self):
        self.web.shutdown();self.web.server_close();self.thread.join(timeout=4);self.tmp.cleanup()
    def req(self,path,body=None,headers=None):
        req=urllib.request.Request(self.base+path,data=body,headers=headers or {})
        try:
            with urllib.request.urlopen(req,timeout=3) as r:return r.status,r.read()
        except urllib.error.HTTPError as e:return e.code,e.read()
    def test_fast_submission_and_readonly_reports(self):
        good={'X-NTK-CSRF':'test-token','X-NTK-Scan-Mode':'fast',
              'X-NTK-Consent':'TRUSTED_JDK_ONLY_RUN_FAST_E1','Content-Type':'application/zip',
              'X-NTK-Project-Name':'trusted.zip'}
        self.assertEqual(self.req('/api/jobs',b'PKfake',{**good,'X-NTK-Consent':'TRUSTED_JDK_ONLY_RUN_ALL_FOUR_ARMS'})[0],403)
        code,body=self.req('/api/jobs',b'PKfake',good)
        self.assertEqual(code,202)
        self.assertEqual(json.loads(body)['mode'],'fast')
        code,body=self.req('/api/runs')
        self.assertEqual(code,200)
        self.assertEqual(json.loads(body)[0]['mode'],'fast')
        code,body=self.req('/api/runs/'+FRID)
        self.assertEqual(code,200)
        self.assertIn('profile_discovery',json.loads(body))
        code,body=self.req('/api/runs/'+FRID+'/epoch_1')
        self.assertEqual(json.loads(body)['findings'][0]['score']['final_score'],51)
        self.assertEqual(self.req('/api/runs/'+FRID+'/base')[0],404)
        code,body=self.req('/api/runs/'+FRID+'/evidence.zip')
        self.assertEqual(body,b'PK-FAKE-BYTES')
    def test_registry_clear_does_not_delete_backend(self):
        self.fast.submit(b'PKfake','test.zip')
        self.reg.add(FJID,'test.zip', 'fast')
        h={'X-NTK-CSRF':'test-token','Content-Type':'application/json'}
        code,body=self.req('/api/session/clear',b'{"confirm":"HIDE_LOCAL_UI_SCAN_HISTORY"}',h)
        self.assertEqual(code,200)
        self.assertTrue(json.loads(body)['verified_evidence_preserved'])
        self.assertEqual(self.req('/api/runs/'+FRID)[0],404)
        self.assertIn(FJID,self.fast._jobs)
    def test_no_parallel_scan(self):
        self.fast.active=FJID
        h={'X-NTK-CSRF':'test-token','X-NTK-Scan-Mode':'deep',
           'X-NTK-Consent':'TRUSTED_JDK_ONLY_RUN_ALL_FOUR_ARMS','Content-Type':'application/zip'}
        self.assertEqual(self.req('/api/jobs',b'PKfake',h)[0],409)
        self.assertEqual(self.req('/api/runs')[0],200)
        self.assertEqual(self.req('/api/session/clear',b'{"confirm":"HIDE_LOCAL_UI_SCAN_HISTORY"}',
                                  {'X-NTK-CSRF':'test-token','Content-Type':'application/json'})[0],409)
    def test_origin_guards(self):
        self.assertEqual(self.req('/api/connect',headers={'Origin':'https://attacker.example'})[0],403)
        code,body=self.req('/api/connect')
        self.assertTrue(json.loads(body)['backend']['fast_available'])
        self.assertTrue(json.loads(body)['single_port'])

if __name__=='__main__':unittest.main()
