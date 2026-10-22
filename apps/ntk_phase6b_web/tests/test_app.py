"""Local CPU-only tests; fake engine is TEST-ONLY, never shipped as demo scan data."""
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
from dataset_io import create_xlsx, parse_xlsx, parse_jsonl

RID='b39b4_20261020T100814Z_63d29938'
JID='a'*20


class FakeStore:
    def overview(self, rid):
        assert rid == RID
        return {'summary': {'raw_opengrep_findings': 1, 'elapsed_s': 43, 'input_sha256': 'a'*64},
                'comparison': {'arms': {arm: {'retained_opengrep': 1, 'evidence_by_cwe': {'22':{'qualified_paths': 1},'78':{'qualified_paths': 0},'79':{'qualified_paths': 0},'89':{'qualified_paths': 0}}} for arm in server.ARMS}},
                'native': {k: {'accepted': 1, 'abstain': 0} for k in server.ARMS[1:]}}
    def view(self, rid, arm):
        assert rid == RID and arm in server.ARMS
        return {'findings': [{'id':'TEST_ONLY','cwe':'22','score':{'final_score':88.5,'risk_level':'HIGH'},
                              'location':{'uri':'src/Example.java','start_line':7},'evidence_origin':'MODEL_DERIVED'}]}
    def evidence(self, rid): return b'PKtest-only', None
    def full_file(self, rid, arm, leaf): return b'{}'


class FakeEngine:
    def __init__(self):
        self.enable_scan = True
        self.store = FakeStore()
        self.active = None
        self.cfg = {'engine': '/nonexistent-test-engine'}
        self.samples = {}
        self._jobs = {}
    def job(self, jid): return self._jobs[jid]
    def submit(self, blob):
        assert blob.startswith(b'PK')
        self._jobs[JID] = {'id': JID, 'status': 'COMPLETE', 'run_id': RID, 'stage': 'DONE'}
        return JID
    def request_stop(self, jid): raise ValueError('Nothing running')


class DataTest(unittest.TestCase):
    def test_jsonl_counts_and_xlsx_roundtrip(self):
        rows=[{'role':'sink','api':'=SUM(1,2)'},{'role':'none','api':'org.example.run'}]
        parsed=parse_jsonl(('\n'.join(json.dumps(x) for x in rows)+'\n').encode())
        self.assertEqual(parsed['count'],2)
        blob=create_xlsx(parsed['columns'],parsed['rows'])
        self.assertEqual(parse_xlsx(blob)['rows'],parsed['rows'])
        self.assertNotIn(b'<f>',blob)
    def test_catalog_exact_counts_and_sha(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);d=base/'batch39b2_data_runtime'/'data';d.mkdir(parents=True)
            for split, name in server.LOCAL_DATASET_NAMES.items():
                with (d/name).open('w') as f:
                    for i in range(server.EXPECTED_COUNTS[split]):
                        f.write(json.dumps({'id':i,'type':'sink'},ensure_ascii=False)+'\n')
            c=server.DatasetCatalog(base)
            self.assertEqual(c.get('train')['count'],950)
            self.assertEqual(c.get('validation')['count'],137)
            self.assertEqual(len(c.info()['train']['sha256']),64)
    def test_does_not_invent_missing_train(self):
        with tempfile.TemporaryDirectory() as td:
            c=server.DatasetCatalog(td)
            self.assertFalse(c.info()['train']['available'])
            with self.assertRaises(ValueError):c.get('train')
    def test_reject_ambiguous_candidate_sources(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'batch39b2_data_runtime'
            for sub, val in (('one',1),('two',2)):
                p=root/sub;p.mkdir(parents=True)
                with (p/server.LOCAL_DATASET_NAMES['train']).open('w') as f:
                    for i in range(950):f.write(json.dumps({'id':i,'seed':val})+'\n')
            c=server.DatasetCatalog(td)
            self.assertFalse(c.info()['train']['available'])
            self.assertIn('nhiều bản',c.info()['train']['message'])


class SessionTest(unittest.TestCase):
    def test_only_new_jobs_and_clear_does_not_touch_workbench(self):
        with tempfile.TemporaryDirectory() as td:
            ui=server.SessionCatalog(td)
            eng=FakeEngine()
            eng._jobs['b'*20]={'id':'b'*20,'status':'COMPLETE','run_id':RID}
            self.assertEqual(ui.run_items(eng),[])  # archived engine run hidden
            ui.add(JID,'Customer.zip')
            self.assertEqual(len(ui.run_items(eng)),0)  # job not yet submitted
            eng.submit(b'PKtest')
            self.assertEqual(len(ui.run_items(eng)),1)
            self.assertEqual(ui.run_items(eng)[0]['project'],'Customer.zip')
            ui.clear(eng)
            self.assertEqual(ui.run_items(eng),[])
            self.assertIn(JID, eng._jobs)  # untouched research engine artifacts
    def test_clear_fails_when_active(self):
        with tempfile.TemporaryDirectory() as td:
            ui=server.SessionCatalog(td)
            eng=FakeEngine();eng.active='c'*20
            with self.assertRaises(ValueError):ui.clear(eng)


class HttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.eng=FakeEngine()
        self.data=server.DatasetCatalog(self.tmp.name)
        self.session=server.SessionCatalog(Path(self.tmp.name)/'ui')
        self.http=server.create_server(self.eng,object(),self.data,self.session,port=0)
        self.http.token='test-ui-token'
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()
        self.base='http://127.0.0.1:'+str(self.http.server_port)
    def tearDown(self):
        self.http.shutdown();self.http.server_close();self.thread.join(timeout=3)
        self.tmp.cleanup()
    def req(self,path,body=None,headers=None,method=None):
        request=urllib.request.Request(self.base+path,method=method or ('POST' if body is not None else 'GET'),data=body,headers=headers or {})
        try:
            with urllib.request.urlopen(request,timeout=5) as r:return r.status,r.read(),r.headers
        except urllib.error.HTTPError as e:return e.code,e.read(),e.headers
    def test_page_and_empty_results_no_legacy(self):
        code,data,_=self.req('/')
        self.assertEqual(code,200)
        self.assertIn('NTK SAST'.encode(),data)
        self.assertNotIn(b'B39B.8',data)
        self.assertNotIn(b'8767',data)
        code,data,_=self.req('/api/runs')
        self.assertEqual(json.loads(data),[])
    def test_post_guards(self):
        code,_,_=self.req('/api/jobs',b'PKfake')
        self.assertEqual(code,403)
        good={'X-NTK-CSRF':'test-ui-token','X-NTK-Consent':'TRUSTED_JDK_ONLY_RUN_ALL_FOUR_ARMS',
              'X-NTK-Project-Name':'MyProject.zip','Content-Type':'application/zip'}
        code,data,_=self.req('/api/jobs',b'PKtest',good)
        self.assertEqual(code,202)
        self.assertEqual(json.loads(data)['job_id'],JID)
        code,data,_=self.req('/api/runs')
        self.assertEqual(len(json.loads(data)),1)
        code,data,_=self.req('/api/runs/'+RID+'/epoch_1')
        self.assertEqual(json.loads(data)['findings'][0]['score']['risk_level'],'HIGH')
        code,data,_=self.req('/api/session/clear',json.dumps({'confirm':'HIDE_LOCAL_UI_SCAN_HISTORY'}).encode(),
            {'X-NTK-CSRF':'test-ui-token','Content-Type':'application/json'})
        self.assertEqual(code,200)
        self.assertTrue(json.loads(data)['verified_evidence_preserved'])
        code,data,_=self.req('/api/runs/'+RID)
        self.assertEqual(code,404)
    def test_cross_origin_and_unknown_paths(self):
        self.assertEqual(self.req('/',headers={'Origin':'https://attacker.example'})[0],403)
        self.assertEqual(self.req('/api/private/files')[0],404)
        self.assertEqual(self.req('/api/dataset/train')[0],409)
    def test_http_xlsx(self):
        body=json.dumps({'columns':['api'],'rows':[['=2+2']]}).encode()
        status,raw,_=self.req('/api/dataset/export',body,
            {'X-NTK-CSRF':'test-ui-token','Content-Type':'application/json'})
        self.assertEqual(status,200)
        self.assertEqual(parse_xlsx(raw)['rows'],[['=2+2']])


if __name__=='__main__':unittest.main()
