#!/usr/bin/env python3
"""Synthetic fixtures, real local HTTP, fake backend subprocess. NO model or CodeQL."""
from pathlib import Path
import copy, http.client, io, json, os, subprocess, sys, tempfile, threading, time, unittest, zipfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from store import *
from workbench import App,handler,ThreadingHTTPServer,validate_upload,verify_engine

RID='b39b4_20000101T000000Z_11111111'
NEW_RID='b39b4_20000101T000000Z_22222222'

def zip_bytes(files):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
        for n,x in files.items():
            i=zipfile.ZipInfo(n,date_time=(2026,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,x if isinstance(x,bytes) else x.encode())
    return b.getvalue()

def make_fixture(root):
    work=root/'work';state=root/'state';run=work/'batch39b4_hybrid_runs'/RID;state.mkdir(parents=True);run.mkdir(parents=True)
    engine=root/'engine';engine.mkdir();downloads=root/'downloads';downloads.mkdir()
    input_sha=sha(zip_bytes({'T.java':'class T {}'}));data={};findings={};files={};comparison={};natives={}
    for arm in ARMS:
        rows=[];per={};ev={}
        for i,c in enumerate(CWES):
            has=(arm!='opengrep_only' and c=='79') or (arm in ('epoch_1','epoch_2') and c=='22')
            score=75.8 if has else 50.0
            flow=[{'uri':'SYNTHETIC.java','start_line':1,'type':'source'},{'uri':'SYNTHETIC.java','start_line':2,'type':'sink'}] if has else []
            row={'id':'opengrep:'+str(i),'cwe':c,'origin':'OPENGREP','retained':True,'vulnerability_confirmed':False,
                 'rule_id':'synthetic/cwe'+c,'location':{'uri':'SYNTHETIC.java','start_line':2},
                 'score':{'final_score':score,'ai_confidence_score':0.5,'risk_level':'HIGH' if has else 'MEDIUM','risk_description':'LEGACY_WORDING_DO_NOT_RENDER'},
                 'dataflow':flow,'evidence_origin':'OPENGREP_ONLY' if arm=='opengrep_only' else POLICY if c=='79' else 'MODEL_DERIVED',
                 'evidence_status':'TEST_QUALIFIED' if has else 'REVIEW_ONLY','callsite':{'package':'test','class':'Test','method':'api'},
                 'model_observation':{'status':'ACCEPTED','label':{'type':'sink'},'raw_completion':'PRIVATE_MODEL_TEXT','expected_messages':['PRIVATE_PROMPT']}}
            rows.append(row);per[c]={'findings':1,'opengrep_kept':1,'score_values':[score]}
            ev[c]={'qualified_paths':int(has),'model_only_paths':int(has and c!='79'),'evidence_origin':POLICY if c=='79' else 'MODEL_DERIVED'}
            if c=='79':ev[c]['raw_policy_paths']=1
        summary={'findings':4,'retained_opengrep':4,'scorer_replay_checked':4,'per_cwe':per,'qualified_paths':sum(x['qualified_paths'] for x in ev.values())}
        if arm!='opengrep_only':summary['evidence_by_cwe']=ev
        comparison[arm]=summary;data['OPENGREP_ONLY.json' if arm=='opengrep_only' else 'FUSION_'+arm+'.json']=summary
        report={'arm':arm,'input_sha256':input_sha,'independent_gold':False,'model_xss_gate_granted':False,'findings':rows}
        for leaf,obj in [('result.json',report),('report.sarif',{'version':'2.1.0','runs':[{'results':[{} for r in rows]}]})]:
            path='analysis/'+arm+'/'+leaf;b=(canonical(obj)+'\n').encode();files[path]=b
            p=run/'private'/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        findings[arm]=rows
        if arm!='opengrep_only':
            row={'case_key':'case1','cwe':'22','prompt_sha256':'f'*64,'input_token_ids_sha256':'a'*64,'input_tokens':1,'generation_s':0.01,
                 'status':'ABSTAIN' if arm=='base' else 'ACCEPTED','reason':'INVALID_STRICT_JSON' if arm=='base' else 'STRICT_CONTRACT_ACCEPTED_NOT_GOLD','cache_key':sha(arm.encode())}
            a={'candidates':1,'new_requests':1,'cache_hits':1,'accepted':int(arm!='base'),'abstain':int(arm=='base'),'details':[row],
               'reasons':{row['reason']:1},'performance':{'generation_total_s':0.01},'cleanup':{'worker_returncode':0,'worker_still_running':False},
               'worker':{'arm':arm,'ready':True,'trainable_parameters':0,'training_executed':False,'versions':{'synthetic':'test'},
               'isolation':{'AF_INET':'DENIED_EPERM','AF_INET6':'DENIED_EPERM'}}}
            data['NATIVE_'+arm+'.json']=a;natives[arm]=a
    data['00_RESULT.json']={'status':'B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE','blockers':[],'completed_arms':list(ARMS),
          'new_training':False,'independent_gold':False,'model_xss_gate_granted':False,'web_gate_changed_by_runner':False,'input_sha256':input_sha,
          'raw_opengrep_findings':4,'new_native_requests':3,'warm_cache_hits':3,'elapsed_s':0.01,'input_kind':'SYNTHETIC_TEST_ONLY'}
    data['COMPARISON.json']={'arms':comparison,'parity':{'new_native_requests':3,'warm_cache_hits':3}}
    data['RUN_PROTOCOL.json']={'input_sha256':input_sha,'model_candidates':1,'runtime':{'runtime_versions':{'synthetic':'test'}},'planned_model_requests':3}
    data['DATABASE_PROOF.json']={'input_sha256':input_sha,'created_in_this_run':True,'count':1,'synthetic_test':True}
    data['TOKENIZER_PREFLIGHT.json']={'rows':[{'case_key':'case1','prompt_sha256':'f'*64,'input_token_ids_sha256':'a'*64,'input_tokens':1}]}
    data['POLICY79.json']={'raw_paths':1,'qualified_paths':1};data['COMMAND_TIMINGS.json']=[]
    data['BEFORE.json']={'synthetic':True};data['AFTER.json']={'synthetic':True};data['PRIVATE_RESULT_MANIFEST.json']={p:sha(b) for p,b in files.items()}
    contents={k:(canonical(v)+'\n').encode() for k,v in data.items()}
    for k,b in contents.items():(run/k).write_bytes(b)
    contents['SHA256SUMS']=''.join(sha(b)+'  '+k+'\n' for k,b in sorted(contents.items())).encode()
    raw=zip_bytes(contents);zp=downloads/(RID+'_result.zip');zp.write_bytes(raw)
    newrun=run.parent/NEW_RID;newzip=downloads/(NEW_RID+'_result.zip')
    fake=('import time,shutil\ntime.sleep(0.3)\nshutil.copytree('+repr(str(run))+','+repr(str(newrun))+')\n'
          +'shutil.copy2('+repr(str(zp))+','+repr(str(newzip))+')\n'
          +'print("STATUS=B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE",flush=True)\nprint("RUN_DIR='+str(newrun)+'",flush=True)\nprint("OUTPUT_ZIP='+str(newzip)+'",flush=True)\nprint("OUTPUT_SHA256='+sha(raw)+'",flush=True)\n')
    (engine/'run_hybrid.py').write_text(fake);(engine/'SHA256SUMS').write_text(sha(fake.encode())+'  run_hybrid.py\n')
    cfg={'work':str(work),'engine':str(engine),'downloads':str(downloads),'host_python':sys.executable,'repo':str(root/'repo'),'github':str(root/'github'),
         'engine_manifest_sha256':sha((engine/'SHA256SUMS').read_bytes()),'baseline':{}}
    write_json(state/'config.json',cfg)
    return {'work':work,'state':state,'run':run,'engine':engine,'zip':zp,'raw':raw,'hash':sha(raw),'data':data,'rows':findings,'contents':contents}

class Base(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.f=make_fixture(self.root)
    def tearDown(self):self.tmp.cleanup()
    def store(self):
        s=Store(self.f['state'],self.f['work']);s.register(RID,self.f['zip'],self.f['hash'],'SYNTHETIC_TEST');return s

class Integrity(Base):
    def test_manifest_and_metadata(self):self.assertEqual(audit_metadata(archive(self.f['raw'],self.f['hash']))['new_native_requests'],3)
    def test_wrong_archive_hash(self):
        with self.assertRaises(Blocked):archive(self.f['raw'],'0'*64)
    def test_member_hash_change(self):
        c=dict(self.f['contents']);c['00_RESULT.json']=b'{}'
        with self.assertRaises(Blocked):archive(zip_bytes(c))
    def test_unknown_member(self):
        c=dict(self.f['contents']);c['surprise.txt']=b'X'
        with self.assertRaises(Blocked):archive(zip_bytes(c))
    def test_missing_member(self):
        c=dict(self.f['contents']);c.pop('AFTER.json')
        with self.assertRaises(Blocked):archive(zip_bytes(c))
    def test_unsafe_names(self):
        for n in ('../secret','a/../b','/absolute','C:/bad','a\\b','a//b','a/./b','bad\x00file'):
            with self.subTest(n=n),self.assertRaises(Blocked):safe_name(n)
    def test_symlink_read(self):
        p=self.root/'link';p.symlink_to(self.f['zip'])
        with self.assertRaises(Blocked):read(p)
    def test_symlink_parent(self):
        d=self.root/'d';d.mkdir();(d/'link').symlink_to(self.f['run'],target_is_directory=True)
        with self.assertRaises(Blocked):under(d,'link/00_RESULT.json')
    def test_duplicate_json(self):
        with self.assertRaises(Blocked):loads('{"a":1,"a":2}')
    def test_nonfinite_json(self):
        for x in ('NaN','Infinity','-Infinity'):
            with self.assertRaises(Blocked):loads(x)
    def test_metadata_counter_mismatch(self):
        c=dict(self.f['contents']);s=copy.deepcopy(self.f['data']['00_RESULT.json']);s['new_native_requests']=99;c['00_RESULT.json']=canonical(s).encode()
        with self.assertRaises(Blocked):audit_metadata(c)
    def test_scope_inflation(self):
        c=dict(self.f['contents']);s=copy.deepcopy(self.f['data']['00_RESULT.json']);s['independent_gold']=True;c['00_RESULT.json']=canonical(s).encode()
        with self.assertRaises(Blocked):audit_metadata(c)
    def test_token_mismatch(self):
        c=dict(self.f['contents']);s=copy.deepcopy(self.f['data']['NATIVE_epoch_1.json']);s['details'][0]['input_tokens']=6;c['NATIVE_epoch_1.json']=canonical(s).encode()
        with self.assertRaises(Blocked):audit_metadata(c)
    def test_engine_integrity(self):
        verify_engine(self.f['engine']);(self.f['engine']/'run_hybrid.py').write_text('changed')
        with self.assertRaises(Blocked):verify_engine(self.f['engine'])

class Persistence(Base):
    def test_register_eight_exports(self):
        s=Store(self.f['state'],self.f['work']);self.assertEqual(len(s.register(RID,self.f['zip'],self.f['hash'],'TEST')),8)
    def test_reopen_state(self):
        a=self.store();b=Store(self.f['state'],self.f['work']);self.assertEqual(a.overview(RID),b.overview(RID))
    def test_idempotent_registration(self):
        s=self.store();before=read(s.catalog_path);s.register(RID,self.f['zip'],self.f['hash'],'OTHER');self.assertEqual(before,read(s.catalog_path))
    def test_byte_identical_download(self):
        s=self.store()
        for a in ARMS:
            for f in ('result.json','report.sarif'):self.assertEqual(s.full_file(RID,a,f),read(self.f['run']/'private/analysis'/a/f))
    def test_local_drift_not_hidden(self):
        s=self.store();(self.f['run']/'private/analysis/base/result.json').write_text('{}')
        with self.assertRaises(Blocked):s.view(RID,'base')
    def test_wrong_local_metadata(self):
        (self.f['run']/'00_RESULT.json').write_text('{}')
        with self.assertRaises(Blocked):self.store()
    def test_no_private_model_text_in_ui(self):
        s=self.store();v=canonical(s.view(RID,'epoch_1'));self.assertNotIn('PRIVATE_MODEL_TEXT',v);self.assertNotIn('PRIVATE_PROMPT',v);self.assertNotIn('LEGACY_WORDING_DO_NOT_RENDER',v)
    def test_restricted_downloads(self):
        s=self.store()
        for f in ('../../../secret','native_trace.jsonl','project.zip','model.safetensors'):
            with self.assertRaises(Blocked):s.full_file(RID,'base',f)
    def test_policy_ai_not_overridden(self):
        r=loads(read(self.f['run']/'private/analysis/epoch_1/result.json'));r['findings'][2]['score']['ai_confidence_score']=0.9
        with self.assertRaises(Blocked):verify_report(r,self.f['data']['FUSION_epoch_1.json'],'epoch_1',r['input_sha256'])
    def test_no_confirmed_findings(self):
        r=loads(read(self.f['run']/'private/analysis/epoch_1/result.json'));r['findings'][0]['vulnerability_confirmed']=True
        with self.assertRaises(Blocked):verify_report(r,self.f['data']['FUSION_epoch_1.json'],'epoch_1',r['input_sha256'])
    def test_no_safe_from_no_path(self):
        v=self.store().view(RID,'opengrep_only');self.assertTrue(all(x['confirmed'] is False and x['retained'] for x in v['findings']))

class UploadValidation(unittest.TestCase):
    def test_valid_java(self):self.assertEqual(validate_upload(zip_bytes({'pkg/T.java':'class T {}'}))['java_files'],1)
    def test_no_java(self):
        with self.assertRaises(Blocked):validate_upload(zip_bytes({'empty/':b''}))
    def test_build_script_rejected(self):
        with self.assertRaises(Blocked):validate_upload(zip_bytes({'T.java':'class T {}','pom.xml':'x'}))
    def test_traversal(self):
        with self.assertRaises(Blocked):validate_upload(zip_bytes({'../T.java':'x'}))
    def test_zip_symlink(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            i=zipfile.ZipInfo('T.java');i.external_attr=(0o120777<<16);z.writestr(i,'secret')
        with self.assertRaises(Blocked):validate_upload(b.getvalue())
    def test_25_java_files(self):
        with self.assertRaises(Blocked):validate_upload(zip_bytes({str(n)+'.java':'x' for n in range(25)}))
    def test_invalid_zip(self):
        with self.assertRaises(Blocked):validate_upload(b'not zip')
    def test_case_duplicate(self):
        with self.assertRaises(Blocked):validate_upload(zip_bytes({'T.java':'x','t.java':'x'}))

class HTTP(Base):
    def setUp(self):
        super().setUp();self.store();self.app=App(self.f['state'],0)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.app));self.app.port=self.server.server_port
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.app.close();super().tearDown()
    def req(self,path,method='GET',headers=None,body=None):
        c=http.client.HTTPConnection('127.0.0.1',self.app.port,timeout=5)
        try:
            c.request(method,path,body=body,headers=headers or {});r=c.getresponse();return r.status,dict(r.getheaders()),r.read()
        finally:c.close()
    def test_all_get_routes(self):
        for path in ('/','/app.js','/style.css','/api/health','/api/runs','/api/jobs','/api/runs/'+RID):
            self.assertEqual(self.req(path)[0],200)
        for a in ARMS:
            for tail in ('','/result.json','/report.sarif'):self.assertEqual(self.req('/api/runs/'+RID+'/'+a+tail)[0],200)
    def test_health_read_only(self):self.assertIs(loads(self.req('/api/health')[2])['scan_enabled'],False)
    def test_wrong_host(self):self.assertEqual(self.req('/api/runs',headers={'Host':'evil.example'})[0],403)
    def test_cross_origin(self):self.assertEqual(self.req('/api/runs',headers={'Origin':'https://evil.example'})[0],403)
    def test_cross_site(self):self.assertEqual(self.req('/api/runs',headers={'Sec-Fetch-Site':'cross-site'})[0],403)
    def test_csrf_missing(self):self.assertEqual(self.req('/api/jobs','POST',body=b'')[0],403)
    def test_read_only_post_denied_with_valid_csrf(self):self.assertEqual(self.req('/api/jobs','POST',headers={'X-NTK-CSRF':self.app.csrf},body=b'')[0],403)
    def test_no_arbitrary_file_route(self):self.assertNotEqual(self.req('/api/runs/'+RID+'/base/../../input.zip')[0],200)
    def test_download_hash_and_headers(self):
        code,headers,b=self.req('/api/runs/'+RID+'/epoch_1/result.json');self.assertEqual(code,200);self.assertIn('attachment',headers['Content-Disposition']);self.assertEqual(sha(b),sha(read(self.f['run']/'private/analysis/epoch_1/result.json')))
    def test_http_security_headers(self):
        _,headers,_=self.req('/');self.assertEqual(headers['X-Content-Type-Options'],'nosniff');self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
    def test_no_scan_side_effect_from_get(self):
        self.req('/api/runs');self.req('/api/runs/'+RID+'/base');self.assertEqual(self.app.jobs(),[]);self.assertIsNone(self.app.process)

class JobLifecycle(Base):
    def test_disabled_submit(self):
        a=App(self.f['state'],8767)
        with self.assertRaises(Blocked):a.submit(zip_bytes({'T.java':'class T {}'}))
    def test_stale_job_not_resumed(self):
        d=self.f['state']/'jobs'/('a'*20);d.mkdir(parents=True);write_json(d/'job.json',{'id':'a'*20,'status':'RUNNING','pid':12345})
        a=App(self.f['state'],8767);self.assertEqual(a.job('a'*20)['status'],'INTERRUPTED_UNCONFIRMED');self.assertIsNone(a.process)
    def test_explicit_fake_backend_success_persists(self):
        a=App(self.f['state'],8767,True)
        with patch('workbench.release_state',return_value={}):jid=a.submit(zip_bytes({'T.java':'class T {}'}))
        a.thread.join(timeout=10);self.assertEqual(a.job(jid)['status'],'COMPLETE');self.assertEqual(a.job(jid)['run_id'],NEW_RID)
        self.assertIn(NEW_RID,Store(self.f['state'],self.f['work']).catalog);self.assertIsNone(a.process);a.close()
    def test_backend_wrong_input_is_blocked(self):
        a=App(self.f['state'],8767,True)
        with patch('workbench.release_state',return_value={}):jid=a.submit(zip_bytes({'Different.java':'class Different {}'}))
        a.thread.join(timeout=10);self.assertEqual(a.job(jid)['status'],'BLOCKED');self.assertIn('BACKEND_INPUT_NOT_THIS_UPLOAD',a.job(jid)['error']);self.assertEqual(a.store.catalog,{});a.close()
    def test_prevent_concurrent_job(self):
        a=App(self.f['state'],8767,True)
        with patch('workbench.release_state',return_value={}):
            jid=a.submit(zip_bytes({'T.java':'class T {}'}))
            with self.assertRaises(Blocked):a.submit(zip_bytes({'T.java':'class T {}'}))
        a.thread.join(timeout=10);a.close()
    def test_failed_backend_not_registered(self):
        code='import sys\nsys.exit(2)\n';(self.f['engine']/'run_hybrid.py').write_text(code);(self.f['engine']/'SHA256SUMS').write_text(sha(code.encode())+'  run_hybrid.py\n')
        cfg=loads(read(self.f['state']/'config.json'));cfg['engine_manifest_sha256']=verify_engine(self.f['engine']);write_json(self.f['state']/'config.json',cfg)
        a=App(self.f['state'],8767,True)
        with patch('workbench.release_state',return_value={}):jid=a.submit(zip_bytes({'T.java':'class T {}'}))
        a.thread.join(timeout=10);self.assertEqual(a.job(jid)['status'],'BLOCKED');self.assertEqual(a.store.catalog,{});a.close()
    def test_stop_only_owned_fake_runner(self):
        code='import time\ntime.sleep(60)\n';(self.f['engine']/'run_hybrid.py').write_text(code);(self.f['engine']/'SHA256SUMS').write_text(sha(code.encode())+'  run_hybrid.py\n')
        cfg=loads(read(self.f['state']/'config.json'));cfg['engine_manifest_sha256']=verify_engine(self.f['engine']);write_json(self.f['state']/'config.json',cfg)
        a=App(self.f['state'],8767,True)
        other=subprocess.Popen([sys.executable,'-c','import time;time.sleep(15)'])
        try:
            with patch('workbench.release_state',return_value={}):jid=a.submit(zip_bytes({'T.java':'class T {}'}))
            deadline=time.monotonic()+5
            while a.process is None and time.monotonic()<deadline:time.sleep(0.01)
            a.request_stop(jid);a.thread.join(timeout=10);self.assertIsNone(other.poll());self.assertEqual(a.job(jid)['status'],'BLOCKED');a.close()
        finally:other.terminate();other.wait(timeout=5)

if __name__=='__main__':unittest.main(verbosity=2)
