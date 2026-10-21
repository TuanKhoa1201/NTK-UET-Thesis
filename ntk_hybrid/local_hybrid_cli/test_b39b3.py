#!/usr/bin/env python3
"""Synthetic tests only. No real IRIS module, ML model, GPU or CodeQL is run here."""
from __future__ import annotations
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import run_b39b3 as b3
from native_driver import routes_for, prepare_cases
from ntk_core import *
from test_b39b2 import example, zip_bytes


def queries():
    return {'cwe-%03d'%int(c):{'cwe_id':c,'prompts':{'desc':'CWE-'+c,'long_desc':'synthetic '+c,'examples':[]}} for c in CWES}


def fake_bundle(arm='epoch_1',n=4):
    original,targets=convert_rows([example(i+1,c,role='none') for i,c in enumerate(CWES)])
    raw=[{**r['candidate'],'source_record_sha256':r['source_record_sha256']} for r in original]
    cases=prepare_cases(raw,'SYNTHETIC_NATIVE_SYSTEM','{cwe_id}:{methods}',routes_for(queries()))
    req,prompt=b3.build_requests(original,cases)
    trace=[]
    for phase in ('cold','warm'):
        for r,t in zip(req,targets):
            raw=canonical(t['label']);key=b3.native_key(r['candidate'])
            trace.append({'case_key':key,'phase':phase,'candidate':{k:r['candidate'][k] for k in (*IDENTITY,'cwe')},
                'status':'ACCEPTED','reason':'STRICT_CONTRACT_ACCEPTED_NOT_GOLD','label':t['label'],
                'raw_completion':raw,'prompt_sha256':r['prompt_sha256'], 'source_record_sha256':r['source_record_sha256'],
                'cache_key':digest([key,arm]),'cache_hit':phase=='warm','latency_s':1.2 if phase=='cold' else 0,
                'worker':{'generation_s':1.0,'input_tokens':10,'output_tokens':5,
                          'input_token_ids_sha256':digest(r['messages']),
                          'peak_vram_allocated_bytes':100,'peak_vram_reserved_bytes':200} if phase=='cold' else None})
    summary={'status':'B39B3_NATIVE_ARM_COMPLETE','arm':arm,'native_method_invocations':8,
             'worker':{'arm':arm,'ready':True,'versions':b3.PINS['runtime_versions'],
               'training_executed':False,'trainable_parameters':0,'load_s':1.0,
               'isolation':{'AF_INET':'DENIED_EPERM','AF_INET6':'DENIED_EPERM'},'tokenizer_chat_template_sha256':digest('template')},
             'cleanup':{'worker_returncode':0,'worker_still_running':False}}
    return req,targets,trace,summary


class NativeInputTests(unittest.TestCase):
    def test_routes_exact_preferred(self):
        q=queries();q['other']={**q['cwe-089'],'prompts':{'desc':'other'}}
        self.assertEqual(routes_for(q)['89'][0],'cwe-089')
    def test_missing_route_blocked(self):
        q=queries();del q['cwe-089']
        with self.assertRaises(Blocker):routes_for(q)
    def test_ambiguous_route_blocked(self):
        q=queries();a=q.pop('cwe-089');q['one']=a;q['two']={**a,'prompts':{'desc':'other'}}
        with self.assertRaises(Blocker):routes_for(q)
    def test_cases_no_role_or_target_fields(self):
        r,t=convert_rows([example()]);raw=[{**r[0]['candidate'],'source_record_sha256':r[0]['source_record_sha256']}]
        out=prepare_cases(raw,'s','{methods}',routes_for(queries()))
        self.assertNotIn('type',out[0]);self.assertNotIn('sink_args',out[0]);self.assertNotIn('label',out[0])
        self.assertEqual([x['role'] for x in out[0]['expected_messages']],['system','user'])
    def test_case_target_injection_rejected(self):
        r,t=convert_rows([example()]);raw=[{**r[0]['candidate'],'source_record_sha256':'x','label':t[0]['label']}]
        with self.assertRaises(Blocker):prepare_cases(raw,'s','{methods}',routes_for(queries()))
    def test_duplicate_case_blocked(self):
        r,t=convert_rows([example()]);row={**r[0]['candidate'],'source_record_sha256':'x'}
        with self.assertRaises(Blocker):prepare_cases([row,row],'s','{methods}',routes_for(queries()))
    def test_prompt_shift_is_reported_not_repaired(self):
        r,t=convert_rows([example()]);raw=[{**r[0]['candidate'],'source_record_sha256':r[0]['source_record_sha256']}]
        n,p=b3.build_requests(r,prepare_cases(raw,'native','{methods}',routes_for(queries())))
        self.assertEqual(p['changed_b28_prompt'],1);self.assertNotEqual(n[0]['messages'],r[0]['messages'])
    def test_missing_candidate_blocked(self):
        r,t=convert_rows([example()])
        with self.assertRaises(Blocker):b3.build_requests(r,[])
    def test_extra_assistant_blocked(self):
        r,t=convert_rows([example()]);raw=[{**r[0]['candidate'],'source_record_sha256':r[0]['source_record_sha256']}]
        c=prepare_cases(raw,'s','{methods}',routes_for(queries()));c[0]['expected_messages'].append({'role':'assistant','content':'x'})
        with self.assertRaises(Blocker):b3.build_requests(r,c)


class NativeTraceTests(unittest.TestCase):
    def summarize(self,bundle):return b3.summarize_trace(*bundle,b3.PINS['runtime_versions'])
    def test_complete_metrics_and_cwe_zero_support(self):
        m,p=self.summarize(fake_bundle());self.assertEqual(m['metrics']['accepted'],4)
        self.assertIsNone(m['per_cwe']['78']['per_role']['sink']['recall'])
        self.assertEqual(m['performance']['cache_hit_latency_benchmark'],'NOT_MEASURED_FROZEN_PROVIDER_REPORTS_PLACEHOLDER_ZERO')
    def test_all_abstain_still_complete_not_none(self):
        b=list(fake_bundle())
        for x in b[2]:x.update(raw_completion='not json',label=None,status='ABSTAIN',reason='INVALID_STRICT_JSON')
        m,_=self.summarize(b);self.assertEqual(m['metrics']['abstain'],4)
        self.assertEqual(m['metrics']['confusion_matrix']['none']['ABSTAIN'],4)
    def test_missing_prediction_not_abstain(self):
        b=list(fake_bundle());b[2].pop()
        with self.assertRaises(Blocker):self.summarize(b)
    def test_duplicate_prediction_blocked(self):
        b=list(fake_bundle());b[2].append(deepcopy(b[2][0]))
        with self.assertRaises(Blocker):self.summarize(b)
    def test_infra_error_blocked(self):
        b=list(fake_bundle());b[2][0]['infrastructure_failure']=True
        with self.assertRaises(Blocker):self.summarize(b)
    def test_cold_cache_hit_blocked(self):
        b=list(fake_bundle());b[2][0]['cache_hit']=True
        with self.assertRaises(Blocker):self.summarize(b)
    def test_warm_raw_drift_blocked(self):
        b=list(fake_bundle());b[2][-1]['raw_completion']='different'
        with self.assertRaises(Blocker):self.summarize(b)
    def test_prompt_drift_blocked(self):
        b=list(fake_bundle());b[2][0]['prompt_sha256']='0'*64
        with self.assertRaises(Blocker):self.summarize(b)
    def test_candidate_drift_blocked(self):
        b=list(fake_bundle());b[2][0]['candidate']['class']='Other'
        with self.assertRaises(Blocker):self.summarize(b)
    def test_evaluator_and_native_verdict_must_match(self):
        b=list(fake_bundle());
        for x in b[2]:x.update(status='ABSTAIN',label=None,reason='INVALID_STRICT_JSON')
        with self.assertRaises(Blocker):self.summarize(b)
    def test_nan_measurement_blocked(self):
        b=list(fake_bundle());b[2][0]['worker']['generation_s']=float('nan')
        with self.assertRaises(Blocker):self.summarize(b)
    def test_nonzero_trainable_blocked(self):
        b=list(fake_bundle());b[3]['worker']['trainable_parameters']=10
        with self.assertRaises(Blocker):self.summarize(b)
    def test_wrong_versions_blocked(self):
        b=list(fake_bundle());b[3]['worker']['versions']={'torch':'unknown'}
        with self.assertRaises(Blocker):self.summarize(b)
    def test_cleanup_nonzero_blocked(self):
        b=list(fake_bundle());b[3]['cleanup']['worker_returncode']=-9
        with self.assertRaises(Blocker):self.summarize(b)
    def test_cross_arm_token_parity(self):
        results={a:self.summarize(fake_bundle(a))[0] for a in b3.ARMS}
        self.assertTrue(b3.cross_arm(results)['distinct_arm_cache_keys'])
    def test_cross_arm_token_drift_blocked(self):
        results={a:self.summarize(fake_bundle(a))[0] for a in b3.ARMS}
        results['base']['measurements'][0]['input_token_ids_sha256']='1'*64
        with self.assertRaises(Blocker):b3.cross_arm(results)
    def test_cross_arm_cache_collision_blocked(self):
        results={a:self.summarize(fake_bundle(a))[0] for a in b3.ARMS}
        results['base']['cache_keys']=results['epoch_1']['cache_keys']
        with self.assertRaises(Blocker):b3.cross_arm(results)


class ArchiveProcessTests(unittest.TestCase):
    def tar(self,name='src/iris.py',symlink=None):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as z:
            i=tarfile.TarInfo(name)
            if symlink:
                i.type=tarfile.SYMTYPE;i.linkname=symlink;z.addfile(i)
            else:
                x=b'# synthetic only\n';i.size=len(x);z.addfile(i,io.BytesIO(x))
        return data.getvalue()
    def test_snapshot_extract(self):
        with tempfile.TemporaryDirectory() as d:
            m=b3.unpack_snapshot(self.tar(),Path(d)/'snapshot');self.assertEqual(m['regular_file_count'],1)
    def test_snapshot_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Blocker):b3.unpack_snapshot(self.tar('../escape'),Path(d)/'snapshot')
    def test_snapshot_external_link_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Blocker):b3.unpack_snapshot(self.tar('bad','/tmp/other'),Path(d)/'snapshot')
    def test_child_success(self):
        with tempfile.TemporaryDirectory() as d:
            r=b3.run_child([sys.executable,'-c','print("synthetic child")'],Path(d)/'log.txt',d,10)
            self.assertEqual(r['returncode'],0);self.assertFalse(r['process_group_still_running'])
    def test_child_failure_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            r=b3.run_child([sys.executable,'-c','raise SystemExit(7)'],Path(d)/'log.txt',d,10)
            self.assertEqual(r['returncode'],7)
    def test_child_timeout_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Blocker):b3.run_child([sys.executable,'-c','import time;time.sleep(30)'],Path(d)/'log.txt',d,0.1)
            r=loads((Path(d)/'log.process.json').read_bytes());self.assertFalse(r['still_running']);self.assertTrue(r['timed_out'])
    def test_missing_baseline_failure_exports(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);w=root/'w';downloads=root/'downloads';w.mkdir();downloads.mkdir()
            cmd=[sys.executable,'-I','-B',str(ROOT/'run_b39b3.py'),'--host-python',sys.executable,
                 '--work',str(w),'--downloads',str(downloads),'--repo',str(root/'no_iris'),'--github',str(root/'no_github')]
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
            self.assertEqual(p.returncode,2,p.stdout+p.stderr)
            z=list(downloads.glob('*_result.zip'));self.assertEqual(len(z),1)
            m=zip_members(z[0].read_bytes());verify_sums(m);self.assertEqual(loads(m['00_RESULT.json'])['status'],'B39B3_BLOCKED')
            self.assertFalse(any('private/' in s for s in m))




class DriverLifecycleTests(unittest.TestCase):
    def setup_fake(self,root):
        # Entire imported engine is synthetic. This tests orchestration, not IRIS correctness.
        engine=root/'engine';snapshot=root/'snapshot';prep=root/'prepare'
        for path in (engine/'ntk_b33',snapshot/'src/ntk_stage3_native',prep):path.mkdir(parents=True)
        for path in (engine/'ntk_b33/__init__.py',snapshot/'src/__init__.py',snapshot/'src/ntk_stage3_native/__init__.py'):path.write_text('')
        (engine/'ntk_b33/patcher.py').write_text("def apply(snapshot,engine): return {'diff':'SYNTHETIC','stage4_and_get_model_body_unchanged':True}\ndef native_system_prompt(source): return 'SYNTHETIC_NATIVE_SYSTEM'\n")
        (snapshot/'src/iris.py').write_text(
            "QUERIES="+repr(queries())+"\nAPI_LABELLING_USER_PROMPT='{cwe_id}:{methods}'\n"
            "class SAPipeline:\n    def query_gpt_for_api_src_tp_sink_batched(self):\n        self._ntk_stage3_provider.simulate(self.cwe_id)\n")
        (engine/'run_native37.py').write_text(
            "from pathlib import Path\n"
            "def assert_protocol(protocol,system,template,query):\n    assert protocol['synthetic'] is True\n"
            "def new_stage3_pipeline(cls,cfg,cwe,key,query,phase):\n    p=cls();p.cwe_id=cwe;p.api_labels_cache_path=str(Path(cfg['output_dir'])/('not_created_'+phase+cwe));return p\n")
        (snapshot/'src/ntk_stage3_native/provider.py').write_text(
            "import json\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "class NativeProvider:\n"
            "    def __init__(self,cfg):\n        self.cfg=cfg;self.observations=[];self.native_invocations=0;self.phase='cold';self.process=None;self.worker_meta={'synthetic_only':True}\n"
            "    def simulate(self,cwe):\n        self.native_invocations+=1\n        self.process=SimpleNamespace(pid=777,poll=lambda:0)\n        for c in self.cfg['cases']:\n            if c['cwe']==cwe:self.observations.append({'phase':self.phase,'cache_hit':self.phase=='warm','raw_completion':'SYNTHETIC_RESPONSE'})\n"
            "    def close(self):\n        self.process=None\n")
        protocol=root/'protocol.json';write_json(protocol,{'synthetic':True})
        req,t=convert_rows([example(i+1,c,role='none') for i,c in enumerate(CWES)])
        cfg={'snapshot':str(snapshot),'engine':str(engine),'protocol_path':str(protocol),
             'prepare_dir':str(prep),'raw_cases':[{**r['candidate'],'source_record_sha256':r['source_record_sha256']} for r in req]}
        path=root/'prepare_config.json';write_json(path,cfg)
        return cfg,path
    def run_driver(self,mode,path):
        return subprocess.run([sys.executable,'-I','-B',str(ROOT/'native_driver.py'),mode,str(path)],capture_output=True,text=True,timeout=20)
    def test_prepare_imports_fake_module_without_model(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cfg,path=self.setup_fake(root);p=self.run_driver('prepare',path)
            self.assertEqual(p.returncode,0,p.stderr)
            r=loads((root/'prepare/DRIVER_RESULT.json').read_bytes());self.assertEqual(r['native_stage3_calls'],0)
            self.assertEqual(r['model_inference'],'NOT_EXECUTED')
    def test_native_driver_full_lifecycle_synthetic_only(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cfg,path=self.setup_fake(root);p=self.run_driver('prepare',path);self.assertEqual(p.returncode,0,p.stderr)
            out=root/'arm';out.mkdir()
            cfg.update(cases=loads((root/'prepare/NATIVE_INPUTS.json').read_bytes()),
                       preparation_proof=loads((root/'prepare/PREPARED.json').read_bytes()),output_dir=str(out),arm='base')
            path=root/'run_config.json';write_json(path,cfg);p=self.run_driver('run',path)
            self.assertEqual(p.returncode,0,p.stderr)
            r=loads((out/'DRIVER_RESULT.json').read_bytes());self.assertEqual(r['native_method_invocations'],8)
            self.assertEqual(r['cold_live_responses'],4);self.assertEqual(r['warm_cache_hits'],4)
            self.assertTrue(r['worker']['synthetic_only'])
    def test_prepare_proof_tampering_blocks_before_calls(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cfg,path=self.setup_fake(root);p=self.run_driver('prepare',path);self.assertEqual(p.returncode,0,p.stderr)
            out=root/'arm';out.mkdir();proof=loads((root/'prepare/PREPARED.json').read_bytes());proof['source_sha256']='bad'
            cfg.update(cases=loads((root/'prepare/NATIVE_INPUTS.json').read_bytes()),preparation_proof=proof,output_dir=str(out),arm='base')
            path=root/'run_config.json';write_json(path,cfg);p=self.run_driver('run',path)
            self.assertEqual(p.returncode,2,p.stderr)
            r=loads((out/'DRIVER_RESULT.json').read_bytes());self.assertIn('PREPARATION_OR_IMPORT_DRIFT',r['blocker'])
            self.assertFalse((out/'effective_native_config.json').exists())


class TokenizerTests(unittest.TestCase):
    def cases(self):
        r,t=convert_rows([example()]);raw=[{**r[0]['candidate'],'source_record_sha256':r[0]['source_record_sha256']}]
        return prepare_cases(raw,'system','{methods}',routes_for(queries()))
    def tokenizer(self):
        class SyntheticTokenizer:
            def apply_chat_template(self,messages,**kwargs):return 'synthetic text'
            def __call__(self,text,**kwargs):return {'input_ids':[10,20,30]}
        return SyntheticTokenizer()
    def test_token_fingerprint(self):
        from tokenizer_preflight import tokenize_cases
        x=tokenize_cases(self.tokenizer(),self.cases(),3)
        self.assertEqual(x[0]['input_token_ids_sha256'],digest([10,20,30]))
    def test_no_silent_truncation(self):
        from tokenizer_preflight import tokenize_cases
        with self.assertRaises(Blocker):tokenize_cases(self.tokenizer(),self.cases(),2)
    def test_tokenizer_target_message_rejected(self):
        from tokenizer_preflight import tokenize_cases
        c=self.cases();c[0]['expected_messages'].append({'role':'assistant','content':'target'})
        with self.assertRaises(Blocker):tokenize_cases(self.tokenizer(),c,3)
    def test_cpu_tokenizer_does_not_change_cases(self):
        from tokenizer_preflight import tokenize_cases
        c=self.cases();old=deepcopy(c);tokenize_cases(self.tokenizer(),c,3);self.assertEqual(c,old)


if __name__=='__main__':unittest.main(verbosity=2)
