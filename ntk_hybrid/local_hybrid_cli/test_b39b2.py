#!/usr/bin/env python3
"""Synthetic unit/integration tests. No actual model, GPU, IRIS or CodeQL executed."""
from __future__ import annotations
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ntk_core import *
from ntk_runtime import Worker
import run_b39b2 as runner
from vendor.common import ADAPTER_CONFIG_SHA, ADAPTER_SHA, parameter_names


def example(i=1, cwe='89', role='sink', args=None):
    if args is None:
        args = ['p0'] if role == 'sink' else []
    label = {'package': 'unit.only', 'class': 'Synthetic', 'method': 'call'+str(i),
             'signature': 'void call'+str(i)+'(String p0)', 'type': role, 'sink_args': args}
    return {'id': 'id_'+str(i), 'metadata': {'cwe': cwe}, 'messages': [
        {'role': 'system', 'content': 'SYNTHETIC_ONLY'},
        {'role': 'user', 'content': 'Classify synthetic ' + str(i) + ' CWE-' + cwe},
        {'role': 'assistant', 'content': canonical(label)}]}


def zip_bytes(m):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for k, v in m.items():
            z.writestr(k, v)
    return out.getvalue()


class DataTests(unittest.TestCase):
    def test_exact_prompt_and_target_separation(self):
        x = example(); r, t = convert_rows([x])
        self.assertEqual(r[0]['messages'], x['messages'][:2])
        self.assertNotIn('label', r[0]); self.assertNotIn('type', r[0]['candidate'])
        self.assertEqual(t[0]['label']['type'], 'sink')
    def test_cwe_from_original_row(self):
        x = example(); x['cwe'] = x.pop('metadata')['cwe']
        self.assertEqual(convert_rows([x])[0][0]['cwe'], '89')
    def test_ambiguous_cwe_rejected(self):
        x = example(); x['cwe'] = '22'
        with self.assertRaises(Blocker): convert_rows([x])
    def test_boolean_cwe_rejected(self):
        x = example(); x['metadata']['cwe'] = True
        with self.assertRaises(Blocker): convert_rows([x])
    def test_duplicate_ids_rejected(self):
        with self.assertRaises(Blocker): convert_rows([example(), example()])
    def test_bad_role_sequence_rejected(self):
        x = example(); x['messages'].reverse()
        with self.assertRaises(Blocker): convert_rows([x])
    def test_extra_assistant_never_silently_dropped(self):
        x = example(); x['messages'].append(x['messages'][2])
        with self.assertRaises(Blocker): convert_rows([x])
    def test_reference_json_fence_not_repaired(self):
        x = example(); x['messages'][2]['content'] = '```json\n'+x['messages'][2]['content']+'\n```'
        with self.assertRaises(Blocker): convert_rows([x])
    def test_reference_extra_fields_rejected(self):
        x = example(); lab = loads(x['messages'][2]['content']); lab['extra'] = 'x'
        x['messages'][2]['content'] = canonical(lab)
        with self.assertRaises(Blocker): convert_rows([x])
    def test_unsupported_reference_argument_kept_and_flagged(self):
        r, t = convert_rows([example(args=['this'])])
        self.assertEqual(len(r), 1)
        self.assertEqual(t[0]['native_reference_contract']['reason'], 'RECEIVER_SEMANTICS_UNPROVEN')
    def test_reference_role_args_contradiction_rejected(self):
        with self.assertRaises(Blocker): convert_rows([example(role='none', args=['p0'])])
    def test_ambiguous_explicit_identity_rejected(self):
        x = example(); x['metadata']['method'] = 'different'
        with self.assertRaises(Blocker): convert_rows([x])
    def test_numeric_and_string_ids_not_confused(self):
        a,b = example(1), example(2); a['id'], b['id'] = 1, '1'
        r,t = convert_rows([a,b]); self.assertEqual(len(r), 2)
    def test_four_cwe_input_only_selection(self):
        rows = [example(i,c,role='none') for i,c in enumerate(CWES)]
        req,_ = convert_rows(rows)
        selected = select_smoke(req + list(reversed(req)))
        self.assertEqual([x['cwe'] for x in selected], list(CWES))
    def test_smoke_requires_all_four_cwes(self):
        r,_ = convert_rows([example()])
        with self.assertRaises(Blocker): select_smoke(r)
    def test_exact_overlap(self):
        r,_ = convert_rows([example()]); o = overlap(r,r)
        self.assertEqual((o['id_overlap'],o['identity_cwe_overlap'],o['prompt_overlap']), (1,1,1))
    def test_json_duplicate_key_rejected(self):
        with self.assertRaises(Blocker): loads('{"a":1,"a":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(Blocker): loads('{"a":NaN}')
    def test_malformed_jsonl_not_partial_success(self):
        with self.assertRaises(Blocker): jsonl(b'{"id":1}\nINVALID\n')
    def test_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x';p.write_bytes(b'x')
            with self.assertRaises(Blocker): read_checked(p, '0'*64)
    def test_zip_traversal_rejected(self):
        with self.assertRaises(Blocker): zip_members(zip_bytes({'../outside': b'x'}))
    def test_zip_duplicate_rejected(self):
        import warnings
        out=io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(out,'w') as z:z.writestr('a','1');z.writestr('a','2')
        with self.assertRaises(Blocker): zip_members(out.getvalue())
    def test_zip_size_guard(self):
        with self.assertRaises(Blocker): zip_members(zip_bytes({'a': b'xx'}), max_total=1)
    def test_manifest_exact_membership(self):
        m={'a':b'x','SHA256SUMS':(sha(b'x')+'  a\n').encode()}
        self.assertEqual(verify_sums(m),1)
        m['extra']=b''
        with self.assertRaises(Blocker): verify_sums(m)
    def test_manifest_corrupt_member(self):
        with self.assertRaises(Blocker): verify_sums({'a':b'x','SHA256SUMS':('0'*64+'  a\n').encode()})
    def test_out_file_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.json';write_json(p,{'a':1})
            with self.assertRaises(FileExistsError): write_json(p,{'a':2})


class EvaluatorTests(unittest.TestCase):
    def setup_prediction(self, role='none'):
        r,t = convert_rows([example(role=role)])
        return r,t,[{'id':r[0]['id'],'raw':canonical(t[0]['label'])}]
    def test_exact_success(self):
        r,t,p=self.setup_prediction('sink'); m,_=evaluate(r,t,p)
        self.assertEqual(m['sink_args_joint_correct'],1);self.assertEqual(m['coverage'],1)
    def test_abstain_not_none(self):
        r,t,p=self.setup_prediction('none');p[0]['raw']='INVALID'
        m,_=evaluate(r,t,p)
        self.assertEqual(m['confusion_matrix']['none']['ABSTAIN'],1)
        self.assertEqual(m['role_accuracy_over_all'],0)
    def test_missing_prediction_not_abstain(self):
        r,t,p=self.setup_prediction()
        with self.assertRaises(Blocker):evaluate(r,t,[])
    def test_duplicate_prediction_not_accepted(self):
        r,t,p=self.setup_prediction()
        with self.assertRaises(Blocker):evaluate(r,t,p+p)
    def test_cwe_prediction_mismatch(self):
        r,t,p=self.setup_prediction();p[0]['cwe']='22'
        with self.assertRaises(Blocker):evaluate(r,t,p)
    def test_infrastructure_error_is_failure(self):
        r,t,p=self.setup_prediction();p[0]['infrastructure_failure']=True
        with self.assertRaises(Blocker):evaluate(r,t,p)
    def test_no_sink_support_is_null(self):
        r,t,p=self.setup_prediction('source');m,_=evaluate(r,t,p)
        self.assertIsNone(m['sink_args_joint_accuracy']);self.assertIsNone(m['per_role']['sink']['recall'])
    def test_fenced_base_not_repaired(self):
        r,t,p=self.setup_prediction();p[0]['raw']='```json\n'+p[0]['raw']+'\n```'
        m,_=evaluate(r,t,p);self.assertEqual(m['abstain'],1)
    def test_wrong_overload_abstains(self):
        r,t,p=self.setup_prediction();l=loads(p[0]['raw']);l['signature']='void call1()';p[0]['raw']=canonical(l)
        m,_=evaluate(r,t,p);self.assertEqual(m['reason_counts']['IDENTITY_OR_OVERLOAD_MISMATCH'],1)
    def test_receiver_requires_evidence(self):
        r,t,p=self.setup_prediction('sink');l=loads(p[0]['raw']);l['sink_args']=['this'];p[0]['raw']=canonical(l)
        m,_=evaluate(r,t,p);self.assertEqual(m['abstain'],1)
    def test_empty_sink_args_abstains(self):
        r,t,p=self.setup_prediction('sink');l=loads(p[0]['raw']);l['sink_args']=[];p[0]['raw']=canonical(l)
        m,_=evaluate(r,t,p);self.assertEqual(m['reason_counts']['EMPTY_SINK_ARGS'],1)
    def test_full_four_role_macro_and_fn(self):
        rows=[example(i,role=role) for i,role in enumerate(sorted(ROLES))]
        r,t=convert_rows(rows);p=[{'id':x['id'],'raw':canonical(y['label'])} for x,y in zip(r,t)]
        m,_=evaluate(r,t,p);self.assertEqual(m['macro_f1_four_roles'],1)
        p[0]['raw']='broken';m,_=evaluate(r,t,p)
        self.assertEqual(m['macro_f1_four_roles'],0.75);self.assertEqual(m['n'],4)
    def test_order_independent_id_join(self):
        r,t=convert_rows([example(1),example(2,role='none')])
        p=[{'id':x['id'],'raw':canonical(x['label'])} for x in t]
        a,_=evaluate(r,t,p);b,_=evaluate(r,list(reversed(t)),list(reversed(p)))
        self.assertEqual(a,b)
    def test_parameter_names_from_frozen_parser(self):
        self.assertEqual(parameter_names('void f(java.util.Map<String, Long> p0, String[] p1)'),['p0','p1'])


class TransportTests(unittest.TestCase):
    def test_partial_line_and_two_replies(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); script=d/'fake.py'
            script.write_text('import sys,time,json\nsys.stdout.write("{\\\"ready\\\":");sys.stdout.flush();time.sleep(.03);print("true}",flush=True)\nfor s in sys.stdin: print(json.dumps({"ok": True, "roles":[x["role"] for x in json.loads(s)["messages"]]}),flush=True)\n')
            w=Worker([sys.executable,'-I','-B',script],d/'err',d)
            try:
                self.assertTrue(w.read(2)['ready'])
                m=[{'role':'system','content':'x'},{'role':'user','content':'y'}]
                self.assertEqual(w.request(m,2)['roles'],['system','user'])
                self.assertTrue(w.request(m,2)['ok'])
            finally:result=w.close()
            self.assertFalse(result['still_running']);self.assertEqual(result['returncode'],0)
    def test_no_newline_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            w=Worker([sys.executable,'-u','-c','import sys,time;print("{",end="",flush=True);time.sleep(.2)'],d/'err',d)
            try:
                with self.assertRaises(Blocker):w.read(.05)
            finally:w.close()
    def test_assistant_not_sent(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);w=Worker([sys.executable,'-c','pass'],d/'err',d)
            try:
                with self.assertRaises(Blocker):w.request([{'role':'user'},{'role':'assistant'}],1)
            finally:w.close()
    def test_eof_failure_not_none(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);w=Worker([sys.executable,'-c','pass'],d/'err',d)
            try:
                with self.assertRaises(Blocker):w.read(2)
            finally:w.close()


class LineageIntegrationTests(unittest.TestCase):
    def test_synthetic_preparation_950_138_137_and_three_replays(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d)/'work';downloads=Path(d)/'downloads';run=Path(d)/'run'
            for p in (work,downloads,run):p.mkdir()
            train=[example(i,CWES[i%4],sorted(ROLES)[i%4]) for i in range(950)]
            dev=[example(2000+i,CWES[i%4],sorted(ROLES)[i%4]) for i in range(137)]
            dropped=example(4000)
            enc=lambda rows:''.join(canonical(x)+'\n' for x in rows).encode()
            old27={'1_train_SILVER_WEAK_NOT_GOLD.jsonl':enc(train),'1_validation_SILVER_WEAK_NOT_GOLD.jsonl':enc(dev+[dropped])}
            tr='dataset/01_TRAIN_SILVER_WEAK_950.jsonl';va='dataset/02_VALIDATION_WEAK_DISJOINT.jsonl'
            proto=work/'protocol.json';proto.write_text('{}')
            out={tr:enc(train),va:enc(dev)}
            cfg={'seed':20261016}
            out['03_TRAIN_JOB.json']=canonical({'train':str(work/'B28'/tr),'dev':str(work/'B28'/va),'protocol':str(proto),'config':cfg}).encode()
            out['ml/training_manifest.json']=canonical({'train_sha256':sha(out[tr]),'dev_sha256':sha(out[va]),'protocol_sha256':sha(proto.read_bytes()),'config':cfg}).encode()
            out['05_TRAINING_PROCESS_STATUS.json']=b'{"rc":0,"training_attempted":true}'
            out['dataset/05_PREPARATION_AND_LEAKAGE.json']=canonical({'validation_ids_excluded_for_reference_protection':[dropped['id']],'raw_validation':138,'validation_scored_after_family_guard':137}).encode()
            out['dataset/03_VALIDATION_EXCLUDED_LEAKAGE.jsonl']=enc([{'id':dropped['id'],'reason':'SYNTHETIC_REFERENCE_GUARD'}])
            for arm in ('base','epoch_1','epoch_2'):
                out['ml/'+arm+'_predictions.jsonl']=enc([{'id':x['id'],'cwe':x['metadata']['cwe'],'raw':x['messages'][2]['content']} for x in dev])
            b1={'00_RESULT.json':b'{"status":"B39B1_DISCOVERY_COMPLETE_REVIEW_REQUIRED","blockers":[]}'}
            b1['SHA256SUMS']=(sha(b1['00_RESULT.json'])+'  00_RESULT.json\n').encode()
            b1z,b27z,b28z=zip_bytes(b1),zip_bytes(old27),zip_bytes(out)
            (downloads/'b1.zip').write_bytes(b1z);(work/'B27.zip').write_bytes(b27z);(work/'B28.zip').write_bytes(b28z)
            pins={**runner.PINS,'b1_name':'b1.zip','b1_sha256':sha(b1z),'b27_relative':'B27.zip','b27_sha256':sha(b27z),
                  'b28_relative':'B28.zip','b28_sha256':sha(b28z),'b27_members':{k:sha(v) for k,v in old27.items()},
                  'b28_members':{k:{'sha256':sha(v)} for k,v in out.items()}}
            with patch.object(runner,'PINS',pins):
                s,t,lock=runner.prepare_data(work,downloads,run,{})
            self.assertEqual(len(s),4);self.assertEqual(lock['validation']['rows'],137)
            self.assertEqual(lock['validation_138_to_137']['removed'],1)
            requests=jsonl((run/'private/validation.requests.jsonl').read_bytes())
            self.assertTrue(all(len(x['messages'])==2 for x in requests))
            self.assertEqual(loads((run/'REPLAY_SUMMARY.json').read_bytes())['arms']['base']['coverage'],1)
            result,h=runner.pack(run,downloads)
            m=zip_members(result.read_bytes());verify_sums(m)
            self.assertTrue(all('private/' not in k for k in m))
            self.assertEqual(h,sha(result.read_bytes()))
    def test_vendor_byte_pins(self):
        for name,pin in runner.PINS['vendor'].items():
            b=(ROOT/'vendor'/name).read_bytes()
            self.assertEqual(sha(b),pin['sha256'])
            self.assertEqual(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),pin['git_blob'])
    def test_seccomp_worker_guard_subprocess(self):
        p=subprocess.run([sys.executable,'-I','-B','-c',
            'import sys,json;sys.path.insert(0,'+repr(str(ROOT))+');from vendor.common import deny_inet;print(json.dumps(deny_inet()))'],
            capture_output=True,text=True,timeout=15)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['AF_INET6'],'DENIED_EPERM')


class RuntimeIntegrationTests(unittest.TestCase):
    def test_synthetic_three_arm_transport_smoke(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work=root/'work';run=root/'run';fake=root/'fake';fake.mkdir()
            (work/'.ntk_v5_lora_venv/bin').mkdir(parents=True)
            (work/'.ntk_v5_lora_venv/bin/python').symlink_to(sys.executable)
            (run/'private').mkdir(parents=True);(fake/'vendor').mkdir()
            script = """import sys,json,hashlib
cfg=json.load(open(sys.argv[1]))
print(json.dumps({'ready':True,'versions':cfg['runtime_versions'],'arm':cfg['arm'],
 'trainable_parameters':0,'training_executed':False,
 'isolation':{'AF_INET':'DENIED_EPERM','AF_INET6':'DENIED_EPERM'},
 'tokenizer_chat_template_sha256':'0'*64}),flush=True)
for s in sys.stdin:
 r=json.loads(s)
 if set(r)!={'messages'} or [m['role'] for m in r['messages']]!=['system','user']:sys.exit(4)
 h=hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest()
 print(json.dumps({'ok':True,'raw':'SYNTHETIC_ABSTENTION_NOT_REAL_MODEL',
 'input_token_ids_sha256':h,'generation_s':0.01,'input_tokens':10,'output_tokens':2,
 'peak_vram_allocated_bytes':0,'peak_vram_reserved_bytes':0}),flush=True)
"""
            (fake/'vendor/worker.py').write_text(script)
            req,targets=convert_rows([example(i,c) for i,c in enumerate(CWES)])
            cfgs={a:{'arm':a,'runtime_versions':{'fake':'not-real'},'generation':{'generation_timeout_s':2}} for a in ('base','epoch_1','epoch_2')}
            probe=subprocess.CompletedProcess([],0,stdout='',stderr='')
            with patch.object(runner,'ROOT',fake),patch.object(runner.shutil,'which',return_value='/synthetic/nvidia-smi'),patch.object(runner.subprocess,'run',return_value=probe):
                result=runner.smoke(cfgs,req,targets,work,run,lambda x:None)
            self.assertEqual(result['requests_completed'],12)
            self.assertTrue(result['same_tokenized_inputs_across_arms'])
            for a in cfgs:
                self.assertEqual(result['arms'][a]['abstain'],4)
                self.assertFalse(result['arms'][a]['cleanup']['still_running'])
    def test_gpu_busy_refuses_before_worker(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);(work/'.ntk_v5_lora_venv/bin').mkdir(parents=True)
            (work/'.ntk_v5_lora_venv/bin/python').symlink_to(sys.executable)
            probe=subprocess.CompletedProcess([],0,stdout='12, already-running\n',stderr='')
            with patch.object(runner.shutil,'which',return_value='/fake/nvidia-smi'),patch.object(runner.subprocess,'run',return_value=probe),patch.object(runner,'Worker') as W:
                with self.assertRaisesRegex(Blocker,'GPU_COMPUTE_PROCESS'):runner.smoke({},[],[],work,work,lambda x:None)
                W.assert_not_called()
    def test_configuration_targets_not_passed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work=root/'w';down=root/'d';run=root/'r';base=root/'b'
            for p in (work,down,run,base):p.mkdir()
            (base/'config.json').write_bytes(b'{}')
            expected={'config.json':sha(b'{}')};fingerprint=digest(expected)
            members={'inputs/BASE_MANIFEST.json':canonical({'files':expected}).encode()}
            ad_sha={}
            for a in ('epoch_1','epoch_2'):
                ad=root/a;ad.mkdir();(ad/'adapter_model.safetensors').write_bytes(a.encode());(ad/'adapter_config.json').write_bytes(b'{}')
                ad_sha[a]=sha(a.encode())
                cfg={'arm':a,'base_dir':str(base),'base_fingerprint':fingerprint,'adapter_dir':str(ad),
                     'generation':{'seed':1,'max_input_tokens':100,'max_new_tokens':20,'attention':'eager','generation_timeout_s':2},
                     'runtime_versions':{'fake':'unit-only'},'cases':[{'label':'MUST_NOT_PASS'}]}
                members['CONFIG_'+a+'.json']=canonical(cfg).encode()
            members['OUTPUT_MANIFEST.json']=canonical({k:sha(v) for k,v in members.items()}).encode()
            z=zip_bytes(members);(down/'B33.zip').write_bytes(z)
            pins={**runner.PINS,'b33_name':'B33.zip','b33_sha256':sha(z),'base_fingerprint':fingerprint,'runtime_versions':{'fake':'unit-only'}}
            with patch.object(runner,'PINS',pins),patch.object(runner,'ADAPTER_SHA',ad_sha),patch.object(runner,'ADAPTER_CONFIG_SHA',sha(b'{}')):
                cfg=runner.make_runtime_configs(work,down,run,{})
            self.assertIsNone(cfg['base']['adapter_dir'])
            self.assertTrue(all('cases' not in c and 'targets' not in c for c in cfg.values()))
    def test_missing_repo_negative_cli_keeps_old_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work=root/'w';down=root/'d';work.mkdir();down.mkdir()
            old=work/'KEEP';old.write_bytes(b'original')
            p=subprocess.run([sys.executable,'-I','-B',str(ROOT/'run_b39b2.py'),
                '--work',str(work),'--downloads',str(down),'--repo',str(root/'absent'),
                '--github',str(root/'absent2')],capture_output=True,text=True,timeout=30)
            self.assertEqual(p.returncode,2,p.stdout+p.stderr)
            self.assertEqual(old.read_bytes(),b'original')
            archives=list(down.glob('*_result.zip'));self.assertEqual(len(archives),1)
            m=zip_members(archives[0].read_bytes());verify_sums(m)
            self.assertEqual(loads(m['00_RESULT.json'])['model_inference'],'NOT_EXECUTED')


if __name__=='__main__':
    unittest.main(verbosity=2)
