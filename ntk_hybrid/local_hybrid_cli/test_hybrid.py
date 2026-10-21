#!/usr/bin/env python3
"""Synthetic invariant and launcher tests. No live CodeQL/GPU or native IRIS here."""
from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import hybrid_core as h
from ntk_core import Blocker, digest, canonical, sha, loads
from test_b39b3 import fake_bundle
from hybrid_native_driver import prepare_cases, routes_for
from test_b39b3 import queries


def bundle():
    req,t,trace,summary=fake_bundle('epoch_1')
    cases=[{**r['candidate'],'source_record_sha256':r['source_record_sha256'],'expected_messages':r['messages']} for r in req]
    summary['status']='B39B4_NATIVE_ARM_COMPLETE'
    token={'tokenizer_chat_template_sha256':summary['worker']['tokenizer_chat_template_sha256'],
           'rows':[{'case_key':h.key(r['candidate']),'input_token_ids_sha256':digest(r['messages'])} for r in req]}
    return cases,trace,summary,'epoch_1',summary['worker']['versions'],token

@dataclass
class Score:
    final_score:float=60.0
    ai_confidence_score:float=0.5
    risk_level:str='MEDIUM'

class Scorer:
    def score_finding(self,record):return Score()

def findings():
    raw={'cwe':'79','check_id':'synthetic','path':'fixture.java'}
    rows=[{'id':'opengrep:0','origin':'OPENGREP','cwe':'79','original_opengrep':deepcopy(raw),
      'retained':True,'vulnerability_confirmed':False,'score':h.scorer_fields(Score()),
      'linked_codeql_flow_ids':[],'dataflow':[],'model_observation':None,'evidence_origin':h.POLICY}]
    return rows,{'results':[raw]},Scorer()

class HybridTests(unittest.TestCase):
    def test_native_compiler_input_no_labels(self):
        c=deepcopy(bundle()[0][0]);c.pop('expected_messages');c['compiler_signature']='call(java.lang.String)'
        out=h.native_inputs([c]);self.assertNotIn('type',out[0]);self.assertNotIn('expected_messages',out[0])
    def test_missing_compiler_signature_rejected(self):
        c=bundle()[0][0]
        with self.assertRaises(Blocker):h.native_inputs([c])
    def test_duplicate_compiler_key_rejected(self):
        c=bundle()[0][0];c['compiler_signature']='call(java.lang.String)'
        with self.assertRaises(Blocker):h.native_inputs([c,c])
    def test_zero_candidate_rejected(self):
        with self.assertRaises(Blocker):h.native_inputs([])
    def test_cold_and_warm_trace(self):
        d=h.trace_check(*bundle());self.assertEqual(d['new_requests'],4);self.assertEqual(d['cache_hits'],4)
    def test_empty_json_is_abstain_not_none(self):
        b=list(bundle())
        for t in b[1]:t.update(raw_completion='bad',status='ABSTAIN',reason='INVALID_STRICT_JSON',label=None)
        d=h.trace_check(*b);self.assertEqual(d['abstain'],4);self.assertEqual(d['accepted'],0)
    def test_trace_missing_rejected(self):
        b=list(bundle());b[1].pop()
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_trace_cold_cache_rejected(self):
        b=list(bundle());b[1][0]['cache_hit']=True
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_trace_warm_changed_rejected(self):
        b=list(bundle());b[1][-1]['cache_key']='x'
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_trace_prompt_changed_rejected(self):
        b=list(bundle());b[1][0]['prompt_sha256']='0'*64
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_trace_overload_changed_rejected(self):
        b=list(bundle());b[1][0]['candidate']['signature']='other()'
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_trace_parser_forgery_rejected(self):
        b=list(bundle());b[1][0]['reason']='forged'
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_token_preflight_mismatch_rejected(self):
        b=list(bundle());b[-1]['rows'][0]['input_token_ids_sha256']='different'
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_training_enabled_rejected(self):
        b=list(bundle());b[2]['worker']['training_executed']=True
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_network_not_guarded_rejected(self):
        b=list(bundle());b[2]['worker']['isolation']['AF_INET']='ALLOWED'
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_wrong_runtime_rejected(self):
        b=list(bundle());b[4]=dict(b[4],torch='unknown')
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_nonfinite_timing_rejected(self):
        b=list(bundle());b[1][0]['worker']['generation_s']=float('nan')
        with self.assertRaises(Blocker):h.trace_check(*b)
    def test_policy_and_scoring_valid(self):
        r,og,s=findings();v=h.verify_fusion(r,og,s,'base');self.assertEqual(v['retained_opengrep'],1)
    def test_scanner_finding_loss_rejected(self):
        r,og,s=findings()
        with self.assertRaises(Blocker):h.verify_fusion([],og,s,'base')
    def test_raw_change_rejected(self):
        r,og,s=findings();r[0]['original_opengrep']['path']='changed.java'
        with self.assertRaises(Blocker):h.verify_fusion(r,og,s,'base')
    def test_wrong_numeric_score_rejected(self):
        r,og,s=findings();r[0]['score']['final_score']=99
        with self.assertRaises(Blocker):h.verify_fusion(r,og,s,'base')
    def test_policy_origin_forgery_rejected(self):
        r,og,s=findings();r[0]['evidence_origin']=h.MODEL
        with self.assertRaises(Blocker):h.verify_fusion(r,og,s,'base')
    def test_baseline_no_flow(self):
        r,og,s=findings();self.assertEqual(h.verify_fusion(r,og,s,'opengrep_only')['findings'],1)
    def test_baseline_flow_rejected(self):
        r,og,s=findings();r[0]['dataflow']=[{'type':'source'}]
        with self.assertRaises(Blocker):h.verify_fusion(r,og,s,'opengrep_only')
    def test_false_confirmation_rejected(self):
        r,og,s=findings();r[0]['vulnerability_confirmed']=True
        with self.assertRaises(Blocker):h.verify_fusion(r,og,s,'base')
    def test_display_does_not_rewrite_frozen_score(self):
        rows,og,s=findings();before=deepcopy(rows);v=h.results_view(rows,'base','input')
        self.assertEqual(rows,before);self.assertFalse(v['display'][0]['confirmed'])
    def test_comparison_same_tokens(self):
        traces={}
        for arm in h.ARMS:
            t=h.trace_check(*bundle());t['arm']=arm
            for d in t['details']:d['cache_key']=digest([arm,d['case_key']])
            traces[arm]=t
        sums={a:{'retained_opengrep':4} for a in ('opengrep_only',*h.ARMS)}
        v=h.assert_comparison(sums,traces,{a:'same' for a in h.ARMS});self.assertEqual(v['new_native_requests'],12)
        traces['base']['details'][0]['input_token_ids_sha256']='bad'
        with self.assertRaises(Blocker):h.assert_comparison(sums,traces,{a:'same' for a in h.ARMS})
    def test_policy_sharing_change_rejected(self):
        sums={a:{'retained_opengrep':4} for a in ('opengrep_only',*h.ARMS)}
        with self.assertRaises(Blocker):h.assert_comparison(sums,{},dict(base='a',epoch_1='b',epoch_2='b'))
    def test_sarif_baseline_not_hybrid(self):
        def exporter(rows):return {'runs':[{'tool':{'driver':{}},'properties':{},'results':[{'properties':{}}]}]}
        s=h.sarif_view(exporter,[],'opengrep_only')['runs'][0]
        self.assertEqual(s['properties']['mode'],'OPENGREP_ONLY');self.assertFalse(s['results'][0]['properties']['model_role_used_for_xss_score'])
    def test_sample_pin_and_file_scope(self):
        m=loads((ROOT/'SAMPLE_MANIFEST.json').read_bytes());p=ROOT/'samples/B39B4_JDK_INTEGRATION.zip'
        self.assertEqual(sha(p.read_bytes()),m['archive_sha256'])
        with zipfile.ZipFile(p) as z:
            self.assertEqual(len(z.namelist()),16);self.assertFalse(z.testzip());self.assertTrue(all(n.endswith('.java') for n in z.namelist()))
            self.assertEqual({n:sha(z.read(n)) for n in z.namelist()},m['java_files'])
    def test_driver_origin_not_weak_dataset(self):
        s=(ROOT/'hybrid_native_driver.py').read_text()
        self.assertIn('THIS_RUN_CODEQL_COMPILER_IDENTITIES',s);self.assertNotIn('B28_WEAK_DATASET_NOT_NEW_COMPILER_DATABASE',s)
    def test_no_gate_issuance_or_manual_model_labels(self):
        s=(ROOT/'run_hybrid.py').read_text()
        self.assertNotIn('issue_gate(',s);self.assertIn("rp.require_gate(a.work,'DPA','epoch_1',impl)",s)
        self.assertEqual(s.count('rp.manual_labels('),1);self.assertIn("rp.manual_labels(cases['79'],'79')",s)
    def test_early_missing_input_exports_failure_without_gpu(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);w=root/'work';dl=root/'downloads';w.mkdir();dl.mkdir()
            r=subprocess.run([sys.executable,'-I','-B',str(ROOT/'run_hybrid.py'),'--run-hybrid','--work',str(w),'--repo',str(root/'missing_iris'),
                '--github',str(root/'missing_github'),'--downloads',str(dl),'--host-python',sys.executable],capture_output=True,text=True,timeout=30)
            self.assertEqual(r.returncode,2,r.stdout+r.stderr)
            zips=list(dl.glob('*.zip'));self.assertEqual(len(zips),1)
            with zipfile.ZipFile(zips[0]) as z:
                s=loads(z.read('00_RESULT.json'));self.assertEqual(s['status'],'B39B4_BLOCKED');self.assertFalse(s['new_codeql_database']);self.assertFalse(s['new_opengrep_scan'])
                self.assertTrue(all('/private/' not in n for n in z.namelist()))

if __name__=='__main__':unittest.main(verbosity=2)
