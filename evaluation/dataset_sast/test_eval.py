#!/usr/bin/env python3
"""CPU-only tests. Generated labels, sources and model findings are synthetic."""
from __future__ import annotations
import copy
import contextlib
import io
from dataclasses import dataclass
import importlib.util
import itertools
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import cli
from eval_core import *
from ntk_core import (canonical, convert_rows, digest, jsonl, loads, overlap, sha, stats,
                      verify_sums, zip_members)


def units4():
    out=[]
    for i,c in enumerate(CWES):
        uri='src/Case%d.java'%i
        out.append({'uri':uri,'cwe':c,'input_sha256':'a'*64,'source_sha256':digest(uri),
                    'unit_id':unit_id('a'*64,uri,c),'source_line_count':10})
    return out


def labels_for(units,truths=None):
    out=initial_labels(units)
    if truths is None:truths=['POSITIVE']*len(units)
    mapping={u['unit_id']:t for u,t in zip(units,truths)}
    for x in out:
        x.update(truth=mapping[x['unit_id']],review_status='REVIEWED',reviewer='TEST_SYNTHETIC',
            reviewed_at='2026-10-20T00:00:00+00:00',rationale='Synthetic test label, not real gold',
            assumptions='Synthetic fixture only',evidence_lines=[1])
    return out


def vector(u,score=50,raw=True,qualified=False):
    return {'unit_id':u['unit_id'],'cwe':u['cwe'],'score':score,'raw_opengrep':raw,
            'any_reported_alert':score is not None,'qualified_evidence':qualified,
            'qualified_model':qualified and u['cwe']!='79',
            'qualified_policy':qualified and u['cwe']=='79'}


def finding(u,ident,arm,qualified=False):
    raw={'path':u['uri'],'extra':{'message':'SYNTHETIC_RAW_MARKER'},'check_id':'test-'+u['cwe']}
    row={'id':ident,'origin':'OPENGREP','original_opengrep':raw,'cwe':u['cwe'],
         'location':{'uri':u['uri'],'start_line':1},'retained':True,'vulnerability_confirmed':False,
         'score':{'final_score':50.0,'ai_confidence_score':0.5},'linked_codeql_flow_ids':[],
         'dataflow':[],'model_observation':None,'evidence_status':'REVIEW_ONLY'}
    if arm!='opengrep_only':
        row['evidence_origin']=POLICY if u['cwe']=='79' else MODEL
        if u['cwe']=='79':row['raw_policy_flow_ids']=[]
        else: row['model_observation']={'status':'ABSTAIN','label':None,'raw_completion':'SYNTHETIC_PRIVATE_COMPLETION'}
    if qualified:
        row['linked_codeql_flow_ids']=['f1'];row['dataflow']=[{'type':'source'},{'type':'sink'}]
        row['evidence_status']='POLICY_QUALIFIED_UNENCODED_HTML_PATH' if u['cwe']=='79' else 'CODEQL_CWE_'+u['cwe']+'_QUALIFIED_PATH'
        if u['cwe']=='79':row['raw_policy_flow_ids']=['f1']
        else:
            row['model_observation']={'status':'ACCEPTED','label':{'type':'sink','sink_args':['p0']},
                                      'raw_completion':'SYNTHETIC_PRIVATE_COMPLETION'}
    return row


def reports4(units=None):
    units=units or units4()
    return {arm:{'arm':arm,'input_sha256':units[0]['input_sha256'],'independent_gold':False,
              'model_xss_gate_granted':False,'findings':[finding(u,'opengrep:'+str(i),arm)
              for i,u in enumerate(units)]} for arm in ARMS}


def rejection(test,obj,mutate,fn):
    bad=copy.deepcopy(obj);mutate(bad)
    with test.assertRaises(Blocker):fn(bad)


class MetricTests(unittest.TestCase):
    def setUp(self):
        self.units=units4();self.labels=labels_for(self.units,['POSITIVE','NEGATIVE','POSITIVE','NEGATIVE'])
        self.refs={x['unit_id']:x for x in self.labels}
        self.rows=[vector(u,4-i) for i,u in enumerate(self.units)]
    def test_precision_recall_f1(self):
        rows=copy.deepcopy(self.rows)
        for r,b in zip(rows,[True,True,False,False]):r['raw_opengrep']=b
        m=detection(rows,self.refs,'raw_opengrep')
        self.assertEqual((m['tp'],m['fp'],m['fn'],m['tn']),(1,1,1,1))
        self.assertEqual((m['precision'],m['recall'],m['f1']),(0.5,0.5,0.5))
    def test_unknown_not_tn(self):
        self.refs[self.units[1]['unit_id']]['truth']='UNKNOWN'
        m=detection(self.rows,self.refs,'raw_opengrep')
        self.assertEqual(m['unknown'],1);self.assertEqual(m['fp'],1);self.assertEqual(m['tn'],0)
    def test_all_unknown_null(self):
        refs={x['unit_id']:x for x in initial_labels(self.units)}
        m=detection(self.rows,refs,'raw_opengrep')
        self.assertEqual(m['reviewed_binary'],0);self.assertIsNone(m['f1']);self.assertIsNone(m['recall'])
    def test_fn_count_no_flow_is_selector_not_safety(self):
        m=detection(self.rows,self.refs,'qualified_evidence')
        self.assertEqual(m['fn'],2);self.assertTrue(m['not_retrieved_is_not_runtime_safe_verdict'])
    def test_zero_predictions_precision_null(self):
        rows=[{**r,'raw_opengrep':False} for r in self.rows]
        m=detection(rows,self.refs,'raw_opengrep')
        self.assertIsNone(m['precision']);self.assertEqual(m['recall'],0);self.assertEqual(m['f1'],0)
    def test_absent_positives_recall_null(self):
        refs={x['unit_id']:x for x in labels_for(self.units,['NEGATIVE']*4)}
        m=detection(self.rows,refs,'raw_opengrep');self.assertIsNone(m['recall']);self.assertEqual(m['f1'],0)
    def test_prediction_bool_required(self):
        self.rows[0]['raw_opengrep']=1
        with self.assertRaises(Blocker):detection(self.rows,self.refs,'raw_opengrep')
    def test_ap_golden(self):
        m=ranking(self.rows,self.refs,[1,3])
        self.assertAlmostEqual(m['ap_single_list_not_map'],(1+2/3)/2)
        self.assertAlmostEqual(m['top_k']['3']['precision'],2/3)
        self.assertEqual(m['top_k']['3']['recall'],1)
    def test_ndcg_golden(self):
        m=ranking(self.rows,self.refs,[3])
        self.assertAlmostEqual(m['top_k']['3']['ndcg_binary'],1.5/(1+1/math.log2(3)))
    def test_k_not_clamped(self):
        m=ranking(self.rows,self.refs,[5]);self.assertIsNone(m['top_k']['5']['metrics'])
    def test_unknown_ranking_withheld(self):
        self.refs[self.units[3]['unit_id']]['truth']='UNKNOWN'
        self.assertEqual(ranking(self.rows,self.refs,[1])['status'],'WITHHELD_UNREVIEWED_UNITS')
    def test_unknown_unretrieved_still_withheld(self):
        self.refs[self.units[3]['unit_id']]['truth']='UNKNOWN'
        self.rows[3].update(score=None,any_reported_alert=False)
        self.assertEqual(ranking(self.rows,self.refs,[1])['status'],'WITHHELD_UNREVIEWED_UNITS')
    def test_missing_positive_in_denominator(self):
        self.rows[2].update(score=None,any_reported_alert=False)
        m=ranking(self.rows,self.refs,[1]);self.assertEqual(m['positive_not_retrieved'],1)
        self.assertEqual(m['ap_single_list_not_map'],0.5);self.assertEqual(m['top_k']['1']['recall'],0.5)
    def test_no_returned_rows_ap_zero_when_positive(self):
        for r in self.rows:r.update(score=None,any_reported_alert=False)
        self.assertEqual(ranking(self.rows,self.refs,[1])['ap_single_list_not_map'],0)
    def test_no_positive_ap_null(self):
        refs={x['unit_id']:x for x in labels_for(self.units,['NEGATIVE']*4)}
        m=ranking(self.rows,refs,[1]);self.assertIsNone(m['ap_single_list_not_map'])
        self.assertIsNone(m['top_k']['1']['ndcg_binary'])
    def test_tie_precision_expected(self):
        for r in self.rows:r['score']=1
        m=ranking(self.rows,self.refs,[1,3])
        self.assertEqual(m['top_k']['1']['tie_expected_precision'],0.5)
        self.assertEqual(m['top_k']['1']['within_tie_precision_min'],0)
        self.assertEqual(m['top_k']['1']['within_tie_precision_max'],1)
        self.assertEqual(m['top_k']['3']['within_tie_precision_min'],1/3)
        self.assertEqual(m['top_k']['3']['within_tie_precision_max'],2/3)
    def test_tie_ap_and_ndcg_expectations_exhaustive(self):
        for r in self.rows:r['score']=1
        measured=ranking(self.rows,self.refs,[3]);aps=[];ndcgs=[]
        for gains in itertools.permutations([1,0,1,0]):
            hits=0;s=0
            for i,g in enumerate(gains,1):
                hits+=g
                if g:s+=hits/i
            aps.append(s/2)
            ndcgs.append(sum(g/math.log2(i+2) for i,g in enumerate(gains[:3]))/(1+1/math.log2(3)))
        self.assertAlmostEqual(measured['tie_expected_ap'],sum(aps)/len(aps))
        self.assertAlmostEqual(measured['top_k']['3']['tie_expected_ndcg_binary'],sum(ndcgs)/len(ndcgs))
    def test_tie_expectation_across_two_groups(self):
        for i,r in enumerate(self.rows):r['score']=2 if i<2 else 1
        m=ranking(self.rows,self.refs,[1,3]);values=[]
        for a in itertools.permutations([1,0]):
            for b in itertools.permutations([1,0]):
                gain=a+b;hits=0;ap=0
                for i,g in enumerate(gain,1):
                    hits+=g
                    if g:ap+=hits/i
                values.append(ap/2)
        self.assertAlmostEqual(m['tie_expected_ap'],sum(values)/len(values))
    def test_sort_stable_under_input_reordering(self):
        for r in self.rows:r['score']=1
        self.assertEqual(ranking(self.rows,self.refs,[1,3]),ranking(list(reversed(self.rows)),self.refs,[1,3]))
    def test_invalid_score_nan(self):
        self.rows[0]['score']=float('nan')
        with self.assertRaises(Blocker):ranking(self.rows,self.refs,[1])
    def test_invalid_score_bool(self):
        self.rows[0]['score']=True
        with self.assertRaises(Blocker):ranking(self.rows,self.refs,[1])
    def test_missing_score_not_alerted(self):
        self.rows[0]['score']=None
        with self.assertRaises(Blocker):ranking(self.rows,self.refs,[1])
    def test_invalid_k(self):
        for ks in ([0],[-1],[True],[1,1]):
            with self.subTest(ks=ks),self.assertRaises(Blocker):ranking(self.rows,self.refs,ks)
    def test_empty_universe(self):
        self.assertEqual(ranking([],{},[1])['status'],'NOT_COMPUTABLE_EMPTY_UNIVERSE')
    def test_whole_evaluation_no_gold(self):
        vectors={a:copy.deepcopy(self.rows) for a in ARMS}
        result=evaluate_vectors(vectors,self.units,self.labels,PROTOCOL)
        self.assertFalse(result['independent_gold'])
        self.assertEqual(result['arms']['opengrep_only']['scopes']['all']['detection']['qualified_evidence']['status'],'NOT_APPLICABLE_CODEQL_NOT_RUN')
    def test_missing_arm_not_interpreted_as_zero(self):
        with self.assertRaises(Blocker):evaluate_vectors({'base':self.rows},self.units,self.labels,PROTOCOL)
    def test_missing_unit_not_tn(self):
        vectors={a:copy.deepcopy(self.rows) for a in ARMS};vectors['base'].pop()
        with self.assertRaises(Blocker):evaluate_vectors(vectors,self.units,self.labels,PROTOCOL)
    def test_protocol_change_rejected(self):
        p=copy.deepcopy(PROTOCOL);p['ranking_k']=[1]
        with self.assertRaises(Blocker):evaluate_vectors({a:self.rows for a in ARMS},self.units,self.labels,p)
    def test_macro_defined_cwes(self):
        r=evaluate_vectors({a:self.rows for a in ARMS},self.units,self.labels,PROTOCOL)
        self.assertEqual(r['arms']['base']['macro_across_defined_cwes']['raw_opengrep']['recall']['count'],2)


class LabelTests(unittest.TestCase):
    def setUp(self):self.units=units4();self.labels=labels_for(self.units)
    def reject(self,fn):rejection(self,self.labels,fn,lambda v:validate_labels(self.units,v,True))
    def test_initial_all_unknown(self):self.assertEqual({l['truth'] for l in initial_labels(self.units)},{'UNKNOWN'})
    def test_initial_not_lockable(self):
        with self.assertRaises(Blocker):validate_labels(self.units,initial_labels(self.units),True)
    def test_valid_review(self):self.assertEqual(len(validate_labels(self.units,self.labels,True)),4)
    def test_unknown_review_can_lock(self):
        self.labels[0]['truth']='UNKNOWN';validate_labels(self.units,self.labels,True)
    def test_missing_id(self):self.reject(lambda v:v.pop())
    def test_duplicate_id(self):self.reject(lambda v:v.append(v[0]))
    def test_truth_none_not_accepted(self):self.reject(lambda v:v[0].update(truth='none'))
    def test_cwe_drift(self):self.reject(lambda v:v[0].update(cwe='999'))
    def test_source_drift(self):self.reject(lambda v:v[0].update(source_sha256='b'*64))
    def test_no_reviewer(self):self.reject(lambda v:v[0].update(reviewer=''))
    def test_no_reason(self):self.reject(lambda v:v[0].update(rationale=''))
    def test_no_assumptions(self):self.reject(lambda v:v[0].update(assumptions=''))
    def test_bad_timestamp(self):self.reject(lambda v:v[0].update(reviewed_at='yesterday'))
    def test_naive_timestamp(self):self.reject(lambda v:v[0].update(reviewed_at='2026-10-20T01:00:00'))
    def test_no_line_proof(self):self.reject(lambda v:v[0].update(evidence_lines=[]))
    def test_line_outside_source(self):self.reject(lambda v:v[0].update(evidence_lines=[999]))
    def test_cannot_claim_unseen(self):self.reject(lambda v:v[0].update(predictions_exposed_before_review=False))
    def test_cannot_promote_to_gold(self):self.reject(lambda v:v[0].update(provenance='GOLD'))
    def test_positive_unreviewed_blocked(self):self.reject(lambda v:v[0].update(review_status='UNREVIEWED'))
    def test_unit_id_drift(self):
        self.units[0]['unit_id']='b'*64
        with self.assertRaises(Blocker):validate_units(self.units)
    def test_duplicate_unit(self):
        with self.assertRaises(Blocker):validate_units(self.units+[self.units[0]])
    def test_path_traversal(self):
        self.units[0]['uri']='../escape.java'
        with self.assertRaises(Blocker):validate_units(self.units)


class NormalizationTests(unittest.TestCase):
    def setUp(self):self.units=units4();self.reports=reports4(self.units)
    def reject(self,fn):rejection(self,self.reports,fn,lambda r:normalize_reports(r,self.units,'a'*64))
    def test_map_all_units(self):
        vec,a=normalize_reports(self.reports,self.units,'a'*64)
        self.assertTrue(a['raw_opengrep_preserved']);self.assertEqual(len(vec['base']),4)
    def test_source_hash_is_in_unit_id(self):self.assertNotEqual(unit_id('a','X.java','22'),unit_id('b','X.java','22'))
    def test_max_score_per_unit_not_sum(self):
        for arm in ARMS:
            extra=copy.deepcopy(self.reports[arm]['findings'][0]);extra['id']='opengrep:99'
            extra['score']['final_score']=70;self.reports[arm]['findings'].append(extra)
        vec,_=normalize_reports(self.reports,self.units,'a'*64)
        r=next(r for r in vec['base'] if r['cwe']=='22')
        self.assertEqual(r['score'],70);self.assertEqual(r['finding_count'],2);self.assertTrue(r['raw_opengrep'])
    def test_duplicate_id_rejected(self):self.reject(lambda r:r['base']['findings'].append(copy.deepcopy(r['base']['findings'][0])))
    def test_wrong_input(self):self.reject(lambda r:r['base'].update(input_sha256='b'*64))
    def test_wrong_arm(self):self.reject(lambda r:r['base'].update(arm='epoch_1'))
    def test_wrong_cwe_not_ignored(self):self.reject(lambda r:r['base']['findings'][0].update(cwe='79'))
    def test_unknown_origin(self):self.reject(lambda r:r['base']['findings'][0].update(origin='OTHER'))
    def test_extra_file_not_ignored(self):self.reject(lambda r:r['base']['findings'][0]['location'].update(uri='Extra.java'))
    def test_retained_false(self):self.reject(lambda r:r['base']['findings'][0].update(retained=False))
    def test_confirmed_true(self):self.reject(lambda r:r['base']['findings'][0].update(vulnerability_confirmed=True))
    def test_raw_change_rejected(self):self.reject(lambda r:r['base']['findings'][0]['original_opengrep'].update(check_id='CHANGED'))
    def test_missing_raw_rejected(self):self.reject(lambda r:r['base']['findings'][0].pop('original_opengrep'))
    def test_missing_arm(self):self.reject(lambda r:r.pop('epoch_2'))
    def test_path_without_dataflow(self):self.reject(lambda r:r['base']['findings'][0].update(linked_codeql_flow_ids=['x']))
    def test_model_path_requires_sink(self):
        self.reports['base']['findings'][0]=finding(self.units[0],'opengrep:0','base',True)
        self.reject(lambda r:r['base']['findings'][0]['model_observation']['label'].update(type='none'))
    def test_model_path_requires_sink_args(self):
        self.reports['base']['findings'][0]=finding(self.units[0],'opengrep:0','base',True)
        self.reject(lambda r:r['base']['findings'][0]['model_observation']['label'].update(sink_args=[]))
    def test_policy_neutral_ai_required(self):self.reject(lambda r:r['base']['findings'][2]['score'].update(ai_confidence_score=0.9))
    def test_policy_origin_required(self):self.reject(lambda r:r['base']['findings'][2].update(evidence_origin=MODEL))
    def test_raw_policy_not_qualified(self):
        for arm in ARMS[1:]:self.reports[arm]['findings'][2]['raw_policy_flow_ids']=['p1']
        vec,_=normalize_reports(self.reports,self.units,'a'*64)
        r=next(r for r in vec['base'] if r['cwe']=='79')
        self.assertEqual(r['raw_policy_paths'],1);self.assertFalse(r['qualified_evidence'])
    def test_qualified_policy_shared(self):
        for arm in ARMS[1:]:self.reports[arm]['findings'][2]=finding(self.units[2],'opengrep:2',arm,True)
        vec,_=normalize_reports(self.reports,self.units,'a'*64)
        self.assertTrue(next(r for r in vec['base'] if r['cwe']=='79')['qualified_policy'])
    def test_policy_drift_across_arms(self):self.reject(lambda r:r['base']['findings'][2]['score'].update(final_score=65))
    def test_scorer_drift(self):
        @dataclass
        class Score:final_score:float=99;ai_confidence_score:float=0.5
        class BadScorer:
            def score_finding(self,f):return Score()
        with self.assertRaises(Blocker):normalize_reports(self.reports,self.units,'a'*64,BadScorer())
    def test_invalid_inf_score(self):self.reject(lambda r:r['base']['findings'][0]['score'].update(final_score=float('inf')))
    def test_invalid_bool_score(self):self.reject(lambda r:r['base']['findings'][0]['score'].update(final_score=True))
    def test_noncanonical_status(self):self.reject(lambda r:r['base']['findings'][0]['model_observation'].update(status='none'))
    def test_unalerted_unit_kept(self):
        for arm in ARMS:self.reports[arm]['findings'].pop(0)
        vec,_=normalize_reports(self.reports,self.units,'a'*64)
        row=next(r for r in vec['base'] if r['cwe']=='22')
        self.assertIsNone(row['score']);self.assertFalse(row['any_reported_alert'])
    def test_opengrep_policy_not_executed(self):self.reject(lambda r:r['opengrep_only']['findings'][0].update(model_observation={'status':'ABSTAIN'}))


class DataTests(unittest.TestCase):
    def raw(self,ident=1,cwe='22'):
        label=dict(package='java.test', **{'class':'C'},method='f',signature='void f(String p0)',type='sink',sink_args=['p0'])
        return {'id':ident,'cwe':cwe,'messages':[{'role':'system','content':'s'},{'role':'user','content':'u'+str(ident)},
                                              {'role':'assistant','content':canonical(label)}]}
    def test_assistant_target_not_request(self):
        q,t=convert_rows([self.raw()]);self.assertEqual(len(q[0]['messages']),2);self.assertEqual(len(t),1)
    def test_duplicate_sample_id_rejected(self):
        with self.assertRaises(Blocker):convert_rows([self.raw(),self.raw()])
    def test_zero_support_not_hidden(self):
        q,t=convert_rows([self.raw()]);self.assertEqual(stats(q,t)['cwe_role'].get('79|sink',0),0)
    def test_overlap_exact_identity_detected(self):
        q,_=convert_rows([self.raw()]);z,_=convert_rows([self.raw(2)])
        self.assertEqual(overlap(q,z)['identity_cwe_overlap'],1);self.assertEqual(overlap(q,z)['id_overlap'],0)
    def test_receiver_unproven_kept(self):
        row=self.raw();label=loads(row['messages'][2]['content']);label['sink_args']=['this'];row['messages'][2]['content']=canonical(label)
        q,t=convert_rows([row]);self.assertEqual(stats(q,t)['reference_contract_failures_kept'],1)
    def test_cwe_missing_rejected(self):
        row=self.raw();row.pop('cwe')
        with self.assertRaises(Blocker):convert_rows([row])
    def test_duplicate_json_keys(self):
        with self.assertRaises(Blocker):loads('{"x":1,"x":2}')
    def test_nan_json_rejected(self):
        with self.assertRaises(Blocker):loads('{"x":NaN}')


def archive_at(path,contents):
    sums=''.join(sha(v)+'  '+k+'\n' for k,v in sorted(contents.items()))
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
        for k,v in contents.items():z.writestr(k,v)
        z.writestr('SHA256SUMS',sums)
    return sha(path.read_bytes())


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def fake_fixture(root):
    """Synthetic workroot; never uses real user sources, results or labels."""
    work=root/'work';down=root/'downloads';workspace=work/'new_eval';package=root/'package'
    for p in (work,down,workspace,package):p.mkdir(parents=True)
    for name in cli.code_hashes():
        p=package/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
    b4rel='old_b4';priv=work/b4rel/'private';priv.mkdir(parents=True)
    source={u['uri']:('class X%d {} // SYNTHETIC_PRIVATE_SOURCE'%i).encode() for i,u in enumerate(units4())}
    with zipfile.ZipFile(priv/'project.zip','w') as z:
        for name,data in source.items():z.writestr(name,data)
    inputsha=sha((priv/'project.zip').read_bytes())
    us=[{**u,'input_sha256':inputsha,'source_sha256':sha(source[u['uri']]),
         'unit_id':unit_id(inputsha,u['uri'],u['cwe'])} for u in units4()]
    (package/'UNITS.json').write_bytes(encoded({'input_sha256':inputsha,'units':[
        {k:u[k] for k in ('uri','cwe','source_sha256')} for u in us]}))
    reports=reports4(us);manifest={}
    for arm in ARMS:
        r=reports[arm];r['input_sha256']=inputsha
        fol=priv/'analysis'/arm;fol.mkdir(parents=True)
        (fol/'result.json').write_bytes(encoded(r))
        sf={'version':'2.1.0','runs':[{'properties':{'arm':arm,'score_is_probability':False},'results':[
            {'properties':{'ntk_id':f['id'],'cwe':'CWE-'+f['cwe'],'priority_score':f['score']},
             'locations':[{'physicalLocation':{'artifactLocation':{'uri':f['location']['uri']},'region':{'startLine':1}}}]}
             for f in r['findings']]}]}
        (fol/'report.sarif').write_bytes(encoded(sf))
        for p in fol.iterdir():manifest[str(p.relative_to(priv))]=sha(p.read_bytes())
    cases=[]
    for i,c in enumerate(CWES):
        cases.append({'package':'java.test','class':'C','method':'f','signature':'void f(String p0)',
                      'cwe':c,'expected_messages':[{'role':'system','content':'x'},{'role':'user','content':'y'}]})
    native=priv/'live/base/effective_native_config.json';native.parent.mkdir(parents=True)
    native.write_bytes(encoded({'cases':cases}));manifest[str(native.relative_to(priv))]=sha(native.read_bytes())
    runid='synthetic_run';state={'status':'B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE','blockers':[],
                               'completed_arms':list(ARMS),'input_sha256':inputsha}
    backend={'00_RESULT.json':encoded(state),'BEFORE.json':b'{}','AFTER.json':b'{}',
             'PRIVATE_RESULT_MANIFEST.json':encoded(manifest),
             'COMPARISON.json':encoded({'arms':{a:{'findings':4,'retained_opengrep':4} for a in ARMS}})}
    for a in ARMS[1:]:backend['NATIVE_'+a+'.json']=encoded(dict(candidates=4,accepted=0,abstain=4,reasons={},new_requests=4,cache_hits=4))
    backend_path=root/'backend.zip';bh=archive_at(backend_path,backend)
    receipt={'status':'B39B5_WEB_JOB_HTTP_CHAIN_VERIFIED','blockers':[],'run_id':runid,
             'input_sha256':inputsha,'backend_audit_sha256':bh}
    rn='receipt.zip';rh=archive_at(down/rn,{'WEB_JOB_RECEIPT.json':encoded(receipt),
                                         'backend/'+runid+'_result.zip':backend_path.read_bytes()})
    b2rel='old_b2';b2priv=work/b2rel/'private';b2priv.mkdir(parents=True)
    train=[DataTests().raw(1),DataTests().raw(2,'89')];val=[DataTests().raw(3,'78')]
    refs={};pr={}
    for name,raw in [('train',train),('validation',val)]:
        p=b2priv/(name+'_original.jsonl');p.write_text(''.join(canonical(x)+'\n' for x in raw))
        q,t=convert_rows(raw);refs[name]=stats(q,t);pr[name]=q
    b2lock={**refs,'private_artifact_hashes':{p.name:sha(p.read_bytes()) for p in b2priv.iterdir()},'exact_overlap':overlap(pr['train'],pr['validation'])}
    b2name='b2.zip';b2h=archive_at(down/b2name,{'DATA_LOCK.json':encoded(b2lock),
              '00_RESULT.json':encoded({'status':'B39B2_DATA_LOCK_AND_LOCAL_ARMS_SMOKE_COMPLETE'})})
    scorer=root/'scorer.py'
    scorer.write_text('from dataclasses import dataclass\n@dataclass\nclass Score:\n    final_score: float\n    ai_confidence_score: float\nclass SASTScoringEngine:\n    def score_finding(self, f): return Score(**f["score"])\n')
    pins={**cli.PINS,'receipt_name':rn,'receipt_sha256':rh,'backend_audit_sha256':bh,'run_id':runid,
          'input_sha256':inputsha,'b4_run_relative':b4rel,'b2_run_relative':b2rel,'b2_name':b2name,
          'b2_sha256':b2h,'scorer_sha256':sha(scorer.read_bytes())}
    (package/'PINS.json').write_bytes(encoded(pins))
    return work,down,workspace,package,scorer,pins


class IOTests(unittest.TestCase):
    def test_read_drift(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input';p.write_bytes(b'old');r=cli.Inputs();r.read(p);p.write_bytes(b'new')
            with self.assertRaises(Blocker):r.verify()
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'a').write_bytes(b'a');(p/'b').symlink_to(p/'a')
            with self.assertRaises(Blocker):cli.Inputs().read(p/'b')
    def test_path_outside(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(Blocker):cli.safe_under(t,'../bad')
    def test_archive_path_traversal(self):
        import io
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:z.writestr('../bad',b'x')
        with self.assertRaises(Blocker):zip_members(b.getvalue())
    def test_archive_unmanifested(self):
        with self.assertRaises(Blocker):verify_sums({'extra':b'x','SHA256SUMS':b''})
    def test_original_exports_not_in_pack(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);run=p/'run';run.mkdir();(run/'private').mkdir();(run/'private/secret').write_bytes(b'SECRET')
            with self.assertRaises(Blocker):cli.pack(run,p/'out',['private/secret'])
    def test_full_gather_review_lock_eval_synthetic(self):
        import argparse
        with tempfile.TemporaryDirectory() as t:
            work,down,ws,package,scorer,pins=fake_fixture(Path(t))
            with patch.object(cli,'PINS',pins),patch.object(cli,'ROOT',package):
                r=cli.gather(work,down,ws,scorer)
                self.assertEqual(r['units'],4);self.assertEqual(r['scorer_replayed'],16)
                self.assertEqual(r['verified_original_exports'],8)
                _,_,units,vectors=cli.workspace_load(ws)
                self.assertEqual({x['truth'] for x in jsonl((ws/'private/labels.draft.jsonl').read_bytes())},{'UNKNOWN'})
                labels=labels_for(units,['POSITIVE','NEGATIVE','UNKNOWN','NEGATIVE'])
                # Evidence lines must be real source lines: all generated fixtures are one line.
                (ws/'private/labels.draft.jsonl').write_text(''.join(canonical(x)+'\n' for x in labels))
                with patch.object(cli,'deny_inet',return_value={'synthetic_test':True}), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.run_lock(argparse.Namespace(workspace=ws)),0)
                    self.assertEqual(cli.run_evaluate(argparse.Namespace(workspace=ws,downloads=down)),0)
                outputs=list(down.glob('b39b6_eval_*_result.zip'));self.assertEqual(len(outputs),1)
                raw=outputs[0].read_bytes();m=zip_members(raw);verify_sums(m)
                self.assertNotIn(b'SYNTHETIC_PRIVATE_SOURCE',b''.join(m.values()))
                self.assertNotIn(b'SYNTHETIC_PRIVATE_COMPLETION',b''.join(m.values()))
                metrics=loads(m['METRICS.json'])
                self.assertFalse(metrics['independent_gold'])
                self.assertEqual(metrics['arms']['base']['scopes']['all']['ranking']['status'],'WITHHELD_UNREVIEWED_UNITS')
                # Mutating a locked draft is not silently accepted.
                (ws/'private/labels.draft.jsonl').write_text('{}\n')
                with patch.object(cli,'deny_inet',return_value={}),self.assertRaises(Blocker):
                    cli.run_evaluate(argparse.Namespace(workspace=ws,downloads=down))
    def test_source_and_snapshot_unchanged_synthetic(self):
        with tempfile.TemporaryDirectory() as t:
            work,down,ws,package,scorer,pins=fake_fixture(Path(t))
            originals={str(p):sha(p.read_bytes()) for p in work.rglob('*') if p.is_file()}
            with patch.object(cli,'PINS',pins),patch.object(cli,'ROOT',package):cli.gather(work,down,ws,scorer)
            for p,h in originals.items():self.assertEqual(sha(Path(p).read_bytes()),h)
    def test_drifted_original_blocked_before_eval(self):
        with tempfile.TemporaryDirectory() as t:
            work,down,ws,package,scorer,pins=fake_fixture(Path(t))
            with patch.object(cli,'PINS',pins),patch.object(cli,'ROOT',package):
                cli.gather(work,down,ws,scorer)
                (work/pins['b4_run_relative']/'private/analysis/base/result.json').write_bytes(b'{}')
                with self.assertRaises(Blocker):cli.workspace_load(ws)
    def test_protocol_tamper_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            work,down,ws,package,scorer,pins=fake_fixture(Path(t))
            with patch.object(cli,'PINS',pins),patch.object(cli,'ROOT',package):
                cli.gather(work,down,ws,scorer);(ws/'EVAL_PROTOCOL.json').write_bytes(b'{}')
                with self.assertRaises(Blocker):cli.workspace_load(ws)
    def test_wrong_report_hash_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            work,down,ws,package,scorer,pins=fake_fixture(Path(t))
            (work/pins['b4_run_relative']/'private/analysis/base/result.json').write_bytes(b'{}')
            with patch.object(cli,'PINS',pins),patch.object(cli,'ROOT',package),self.assertRaises(Blocker):
                cli.gather(work,down,ws,scorer)


if __name__=='__main__':unittest.main(verbosity=2)
