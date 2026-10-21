#!/usr/bin/env python3
"""Synthetic tests and pinned-artifact authoring checks (not real WSL private replay)."""
import importlib.util
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

spec=importlib.util.spec_from_file_location('ntk39b8_closeout',Path(__file__).with_name('closeout.py'))
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

EV=Path(os.environ.get('NTK_B39B8_EVAL_ZIP',
    '/mnt/data/b39b7_eval_20261020T103624Z_364e7982_result.zip'))
BK=Path(os.environ.get('NTK_B39B8_BACKEND_ZIP',
    '/mnt/data/b39b4_20261020T100814Z_63d29938_result.zip'))
SRC=Path(os.environ.get('NTK_B39B8_SOURCE_ZIP',
    '/mnt/data/ntk_b39b7_holdout_eval_20261020/samples/B39B7_HOLDOUT_JDK.zip'))

class ArithTests(unittest.TestCase):
    def test_confusion_all_correct(self):
        labels={'1':{'truth':'POSITIVE'},'2':{'truth':'NEGATIVE'}}
        rows=[{'unit_id':'1','x':True},{'unit_id':'2','x':False}]
        self.assertEqual(mod.confusion(rows,labels,'x')['f1'],1)
        self.assertEqual(mod.confusion(rows,labels,'x')['specificity'],1)
    def test_confusion_no_predictions(self):
        labels={'1':{'truth':'POSITIVE'},'2':{'truth':'NEGATIVE'}}
        rows=[{'unit_id':'1','x':False},{'unit_id':'2','x':False}]
        r=mod.confusion(rows,labels,'x');self.assertIsNone(r['precision']);self.assertEqual(r['f1'],0)
    def test_confusion_reject_non_bool(self):
        with self.assertRaises(mod.Blocked):mod.confusion([{'unit_id':'1','x':1}],{'1':{'truth':'POSITIVE'}},'x')
    def test_ranking_tie_expected(self):
        l={'1':{'unit_id':'1','truth':'POSITIVE'},'2':{'unit_id':'2','truth':'NEGATIVE'}}
        r=[{'unit_id':'1','score':80,'any_reported_alert':True}, {'unit_id':'2','score':80,'any_reported_alert':True}]
        v=mod.ranking(r,l)
        self.assertAlmostEqual(v['tie_expected_ap'],.75)
        self.assertAlmostEqual(v['top_k']['1']['tie_expected_precision'],.5)
        self.assertAlmostEqual(v['top_k']['1']['within_tie_precision_min'],0.)
        self.assertAlmostEqual(v['top_k']['1']['within_tie_precision_max'],1.)
    def test_ranking_not_retrieved(self):
        l={'1':{'unit_id':'1','truth':'POSITIVE'},'2':{'unit_id':'2','truth':'POSITIVE'}}
        r=[{'unit_id':'1','score':80,'any_reported_alert':True},{'unit_id':'2','score':0,'any_reported_alert':False}]
        v=mod.ranking(r,l)
        self.assertEqual(v['positive_not_retrieved'],1)
        self.assertEqual(v['ap_single_list_not_map'],.5)
        self.assertEqual(v['top_k']['3']['status'],'INSUFFICIENT_RETRIEVED_K')
    def test_numeric_diff_detected(self):
        with self.assertRaises(mod.Blocked):mod.numeric_equal({'f1':.5},{'f1':.50001})

class ArchiveTests(unittest.TestCase):
    def test_zip_path_traversal_refused(self):
        for name in ('../evil','/abs','a\\b','C:/a','a/../b'):
            with self.assertRaises(mod.Blocked):mod.validate_zip_path(name)
    def test_bad_manifest_refused(self):
        m={'A':b'one','SHA256SUMS':(mod.sha_bytes(b'two')+'  A\n').encode()}
        with self.assertRaises(mod.Blocked):mod.verify_manifest(m)
    def test_duplicate_members_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'dup.zip'
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with zipfile.ZipFile(p,'w') as z:z.writestr('same',b'1');z.writestr('same',b'2')
            with self.assertRaises(mod.Blocked):mod.read_zip(p)
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'symlink.zip'
            with zipfile.ZipFile(p,'w') as z:
                x=zipfile.ZipInfo('link');x.create_system=3;x.external_attr=(0o120777<<16)
                z.writestr(x,'target')
            with self.assertRaises(mod.Blocked):mod.read_zip(p)

class PinnedMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(p.exists() for p in (EV,BK,SRC)):
            raise unittest.SkipTest('Pinned inputs unavailable in this local authoring environment')
        cls.ev=mod.read_zip(EV);cls.bk=mod.read_zip(BK)
        cls.lock=mod.parse_json(cls.ev['HOLDOUT_LOCK_PUBLIC.json'])
        cls.v=mod.verify_vectors_and_metrics(cls.ev)
    def test_pins(self):
        self.assertEqual(mod.sha_file(EV),mod.EVAL_SHA)
        self.assertEqual(mod.sha_file(BK),mod.BACKEND_SHA)
        self.assertEqual(mod.sha_file(SRC),mod.SOURCE_SHA)
    def test_full_zip_manifest(self):
        self.assertEqual(mod.verify_manifest(self.ev),6)
        self.assertEqual(mod.verify_manifest(self.bk),27)
    def test_source_hashes(self):
        self.assertEqual(mod.check_source_zip(SRC,self.lock)['source_file_sha256_verified'],24)
    def test_all_metric_replay(self):
        self.assertTrue(self.v['all_metric_values_consistent'])
        self.assertEqual(self.v['metric_scopes_replayed'],20)
        self.assertEqual(self.v['detection_cells_replayed'],55)
    def test_errors_are_not_silently_relabelled(self):
        e=mod.file_based_diagnostic(self.v['vectors'],self.lock)
        self.assertEqual(e['error_count'],5)
        self.assertFalse(e['root_causes_proven'])
        self.assertFalse(any(x['human_gold'] for x in e['cases']))
    def test_runtime_provenance(self):
        r=mod.runtime_summary(self.bk)
        self.assertEqual(r['new_codeql_databases'],1)
        self.assertFalse(r['before_after_frozen_repo_gates_equal'] is False)
        self.assertEqual(r['model_only_xss_proven_paths'],0)
        self.assertEqual(sum(n['requests'] for n in r['model_arms_native'].values()),51)
    def test_public_private_lock_roundtrip_from_known_format(self):
        # The original B39B7 prepare tool wrote JSON in insertion order.
        # Restore only the omitted top-level reviewer using the lock's own unit metadata.
        reviewer=self.lock['units'][0]['reviewer']
        rebuilt={}
        for k,v in self.lock.items():
            rebuilt[k]=v
            if k=='scope':rebuilt['reviewer']=reviewer
        raw=(json.dumps(rebuilt,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')
        self.assertEqual(mod.sha_bytes(raw),mod.LOCK_SHA)
        with tempfile.TemporaryDirectory() as temp:
            ws=Path(temp)
            (ws/'HOLDOUT_LOCK.json').write_bytes(raw)
            link={'backend_result_zip':str(BK.resolve()),
                  'backend_result_sha256':mod.BACKEND_SHA,
                  'holdout_lock_sha256':mod.LOCK_SHA}
            (ws/'PREDICTION_RUN_LINK.json').write_text(json.dumps(link),encoding='utf-8')
            lock=mod.verify_archive_links(self.ev,self.bk,
                {'backend_path':BK.resolve()},ws,ws)
            self.assertEqual(lock,self.lock)

    def test_e1_equals_e2_holdout_only(self):
        self.assertEqual(self.v['vectors']['epoch_1'],self.v['vectors']['epoch_2'])
    def test_authoring_cannot_be_final_closeout(self):
        # The status of a metadata-only test run cannot equal full closeout.
        self.assertNotEqual('B39B8_METADATA_ONLY_AUTHORING_NOT_PRODUCTION_CLOSURE',mod.FINAL_STATUS)


class PrivateReconstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EV.exists():raise unittest.SkipTest('Pinned eval missing')
        cls.ev=mod.read_zip(EV)
        cls.lock=mod.parse_json(cls.ev['HOLDOUT_LOCK_PUBLIC.json'])
        cls.vectors=mod.parse_json(cls.ev['EVALUATION_VECTORS.json'])

    def create_fixture(self,base):
        root=base/'private';pm={}
        for arm in mod.ARMS:
            fs=[]
            for i,r in enumerate(self.vectors[arm]):
                li=['q:'+r['unit_id']] if r['qualified_paths'] else []
                raws=['p:'+r['unit_id']] if r['raw_policy_paths'] else []
                f={'id':'opengrep:'+str(i),'origin':'OPENGREP','retained':True,
                   'vulnerability_confirmed':False,'cwe':r['cwe'],'location':{'uri':r['uri']},
                   'score':{'final_score':r['score'],'ai_confidence_score':.5},
                   'original_opengrep':{'id':i,'same_across_arms':True},
                   'linked_codeql_flow_ids':li,'dataflow':[{'type':'source'}] if li else []}
                if arm=='opengrep_only':f['model_observation']=None
                elif r['cwe']=='79':
                    f['evidence_origin']='CODEQL_CONTEXTUAL_POLICY_ASSISTED'
                    f['raw_policy_flow_ids']=raws
                    if li:f['evidence_status']='POLICY_QUALIFIED_UNENCODED_HTML_PATH'
                else:
                    f['evidence_origin']='MODEL_DERIVED'
                    if li:
                        f['model_observation']={'status':'ACCEPTED','label':{'type':'sink'}}
                        f['evidence_status']='CODEQL_CWE_'+r['cwe']+'_QUALIFIED_PATH'
                fs.append(f)
            for leaf,content in [('result.json',{'arm':arm,'input_sha256':mod.SOURCE_SHA,'findings':fs}),
                                 ('report.sarif',{'version':'2.1.0','runs':[]})]:
                rel='analysis/'+arm+'/'+leaf;dest=root/rel;dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_text(json.dumps(content),encoding='utf-8');pm[rel]=mod.sha_file(dest)
        return root,pm

    def test_synthetic_private_exports_match_vectors(self):
        with tempfile.TemporaryDirectory() as t:
            private,pm=self.create_fixture(Path(t))
            r=mod.reconstruct(private,self.vectors,self.lock,pm,mod.SOURCE_SHA)
            self.assertEqual(r['exports_verified'],8)
            self.assertEqual(r['unit_rows_reconstructed'],96)

    def test_tamper_private_export_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            private,pm=self.create_fixture(Path(t))
            p=private/'analysis/epoch_1/result.json'
            p.write_text(p.read_text(encoding='utf-8')+' ',encoding='utf-8')
            with self.assertRaisesRegex(mod.Blocked,'PRIVATE_EXPORT_SHA'):
                mod.reconstruct(private,self.vectors,self.lock,pm,mod.SOURCE_SHA)

    def test_uncorroborated_qualifier_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            private,pm=self.create_fixture(Path(t))
            p=private/'analysis/epoch_1/result.json'
            obj=json.loads(p.read_text(encoding='utf-8'))
            match=next(x for x in obj['findings'] if x['cwe']!='79' and x['linked_codeql_flow_ids'])
            match['model_observation']={'status':'ABSTAIN','label':{'type':'sink'}}
            p.write_text(json.dumps(obj),encoding='utf-8')
            pm['analysis/epoch_1/result.json']=mod.sha_file(p)
            with self.assertRaisesRegex(mod.Blocked,'PATH_WITHOUT_ACCEPTED_MODEL_SINK'):
                mod.reconstruct(private,self.vectors,self.lock,pm,mod.SOURCE_SHA)

    def test_cwe79_policy_ai_neutral(self):
        with tempfile.TemporaryDirectory() as t:
            private,pm=self.create_fixture(Path(t))
            p=private/'analysis/base/result.json'
            obj=json.loads(p.read_text(encoding='utf-8'))
            match=next(x for x in obj['findings'] if x['cwe']=='79' and x['linked_codeql_flow_ids'])
            match['score']['ai_confidence_score']=.9
            p.write_text(json.dumps(obj),encoding='utf-8')
            pm['analysis/base/result.json']=mod.sha_file(p)
            with self.assertRaisesRegex(mod.Blocked,'XSS_POLICY_MUST_HAVE_NEUTRAL_AI'):
                mod.reconstruct(private,self.vectors,self.lock,pm,mod.SOURCE_SHA)

if __name__=='__main__':unittest.main(verbosity=2)
