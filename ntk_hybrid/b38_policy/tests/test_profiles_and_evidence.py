import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bootstrap import ROOT,ENGINE
from ntk_b33.common import Blocker,IDENTITY,parameter_names,digest
from ntk_b34.core import load_scorer
from ntk_b38.profiles import (SINKS,SOURCE_POLICY,RULE_IDS,POLICY_SHA,select_candidates,
                             adjudicate,manual_labels)
from ntk_b38.core import (emit_flow,parse_flows,calibrated_fusion,to_sarif,read_calls)
from ntk_b38.scanner import canonical_rule,rules,validate
from run_batch38 import check_cases,fixture_for,implementation_sha,pack,require_gate,gate_path,verify_fixture_scanner

E=ROOT/'tests/evidence37c'
def j(name):return json.loads((E/name).read_text())
def case(cwe,pkg,cls,sig):
 from ntk_b34.core import split_types
 method,rest=sig.split('(',1);types=split_types(rest[:-1])
 return {'package':pkg,'class':cls,'method':method,'compiler_signature':sig,'cwe':cwe,
  'signature':'void '+method+'('+', '.join(t+' p'+str(i) for i,t in enumerate(types))+')',
  'arity':len(types),'is_static':cls=='Files','receiver_policy':'HOLD_THIS_UNTIL_SEMANTIC_REVIEW',
  'source_record_sha256':'unit'}
def label(c,*args):return {**{k:c[k] for k in IDENTITY},'type':'sink','sink_args':list(args)}

class ProfileTests(unittest.TestCase):
 def test_all_cwe_allowlists_exact_arguments(self):
  for cwe,rows in SINKS.items():
   for pkg,cls,sig,n in rows:
    with self.subTest(cwe=cwe,sig=sig):
     c=case(cwe,pkg,cls,sig);l=label(c,'p'+str(n))
     eligible,dec=adjudicate([c],[l],cwe)
     self.assertEqual(eligible,[l]);self.assertEqual(dec[0]['decision'],'ELIGIBLE_EXACT_CWE_ARGUMENT')
 def test_runtime_environment_is_not_command_sink(self):
  c=case('78','java.lang','Runtime','exec(java.lang.String,java.lang.String[])')
  eligible,dec=adjudicate([c],[label(c,'p1')],'78');self.assertFalse(eligible)
  self.assertEqual(dec[0]['decision'],'WITHHELD_UNKNOWN_OR_IRRELEVANT_ARGUMENT')
 def test_setstring_value_is_not_sql_grammar(self):
  c=case('89','java.sql','PreparedStatement','setString(int,java.lang.String)')
  eligible,dec=adjudicate([c],[label(c,'p1')],'89');self.assertFalse(eligible)
  self.assertEqual(dec[0]['decision'],'WITHHELD_BOUND_VALUE_NOT_SQL_GRAMMAR')
 def test_dynamic_prepare_is_not_blanket_excluded(self):
  c=case('89','java.sql','Connection','prepareStatement(java.lang.String)')
  self.assertEqual(adjudicate([c],[label(c,'p0')],'89')[0],[label(c,'p0')])
 def test_offset_and_count_not_xss_sinks(self):
  c=case('79','java.io','OutputStream','write(byte[],int,int)')
  self.assertFalse(adjudicate([c],[label(c,'p1','p2')],'79')[0])
 def test_receiver_not_silently_guessed(self):
  c=case('78','java.lang','ProcessBuilder','start()')
  with self.assertRaises(Blocker):adjudicate([c],[label(c,'this')],'78')
 def test_wrong_owner_fails_semantics(self):
  c=case('22','evil','Files','readAllBytes(java.nio.file.Path)')
  self.assertFalse(adjudicate([c],[label(c,'p0')],'22')[0])
 def test_cross_cwe_label_rejected(self):
  c=case('22','java.nio.file','Files','readString(java.nio.file.Path)')
  with self.assertRaises(Blocker):adjudicate([c],[label(c,'p0')],'89')
 def test_duplicate_label_rejected(self):
  c=case('22','java.nio.file','Files','readString(java.nio.file.Path)');l=label(c,'p0')
  with self.assertRaises(Blocker):adjudicate([c],[l,l],'22')
 def test_invalid_index_rejected(self):
  c=case('22','java.nio.file','Files','readString(java.nio.file.Path)')
  with self.assertRaises(Blocker):adjudicate([c],[label(c,'p2')],'22')
 def test_empty_list_is_not_none(self):
  c=case('22','java.nio.file','Files','readString(java.nio.file.Path)')
  with self.assertRaises(Blocker):adjudicate([c],[label(c)],'22')
 def test_raw_labels_immutable(self):
  c=case('78','java.lang','Runtime','exec(java.lang.String,java.lang.String[])');l=label(c,'p0','p1');saved=copy.deepcopy(l)
  eligible,dec=adjudicate([c],[l],'78');self.assertEqual(l,saved);self.assertEqual(eligible[0]['sink_args'],['p0'])
 def test_candidate_cwe_and_provenance_separate(self):
  c=case('89','java.lang','System','getenv(java.lang.String)');saved=copy.deepcopy(c)
  a=select_candidates([c],'22');b=select_candidates([c],'78')
  self.assertEqual(c,saved);self.assertNotEqual(a[0]['source_record_sha256'],b[0]['source_record_sha256'])
 def test_unknown_method_not_auto_added(self):
  c=case('22','java.nio.file','Files','imaginary(java.nio.file.Path)')
  self.assertEqual(select_candidates([c],'22'),[])
 def test_manual_is_diagnostic_only(self):
  c=case('22','java.nio.file','Files','readString(java.nio.file.Path)')
  q,proof=emit_flow((ROOT/'queries/Flow.template').read_text(),[c],manual_labels([c],'22'),'22','epoch_1','diagnostic')
  self.assertIn('diagnostic-epoch-1',q)
  self.assertEqual(proof[0]['label_origin'],'MANUAL_DIAGNOSTIC_ONLY_NOT_LLM')
 def test_empty_sinks_remain_empty(self):
  q,p=emit_flow((ROOT/'queries/Flow.template').read_text(),[],[],'79','epoch_1')
  self.assertIn('1 = 0',q);self.assertFalse(p);self.assertNotIn('__',q)
 def test_generated_ql_exact_owner_and_profile(self):
  for cwe,rows in SINKS.items():
   pkg,cls,sig,n=rows[0];c=case(cwe,pkg,cls,sig)
   q,p=emit_flow((ROOT/'queries/Flow.template').read_text(),[c],[label(c,'p'+str(n))],cwe,'epoch_1')
   self.assertIn('ntkSinkContext(call, "'+cwe+'")',q);self.assertIn(sig,q);self.assertNotIn('__',q)
 def test_no_old_fixture_names_in_new_queries(self):
  for p in (ROOT/'queries').iterdir():
   if p.is_file():
    text=p.read_text()
    for bad in ('Case01','UnsafeStatement','RiskyRelativeRead','ntk.b34'):self.assertNotIn(bad,text)
 def test_http_context_not_generic_string_sink(self):
  q=(ROOT/'queries/NtkScope.qll').read_text()
  for required in ('getRequestURI()','getResponseBody()','sendResponseHeaders(int,long)','content-type','text/html','ntkSameHttpExchange'):
   self.assertIn(required,q)
  self.assertFalse(any(x[1]=='String' for x in SINKS['79']))
 def test_zero_sources_is_not_safe(self):
  self.assertTrue(all('LLM' in p for p in SOURCE_POLICY.values()))

class ScannerTests(unittest.TestCase):
 def test_namespaced_ids(self):
  for c,r in RULE_IDS.items():self.assertEqual(canonical_rule('tmp.abc.'+r,list(RULE_IDS)),(c,r))
 def test_deceptive_rule_ids(self):
  for bad in ('something','ntk-b34-java-sql-call-review-evil','../../x:no'):
   with self.assertRaises(Blocker):canonical_rule(bad,list(RULE_IDS))
 def test_unselected_cwe_rejected(self):
  with self.assertRaises(Blocker):canonical_rule(RULE_IDS['79'],['22'])
 def test_sql_pattern_invariant(self):
  obj=rules(['89'])['rules'][0]
  self.assertEqual(obj['pattern-either'],[{'pattern':s} for s in ('$S.executeQuery($SQL)','$S.execute($SQL)','$C.prepareStatement($SQL)')])
 def test_multi_rules_distinct_cwes(self):
  obj=rules(['22','78','79','89'])['rules']
  self.assertEqual(len(set(r['id'] for r in obj)),4)
  self.assertEqual([r['metadata']['cwe'] for r in obj],[['CWE-'+c] for c in ('22','78','79','89')])
 def test_empty_real_result_valid(self):
  with tempfile.TemporaryDirectory() as d:self.assertEqual(validate({'results':[]},Path(d),['22']),{'results':[]})
 def test_errors_fail_closed(self):
  with self.assertRaises(Blocker):validate({'results':[],'errors':['parse error']},Path('/tmp'),['22'])
 def test_metadata_mismatch(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'A.java';p.write_text('class A {}')
   r={'check_id':RULE_IDS['22'],'path':str(p),'start':{'line':1,'col':1},'end':{'line':1,'col':10},'extra':{'metadata':{'cwe':['CWE-89']}}}
   with self.assertRaises(Blocker):validate({'results':[r]},Path(d),['22'])
 def test_outside_file_rejected(self):
  r={'check_id':RULE_IDS['22'],'path':'/etc/passwd'}
  with self.assertRaises(Blocker):validate({'results':[r]},Path('/tmp/a'),['22'])

class SQLReplayTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.target=Path(self.tmp.name)
  self.cases=j('CANDIDATES_FROM_NEW_CODEQL_DB.json');self.calls=j('CALLS_FROM_NEW_CODEQL_DB.json')
  self.flows=j('analysis/epoch_1/CODEQL_VERIFIED_PATHS.json');self.og=j('OPENGREP_CANONICAL_DERIVED.json')
  for r in self.og['results']:
   matches=[c['uri'] for c in self.calls if r['path'].endswith(c['uri'])]
   uri=sorted(set(matches))[0];r['path']=str(self.target/uri);r['cwe']='89'
   (self.target/uri).parent.mkdir(parents=True,exist_ok=True);(self.target/uri).write_text('// Source withheld; replay locations only.\n')
  self.trace=[json.loads(x) for x in (E/'live/epoch_1/native_trace.jsonl').read_text().splitlines()]
  self.scorer=load_scorer(E/'SCORER_FROZEN.py')
  self.labels=j('analysis/epoch_1/RAW_STAGE3_SINK_LABELS.json')
 def tearDown(self):self.tmp.cleanup()
 def test_saved_evidence_hashes(self):
  for p,h in j('REFERENCE_MANIFEST.json')['files'].items():self.assertEqual(hashlib.sha256((E/p).read_bytes()).hexdigest(),h)
 def test_sql_scores_unchanged_on_real_37c_replay(self):
  eligible,dec=adjudicate(self.cases,self.labels,'89')
  rows=calibrated_fusion(self.og,self.flows,self.trace,self.calls,self.target,self.scorer,'89',dec)
  old=j('analysis/epoch_1/FUSED_FINDINGS.json')
  self.assertEqual(len(rows),4)
  self.assertEqual({r['location']['uri']:r['score']['final_score'] for r in rows},
                   {r['location']['uri']:r['score']['final_score'] for r in old})
  self.assertTrue(all(r['retained'] for r in rows));self.assertEqual(len(eligible),3)
 def test_no_flow_never_upgrades_api_alone(self):
  _,dec=adjudicate(self.cases,self.labels,'89')
  rows=calibrated_fusion(self.og,[],self.trace,self.calls,self.target,self.scorer,'89',dec)
  self.assertEqual(len(rows),4)
  self.assertTrue(all(r['score']['final_score']==60 for r in rows))
  self.assertTrue(all(r['evidence_status']=='REVIEW_ONLY' for r in rows))
 def test_flow_without_live_accepted_label_rejected(self):
  _,dec=adjudicate(self.cases,self.labels,'89')
  with self.assertRaises(Blocker):calibrated_fusion(self.og,self.flows,[],self.calls,self.target,self.scorer,'89',dec)
 def test_flow_without_semantic_acceptance_rejected(self):
  with self.assertRaises(Blocker):calibrated_fusion(self.og,self.flows,self.trace,self.calls,self.target,self.scorer,'89',[])
 def test_parse_real_paths_uses_current_source_inventory(self):
  _,proof=emit_flow((ROOT/'queries/Flow.template').read_text(),self.cases,adjudicate(self.cases,self.labels,'89')[0],'89','epoch_1')
  sarif=j('analysis/epoch_1/codeql.sarif')
  flows=parse_flows(sarif,self.target,self.calls,j('ARGUMENTS_FROM_NEW_CODEQL_DB.json'),proof,j('CODEQL_DISCOVERED_SOURCE_CALLS.json')['callsites'],'89')
  self.assertEqual(len(flows),2)
 def test_fabricated_or_absent_source_rejected(self):
  _,proof=emit_flow((ROOT/'queries/Flow.template').read_text(),self.cases,adjudicate(self.cases,self.labels,'89')[0],'89','epoch_1')
  with self.assertRaises(Blocker):parse_flows(j('analysis/epoch_1/codeql.sarif'),self.target,self.calls,j('ARGUMENTS_FROM_NEW_CODEQL_DB.json'),proof,[],'89')
 def test_sarif_cwe_is_not_always_89(self):
  _,dec=adjudicate(self.cases,self.labels,'89')
  rows=calibrated_fusion(self.og,self.flows,self.trace,self.calls,self.target,self.scorer,'89',dec)
  for c,row in zip(['22','78','79','89'],rows):row['cwe']=c
  obj=to_sarif(rows)
  self.assertEqual([r['properties']['cwe'] for r in obj['runs'][0]['results']],['CWE-22','CWE-78','CWE-79','CWE-89'])

class GateTests(unittest.TestCase):
 def test_sample_manifest_hashes(self):
  manifest=json.loads((ROOT/'samples/MANIFEST.json').read_text())
  import zipfile
  for name,v in manifest.items():
   self.assertEqual(hashlib.sha256((ROOT/'samples'/name).read_bytes()).hexdigest(),v['archive_sha256'])
   with zipfile.ZipFile(ROOT/'samples'/name) as z:
    self.assertEqual({n:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()},v['files'])
   self.assertEqual(fixture_for(v['archive_sha256']),v)
 def test_missing_scanner_signal_blocks_known_fixture(self):
  fixture={'expectations':{'22':{'a.java':{'expected_flow':True}}}}
  with self.assertRaises(Blocker):verify_fixture_scanner({'results':[]},fixture,Path('/tmp'),['22'])
 def test_scanner_fixture_control_must_also_be_covered(self):
  fixture={'expectations':{'22':{'a.java':{'expected_flow':True},'b.java':{'expected_flow':False}}}}
  rows={'results':[{'cwe':'22','path':'a.java'}]}
  with self.assertRaises(Blocker):verify_fixture_scanner(rows,fixture,Path('/tmp'),['22'])
 def test_unknown_input_not_a_fixture(self):self.assertIsNone(fixture_for('f'*64))
 def test_expected_control_false_does_not_mean_remove_finding(self):
  report=check_cases([],{'control.java':{'expected_flow':False}});self.assertTrue(report['match'])
  self.assertEqual(report['unit'],'FILE_PRESENCE_OF_CWE_QUALIFIED_PATH_NOT_RAW_FINDING_COUNT')
 def test_unexpected_path_fails_fixture(self):
  report=check_cases([{'location':{'uri':'extra.java'}}],{'control.java':{'expected_flow':False}});self.assertFalse(report['match'])
 def test_missing_gate_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(Blocker):require_gate(Path(d),'A','epoch_1','test')
 def test_manifest_gate_tamper_and_diagnostic_rejected(self):
  from ntk_b33.common import write_json,sha_file
  with tempfile.TemporaryDirectory() as d:
   w=Path(d);r=w/'run';r.mkdir();downloads=w/'downloads';downloads.mkdir()
   s={'status':'B38_SCOPED_DEMO_COMPLETE','phase':'A','arms':{'epoch_1':{}},'frozen_unchanged':True,'diagnostic_only':False}
   write_json(r/'00_SUMMARY.json',s);(r/'value.txt').write_text('real evidence placeholder for UNIT TEST')
   _,m=pack(r,downloads,s)
   g={'summary_path':str(r/'00_SUMMARY.json'),'summary_sha256':sha_file(r/'00_SUMMARY.json'),
      'manifest_path':str(m),'manifest_sha256':sha_file(m),'implementation_sha256':'test'}
   write_json(gate_path(w,'A','epoch_1'),g)
   self.assertEqual(require_gate(w,'A','epoch_1','test'),g)
   (r/'value.txt').write_text('tampered')
   with self.assertRaises(Blocker):require_gate(w,'A','epoch_1','test')
 def test_code_fingerprint_is_deterministic(self):self.assertEqual(implementation_sha(),implementation_sha())
 def test_pack_excludes_binary_cache_and_uploaded_source(self):
  import zipfile
  with tempfile.TemporaryDirectory() as d:
   w=Path(d);r=w/'run';r.mkdir();o=w/'outputs';o.mkdir()
   for p in ('opengrep/.cache/lib.so','uploaded_project/Test.java','cache/key.json','normal.json'):
    f=r/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('test')
   out,_=pack(r,o,{})
   with zipfile.ZipFile(out) as z:
    self.assertIn('normal.json',z.namelist());self.assertNotIn('uploaded_project/Test.java',z.namelist())
    self.assertNotIn('opengrep/.cache/lib.so',z.namelist());self.assertNotIn('cache/key.json',z.namelist())

if __name__=='__main__':unittest.main()
