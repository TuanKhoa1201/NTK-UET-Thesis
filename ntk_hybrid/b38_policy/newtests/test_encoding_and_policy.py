"""Real javac AST tests plus replay of archived CodeQL evidence, NOT new CodeQL/GPU."""
from pathlib import Path
from copy import deepcopy
import hashlib,json,subprocess,sys,tempfile,unittest,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bootstrap import ROOT
from c4.policy import *
from c4.gates import require_gate,issue_gate,gate_path
from ntk_b34.core import load_scorer
from ntk_b38.core import read_calls,parse_flows
from ntk_b38.profiles import manual_labels
import run_policy

class CompilerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.work=Path(cls.tmp.name);cls.classes=cls.work/'classes';cls.classes.mkdir()
  subprocess.run(['javac','-proc:none','--release','21','-d',str(cls.classes),str(ROOT/'trusted/NtkEncodingAudit.java')],check=True,capture_output=True)
  cls.source=cls.work/'input';cls.source.mkdir()
  with zipfile.ZipFile(ROOT/'samples/C4_CONTEXT_JAVA.zip') as z:z.extractall(cls.source)
  cls.base=cls.source/'src/edu/ntk/context/EncodedBody.java'
  cls.original=cls.base.read_text()
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def run_ast(self,root):
  p=subprocess.run(['java','--add-modules','jdk.compiler','-cp',str(self.classes),'NtkEncodingAudit',str(root)],check=True,capture_output=True,text=True)
  return json.loads(p.stdout)
 def mutate(self,old,new,name='EncodedBody.java'):
  p=self.source/'src/edu/ntk/context'/name;s=p.read_text()
  self.assertIn(old,s)
  try:
   p.write_text(s.replace(old,new));out=self.run_ast(self.source)
   return next(x for x in out['findings'] if x['location']['uri'].endswith('/'+name))
  finally:p.write_text(s)
 def test_real_12_compiler_classifications(self):
  actual=self.run_ast(self.source);exp=json.loads((ROOT/'POLICY_SAMPLES.json').read_text())['C4']
  self.assertEqual(actual['source_hashes'],exp['java_hashes'])
  self.assertEqual(len(actual['findings']),12)
  for r in actual['findings']:self.assertEqual(r['assessment'],exp['expectations79'][r['location']['uri']]['ast_assessment'])
 def test_helper_renaming_does_not_change_proof(self):
  self.assertEqual(self.mutate('encode','unrelatedLabel')['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_encoded_then_append_raw_not_protected(self):
  self.assertNotEqual(self.mutate('encode(input) + "</p>"','encode(input) + input + "</p>"')['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_byte_array_mutation_not_protected(self):
  r=self.mutate('exchange.sendResponseHeaders(200, bytes.length);','exchange.sendResponseHeaders(200, bytes.length);\n    bytes[0] = 60;')
  self.assertNotEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_byte_array_escape_to_mutator_not_protected(self):
  r=self.mutate('exchange.sendResponseHeaders(200, bytes.length);','exchange.sendResponseHeaders(200, bytes.length);\n    java.util.Arrays.fill(bytes, (byte)60);')
  self.assertNotEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_reassignment_not_protected(self):
  r=self.mutate('byte[] bytes = html.getBytes(StandardCharsets.UTF_8);','html = input;\n    byte[] bytes = html.getBytes(StandardCharsets.UTF_8);')
  self.assertNotEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_wrong_ampersand_order_not_certified(self):
  r=self.mutate('replace("&", "&amp;").replace("<", "&lt;")','replace("<", "&lt;").replace("&", "&amp;")')
  self.assertNotEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_decode_after_encode_not_protected(self):
  r=self.mutate('encode(input) + "</p>"','encode(input).replace("&lt;", "<") + "</p>"')
  self.assertNotEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_script_is_not_html_text(self):
  self.assertEqual(self.mutate('"<p>" + encode(input) + "</p>"','"<script>" + encode(input) + "</script>"')['assessment'],'REVIEW_REQUIRED_OUTPUT_CONTEXT')
 def test_unquoted_attribute_not_certified(self):
  r=self.mutate('"<p>" + encode(input) + "</p>"','"<div title=" + encode(input) + ">x</div>"')
  self.assertNotEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_conditional_header_or_write_not_certified(self):
  r=self.mutate('exchange.getResponseBody().write(bytes);','if (input != null) exchange.getResponseBody().write(bytes);')
  self.assertEqual(r['assessment'],'REVIEW_REQUIRED_CONTROL_FLOW')
 def test_misleading_name_single_identity_return_not_protected(self):
  r=self.mutate('return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\\"", "&quot;").replace("\'", "&#39;");','return value;')
  self.assertEqual(r['assessment'],'REVIEW_REQUIRED_ENCODER')
 def test_same_encoder_sufficient_for_single_quoted_attribute(self):
  r=self.mutate('"<p>" + encode(input) + "</p>"','"<div title=\'" + encode(input) + "\'>x</div>"')
  self.assertEqual(r['assessment'],'ENCODING_VERIFIED_SCOPED')
 def test_missing_quote_not_certified_for_attribute(self):
  r=self.mutate('.replace("\\\"", "&quot;")','',name='EncodedAttribute.java')
  self.assertEqual(r['assessment'],'REVIEW_REQUIRED_ENCODER')
 def test_compile_combined_24_files(self):
  target=self.work/'combined';target.mkdir(exist_ok=True)
  with zipfile.ZipFile(ROOT/'samples/D_POLICY_JAVA.zip') as z:z.extractall(target)
  p=subprocess.run(['javac','-proc:none','--release','21','-d',str(self.work/'combined-classes'),*map(str,sorted(target.rglob('*.java')))],capture_output=True)
  self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(len(list(target.rglob('*.java'))),24)
 def test_actual_c3_escape_challenge_replay_proof(self):
  target=self.work/'oldC3';target.mkdir(exist_ok=True)
  with zipfile.ZipFile(ROOT/'evidence_c3/C3_HTTP_CONTEXT_PROJECT.zip') as z:z.extractall(target)
  actual=self.run_ast(target)
  proof=bind_ast(actual,json.loads((ROOT/'evidence_c3/ALL_CALLS.json').read_text()),actual['source_hashes'])
  flows=tag_paths(json.loads((ROOT/'evidence_c3/diagnostic/cwe-79/PATHS.json').read_text()),'79')
  qual,assessment=assess_paths(flows,proof)
  escaped=next(x for x in assessment if 'ChallengeEscapedHtml' in x['callsite']['uri'])
  self.assertEqual(escaped['status'],'ENCODING_VERIFIED_SCOPED_REVIEW_RETAINED')
  self.assertEqual(len(flows),4);self.assertGreaterEqual(len(qual),2)
  # Rebase old scanner paths only for replay; never claim these are new scans.
  og=json.loads((ROOT/'evidence_c3/opengrep/canonical_derived.json').read_text())
  oldroot=json.loads((ROOT/'evidence_c3/UPLOADED_INPUT_PROVENANCE.json').read_text()).get('source_root')
  for r in og['results']:
   suffix=next(p for p in actual['source_hashes'] if str(r['path']).endswith(p));r['path']=str(target/suffix)
  scorer=load_scorer(ROOT/'evidence_c3/SCORER_FROZEN.py')
  out=policy_fusion(og,flows,qual,assessment,proof,json.loads((ROOT/'evidence_c3/ALL_CALLS.json').read_text()),target,scorer,[])
  self.assertEqual(sum(x['origin']=='OPENGREP' for x in out),len(og['results']))
  self.assertTrue(all(x['score']['ai_confidence_score']==0.5 for x in out))
  self.assertTrue(all(x['retained'] for x in out))
  self.assertTrue(all(not x['vulnerability_confirmed'] for x in out))
  self.assertTrue(any(x['raw_policy_flow_ids'] and not x['dataflow'] for x in out))
  with (self.work/'replay.json').open('w') as f:json.dump(out,f)

class ContractTests(unittest.TestCase):
 def test_java_wrapper_strips_ambient_agents_and_options(self):
  import os
  env=dict(os.environ,JAVA_TOOL_OPTIONS='-NTKInvalidOption',_JAVA_OPTIONS='-NTKInvalidOption',JDK_JAVA_OPTIONS='-NTKInvalidOption',CLASSPATH='/nonexistent/ambient')
  p=subprocess.run([sys.executable,'-B',str(ROOT/'java_clean.py'),'java','-version'],env=env,capture_output=True,text=True)
  self.assertEqual(p.returncode,0,p.stderr);self.assertNotIn('Picked up',p.stderr)
 def test_java_wrapper_rejects_non_java_commands(self):
  p=subprocess.run([sys.executable,'-B',str(ROOT/'java_clean.py'),'sh','-c','exit 0'],capture_output=True,text=True)
  self.assertNotEqual(p.returncode,0)

 def test_metadata_scoped_without_changing_original(self):
  a=[{'cwe':'89','method':'write'}];b=tagged(a,'79');self.assertEqual(a[0]['cwe'],'89');self.assertEqual(b[0]['cwe'],'79');self.assertNotIn('cwe',tagged(a)[0])
 def test_fake_or_wrong_javac_input_rejected(self):
  with self.assertRaises(Blocker):bind_ast({'schema':'NTK_C4_JAVAC_ENCODING_PROOF_V1','source_application_executed':False,'source_hashes':{}},[],{'a.java':'hash'})
 def test_model_gate_different_path(self):
  self.assertNotIn('batch38_gates',str(gate_path(Path('/tmp/x'),'DPA','epoch_1')))
 def test_fixture_cross_cwe_extra_flow_fails(self):
  f=run_policy.fixture_for(json.loads((ROOT/'POLICY_SAMPLES.json').read_text())['DPA']['sha256'])
  exp=f['expectations']['89'];self.assertEqual(len(exp),24)
  raw=[{'location':{'uri':p}} for p,v in exp.items() if v['expected_flow']]
  self.assertTrue(run_policy.check_cases(raw,exp)['match'])
  raw.append({'location':{'uri':'src/edu/ntk/context/HtmlBody.java'}})
  self.assertFalse(run_policy.check_cases(raw,exp)['match'])
 def test_wrong_gate_kind_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   w=Path(t);p=gate_path(w,'C4','none');write_json(p,{'kind':'MODEL_DERIVED','summary_path':'none','manifest_path':'none','implementation_sha256':'x'})
   with self.assertRaises(Blocker):require_gate(w,'C4','none','x')
 def test_receipt_verifies_artifact_not_just_status(self):
  with tempfile.TemporaryDirectory() as t:
   w=Path(t);run=w/'run';run.mkdir();s={'phase':'C4','status':'B38_C4_POLICY_SCOPED_COMPLETE','frozen_unchanged':True,'model_derived_xss_gate':'NOT_GRANTED','old_gate_D':'UNCHANGED_NOT_GRANTED'}
   write_json(run/'00_SUMMARY.json',s);(run/'e.txt').write_text('original')
   m=run/'OUTPUT_MANIFEST.json';write_json(m,{'00_SUMMARY.json':sha_file(run/'00_SUMMARY.json'),'e.txt':sha_file(run/'e.txt')})
   issue_gate(w,'C4','none','impl',run,m);require_gate(w,'C4','none','impl')
   (run/'e.txt').write_text('tampered')
   with self.assertRaises(Blocker):require_gate(w,'C4','none','impl')
 def test_policy_never_requires_manufactured_ai_sink(self):
  self.assertEqual(POLICY['model_xss_gate'],'NOT_GRANTED')
 def test_query_logic_unchanged_from_b38r1(self):
  p=json.loads((ROOT/'BASELINE_PROVENANCE.json').read_text())['files']
  for n in ['queries/Flow.template','queries/NtkScope.qll','queries/ApiCalls.ql','queries/ArgumentSpans.ql','queries/Source.template']:
   self.assertEqual(sha_file(ROOT/n),p[n])
 def test_original_engine_unchanged(self):
  p=json.loads((ROOT/'BASELINE_PROVENANCE.json').read_text())['files']
  for n,h in p.items():
   if n.startswith('engine/') and not n.endswith('.pyc'):self.assertEqual(sha_file(ROOT/n),h)

if __name__=='__main__':unittest.main()
