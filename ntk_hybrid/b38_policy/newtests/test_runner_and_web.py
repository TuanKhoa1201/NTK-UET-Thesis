"""Mock CodeQL/model orchestration tests. The fixture AST proofs are from real javac.
These tests are NOT a claim of CodeQL or GPU execution in the authoring environment.
"""
from contextlib import ExitStack,redirect_stdout
from copy import deepcopy
import io,json,shutil,subprocess,sys,tempfile,threading,unittest,zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.request import urlopen,Request
from urllib.error import HTTPError
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from test_profiles_and_evidence import case
from bootstrap import ROOT
from ntk_b33.common import Blocker,COMMIT,write_json,sha_file
from ntk_b38.profiles import manual_labels,SINKS,RULE_IDS
import run_policy as runner
import web_policy

class MockPolicyRunnerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.t=tempfile.TemporaryDirectory();p=Path(cls.t.name);cl=p/'cl';cl.mkdir()
  subprocess.run(['javac','-proc:none','--release','21','-d',str(cl),str(ROOT/'trusted/NtkEncodingAudit.java')],capture_output=True,check=True)
  cls.ast={}
  for phase in ['C4','DPA']:
   spec=json.loads((ROOT/'POLICY_SAMPLES.json').read_text())[phase];src=p/phase;src.mkdir()
   with zipfile.ZipFile(ROOT/spec['archive']) as z:z.extractall(src)
   cls.ast[phase]=json.loads(subprocess.run(['java','--add-modules','jdk.compiler','-cp',str(cl),'NtkEncodingAudit',str(src)],capture_output=True,text=True,check=True).stdout)
 @classmethod
 def tearDownClass(cls):cls.t.cleanup()
 def simulate(self,phases=('C4',),fail_at=None,missing_model=False,wrong_context=False):
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);base=Path(td.name);work=base/'work';repo=base/'repo';downloads=base/'out'
  for p in [work,repo,downloads]:p.mkdir()
  py=work/'.ntk_v5_lora_venv/bin/python';py.parent.mkdir(parents=True);py.write_text('MOCK_INTERPRETER_ONLY')
  state={'head':COMMIT,'status_porcelain':'','mock':True};cur={'phase':None,'calls':[],'output':[],'commands':[]}
  templates=[]
  for c,rows in SINKS.items():
   for pkg,cls,sig,_ in rows:templates.append(case(c,pkg,cls,sig))
  def setup_calls(phase):
   calls=[]
   for r in self.ast[phase]['findings']:
    calls.append(dict(r['location'],package='java.io',**{'class':'OutputStream'},method='write',signature='void write(byte[] p0)',compiler_signature='write(byte[])',arity=1,cwe='89'))
   spec=json.loads((ROOT/'POLICY_SAMPLES.json').read_text())[phase]
   for c,vals in spec.get('model_expectations',{}).items():
    t=next(x for x in templates if x['cwe']==c)
    for uri in vals:calls.append(dict(t,uri=uri,start_line=10,start_column=1,end_line=10,end_column=50))
   return calls
  def scan(run,target,cwes,mlpy):
   cur['calls']=setup_calls(cur['phase']);cur['target']=target
   f=runner.fixture_for(json.loads((ROOT/'POLICY_SAMPLES.json').read_text())[cur['phase']]['sha256'])
   out=[]
   for c in cwes:
    for uri in f['scanner_expectations'][c]:
     call=next(x for x in cur['calls'] if x['uri']==uri)
     out.append({'cwe':c,'path':str(target/uri),'check_id':RULE_IDS[c],
      'start':{'line':call['start_line'],'col':call['start_column']},'end':{'line':call['end_line'],'col':call['end_column']},
      'extra':{'severity':'ERROR','metadata':{'cwe':['CWE-'+c]},'message':'MOCK SCANNER SIGNAL FOR ORCHESTRATION ONLY'}})
   return {'results':out}
  def extract(z,d):
   write_json(d/'FROZEN_BEFORE.json',state);write_json(d/'inputs/runtime_protocol.json',{'mock':True});return {'iris_host_python':str(py)}
  def snapshot(repo,d):
   (d/'src/queries').mkdir(parents=True);(d/'src/queries/codeql-pack.lock.yml').write_text('mock: true\n')
   p=d/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py';p.parent.mkdir(parents=True)
   shutil.copy2(ROOT/'tests/evidence37c/SCORER_FROZEN.py',p)
  def cmd(argv,log,**kwargs):
   args=list(map(str,argv));cur['commands'].append(args);log=Path(log);log.parent.mkdir(parents=True,exist_ok=True);log.write_text('MOCK TOOL EXECUTION NOT REAL CODEQL/GPU\n')
   if fail_at and fail_at in log.name:raise Blocker('MOCK_FAILURE_'+fail_at)
   if log.name=='ENCODING_COMPILER_RUN.log':
    a=deepcopy(self.ast[cur['phase']])
    if wrong_context:a['findings'][0]['assessment']='TEST_WRONG_ASSESSMENT'
    return json.dumps(a)
   if args[:2]==['javac','-version']:return 'javac 21.0.0 SIMULATED'
   if 'database' in args and 'create' in args:
    db=Path(args[args.index('create')+1]);(db/'db-java').mkdir(parents=True);(db/'src.zip').write_bytes(b'MOCK');(db/'codeql-database.yml').write_text('mock: true')
   if 'run-queries' in args:
    i=args.index('run-queries');b=Path(args[i+1])/'results'/Path(args[i+2]).with_suffix('.bqrs').name;b.parent.mkdir(parents=True,exist_ok=True);b.write_bytes(b'MOCK_BQRS')
   if 'interpret-results' in args:
    name=Path(args[args.index('interpret-results')+2]).stem
    p=Path(next(x.split('=',1)[1] for x in args if x.startswith('--output=')));write_json(p,{'runs':[{'results':[]}],'mock_query':name})
   if any(x.endswith('run_native37.py') for x in args) and '--import-only' not in args:
    cfg=json.loads(Path(args[-1]).read_text());o=Path(cfg['output_dir']);cases=cfg['cases'];trace=[]
    write_json(o/'SUMMARY.json',{'cold_live_responses':len(cases),'warm_exact_cache_hits':len(cases),'mock':True})
    for c in sorted({x['cwe'] for x in cases}):
     labels=[] if c=='79' or missing_model else manual_labels([x for x in cases if x['cwe']==c],c)
     write_json(o/'cold'/('cwe-'+c)/'llm_labelled_sink_apis.json',labels)
     for x in cases:
      if x['cwe']==c:trace.append({'phase':'cold','candidate':x,'status':'ACCEPTED','label':{'type':'none'}})
    (o/'native_trace.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in trace))
   return 'MOCK TOOL OUTPUT'
  def reads(path,target):return (deepcopy(templates),deepcopy(cur['calls']))
  def flows(sarif,target,calls,args,proof,sources,cwe,contexts):
   spec=runner.fixture_for(json.loads((ROOT/'POLICY_SAMPLES.json').read_text())[cur['phase']]['sha256']);name=sarif['mock_query']
   if name.startswith('Live') and (cwe=='79' or missing_model):return []
   result=[]
   for uri,r in spec['expectations'][cwe].items():
    if not r['expected_flow']:continue
    call=next(c for c in cur['calls'] if c['uri']==uri);loc={k:call[k] for k in ('uri','start_line','start_column','end_line','end_column')}
    result.append({'id':cwe+uri,'cwe':cwe,'location':loc,'callsite':call,'http_context_verified':cwe=='79','argument_index':0,
     'paths':[[dict(loc,start_line=1),loc]],'raw_result':{'ruleId':'MOCK_NOT_REAL_QUERY'}})
   return result
  def fusion(og,flows,trace,calls,target,scorer,cwe,dec):
   return [{'id':'mock:'+cwe+':'+str(i),'origin':'OPENGREP','cwe':cwe,'rule_id':'MOCK','location':{'uri':'MOCK.java','start_line':1},
    'score':{'final_score':60,'risk_level':'MEDIUM'},'dataflow':[],'source_policy':'MOCK','evidence_status':'MOCK','message':'MOCK MODEL FUSION'}
    for i,r in enumerate(og['results']) if r['cwe']==cwe]
  with ExitStack() as stack:
   for name,func in [('frozen_state',lambda x:deepcopy(state)),('extract_b33',extract),('snapshot_from_git',snapshot),
    ('apply',lambda *a:{'diff':'MOCK'}),('validate_local_assets',lambda *a:{arm:{'adapter_dir':'MOCK','adapter_sha256':'MOCK','adapter_config_sha256':'MOCK'} for arm in ['epoch_1','epoch_2']}),
    ('scan',scan),('command',cmd),('read_calls',reads),('read_arguments',lambda *a:[]),('parse_flows',flows),('calibrated_fusion',fusion),
    ('select_toolchain',lambda *a,**k:SimpleNamespace(executable='MOCK_CODEQL',database_options=[])),('local_pack_copy',lambda *a:{}),('verify_and_options',lambda *a,**k:([],{}))]:stack.enter_context(patch.object(runner,name,side_effect=func))
   stack.enter_context(patch('ntk_b38.processes.install_cleanup_handler'))
   for phase in phases:
    cur['phase']=phase
    with redirect_stdout(io.StringIO()):code=runner.main(['--phase',phase,'--work',str(work),'--repo',str(repo),'--downloads',str(downloads)])
    path=sorted((work/'batch38_policy_runs').glob('batch38'+phase.lower()+'*'))[-1];s=json.loads((path/'00_SUMMARY.json').read_text());cur['output'].append((code,s,path))
  return work,cur
 def test_mock_c4_then_d_policy_keeps_model_gate_closed(self):
  w,r=self.simulate(('C4','DPA'))
  self.assertEqual([x[0] for x in r['output']],[0,0],str([x[1].get('blocker') for x in r['output']]))
  self.assertFalse((w/'batch38_gates').exists())
  runner.require_gate(w,'C4','none',runner.implementation_sha());runner.require_gate(w,'DPA','epoch_1',runner.implementation_sha())
  d=r['output'][1][1];self.assertEqual(d['arms']['epoch_1']['cwes']['79']['model_only_flow_count'],0)
  self.assertEqual(d['arms']['epoch_1']['cwes']['79']['flow_count'],2)
  self.assertEqual(d['model_derived_xss_gate'],'NOT_GRANTED')
 def test_mock_d_cannot_bypass_c4(self):
  _,r=self.simulate(('DPA',));self.assertEqual(r['output'][0][0],2);self.assertIn('POLICY_GATE_MISSING',r['output'][0][1]['blocker'])
 def test_mock_model_failure_does_not_fallback_other_cwes(self):
  _,r=self.simulate(('C4','DPA'),missing_model=True);self.assertEqual(r['output'][-1][0],3)
 def test_mock_encoder_check_mismatch_does_not_grant_c4(self):
  w,r=self.simulate(wrong_context=True);self.assertEqual(r['output'][0][0],3);self.assertFalse((w/'batch38_policy_gates/C4.json').exists())
 def test_mock_ql_error_before_gpu(self):
  _,r=self.simulate(fail_at='COMPILE_ApiCalls');self.assertEqual(r['output'][0][0],2)
  self.assertFalse(any('run_native37.py' in x for args in r['commands'] for x in args))

class PolicyWebTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.w=Path(self.t.name)
  with patch.object(web_policy,'require_gate',return_value={}):self.app=web_policy.App(self.w,self.w,self.w,8766)
  self.server=web_policy.ThreadingHTTPServer(('127.0.0.1',0),web_policy.handler(self.app));self.app.port=self.server.server_address[1]
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def tearDown(self):self.server.shutdown();self.server.server_close();self.app.close();self.t.cleanup()
 def test_health_explicit_policy_origin(self):
  x=json.load(urlopen(f'http://127.0.0.1:{self.app.port}/api/health'))
  self.assertEqual(x['xss_evidence_origin'],'CODEQL_CONTEXTUAL_POLICY_ASSISTED');self.assertFalse(x['model_xss_gate_granted'])
 def test_new_web_assets_not_legacy_page(self):
  text=urlopen(f'http://127.0.0.1:{self.app.port}/').read().decode()
  self.assertIn('CODEQL_CONTEXTUAL_POLICY_ASSISTED',text);self.assertIn('D_POLICY_JAVA.zip',text)
 def test_no_legacy_gate_means_no_web_start(self):
  with patch.object(web_policy,'require_gate',side_effect=Blocker('not accepted')):
   with self.assertRaises(Blocker):web_policy.App(self.w,self.w,self.w,8766)
 def test_download_combined_sample_exact_hash(self):
  raw=urlopen(f'http://127.0.0.1:{self.app.port}/api/sample/DPA').read()
  self.assertEqual(raw,(ROOT/'samples/D_POLICY_JAVA.zip').read_bytes())
 def test_client_cannot_override_cwe_mix(self):
  with self.assertRaises(ValueError):self.app.submit(b'invalid','epoch_1','79')
 def test_host_rebinding_denied(self):
  req=Request(f'http://127.0.0.1:{self.app.port}/api/health',headers={'Host':'attacker.invalid'})
  with self.assertRaises(HTTPError) as e:urlopen(req)
  self.assertEqual(e.exception.code,403)

if __name__=='__main__':unittest.main()
