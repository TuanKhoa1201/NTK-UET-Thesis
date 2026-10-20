"""Control-flow tests with FAKE tool processes, not CodeQL/GPU execution proofs."""
from contextlib import ExitStack,redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bootstrap import ROOT
import run_batch38 as runner
from ntk_b33.common import COMMIT,IDENTITY,Blocker,write_json
from ntk_b38.profiles import SINKS,manual_labels
from test_profiles_and_evidence import case


class MockRunnerTests(unittest.TestCase):
 def simulate(self,phases=('A',),fail_at=None,missing_live=False,diagnostic=False):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
  w=Path(tmp.name);work=w/'work';work.mkdir();downloads=w/'downloads';downloads.mkdir();repo=w/'repo';repo.mkdir()
  ml=work/'.ntk_v5_lora_venv/bin/python';ml.parent.mkdir(parents=True);ml.write_text('FAKE INTERPRETER PATH FOR UNIT TEST ONLY')
  state={'head':COMMIT,'status_porcelain':'','mock':True};current={'run':None,'phase':None,'output':[],'events':[]}
  templates=[]
  for c,rows in SINKS.items():
   for pkg,cls,sig,_ in rows:templates.append(case(c,pkg,cls,sig))
  def fake_extract(z,d):
   write_json(d/'FROZEN_BEFORE.json',state);write_json(d/'inputs/runtime_protocol.json',{'mock':True});return {'iris_host_python':str(ml)}
  def fake_snapshot(repo,d):
   (d/'src/queries').mkdir(parents=True);(d/'src/queries/codeql-pack.lock.yml').write_text('mock: true\n')
   p=d/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py';p.parent.mkdir(parents=True)
   shutil.copy2(ROOT/'tests/evidence37c/SCORER_FROZEN.py',p)
  def fake_assets(*a):return {arm:{'arm':arm,'generation':{'seed':1},'adapter_dir':'MOCK','adapter_sha256':'MOCK','adapter_config_sha256':'MOCK'} for arm in ('epoch_1','epoch_2')}
  def fake_calls(path,target):
   return (deepcopy(templates),[]) if path.name=='ApiCalls.csv' else ([],[])
  def fake_scan(run,target,cwes,mlpy):
   current['run']=run
   fixture=json.loads((ROOT/'samples/MANIFEST.json').read_text())['B38'+current['phase']+'_JAVA.zip']
   return {'results':[{'cwe':c,'path':str(target/p)} for c in cwes for p in fixture['scanner_expectations'][c]]}
  def fake_command(argv,log,**kwargs):
   args=list(map(str,argv));current['events'].append(args);log=Path(log);log.parent.mkdir(parents=True,exist_ok=True)
   log.write_text('SIMULATED_TOOL_PROCESS_NOT_CODEQL_OR_GPU\n')
   if fail_at and fail_at in log.name:raise Blocker('SIMULATED_FAILURE_'+fail_at)
   if args[:2]==['javac','-version']:return 'javac 21.0.0 (SIMULATED)'
   if 'database' in args and 'create' in args:
    db=Path(args[args.index('create')+1]);(db/'db-java').mkdir(parents=True)
    (db/'src.zip').write_bytes(b'MOCK_SOURCE_ARCHIVE');(db/'codeql-database.yml').write_text('mock: true\n')
   if 'run-queries' in args:
    i=args.index('run-queries');db=Path(args[i+1]);q=Path(args[i+2]);b=db/'results'/q.with_suffix('.bqrs').name
    b.parent.mkdir(parents=True,exist_ok=True);b.write_bytes(b'UNIT_TEST_FAKE_BQRS')
   if 'interpret-results' in args:
    name=Path(args[args.index('interpret-results')+2]).stem
    p=Path(next(x.split('=',1)[1] for x in args if x.startswith('--output=')))
    write_json(p,{'runs':[{'results':[]}],'MOCK_QUERY_NAME':name})
   if any(x.endswith('run_native37.py') for x in args) and '--import-only' not in args:
    cfg=json.loads(Path(args[-1]).read_text());o=Path(cfg['output_dir']);cases=cfg['cases']
    write_json(o/'SUMMARY.json',{'cold_live_responses':len(cases),'warm_exact_cache_hits':len(cases),'mock':True})
    trace=[]
    for c in sorted({r['cwe'] for r in cases}):
     ls=manual_labels([r for r in cases if r['cwe']==c],c)
     if missing_live:ls=[]
     write_json(o/'cold'/('cwe-'+c)/'llm_labelled_sink_apis.json',ls)
     for x in cases:
      if x['cwe']==c:trace.append({'phase':'cold','candidate':x,'status':'ACCEPTED','label':ls[0] if ls else {'type':'none'}})
    (o/'native_trace.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in trace))
   return 'SIMULATED_TOOL_OUTPUT'
  def fake_paths(sarif,target,calls,args,proof,sources,cwe,contexts):
   name=sarif['MOCK_QUERY_NAME'];exp=json.loads((ROOT/'samples/MANIFEST.json').read_text())
   f=exp['B38'+current['phase']+'_JAVA.zip']['expectations'][cwe]
   return [{'location':{'uri':p},'MOCK':True} for p,r in f.items() if r['expected_flow'] and (not missing_live or name.startswith('Diagnostic'))]
  def fake_fusion(og,flows,trace,calls,target,scorer,cwe,dec):
   return [{'id':'mock'+cwe+str(i),'origin':'OPENGREP','cwe':cwe,'rule_id':'MOCK','location':{'uri':'TEST.java','start_line':1},
     'score':{'final_score':60,'risk_level':'MEDIUM'},'dataflow':[],'source_policy':'MOCK','evidence_status':'MOCK','message':'UNIT TEST ONLY'} for i,row in enumerate(og['results']) if row['cwe']==cwe]
  with ExitStack() as stack:
   for name,func in [('frozen_state',lambda x:deepcopy(state)),('extract_b33',fake_extract),('snapshot_from_git',fake_snapshot),
    ('apply',lambda *a:{'diff':'UNIT TEST'}),('validate_local_assets',fake_assets),('read_calls',fake_calls),
    ('read_arguments',lambda *a:[]),('scan',fake_scan),('command',fake_command),('parse_flows',fake_paths),
    ('calibrated_fusion',fake_fusion),('select_toolchain',lambda *a,**k:SimpleNamespace(executable='FAKE_CODEQL',database_options=[])),
    ('local_pack_copy',lambda *a:{}),('verify_and_options',lambda *a,**k:([],{}))]:stack.enter_context(patch.object(runner,name,side_effect=func))
   stack.enter_context(patch('ntk_b38.processes.install_cleanup_handler'))
   for phase in phases:
    current['phase']=phase
    args=['--phase',phase,'--work',str(work),'--repo',str(repo),'--downloads',str(downloads)]
    if diagnostic:args+=['--diagnostic-only']
    with redirect_stdout(io.StringIO()):code=runner.main(args)
    runs=sorted((work/'batch38_runs').glob('batch38'+phase.lower()+'*'))
    summary=json.loads((runs[-1]/'00_SUMMARY.json').read_text())
    current['output'].append((phase,code,summary,runs[-1]))
  return work,downloads,current

 def test_mock_orchestration_abcd_with_separate_diagnostics_and_reports(self):
  work,out,s=self.simulate(('A','B','C','D'))
  self.assertEqual([r[1] for r in s['output']],[0,0,0,0]);self.assertEqual(len(list(out.glob('*_result.zip'))),4)
  for phase,_,summary,run in s['output']:
   self.assertEqual(summary['status'],'B38_SCOPED_DEMO_COMPLETE')
   self.assertEqual(json.loads((run/'PROGRESS.json').read_text())['status'],summary['status'])
   gate=runner.require_gate(work,phase,'epoch_1',runner.implementation_sha());self.assertEqual(gate['phase'],phase)
   for c in summary['cwes']:
    self.assertTrue(summary['arms']['epoch_1']['cwes'][c]['fixture_check']['match'])
    self.assertTrue((run/'diagnostic'/('cwe-'+c)/'flow.bqrs').is_file())
    self.assertTrue((run/'analysis/epoch_1'/('cwe-'+c)/'flow.bqrs').is_file())
 def test_mock_ql_error_does_not_run_model(self):
  _,_,s=self.simulate(fail_at='COMPILE_ApiCalls')
  self.assertEqual(s['output'][0][1],2);self.assertFalse(any(any(x.endswith('run_native37.py') for x in args) for args in s['events']))
 def test_mock_empty_live_sink_is_review_not_manual_fallback(self):
  w,_,s=self.simulate(missing_live=True)
  self.assertEqual(s['output'][0][1],3);self.assertFalse(runner.gate_path(w,'A','epoch_1').exists())
  summary=s['output'][0][2]
  self.assertTrue(summary['diagnostics']['22']['fixture_check']['match'])
  self.assertFalse(summary['arms']['epoch_1']['cwes']['22']['fixture_check']['match'])
 def test_mock_diagnostics_only_never_writes_model_gate(self):
  w,_,s=self.simulate(diagnostic=True)
  self.assertEqual(s['output'][0][1],0);self.assertEqual(s['output'][0][2]['arms'],{})
  self.assertFalse(runner.gate_path(w,'A','epoch_1').exists())
 def test_mock_missing_earlier_gates_blocks_d(self):
  _,_,s=self.simulate(('D',))
  self.assertEqual(s['output'][0][1],2);self.assertIn('REQUIRED_GATE_MISSING',s['output'][0][2]['blocker'])

if __name__=='__main__':unittest.main()
