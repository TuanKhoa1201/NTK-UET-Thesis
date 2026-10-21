#!/usr/bin/env python3
"""Full controller lifecycle with synthetic backends only (zero CodeQL/GPU calls)."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import run_hybrid as b4
import hybrid_core as h
from ntk_core import loads,write_json,sha,digest,canonical
from test_hybrid import Scorer,Score
from test_b39b3 import fake_bundle

class ControllerLifecycle(unittest.TestCase):
    def test_all_four_arms_complete_with_all_abstain_and_no_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);w=root/'work';dl=root/'downloads';source=root/'source';repo=root/'iris';g=root/'github'
            for p in (w,dl,source,repo,g):p.mkdir()
            (w/'NTK_BATCH38_POLICY_TOOL_PATH.txt').write_text(str(source))
            (source/'run_policy.py').write_text('# fake backend for tests only\n')
            qp=source/'queries';qp.mkdir()
            for name in ('Flow.template','Source.template','ApiCalls.ql'):(qp/name).write_text('ntkRelevant(m) __CWE__')
            (w/'.ntk_v5_lora_venv/bin').mkdir(parents=True);(w/'.ntk_v5_lora_venv/bin/python').write_text('fake')
            rawreq,target,_,base_summary=fake_bundle()
            rawcases=[{**r['candidate'],'source_record_sha256':r['source_record_sha256'], 'compiler_signature':'call(java.lang.String)'} for r in rawreq]
            og={'results':[{'cwe':c,'check_id':'fake-'+c,'path':'source.java'} for c in h.CWES]}
            score=Scorer()
            def rows(c,policy=False):
                i=list(h.CWES).index(c)
                return [{'id':'opengrep:'+str(i),'origin':'OPENGREP','cwe':c,'original_opengrep':deepcopy(og['results'][i]),
                    'retained':True,'vulnerability_confirmed':False,'score':h.scorer_fields(Score()),'dataflow':[],
                    'linked_codeql_flow_ids':[],'model_observation':None,'evidence_origin':h.POLICY if policy else h.MODEL}]
            def intake(archive,target):
                target.mkdir();(target/'Test.java').write_text('class Test {}')
                return {'java_source_hashes':{'Test.java':sha((target/'Test.java').read_bytes())},'archive_sha256':sha(Path(archive).read_bytes())}
            def scanner(private,target,cwes,ml):
                write_json(private/'opengrep/PROOF.json',{'synthetic':True});return deepcopy(og)
            def select(original,work,downloads,private,**kw):
                write_json(private/'CODEQL_SELECTION.json',{'synthetic':True});return SimpleNamespace(executable=Path('/fake/codeql'),database_options=[])
            def exporter(rows):return {'runs':[{'tool':{'driver':{}},'properties':{},'results':[{'properties':{}} for r in rows]}]}
            rp=SimpleNamespace(__file__=str(source/'run_policy.py'),implementation_sha=lambda:'impl',require_gate=lambda *a:None,
                ensure_safe_input=intake,scan=scanner,load_scorer=lambda p:score,calibrated_fusion=lambda og,f,t,calls,tar,s,c,d:rows(c),
                to_sarif=exporter,select_toolchain=select,local_pack_copy=lambda *a:{},verify_and_options=lambda *a,**kw:([],{}),
                emit_flow=lambda *a:('query',[]),read_calls=lambda *a:(deepcopy(rawcases),[]),tagged=lambda rows,*a:rows,
                read_arguments=lambda *a:[],select_candidates=lambda cases,c:[x for x in cases if x['cwe']==c],
                bind_ast=lambda *a:[],manual_labels=lambda *a:[],parse_flows=lambda *a:[],tag_paths=lambda f,c:f,
                adjudicate=lambda *a:([],[]),assess_paths=lambda *a:([],[]),C4_SHA='policy79',POLICY_SHA='semantics',SOURCE_POLICY={},
                policy_fusion=lambda *a:rows('79',True))
            def runtime(work,downloads,assets,states):
                cfg={a:{'arm':a,'base_dir':'base','adapter_dir':None,'runtime_versions':b4.PINS['runtime_versions'],
                        'generation':{'generation_timeout_s':120}} for a in h.ARMS}
                write_json(assets/'RUNTIME_CONFIG_PROVENANCE.json',{'adapter_sha256':{'epoch_1':'1','epoch_2':'2'}});return cfg
            def unpack(raw,dest):
                (dest/'src/queries').mkdir(parents=True);(dest/'src/queries/codeql-pack.lock.yml').write_text('fake')
                p=dest/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py';p.parent.mkdir(parents=True);p.write_bytes(b'fake_scorer')
                return {'synthetic':True}
            def subrun(argv,**kw):return SimpleNamespace(returncode=0,stdout=b'fake' if 'archive' in argv else '',stderr='')
            def child(argv,log,cwd,timeout,*args,**kw):
                argv=list(map(str,argv));log=Path(log);log.write_text('21.0.12.1' if argv[0]=='javac' else '{}')
                private=next(p for p in log.parents if p.name=='private')
                if 'database' in argv and 'create' in argv:
                    db=Path(argv[argv.index('create')+1]);(db/'db-java').mkdir(parents=True);(db/'src.zip').write_bytes(b'fake');(db/'codeql-database.yml').write_bytes(b'fake')
                if 'run-queries' in argv:
                    db=Path(argv[argv.index('run-queries')+1]);q=Path(argv[argv.index('run-queries')+2]);(db/'results').mkdir(exist_ok=True);(db/'results'/(q.stem+'.bqrs')).write_bytes(b'fake')
                if 'interpret-results' in argv:
                    dest=Path(next(a.split('=',1)[1] for a in argv if a.startswith('--output=')));dest.write_text('{"runs":[]}')
                if str(ROOT/'hybrid_native_driver.py') in argv:
                    cfg=loads(Path(argv[-1]).read_bytes());folder=Path(cfg['prepare_dir'] if 'prepare' in argv else cfg['output_dir'])
                    if 'prepare' in argv:
                        cases=[{**x,'expected_messages':rawreq[i]['messages']} for i,x in enumerate(cfg['raw_cases'])]
                        write_json(folder/'PREPARED.json',{'candidate_origin':'THIS_RUN_CODEQL_COMPILER_IDENTITIES'})
                        write_json(folder/'NATIVE_INPUTS.json',cases)
                    else:
                        arm=cfg['arm'];trace=[]
                        for phase in ('cold','warm'):
                            for c in cfg['cases']:
                                k=h.key(c);m={'generation_s':1.,'input_tokens':10,'output_tokens':5,
                                    'input_token_ids_sha256':digest(c['expected_messages']),'peak_vram_allocated_bytes':10,'peak_vram_reserved_bytes':20}
                                trace.append({'phase':phase,'case_key':k,'candidate':{x:c[x] for x in (*h.IDENTITY,'cwe')},
                                    'source_record_sha256':c['source_record_sha256'],'prompt_sha256':digest(c['expected_messages']),
                                    'raw_completion':'bad','status':'ABSTAIN','reason':'INVALID_STRICT_JSON','label':None,
                                    'cache_hit':phase=='warm','cache_key':digest([arm,k]),'worker':m if phase=='cold' else None})
                                write_json(folder/phase/('cwe-'+c['cwe'])/'llm_labelled_sink_apis.json',[])
                        (folder/'native_trace.jsonl').write_text(''.join(canonical(r)+'\n' for r in trace))
                        summary=deepcopy(base_summary);summary.update(status='B39B4_NATIVE_ARM_COMPLETE',arm=arm)
                        summary['worker']['arm']=arm;write_json(folder/'DRIVER_RESULT.json',summary)
                if str(ROOT/'tokenizer_preflight.py') in argv:
                    cfg=loads(Path(argv[-2]).read_bytes())
                    write_json(Path(argv[-1]),{'status':'TOKENIZER_CPU_PREFLIGHT_COMPLETE','n':4,
                       'tokenizer_chat_template_sha256':base_summary['worker']['tokenizer_chat_template_sha256'],
                       'rows':[{'case_key':h.key(c),'input_token_ids_sha256':digest(c['expected_messages'])} for c in cfg['cases']]})
                return {'returncode':0,'elapsed_s':0,'still_running':False,'process_group_still_running':False}
            origread=b4.read_checked
            def read(path,*a,**kw):
                if Path(path).name in (b4.B3_NAME,b4.PINS['b33_name']):return b'fake_archive'
                return origread(path,*a,**kw)
            members={'00_RESULT.json':json.dumps({'status':'B39B3_NATIVE_WEAK_VALIDATION_COMPLETE'}).encode(),
                     'inputs/runtime_protocol.json':b'{}'}
            with patch.object(b4,'baseline',return_value={'synthetic':True}),patch.object(b4,'read_checked',side_effect=read),\
                 patch.object(b4,'zip_members',return_value=members),patch.object(b4,'verify_sums',return_value=1),\
                 patch.object(b4,'audit',return_value={'synthetic':True}),patch.object(b4.importlib,'import_module',return_value=rp),\
                 patch.object(b4,'make_runtime_configs',side_effect=runtime),patch.object(b4,'unpack_snapshot',side_effect=unpack),\
                 patch.object(b4.subprocess,'run',side_effect=subrun),patch.object(b4,'run_child',side_effect=child),\
                 patch.object(b4.shutil,'disk_usage',return_value=SimpleNamespace(free=10*1024**3)),\
                 patch.object(b4,'sha',side_effect=lambda x:'c1b9cbf071739ca6d96062032867835dbf4db185f4e0ac1e2d609bd319e0de7e' if x==b'fake_scorer' else sha(x)):
                rc=b4.main(['--run-hybrid','--work',str(w),'--repo',str(repo),'--github',str(g),'--downloads',str(dl),'--host-python',sys.executable])
            zips=list(dl.glob('*.zip'));self.assertEqual(len(zips),1)
            with zipfile.ZipFile(zips[0]) as z:
                result=loads(z.read('00_RESULT.json'));self.assertEqual(rc,0,result)
                self.assertEqual(result['new_native_requests'],12);self.assertEqual(result['completed_arms'],['opengrep_only',*h.ARMS])
                self.assertFalse(result['independent_gold']);self.assertFalse(result['web_gate_changed_by_runner'])
                self.assertTrue(result['new_codeql_database']);self.assertTrue(result['new_opengrep_scan'])
                self.assertTrue(all('/' not in name for name in z.namelist()))

if __name__=='__main__':unittest.main(verbosity=2)
