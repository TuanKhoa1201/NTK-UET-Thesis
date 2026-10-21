#!/usr/bin/env python3
"""B39B4 four-arm local hybrid CLI. One scanner run/database, three native model arms.
Separate from production web gates. No learning, new labels, or score threshold tuning.
All source/prompt/SARIF/DB content stays under this run's private directory.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import importlib
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from ntk_core import (CWES, IDENTITY, Blocker, digest, file_state, jsonl, loads, read_checked,
                      require, sha, write_json, zip_members, verify_sums, canonical)
from run_b39b2 import PINS, baseline, make_runtime_configs, pack
from run_b39b3 import unpack_snapshot, run_child
from ntk_runtime import offline_env
from hybrid_core import ARMS, MODEL, POLICY, native_inputs, trace_check, verify_fusion, results_view, assert_comparison, sarif_view
from audit_b39b3 import B3_NAME, B3_SHA, audit


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work',type=Path,default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    p.add_argument('--repo',type=Path,default=Path.home()/'iris')
    p.add_argument('--github',type=Path,default=Path.home()/'migration/ntk_github_publish_20261020')
    p.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
    p.add_argument('--host-python',default=os.environ.get('NTK_IRIS_PYTHON',''))
    p.add_argument('--project-zip',type=Path,default=ROOT/'samples/B39B4_JDK_INTEGRATION.zip')
    p.add_argument('--run-hybrid',action='store_true',help='Required consent for real CodeQL and GPU execution.')
    a=p.parse_args(argv)
    os.environ.update(CODEQL_TELEMETRY_DISABLE='1',SEMGREP_SEND_METRICS='off',OPENGREP_SEND_METRICS='off',SEMGREP_ENABLE_VERSION_CHECK='0',OPENGREP_ENABLE_VERSION_CHECK='0')
    for k in ('work','repo','github','downloads','project_zip'):setattr(a,k,getattr(a,k).expanduser().resolve())
    require(a.run_hybrid,'EXPLICIT_RUN_HYBRID_REQUIRED')
    require(a.work.is_dir() and a.downloads.is_dir(),'WORK_OR_DOWNLOADS_MISSING')
    require(not a.work.is_relative_to(a.repo) and not a.work.is_relative_to(a.github),'WORK_INSIDE_FROZEN_REPOSITORY')
    require(a.host_python and Path(a.host_python).is_file(),'EXPLICIT_HOST_PYTHON_MISSING')
    run=a.work/'batch39b4_hybrid_runs'/('b39b4_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True,exist_ok=False);private=run/'private';private.mkdir()
    s={'status':'B39B4_BLOCKED','blockers':[],'completed_arms':[], 'new_codeql_database':False,'new_opengrep_scan':False,
       'opengrep_state':'NOT_STARTED','codeql_database_state':'NOT_STARTED','model_inference_state':'NOT_STARTED',
       'new_training':False,'new_native_requests':0,'stage4':'NOT_EXECUTED','full_SAPipeline_run':'NOT_EXECUTED',
       'independent_gold':False,'web_gate_changed_by_runner':False,'model_xss_gate_granted':False,
       'scope':'JDK21_MAX24_FILES_FOUR_PROFILE_COMPARISON_CLI_NOT_WEB_GATE_ACCEPTANCE'}
    began=time.monotonic();states={};before=None;locks=[];commands=[];rp=None
    def update_report(name,value):
        require(name in ('PROGRESS.json','COMMAND_TIMINGS.json','GPU_PREFLIGHT.json'),'MUTABLE_REPORT_NOT_ALLOWED')
        path=run/name;tmp=run/(name+'.tmp')
        tmp.write_text(canonical(value)+'\n',encoding='utf-8');tmp.replace(path)
    def event(stage):
        print('B39B4_STAGE='+stage,flush=True);s['current_stage']=stage;update_report('PROGRESS.json',s)
    def cmd(args,log,timeout=900,cwd=None):
        log=Path(log);log.parent.mkdir(parents=True,exist_ok=True)
        write_json(log.with_suffix('.command.json'),{'argv':list(map(str,args)),'cwd':str(cwd or private),'timeout_s':timeout})
        result=run_child(args,log,cwd or private,timeout)
        commands.append({'log':str(log.relative_to(private)),**result})
        update_report('COMMAND_TIMINGS.json',commands)
        require(result['returncode']==0,'COMMAND_FAILED:'+str(log.relative_to(private)))
        return log.read_text(encoding='utf-8',errors='replace')
    def check_gpu():
        r=subprocess.run(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'],
                         capture_output=True,text=True,timeout=30,env=offline_env())
        require(r.returncode==0 and not r.stdout.strip(),'GPU_NOT_IDLE_OR_QUERY_FAILED')
        update_report('GPU_PREFLIGHT.json',{'returncode':r.returncode,'compute_processes':0,'scope':'COMPUTE_QUERY_NOT_GLOBAL_MONITOR'})
    def ql(qfile,out,codeql,db,opts,res):
        out.mkdir(parents=True,exist_ok=False)
        cmd([codeql,'query','compile','--check-only',qfile,*opts,*res],out/'compile.log')
        cmd([codeql,'database','run-queries',db,qfile,*opts,*res,'--no-default-compilation-cache',
            '--compilation-cache='+str(private/'query-compilation-cache')],out/'run.log',1800)
        sarif=out/'codeql.sarif'
        cmd([codeql,'database','interpret-results',db,qfile,'--format=sarifv2.1.0','--output='+str(sarif),
             '--max-paths=4',*opts],out/'interpret.log',600)
        matches=list((db/'results').rglob(qfile.stem+'.bqrs'));require(len(matches)==1,'BQRS_RESULT_NOT_UNIQUE')
        shutil.copy2(matches[0],out/'flow.bqrs')
        return loads(sarif.read_bytes())
    try:
        event('VERIFY_B39B3_AND_FROZEN_RELEASE')
        b3=read_checked(a.downloads/B3_NAME,B3_SHA,states=states);b3m=zip_members(b3);verify_sums(b3m)
        require(loads(b3m['00_RESULT.json'])['status']=='B39B3_NATIVE_WEAK_VALIDATION_COMPLETE','B39B3_NOT_COMPLETE')
        write_json(run/'INPUT_B39B3_AUDIT.json',audit(a.downloads/B3_NAME))
        before=baseline(a.work,a.repo,a.github,states);write_json(run/'BEFORE.json',before)
        source=Path((a.work/'NTK_BATCH38_POLICY_TOOL_PATH.txt').read_text().strip()).resolve()
        for name in ('batch38_gpu_scan.lock','batch39b2_gpu.lock','batch39b3_gpu.lock','batch39b4_gpu.lock'):
            f=(a.work/name).open('a+');locks.append(f)
            try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Blocker('ACTIVE_SCAN_LOCK:'+name) from None
        check_gpu();require(shutil.disk_usage(private).free>=4*1024**3,'LESS_THAN_4_GIB_FREE')
        sys.path[:0]=[str(source),str(source/'engine')]
        rp=importlib.import_module('run_policy')
        require(Path(rp.__file__).resolve()==source/'run_policy.py','IMPORTED_WRONG_RELEASE_MODULE')
        # These are integrity preconditions for the original release only, not approval of the new arms.
        impl=rp.implementation_sha()
        rp.require_gate(a.work,'C4','none',impl);rp.require_gate(a.work,'DPA','epoch_1',impl)
        write_json(run/'RELEASE_REUSE.json',{'source_manifest_sha256':PINS['source_manifest_sha256'],
            'source_implementation_sha256':impl,'original_C4_and_DPA_epoch1_receipts_verified':True,
            'new_gate_issued':False,'reuse':'UNCHANGED_SCANNER_COMPILER_SEMANTICS_POLICY_SCORER_AND_NATIVE_PROVIDER'})
        event('SECURE_JAVA_INTAKE_AND_REAL_OPENGREP')
        input_raw=read_checked(a.project_zip,limit=16*1024**2,states=states)
        saved=private/'project.zip';saved.write_bytes(input_raw)
        target=private/'uploaded_project';inp=rp.ensure_safe_input(saved,target)
        write_json(private/'UPLOADED_INPUT_PROVENANCE.json',inp)
        s['input_sha256']=inp['archive_sha256']
        sample=loads((ROOT/'SAMPLE_MANIFEST.json').read_bytes())
        s['input_kind']='SYNTHETIC_INTEGRATION_NOT_GOLD' if s['input_sha256']==sample['archive_sha256'] else 'OPERATOR_PROJECT_NOT_GOLD'
        ml=a.work/'.ntk_v5_lora_venv/bin/python'
        require(ml.is_file(),'ML_PYTHON_MISSING')
        s['opengrep_state']='ATTEMPTED'
        og=rp.scan(private,target,list(CWES),ml);s['opengrep_state']='COMPLETED';s['new_opengrep_scan']=True;s['raw_opengrep_findings']=len(og['results'])
        write_json(run/'SCANNER_PROOF.json',loads((private/'opengrep/PROOF.json').read_bytes()))
        event('VERIFY_MODELS_AND_LOAD_FROZEN_SCORER')
        assets=private/'runtime_assets';assets.mkdir()
        configs=make_runtime_configs(a.work,a.downloads,assets,states)
        runtime=loads((assets/'RUNTIME_CONFIG_PROVENANCE.json').read_bytes())
        runtime.update(scope='NATIVE_STAGE3_THREE_ARMS_COMPILER_CANDIDATES',cache='PER_ARM_FRESH_COLD_THEN_WARM')
        write_json(run/'RUNTIME_CONFIG_PROVENANCE.json',runtime)
        snapshot=private/'snapshot'
        rr=subprocess.run(['git','-C',str(a.repo),'archive','--format=tar',PINS['iris_commit']],capture_output=True,timeout=180,env=offline_env())
        require(rr.returncode==0,'GIT_SNAPSHOT_FAILED');write_json(run/'SNAPSHOT.json',unpack_snapshot(rr.stdout,snapshot))
        b33=zip_members(read_checked(a.downloads/PINS['b33_name'],PINS['b33_sha256'],states=states))
        protocol=private/'runtime_protocol.json';protocol.write_bytes(b33['inputs/runtime_protocol.json'])
        scorer_file=snapshot/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py'
        require(sha(scorer_file.read_bytes())=='c1b9cbf071739ca6d96062032867835dbf4db185f4e0ac1e2d609bd319e0de7e','FROZEN_SCORER_SHA')
        scorer=rp.load_scorer(scorer_file)
        summaries={};traces={};policy_hashes={}
        baseline_rows=[]
        for c in CWES:
            baseline_rows.extend(rp.calibrated_fusion(og,[],[],[],target,scorer,c,[]))
        for r in baseline_rows:
            r['evidence_origin']='OPENGREP_ONLY';r['source_policy_applied']=False
        baseline_dir=private/'analysis/opengrep_only';baseline_dir.mkdir(parents=True)
        write_json(baseline_dir/'result.json',results_view(baseline_rows,'opengrep_only',s['input_sha256']))
        write_json(baseline_dir/'report.sarif',sarif_view(rp.to_sarif,baseline_rows,'opengrep_only'))
        summaries['opengrep_only']=verify_fusion(baseline_rows,og,scorer,'opengrep_only')
        summaries['opengrep_only'].update(model_inference=False,codeql_evidence=False,qualified_paths=0)
        s['completed_arms'].append('opengrep_only');write_json(run/'OPENGREP_ONLY.json',summaries['opengrep_only'])
        event('PINNED_CODEQL_AND_QUERY_COMPILE_PREFLIGHT')
        chosen=rp.select_toolchain(a.repo/'codeql/codeql',a.work,a.downloads,private,allow_download=False)
        codeql=chosen.executable;cache=private/'codeql-cache'
        packs=rp.local_pack_copy(a.repo,cache/'packages');write_json(private/'QLPACK_MANIFEST.json',packs)
        add,resolution=rp.verify_and_options(packs,source/'engine/B34R2_OBSERVED_QLPACK_PINS.json',run=private,common_caches=cache)
        opts=[*add,'--common-caches='+str(cache)];res=['--threads=1','--ram=3072']
        write_json(run/'TOOLCHAIN.json',{'selection':loads((private/'CODEQL_SELECTION.json').read_bytes()),
            'packs':{k:{'version':v['version'],'fingerprint':v['fingerprint']} for k,v in packs.items()},
            'resolution':resolution,'query_resource_options':res,'network_pack_install':False})
        qp=private/'queries';shutil.copytree(source/'queries',qp)
        shutil.copy2(snapshot/'src/queries/codeql-pack.lock.yml',qp/'codeql-pack.lock.yml')
        cmd([codeql,'pack','resolve-dependencies','--mode=verify',*opts,qp],private/'PACK_RESOLVE.log',180)
        template=(qp/'Flow.template').read_text()
        for c in CWES:
            (qp/('Sources_'+c+'.ql')).write_text((qp/'Source.template').read_text().replace('__CWE__',c))
            (qp/('Compile_'+c+'.ql')).write_text(rp.emit_flow(template,[],[],c,'base','compile')[0])
        ct=(qp/'ApiCalls.ql').read_text().replace('ntkRelevant(m)','ntkRelevant(m) and ntkSinkContext(call, "79")')
        (qp/'HttpContexts.ql').write_text(ct.replace('api-calls','http-contexts'))
        for qfile in sorted(qp.glob('*.ql')):cmd([codeql,'query','compile','--check-only',qfile,*opts,*res],private/('COMPILE_'+qfile.stem+'.log'))
        event('JDK_COMPILATION_AND_ENCODING_AUDIT')
        version=cmd(['javac','-version'],private/'JAVAC_VERSION.log',30)
        require(re.search(r'\b21\.',version) is not None,'JDK21_REQUIRED')
        cmd([ml,'-B',source/'engine/build_jdk_only.py',target,private/'javac_preflight'],private/'JAVAC_PREFLIGHT.log',180)
        astclasses=private/'encoding_compiler';astclasses.mkdir()
        cmd([ml,'-B',source/'java_clean.py','javac','-proc:none','--release','21','-d',astclasses,source/'trusted/NtkEncodingAudit.java'],private/'ENCODING_BUILD.log',180)
        rawast=cmd([ml,'-B',source/'java_clean.py','java','-Xmx768m','--add-modules','jdk.compiler','-cp',astclasses,'NtkEncodingAudit',target],private/'ENCODING_RUN.log',180)
        ast=loads(rawast);write_json(private/'ENCODING_COMPILER_RAW.json',ast)
        event('ONE_NEW_CODEQL_DATABASE_SHARED_BY_ALL_ARMS')
        db=private/'database';builder=' '.join(shlex.quote(str(x)) for x in [ml,'-B',source/'engine/build_jdk_only.py',target,private/'javac_codeql'])
        s['codeql_database_state']='ATTEMPTED'
        cmd([codeql,'database','create',db,'--language=java','--source-root='+str(target),'--command='+builder,
            '--no-pre-finalize','--common-caches='+str(cache),*chosen.database_options,*res],private/'DATABASE_CREATE.log',1800)
        require((db/'db-java').is_dir() and (db/'src.zip').is_file(),'NEW_DATABASE_INCOMPLETE')
        s['new_codeql_database']=True;s['codeql_database_state']='CREATED'
        write_json(run/'DATABASE_PROOF.json',{'created_in_this_run':True,'count':1,'input_sha256':s['input_sha256'],
             'db_metadata_sha256':sha((db/'codeql-database.yml').read_bytes()),'db_src_zip_sha256':sha((db/'src.zip').read_bytes()),
             'shared_for_three_model_arms':True,'java_application_executed':False,'project_build_scripts_executed':False,
             'scope':'NOT_A_SECURITY_SANDBOX_FOR_UNTRUSTED_JAVA'})
        event('EXTRACT_THIS_DATABASE_COMPILER_CANDIDATES_AND_SOURCES')
        for name in ['ApiCalls','ArgumentSpans','HttpContexts',*['Sources_'+c for c in CWES]]:
            cmd([codeql,'query','run',qp/(name+'.ql'),'--database='+str(db),'--output='+str(private/(name+'.bqrs')),
                 *opts,*res,'--no-default-compilation-cache','--compilation-cache='+str(private/'query-compilation-cache')],private/(name+'_QUERY.log'),1800)
            cmd([codeql,'bqrs','decode',private/(name+'.bqrs'),'--format=csv','--output='+str(private/(name+'.csv'))],private/(name+'_DECODE.log'),180)
        allcases,calls=rp.read_calls(private/'ApiCalls.csv',target);calls=rp.tagged(calls)
        arguments=rp.read_arguments(private/'ArgumentSpans.csv',target)
        contexts=rp.tagged(rp.read_calls(private/'HttpContexts.csv',target)[1],'79')
        cases={c:rp.select_candidates(allcases,c) for c in CWES}
        require(all(cases[c] for c in CWES),'FOUR_PROFILE_COMPARISON_REQUIRES_CANDIDATES_IN_EACH_CWE')
        sources={c:rp.tagged(rp.read_calls(private/('Sources_'+c+'.csv'),target)[1],c) for c in CWES}
        flattened=[x for c in CWES for x in cases[c]];raw_cases=native_inputs(flattened)
        for name,value in [('CANDIDATES_BY_CWE',cases),('ALL_CALLS',calls),('ARGUMENTS',arguments),('HTTP_CONTEXT_CALLS',contexts),('SOURCES_BY_CWE',sources)]:write_json(private/(name+'.json'),value)
        astproof=rp.bind_ast(ast,calls,inp['java_source_hashes']);write_json(private/'ENCODING_COMPILER_BOUND.json',astproof)
        event('CWE79_CONTEXTUAL_POLICY_ONCE_SHARED_NOT_MODEL_DERIVED')
        text,bindings=rp.emit_flow(template,cases['79'],rp.manual_labels(cases['79'],'79'),'79','base','diagnostic')
        text=text.replace('-diagnostic-','-context-policy-')
        for b in bindings:b.update(label_origin=POLICY,policy_sha256=rp.C4_SHA)
        qfile=qp/'ContextPolicy_79.ql';qfile.write_text(text)
        qout=private/'context_policy/cwe-79';sarif=ql(qfile,qout,codeql,db,opts,res)
        policy_raw=rp.tag_paths(rp.parse_flows(sarif,target,calls,arguments,bindings,sources['79'],'79',contexts),'79')
        for f in policy_raw:f.update(input_project_sha256=s['input_sha256'],database_created_in_this_run=True,sink_origin=POLICY)
        policy_qualified,assessments=rp.assess_paths(policy_raw,astproof)
        write_json(private/'policy79/RAW_PATHS.json',policy_raw);write_json(private/'policy79/QUALIFIED_PATHS.json',policy_qualified)
        write_json(private/'policy79/ASSESSMENTS.json',assessments)
        write_json(run/'POLICY79.json',{'origin':POLICY,'query_sha256':sha(qfile.read_bytes()),'bqrs_sha256':sha((qout/'flow.bqrs').read_bytes()),
             'policy_sha256':rp.C4_SHA,'raw_paths':len(policy_raw),'qualified_paths':len(policy_qualified),
             'qualified_paths_fingerprint':digest(policy_qualified),'computed_once_shared_by_three_arms':True,'model_xss_gate_granted':False})
        event('NATIVE_IRIS_PREPARE_AND_TOKENIZER_CPU_PREFLIGHT')
        prep=private/'prepare';prep.mkdir()
        cfg={'snapshot':str(snapshot),'engine':str(source/'engine'),'protocol_path':str(protocol),'prepare_dir':str(prep),'raw_cases':raw_cases}
        cp=private/'prepare_config.json';write_json(cp,cfg)
        cmd([a.host_python,'-I','-B','-u',ROOT/'hybrid_native_driver.py','prepare',cp],prep/'driver.log',180)
        proof=loads((prep/'PREPARED.json').read_bytes());prepared=loads((prep/'NATIVE_INPUTS.json').read_bytes())
        require(proof['candidate_origin']=='THIS_RUN_CODEQL_COMPILER_IDENTITIES','WRONG_NATIVE_CANDIDATE_ORIGIN')
        write_json(run/'NATIVE_PREPARATION.json',proof)
        tc=private/'tokenizer_config.json';write_json(tc,{**configs['base'],'cases':prepared})
        cmd([ml,'-I','-B',ROOT/'tokenizer_preflight.py',tc,run/'TOKENIZER_PREFLIGHT.json'],private/'TOKENIZER.log',180)
        token_proof=loads((run/'TOKENIZER_PREFLIGHT.json').read_bytes())
        require(token_proof['status']=='TOKENIZER_CPU_PREFLIGHT_COMPLETE' and token_proof['n']==len(flattened),'TOKENIZER_PREFLIGHT')
        write_json(run/'RUN_PROTOCOL.json',{'locked_before_new_model_inference':True,'arms':['opengrep_only',*ARMS],
            'input_sha256':s['input_sha256'],'database_count':1,'model_candidates':len(prepared),'planned_model_requests':3*len(prepared),
            'runtime':runtime,'native_inputs_fingerprint':digest(prepared),'source_policy':rp.SOURCE_POLICY,
            'semantic_policy_sha256':rp.POLICY_SHA,'policy79_sha256':rp.C4_SHA,'scorer_sha256':sha(scorer_file.read_bytes()),
            'independent_gold':False,'quality_pass_threshold':None,'no_model_output_repair':True,'new_web_gate':False,
            'comparison_limits':'SHARED_EXTRACTION_AND_SINGLE_POLICY_RUN; NOT_THREE_INDEPENDENT_END_TO_END_LATENCY_MEASUREMENTS'})
        check_gpu()
        for arm in ARMS:
            event('NATIVE_STAGE3_REAL_LOCAL_'+arm.upper())
            folder=private/'live'/arm;folder.mkdir(parents=True)
            ac={**cfg,**configs[arm],'cases':prepared,'preparation_proof':proof,
                'output_dir':str(folder),'cache_dir':str(folder/'cache'),'cache_mode':'readwrite',
                'frozen_root':str(a.repo),'ml_python':str(ml),
                'adapter_sha256':None if arm=='base' else runtime['adapter_sha256'][arm],
                'adapter_config_sha256':None if arm=='base' else 'b6305fec9b9ae3a10043fb7cfdeda6c28839ab0604e5f4e388194b65e5211d7e',
                'load_timeout_s':300,'request_timeout_s':configs[arm]['generation']['generation_timeout_s']+30}
            cp=folder/'config.json';write_json(cp,ac)
            s['model_inference_state']='ATTEMPTING_'+arm
            cmd([a.host_python,'-I','-B','-u',ROOT/'hybrid_native_driver.py','run',cp],folder/'driver.log',3600,cwd=folder)
            summary=loads((folder/'DRIVER_RESULT.json').read_bytes());trace=jsonl((folder/'native_trace.jsonl').read_bytes())
            traceinfo=trace_check(prepared,trace,summary,arm,configs[arm]['runtime_versions'],token_proof)
            traces[arm]=traceinfo;write_json(run/('NATIVE_'+arm+'.json'),traceinfo)
            s['new_native_requests']+=traceinfo['new_requests'];s['model_inference_state']='COMPLETED_'+arm
            full=[];allflows=[];per_cwe={}
            for c in CWES:
                event('CODEQL_DATAFLOW_AND_SCORING_'+arm.upper()+'_CWE'+c)
                labels=loads((folder/'cold'/('cwe-'+c)/'llm_labelled_sink_apis.json').read_bytes())
                eligible,decisions=rp.adjudicate(cases[c],labels,c)
                text,binding=rp.emit_flow(template,cases[c],eligible,c,arm)
                qfile=qp/('Live_'+c+'_'+arm+'.ql');qfile.write_text(text)
                out=private/'analysis'/arm/('cwe-'+c)
                sf=ql(qfile,out,codeql,db,opts,res)
                model_flows=rp.tag_paths(rp.parse_flows(sf,target,calls,arguments,binding,sources[c],c,contexts),c)
                for f in model_flows:f.update(input_project_sha256=s['input_sha256'],database_created_in_this_run=True,evidence_origin=MODEL)
                if c=='79':
                    fused=rp.policy_fusion(og,policy_raw,policy_qualified,assessments,astproof,calls,target,scorer,trace)
                    flows=deepcopy(policy_qualified);policy_hashes[arm]=digest(flows)
                    write_json(out/'MODEL_ONLY_PATHS_NOT_POLICY.json',model_flows)
                else:
                    flows=model_flows;fused=rp.calibrated_fusion(og,flows,trace,calls,target,scorer,c,decisions)
                    for r in fused:
                        r['evidence_origin']=MODEL;r['sink_origin']='LOCAL_LIVE_STAGE3'
                        if r.get('callsite'):r['callsite']['cwe']=c
                for name,value in [('RAW_SINK_LABELS',labels),('SEMANTIC_DECISIONS',decisions),('SINK_BINDINGS',binding),('VERIFIED_PATHS',flows),('FUSED_FINDINGS',fused)]:write_json(out/(name+'.json'),value)
                write_json(out/'FUSED_FINDINGS.sarif',sarif_view(rp.to_sarif,fused,arm))
                per_cwe[c]={'qualified_paths':len(flows),'model_only_paths':len(model_flows),
                    'evidence_origin':POLICY if c=='79' else MODEL,'candidates':len(cases[c]),'sources':len(sources[c])}
                if c=='79':per_cwe[c]['raw_policy_paths']=len(policy_raw)
                full.extend(fused);allflows.extend(flows)
            checked=verify_fusion(full,og,scorer,arm)
            checked.update(evidence_by_cwe=per_cwe,qualified_paths=len(allflows),model_inference=True,codeql_evidence=True)
            summaries[arm]=checked
            out=private/'analysis'/arm
            write_json(out/'result.json',results_view(full,arm,s['input_sha256']))
            write_json(out/'report.sarif',sarif_view(rp.to_sarif,full,arm));write_json(out/'VERIFIED_PATHS.json',allflows)
            write_json(run/('FUSION_'+arm+'.json'),checked)
            s['completed_arms'].append(arm);update_report('PROGRESS.json',s)
        comparison=assert_comparison(summaries,traces,policy_hashes)
        write_json(run/'COMPARISON.json',{'parity':comparison,'arms':summaries,
             'score_is_review_priority_not_probability':True,'no_new_web_gate':True,'independent_gold':False,
             'path_absence_is_not_safe':True,'quality_metric_from_fixture':None})
        s.update(status='B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE',model_inference_state='THREE_ARMS_COMPLETED',new_native_requests=comparison['new_native_requests'],warm_cache_hits=comparison['warm_cache_hits'])
    except (Exception,KeyboardInterrupt) as e:
        import traceback
        (private/'FAILURE.txt').write_text(traceback.format_exc())
        s['status']='B39B4_BLOCKED';s['blockers'].append(type(e).__name__+': '+str(e)[:1200])
    finally:
        event('FINAL_SOURCE_INPUT_AND_GATE_PARITY')
        try:
            after=baseline(a.work,a.repo,a.github,{})
            write_json(run/'AFTER.json',after);require(before is not None and before==after,'FROZEN_RELEASE_OR_GATE_CHANGED')
            for path,old in states.items():require(file_state(path)==old,'PINNED_INPUT_CHANGED:'+Path(path).name)
            if 'target' in locals() and target.is_dir():
                hashes={str(f.relative_to(target)):sha(f.read_bytes()) for f in sorted(target.rglob('*.java'))}
                require(hashes==inp['java_source_hashes'],'JAVA_SOURCE_CHANGED')
            s['input_files_checked_unchanged']=len(states)
        except Exception as e:s['status']='B39B4_BLOCKED';s['blockers'].append(type(e).__name__+': '+str(e)[:1200])
        for f in reversed(locks):f.close()
        s['elapsed_s']=round(time.monotonic()-began,3);s['current_stage']='FINISHED'
        write_json(run/'EXPORT_POLICY.json',{'private_sources':False,'raw_prompts':False,'raw_responses':False,'model_weights':False,
            'codeql_database':False,'raw_sarif_and_bqrs':False,'raw_opengrep':False,
            'local_full_results':'private/analysis/<arm>/result.json AND report.sarif',
            'metadata_only_result_zip':True,'public_github_release_approved':False})
        # Hash selected local results for provenance; do not traverse DB, toolchain or model trees.
        artifacts={}
        for root in (private/'analysis',private/'live',private/'policy79',private/'opengrep'):
            if root.exists():
                for f in sorted(root.rglob('*')):
                    if f.is_file() and not f.is_symlink() and f.stat().st_size<32*1024**2:
                        artifacts[str(f.relative_to(private))]=sha(f.read_bytes())
        write_json(run/'PRIVATE_RESULT_MANIFEST.json',artifacts);write_json(run/'00_RESULT.json',s)
        out,h=pack(run,a.downloads)
        print('\n===== B39B.4 RESULT =====',flush=True)
        for k,v in [('STATUS',s['status']),('BLOCKERS',len(s['blockers'])),('COMPLETED_ARMS',','.join(s['completed_arms'])),
                    ('OPENGREP_EXECUTION_STATE',s['opengrep_state']),('CODEQL_DATABASE_STATE',s['codeql_database_state']),
                    ('MODEL_EXECUTION_STATE',s['model_inference_state']),('VERIFIED_COMPLETED_NATIVE_REQUESTS',s['new_native_requests']),('NEW_TRAINING',False),('INDEPENDENT_GOLD',False),
                    ('WEB_GATE_CHANGED_BY_RUNNER',False),('RUN_DIR',run),('OUTPUT_ZIP',out),('OUTPUT_SHA256',h)]:print(str(k)+'='+str(v),flush=True)
        for b in s['blockers']:print('BLOCKER='+b,flush=True)
    return 0 if s['status']=='B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE' else 2

if __name__=='__main__':
    def interrupted(signum,frame):raise KeyboardInterrupt('SIGNAL_'+str(signum))
    signal.signal(signal.SIGTERM,interrupted)
    try:sys.exit(main())
    except Exception as e:print('B39B4_EARLY_BLOCKED='+str(e),flush=True);sys.exit(2)
