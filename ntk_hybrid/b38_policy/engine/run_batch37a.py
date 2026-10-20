#!/usr/bin/env python3
"""NTK B37A: scoped, genuine fresh-Java-ZIP hybrid CLI on WSL.

No reuse of B34/B35 CodeQL paths or labels. Stage3 uses the original IRIS
SAPipeline Stage 3 method in a separate git-archive snapshot; input candidates
come from the newly created database's exact compiler identities.

Explicit limitation: Java 21, JDK-only files, no external dependencies, no
project build scripts executed. Source policy recognizes actual System.getenv
calls in the newly extracted database (declared untrusted), NOT a model source.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import time
import traceback
import uuid
import zipfile

from ntk_b33.common import ADAPTER_CONFIG_SHA, ADAPTER_SHA, Blocker, COMMIT, digest, sha_file, write_json
from ntk_b33.patcher import apply
from ntk_b34.core import (emit_flow, load_scorer, read_calls, read_arguments,
                           parse_flows, to_sarif, SOURCE_POLICY)
from ntk_b34.pack_resolution import verify_and_options
from ntk_b34.toolchain import select_toolchain
from ntk_b37.semantic import POLICY, POLICY_SHA, adjudicate, calibrated_fusion
from vendor_batch33 import frozen_state, snapshot_from_git
from b34_helpers import (PACKS, OPENGREP_SHA, B33_NAME, B33_SHA, extract_b33,
                         local_pack_copy, execute)
from scanner import scan_offline, ScanError, RULE_ID
from secure_intake import secure_unpack, IntakeError

ROOT = Path(__file__).resolve().parent
ARMS = ('epoch_1','epoch_2')
MAX_CANDIDATES = 40
SCOPED_SOURCE = ('java.lang', 'System', 'getenv(java.lang.String)')


def ensure_safe_input(project: Path, workspace: Path) -> dict:
    if not project.is_file() or project.suffix.lower() != '.zip':
        raise Blocker('B37A_PROJECT_ZIP_MISSING')
    # Input is a local file chosen by the operator. No network download; no
    # build scripts from the ZIP are executed. Only Java source is extracted.
    size = project.stat().st_size
    if size > 16*1024*1024:
        raise Blocker('PROJECT_ZIP_OVER_16_MIB')
    proof = secure_unpack(project.read_bytes(), workspace)
    actual = sorted(workspace.rglob('*.java'))
    if not 1 <= len(actual) <= 24:
        raise Blocker('B37A_JDK_ONLY_REQUIRES_1_TO_24_JAVA_FILES')
    files = {str(p.relative_to(workspace)):sha_file(p) for p in actual}
    if any(p.is_symlink() or (not p.is_file() and not p.is_dir()) for p in workspace.rglob('*')):
        raise Blocker('NON_JAVA_OR_SPECIAL_SOURCE_IN_WORKSPACE')
    return dict(proof, java_source_hashes=files,
                project_origin='THIS_RUN_OPERATOR_PROVIDED_ZIP_NOT_B34_B35_FIXTURE',
                input_scope='TRUSTED_JDK_ONLY_NO_BUILD_SCRIPTS_NO_DEPENDENCY_RESOLUTION')


def command(argv, log, *, cwd, timeout=900, extra_env=None):
    extra_env = dict(extra_env or {})
    # Hide ambient Java agents/CLASSPATH. Preserve CODEQL-specific discovery env.
    extras = {'CODEQL_TELEMETRY_DISABLE':'1', 'SEMGREP_SEND_METRICS':'off',
              'OPENGREP_SEND_METRICS':'off', 'SEMGREP_ENABLE_VERSION_CHECK':'0',
              'OPENGREP_ENABLE_VERSION_CHECK':'0',
              'HF_HUB_OFFLINE':'1', 'TRANSFORMERS_OFFLINE':'1',
              'HF_HUB_DISABLE_TELEMETRY':'1', 'TOKENIZERS_PARALLELISM':'false',
              'PYTHONDONTWRITEBYTECODE':'1', 'GIT_OPTIONAL_LOCKS':'0'}
    extras.update(extra_env)
    return execute(argv,log,cwd=cwd,timeout=timeout,extra_env=extras)


def validate_local_assets(repo, b33, root):
    configs={arm:json.loads((b33/f'CONFIG_{arm}.json').read_text()) for arm in ARMS}
    base=Path(configs['epoch_1']['base_dir'])
    expected=json.loads((b33/'inputs/BASE_MANIFEST.json').read_text())['files']
    if not base.is_dir():raise Blocker('PINNED_BASE_DIR_MISSING')
    hashes={str(p.relative_to(base)):sha_file(p) for p in sorted(base.rglob('*')) if p.is_file()}
    if expected!=hashes or digest(hashes)!=configs['epoch_1']['base_fingerprint']:
        raise Blocker('PINNED_LOCAL_BASE_BYTES_DRIFT')
    for arm in ARMS:
        ad=Path(configs[arm]['adapter_dir'])
        for name, expected_sha in (('adapter_model.safetensors',ADAPTER_SHA[arm]),
                                   ('adapter_config.json',ADAPTER_CONFIG_SHA)):
            if not (ad/name).is_file() or sha_file(ad/name)!=expected_sha:
                raise Blocker('LOCAL_LORA_ADAPTER_DRIFT: '+arm+' '+name)
    write_json(root/'B37A_PINNED_LORA_PROOF.json',{
        'base_sha_fingerprint':digest(hashes),
        'adapters':{arm:{'adapter_dir': configs[arm]['adapter_dir'],
                         'adapter_model_sha256':ADAPTER_SHA[arm],
                         'adapter_config_sha256':ADAPTER_CONFIG_SHA} for arm in ARMS}})
    return configs


def preserve_raw_opengrep(payload, parsed, target, run):
    if len(payload['results']) != len(parsed):
        raise Blocker('OPENGREP_NORMALIZATION_CHANGED_FINDING_COUNT')
    rows=[]
    for row, observation in zip(payload['results'], parsed):
        safe=deepcopy(row)
        safe['scanner_check_id']=row['check_id']
        safe['check_id']=RULE_ID  # canonical derivative only; original bytes separately archived
        safe['path']=str(target/observation['uri'])
        rows.append(safe)
    derived={**payload,'results':rows}
    write_json(run/'OPENGREP_ORIGINAL.json',payload)
    write_json(run/'OPENGREP_CANONICAL_DERIVED.json',derived)
    write_json(run/'OPENGREP_RULE_ID_PROVENANCE.json',[
        {'observed':r['check_id'],'canonical':RULE_ID,'uri':p['uri']}
        for r,p in zip(payload['results'],parsed)])
    return derived


def source_inventory(cases, calls):
    records=[x for x in calls if (x['package'],x['class'],x['compiler_signature'])==SCOPED_SOURCE]
    # A source is a qualified method *call in the fresh Java database*, not
    # a fabricated fixed line in an old fixture.
    return {'cwe':'CWE-89','source_kind':'JAVA_SYSTEM_GETENV_STRING_RETURN',
            'callsite_provenance':'NEW_CODEQL_DATABASE_EXACT_DECLARING_CLASS_AND_OVERLOAD',
            'assumption':'EXPLICITLY_DECLARED_UNTRUSTED_FOR_SCOPED_DEMO_NOT_LLM_DISCOVERED',
            'source_count':len(records),'callsites':records,
            'not_general_source_discovery':True}


def assert_guarded_query(qfile: Path, expected_generated: str):
    text=qfile.read_text()
    if text != expected_generated or '__SINK_BODY__' in text:
        raise Blocker('GUARDED_CODEQL_SOURCE_CHANGED')
    if 'ntk.b34' in text or 'Case01' in text:
        raise Blocker('OLD_FIXTURE_REFERENCE_IN_LIVE_QUERY')


def require_b37a_evidence(result:dict, opengrep:dict, cases:list, source:dict, arm:str):
    # An absence of a path is not a false-positive verdict. This operation
    # intentionally limits PASS to a demonstrable end-to-end positive path.
    flow_count = result['flow_count']
    if flow_count and not source['source_count']:
        raise Blocker('CODEQL_FLOW_WITHOUT_DISCOVERED_SOURCE_CALL')
    if result['retained_opengrep'] != len(opengrep['results']):
        raise Blocker('OPENGREP_FINDING_LOST')
    if not cases:raise Blocker('EMPTY_CODEQL_CANDIDATE_MANIFEST')


def bundle(run:Path, downloads:Path, summary:dict):
    excluded={'database','snapshot','codeql-cache','query-compilation-cache',
              'b33_evidence','uploaded_project','classes','javac_codeql','javac_preflight','toolchain_recovery'}
    included=[]; excluded_paths=[]
    for path in sorted(run.rglob('*')):
        if not path.is_file() or path.is_symlink():continue
        rel=path.relative_to(run)
        if rel.parts[0] in excluded or path.stat().st_size>32*1024*1024:
            excluded_paths.append({'path':str(rel),'bytes':path.stat().st_size})
        else:included.append(path)
    write_json(run/'EXCLUDED_FILES.json',excluded_paths)
    included.append(run/'EXCLUDED_FILES.json')
    # Project Java source remains only in RUN_DIR; report ZIP never includes the uploaded source.
    write_json(run/'OUTPUT_MANIFEST.json', {str(p.relative_to(run)):sha_file(p) for p in included})
    included.append(run/'OUTPUT_MANIFEST.json')
    out=downloads/(run.name+'_result.zip')
    if out.exists():raise Blocker('REFUSE_OUTPUT_OVERWRITE')
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for p in included:z.write(p,str(p.relative_to(run)))
    h=sha_file(out)
    (downloads/(out.name+'.sha256')).write_text(h+'  '+out.name+'\n')
    print('\n===== BATCH 37A RESULT =====',flush=True)
    for name,value in [('STATUS',summary['status']),('MODE','NEW_JAVA_ZIP_REAL_HYBRID_SCOPED'),
                       ('CODEQL_DATAFLOW',summary.get('codeql_dataflow')),
                       ('SOURCE_MODEL',summary.get('source_model')),
                       ('FROZEN_REPO_UNCHANGED',summary.get('frozen_unchanged')),
                       ('RUN_DIR',run),('OUTPUT_ZIP',out),('OUTPUT_SHA256',h)]:
        print(name+'='+str(value),flush=True)
    if 'blocker' in summary:print('BLOCKER='+str(summary['blocker']),flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--project-zip',type=Path,required=True)
    parser.add_argument('--work',type=Path,default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    parser.add_argument('--repo',type=Path,default=Path.home()/'iris')
    parser.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'))
    parser.add_argument('--arm',choices=('epoch_1','epoch_2','both'),default='epoch_1')
    args=parser.parse_args()
    run=args.work/'batch37a_new_project_runs'/('batch37a_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:6])
    run.mkdir(parents=True, exist_ok=False)
    began=time.monotonic(); before=None
    arms=ARMS if args.arm=='both' else (args.arm,)
    summary={'status':'B37A_BLOCKED','scope':'NEW_OPERATOR_SELECTED_JDK_ONLY_JAVA_ZIP_CWE89',
             'arms':{},'source_model':SOURCE_POLICY, 'source_discovered_by_llm':False,
             'codeql_dataflow':'NOT_EXECUTED','independent_gold':False,
             'Stage4_posthoc':'NOT_EXECUTED','full_SAPipeline_run':'NOT_EXECUTED',
             'training':'NOT_EXECUTED','CWE22_78_79':'NOT_EXECUTED',
             'web_ui':'NOT_CONNECTED_IN_B37A','query_packs_network_install':'NOT_EXECUTED',
             'scoring_semantics':'V2_2_PRIORITY_ONLY_NOT_VULNERABILITY_PROBABILITY'}
    try:
        if args.repo.resolve()==run.resolve() or args.repo.resolve() in run.resolve().parents:
            raise Blocker('RUN_DIR_INSIDE_FROZEN_REPO')
        if not args.downloads.is_dir():raise Blocker('DOWNLOADS_DIR_MISSING')
        before=frozen_state(args.repo)
        write_json(run/'FROZEN_BEFORE.json',before)
        if before['head']!=COMMIT or before['status_porcelain']:
            raise Blocker('FROZEN_REPOSITORY_NOT_EXPECTED_COMMIT_OR_DIRTY')
        print('===== B37A: SECURELY IMPORT NEW JAVA ZIP =====',flush=True)
        target=run/'uploaded_project'
        inp=ensure_safe_input(args.project_zip,target)
        write_json(run/'UPLOADED_INPUT_PROVENANCE.json',inp)
        mlpy=args.work/'.ntk_v5_lora_venv/bin/python'
        if not mlpy.is_file():raise Blocker('ML_PYTHON_NOT_FOUND')
        # First do the genuine local scanner. Browser's B35 demo is never consulted.
        print('===== B37A: REAL OFFLINE OPENGREP ON NEW CODE =====',flush=True)
        ogbinary=Path.home()/'.opengrep/cli/v1.25.0/opengrep'
        if not ogbinary.is_file() or sha_file(ogbinary)!=OPENGREP_SHA:
            raise Blocker('PINNED_OPENGREP_BINARY_MISSING_OR_CHANGED')
        ogresult=scan_offline(run,target,binary=ogbinary)
        write_json(run/'OPENGREP_VERIFIED_EXECUTION.json',ogresult)
        rawog=json.loads((run/'raw_opengrep.json').read_text())
        og=preserve_raw_opengrep(rawog,ogresult['findings'],target,run)
        summary['opengrep_findings']=len(og['results'])
        print('===== B37A: VERIFY FROZEN MODEL AND STAGE3 PROTOCOL =====',flush=True)
        old=run/'b33_evidence'
        b33=extract_b33(args.downloads/B33_NAME,old)
        cfgs=validate_local_assets(args.repo,old,run)
        if before!=json.loads((old/'FROZEN_BEFORE.json').read_text()):
            raise Blocker('FROZEN_STATE_CHANGED_SINCE_B33')
        snapshot=run/'snapshot'; snapshot_from_git(args.repo,snapshot)
        patch=apply(snapshot,ROOT)
        (run/'STAGE3_PATCH.diff').write_text(patch.pop('diff'))
        write_json(run/'STAGE3_PATCH_PROOF.json',patch)
        shutil.copy2(old/'inputs/runtime_protocol.json',run/'runtime_protocol.json')
        scorer_path=snapshot/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py'
        scorer=load_scorer(scorer_path)
        shutil.copy2(scorer_path,run/'SCORER_FROZEN.py')
        print('===== B37A: VERIFY LOCAL CODEQL AND LOCKED QL PACKS =====',flush=True)
        source_codeql=args.repo/'codeql/codeql'
        if not source_codeql.is_file():raise Blocker('CODEQL_ORIGINAL_EXECUTABLE_MISSING')
        chosen=select_toolchain(source_codeql,args.work,args.downloads,run,allow_download=False)
        codeql=chosen.executable
        cache_root=run/'codeql-cache'
        pack_report=local_pack_copy(args.repo,cache_root/'packages')
        write_json(run/'QLPACK_MANIFEST.json',pack_report)
        additional,resolution=verify_and_options(pack_report,ROOT/'B34R2_OBSERVED_QLPACK_PINS.json',
                                                 run=run,common_caches=cache_root)
        write_json(run/'CODEQL_PACK_RESOLUTION_PROOF.json',resolution)
        qp=run/'queries';shutil.copytree(ROOT/'queries',qp)
        lock=snapshot/'src/queries/codeql-pack.lock.yml'
        shutil.copy2(lock,qp/'codeql-pack.lock.yml')
        cachearg='--common-caches='+str(cache_root)
        common_opts=[*additional,cachearg]
        resource_opts=['--threads=1','--ram=3072']
        execute([codeql,'pack','resolve-dependencies','--mode=verify',*common_opts,qp],
                run/'CODEQL_PACK_RESOLVE.log',cwd=run,timeout=180)
        # Exact compiler checks before expensive DB creation/GPU.
        print('===== B37A: COMPILE ALL CODEQL QUERY TYPES BEFORE DB/GPU =====',flush=True)
        for name in ('ApiCalls','ArgumentSpans'):
            command([codeql,'query','compile','--check-only',qp/(name+'.ql'),*common_opts,*resource_opts],
                    run/('COMPILE_CHECK_'+name+'.log'),cwd=run,timeout=600)
        template=(qp/'Flow.template').read_text()
        # compile a no-sink query before the database build, so the query
        # shape is checked without relying on any hypothetical model labels.
        no_sink=template.replace('__ARM__','epoch_1').replace('__SINK_BODY__','1 = 0')
        (qp/'FLOW_COMPILE_ONLY.ql').write_text(no_sink)
        command([codeql,'query','compile','--check-only',qp/'FLOW_COMPILE_ONLY.ql',*common_opts,*resource_opts],
                run/'COMPILE_CHECK_FLOW.log',cwd=run,timeout=600)
        print('===== B37A: TRUSTED JDK-ONLY JAVAC PRECHECK =====',flush=True)
        version=command(['javac','-version'],run/'JAVAC_VERSION.log',cwd=run,timeout=30)
        if not re.search(r'\b21\.',version):raise Blocker('JDK21_REQUIRED_FOR_SCOPED_JAVA_INTEGRATION')
        command([mlpy,'-B',ROOT/'build_jdk_only.py',target,run/'javac_preflight'],
                run/'JAVAC_PREFLIGHT.log',cwd=run,timeout=180)
        print('===== B37A: NEW REAL CODEQL DATABASE =====',flush=True)
        db=run/'database'
        builder=' '.join(shlex.quote(str(x)) for x in [mlpy,'-B',ROOT/'build_jdk_only.py',target,run/'javac_codeql'])
        argsdb=[codeql,'database','create',db,'--language=java','--source-root='+str(target),
                '--command='+builder,'--no-pre-finalize',cachearg,
                *chosen.database_options,*resource_opts]
        command(argsdb,run/'DATABASE_CREATE.log',cwd=run,timeout=1200)
        if not (db/'db-java').is_dir() or not (db/'codeql-database.yml').is_file() or not (db/'src.zip').is_file():
            raise Blocker('NEW_JAVA_DATABASE_EVIDENCE_MISSING')
        write_json(run/'DATABASE_PROOF.json',{'created_in_this_run':True,
            'new_project_sha256':inp['archive_sha256'],'db_path':str(db),
            'db_metadata_sha256':sha_file(db/'codeql-database.yml'),
            'src_zip_sha256':sha_file(db/'src.zip'),
            'build_mode':'TRUSTED_JAVAC_PROC_NONE_JDK_ONLY',
            'pre_finalize':'SKIPPED_ONLY_JAVA_SOURCE_EXTRACTED_NO_XML'})
        print('===== B37A: GET API IDENTITIES FROM THIS DATABASE =====',flush=True)
        compilation=['--no-default-compilation-cache','--compilation-cache='+str(run/'query-compilation-cache')]
        for name in ('ApiCalls','ArgumentSpans'):
            bqrs=run/(name+'.bqrs')
            command([codeql,'query','run',qp/(name+'.ql'),'--database='+str(db),
                     '--output='+str(bqrs),*common_opts,*compilation,*resource_opts],
                    run/(name+'_QUERY.log'),cwd=run,timeout=1200)
            command([codeql,'bqrs','decode',bqrs,'--format=csv',
                     '--output='+str(run/(name+'.csv'))],run/(name+'_DECODE.log'),cwd=run,timeout=180)
        cases,calls=read_calls(run/'ApiCalls.csv',target)
        argslist=read_arguments(run/'ArgumentSpans.csv',target)
        if len(cases)>MAX_CANDIDATES:raise Blocker('CANDIDATE_LIMIT_EXCEEDED')
        write_json(run/'CANDIDATES_FROM_NEW_CODEQL_DB.json',cases)
        write_json(run/'CALLS_FROM_NEW_CODEQL_DB.json',calls)
        write_json(run/'ARGUMENTS_FROM_NEW_CODEQL_DB.json',argslist)
        sources=source_inventory(cases,calls)
        write_json(run/'CODEQL_DISCOVERED_SOURCE_CALLS.json',sources)
        summary['source_count']=sources['source_count']
        summary['codeql_dataflow']='DATABASE_AND_CALLSITE_QUERIES_EXECUTED'
        # Stage3 local models classify candidates derived from THIS db; no B34 role replay.
        config0=cfgs['epoch_1']
        common=dict(config0,snapshot=str(snapshot),frozen_root=str(args.repo),
                    ml_python=str(mlpy),protocol_path=str(run/'runtime_protocol.json'),
                    cases=cases,base_fingerprint=config0['base_fingerprint'])
        importcfg=run/'IMPORT_CONFIG.json';write_json(importcfg,common)
        candidates=list(dict.fromkeys([os.environ.get('NTK_IRIS_PYTHON',''),
                        b33.get('iris_host_python',''),str(mlpy)]))
        host=None
        for i,candidate in enumerate(candidates):
            if not candidate or not Path(candidate).is_file():continue
            try:
                command([candidate,'-B',ROOT/'run_native37.py',importcfg,'--import-only'],
                        run/('IRIS_IMPORT_'+str(i)+'.log'),cwd=snapshot,timeout=180)
                host=candidate;break
            except Blocker:
                continue
        if host is None:raise Blocker('CANNOT_IMPORT_PINNED_IRIS_WITH_INSTALLED_PYTHON')
        summary['iris_host_python']=host
        for arm in arms:
            print('===== B37A: LOCAL IRIS/LoRA LIVE STAGE3 '+arm+' =====',flush=True)
            cfg=dict(common,arm=arm,output_dir=str(run/'live'/arm),
                     cache_dir=str(run/'cache'/arm),
                     adapter_dir=cfgs[arm].get('adapter_dir'),
                     adapter_sha256=cfgs[arm].get('adapter_sha256'),
                     adapter_config_sha256=cfgs[arm].get('adapter_config_sha256'))
            cfgpath=run/('CONFIG_'+arm+'.json');write_json(cfgpath,cfg)
            command([host,'-B','-u',ROOT/'run_native37.py',cfgpath],
                    run/('LIVE_'+arm+'.log'),cwd=snapshot,timeout=2400)
            liveroot=run/'live'/arm
            stage3=json.loads((liveroot/'SUMMARY.json').read_text())
            if stage3['cold_live_responses']!=len(cases) or stage3['warm_exact_cache_hits']!=len(cases):
                raise Blocker('LIVE_STAGE3_COVERAGE_NOT_COMPLETE')
            sinks=json.loads((liveroot/'cold/cwe-89/llm_labelled_sink_apis.json').read_text())
            eligible,decisions=adjudicate(cases,sinks)
            out=run/'analysis'/arm;out.mkdir(parents=True)
            write_json(out/'RAW_STAGE3_SINK_LABELS.json',sinks)
            write_json(out/'SEMANTIC_SINK_DECISIONS.json',decisions)
            generated,proof=emit_flow(template,cases,eligible,arm)
            flowfile=qp/('Flow_'+arm+'.ql');flowfile.write_text(generated)
            assert_guarded_query(flowfile,generated)
            write_json(out/'GUARDED_EXACT_OVERLOAD_BINDINGS.json',proof)
            print('===== B37A: CODEQL PATH QUERY WITH LIVE LoRA LABELS '+arm+' =====',flush=True)
            command([codeql,'query','compile','--check-only',flowfile,*common_opts,*resource_opts],
                    run/('FLOW_COMPILE_'+arm+'.log'),cwd=run,timeout=600)
            command([codeql,'database','run-queries',db,flowfile,*common_opts,*compilation,*resource_opts],
                    run/('FLOW_RUN_'+arm+'.log'),cwd=run,timeout=1200)
            sarif=out/'codeql.sarif'
            command([codeql,'database','interpret-results',db,flowfile,
                     '--format=sarifv2.1.0','--output='+str(sarif),
                     '--max-paths=4',*common_opts],run/('FLOW_SARIF_'+arm+'.log'),cwd=run,timeout=600)
            bqrsfiles=list((db/'results').rglob(flowfile.stem+'.bqrs'))
            if len(bqrsfiles)!=1:raise Blocker('NO_UNIQUE_REAL_FLOW_BQRS: '+arm)
            shutil.copy2(bqrsfiles[0],out/'flow.bqrs')
            flows=parse_flows(json.loads(sarif.read_text()),target,calls,argslist,proof)
            if flows and not sources['source_count']:
                raise Blocker('SOURCE_CALLSITE_NOT_IN_NEW_DATABASE')
            for f in flows:
                f['source_policy']=SOURCE_POLICY
                f['source_discovered_by_llm']=False
                f['database_created_in_this_run']=True
                f['input_project_sha256']=inp['archive_sha256']
            trace=[json.loads(line) for line in (liveroot/'native_trace.jsonl').read_text().splitlines() if line.strip()]
            fused=calibrated_fusion(og,flows,trace,calls,target,scorer,decisions)
            # B35 guard supports these SQL overloads only; query already generated
            # from admitted sinks, no posthoc fake flow suppression.
            write_json(out/'CODEQL_VERIFIED_PATHS.json',flows)
            write_json(out/'FUSED_FINDINGS.json',fused)
            write_json(out/'FUSED_FINDINGS.sarif',to_sarif(fused))
            result={'arm':arm,'stage3':stage3,'flow_count':len(flows),
                    'retained_opengrep':sum(r['origin']=='OPENGREP' for r in fused),
                    'additional_codeql':sum(r['origin']=='CODEQL_ADDITIONAL' for r in fused),
                    'source_count_from_new_database':sources['source_count'],
                    'scanned_project_sha256':inp['archive_sha256'],
                    'native_candidate_count':len(cases),
                    'model_roles_are_not_vulnerability_ground_truth':True}
            require_b37a_evidence(result,og,cases,sources,arm)
            summary['arms'][arm]=result
            summary['codeql_dataflow']='REAL_QUERY_BQRS_AND_SARIF_EXECUTED'
            write_json(run/'00_PARTIAL_PROGRESS.json',summary)
        positive=any(s['flow_count']>0 for s in summary['arms'].values())
        sample=json.loads((ROOT/'SAMPLE_EXPECTATIONS.json').read_text())
        summary['sample_expected_check']='NOT_APPLICABLE_OPERATOR_SUPPLIED_DIFFERENT_ZIP'
        sample_correct=True
        if inp['archive_sha256']==sample['sample_zip_sha256']:
            expected=sample['cases']
            for arm in arms:
                existing=json.loads((run/'analysis'/arm/'CODEQL_VERIFIED_PATHS.json').read_text())
                observed={uri:any(f['location']['uri']==uri for f in existing) for uri in expected}
                valid=observed==expected
                summary['arms'][arm]['sample_flow_observed']=observed
                summary['arms'][arm]['sample_flow_expected']=expected
                summary['arms'][arm]['sample_regression_match']=valid
                sample_correct=sample_correct and valid
            summary['sample_expected_check']='PASS' if sample_correct else 'NEEDS_REVIEW'
        summary['status']=('B37A_SCOPED_HYBRID_COMPLETE' if positive and
                           sources['source_count'] and sample_correct else 'B37A_COMPLETED_NEEDS_REVIEW')
        summary['gate']='NEW_JDK_ONLY_PROJECT_ONE_CWE_WITH_DECLARED_SOURCE_POLICY'
    except Exception as exc:
        summary['blocker']=str(exc)
        (run/'FAILURE.txt').write_text(traceback.format_exc())
        summary['status']='B37A_BLOCKED'
    finally:
        try:
            after=frozen_state(args.repo)
            write_json(run/'FROZEN_AFTER.json',after)
            summary['frozen_unchanged']=(before is not None and before==after)
            if not summary['frozen_unchanged']:
                summary['status']='B37A_BLOCKED'
                summary['blocker']='FROZEN_REPO_STATE_CHANGED'
        except Exception as exc:
            summary['frozen_unchanged']=False
            summary['status']='B37A_BLOCKED';summary['blocker']='FROZEN_CHECK_FAILED: '+str(exc)
        summary['wall_time_s']=time.monotonic()-began
        write_json(run/'00_SUMMARY.json',summary)
        if args.downloads.is_dir():
            bundle(run,args.downloads,summary)
        else:print('RUN_DIR='+str(run),'BLOCKER='+summary.get('blocker',''),sep='\n')
    return 0 if summary['status']=='B37A_SCOPED_HYBRID_COMPLETE' else 3 if summary['status']=='B37A_COMPLETED_NEEDS_REVIEW' else 2

if __name__=='__main__':
    sys.exit(main())
