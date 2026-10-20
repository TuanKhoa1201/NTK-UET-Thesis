#!/usr/bin/env python3
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid
import zipfile
from ntk_b33.common import ADAPTER_SHA, ADAPTER_CONFIG_SHA, COMMIT, Blocker, digest, sha_file, write_json
from ntk_b33.patcher import apply
from vendor_batch33 import frozen_state, snapshot_from_git
from ntk_b34.toolchain import select_toolchain
from ntk_b34.finalize import validate_java_only_fixture, database_create_argv
from ntk_b34.pack_resolution import verify_and_options
from ntk_b34.core import (SOURCE_POLICY, emit_flow, fuse, load_scorer, normalized_uri, parse_flows,
                         read_arguments, read_calls, to_sarif)

ROOT = Path(__file__).resolve().parent
B33_NAME = 'batch33_20261018T144300Z_6460a4_result.zip'
B33_SHA = '3fb7369e0c3d23edb3994262db31f04b7dd84f369a1b7656fadee768aa1907bb'
OPENGREP_SHA = '9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33'
PACKS = {'controlflow':'2.0.35', 'dataflow':'2.1.7', 'java-all':'9.1.2',
         'java-queries':'1.11.4', 'mad':'1.0.51', 'quantum':'0.0.29',
         'rangeanalysis':'1.0.51', 'regex':'1.0.51', 'ssa':'2.0.27',
         'suite-helpers':'1.0.51', 'threat-models':'1.0.51', 'tutorial':'1.0.51',
         'typeflow':'1.0.51', 'typetracking':'2.0.35', 'util':'2.0.38', 'xml':'1.0.51'}


def diagnostic_sink_preview(root: Path, query_dir: Path):
    """Compile a separate, declared MANUAL diagnostic flow before any GPU call.

    This is NOT an LLM-generated label, not a benchmark prediction, and not
    included in scoring or per-model path evidence.
    """
    cases = [
        {
            'package': 'java.sql', 'class': 'Statement',
            'method': method, 'signature': ret + ' ' + method + '(String p0)',
            'compiler_signature': method + '(java.lang.String)',
            'arity': 1, 'cwe': '89',
        }
        for method, ret in (('executeQuery', 'ResultSet'), ('execute', 'boolean'))
    ]
    labels = [
        {k: c[k] for k in ('package', 'class', 'method', 'signature')} |
        {'type': 'sink', 'sink_args': ['p0']}
        for c in cases
    ]
    ql, proof = emit_flow((root/'queries/Flow.template').read_text(), cases, labels, 'base')
    ql = ql.replace('@id ntk/b34/cwe89-base', '@id ntk/b34/diagnostic-explicit-source-and-sink')
    ql = ql.replace('NTK B34 local IRIS sink flow for CWE-89',
                    'NTK B34R4 MANUAL CODEQL DIAGNOSTIC - NOT LLM EVIDENCE')
    ql = ql.replace('Fixed explicitly declared test source to strict live IRIS-labelled exact-overload sinks.',
                    'Developer-declared integration diagnostics; NOT an LLM result or gold.')
    location = query_dir/'Flow_DIAGNOSTIC_MANUAL.ql'
    location.write_text(ql, encoding='utf-8')
    write_json(query_dir.parent/'MANUAL_DIAGNOSTIC_POLICY.json', {
        'meaning': 'TEST_QUERY_ONLY_NOT_LLM_DETECTED_NOT_GOLD_NOT_FOR_SCORING',
        'source': SOURCE_POLICY,
        'sinks': [c['compiler_signature'] for c in cases],
        'query_sha256': sha_file(location),
    })
    return location, proof


def check_ql_compilation(codeql, path, run, additional_packs, cachearg, resources, label):
    """Use the REAL compiler and pinned packs, not a syntax heuristic."""
    return execute([codeql, 'query', 'compile', '--check-only', path,
                    *additional_packs, cachearg, *resources],
                   run/('COMPILE_CHECK_'+label+'.log'), cwd=run, timeout=600)



def validate_opengrep_results(payload: object, target: Path, expected_uris: set[str]) -> dict:
    """Validate actual OpenGrep JSON without altering any finding or benchmark label."""
    if not isinstance(payload, dict) or not isinstance(payload.get('results'), list):
        raise Blocker('OPENGREP_JSON_SCHEMA_INVALID')
    if payload.get('errors'):
        raise Blocker('OPENGREP_SCAN_REPORTED_ERRORS')
    results = payload['results']
    if not results or len(results) > 100:
        raise Blocker('OPENGREP_DEMO_UNEXPECTED_RESULT_VOLUME')
    observed = {}
    rule_id = 'ntk-b34-java-sql-call-review'
    for row in results:
        if not isinstance(row, dict) or row.get('check_id') != rule_id:
            raise Blocker('OPENGREP_UNEXPECTED_RULE_OR_ROW')
        uri = normalized_uri(row.get('path', ''), target)
        if uri not in expected_uris or not (target / uri).is_file():
            raise Blocker('OPENGREP_MATCH_OUTSIDE_EXPECTED_FIXTURE')
        for key in ('start', 'end'):
            loc = row.get(key)
            if not isinstance(loc, dict) or type(loc.get('line')) is not int or loc['line'] < 1:
                raise Blocker('OPENGREP_INVALID_POSITION')
            if type(loc.get('col', 1)) is not int or loc.get('col', 1) < 1:
                raise Blocker('OPENGREP_INVALID_COLUMN')
        start, end = row['start'], row['end']
        if (start['line'], start.get('col', 1)) > (end['line'], end.get('col', 1)):
            raise Blocker('OPENGREP_REVERSED_SPAN')
        if not isinstance(row.get('extra'), dict):
            raise Blocker('OPENGREP_MISSING_EXTRA')
        observed[uri] = observed.get(uri, 0) + 1
    if set(observed) != expected_uris:
        raise Blocker('OPENGREP_DEMO_EXPECTED_CASE_COVERAGE_MISMATCH')
    return {'findings': len(results), 'case_counts': dict(sorted(observed.items())),
            'rule_id': rule_id, 'classification': 'CALL_PRESENCE_ONLY_NOT_GOLD_OR_VULNERABILITY'}


def run_opengrep_preflight(opengrep: Path, mlpy: Path, target: Path, run: Path,
                           expected_uris: set[str]) -> dict:
    """Use only capabilities verified in OpenGrep 1.25.0 help; fail before CodeQL/GPU."""
    help_text = execute([opengrep, 'scan', '--help'], run/'OPENGREP_SCAN_HELP.log',
                        cwd=target, timeout=30)
    for flag in ('--config', '--json', '--output'):
        if flag not in help_text:
            raise Blocker('OPENGREP_PINNED_CLI_MISSING_REQUIRED_OPTION: ' + flag)
    outfile = run/'OPENGREP_RAW.json'
    proof = run/'OPENGREP_NETWORK_ISOLATION.json'
    argv = [str(mlpy), '-B', str(ROOT/'opengrep_offline_exec.py'), str(proof),
            str(opengrep.resolve()), 'scan', '--config', str(target/'opengrep_demo_rules.yml'),
            '--json', '--output', str(outfile), str(target/'src')]
    execute(argv, run/'OPENGREP.log', cwd=target, timeout=180)
    if not outfile.is_file() or not proof.is_file():
        raise Blocker('OPENGREP_OFFLINE_OUTPUT_OR_ISOLATION_PROOF_MISSING')
    isolation = json.loads(proof.read_text())
    if isolation.get('status') != 'INHERITED_SECCOMP_INSTALLED_BEFORE_EXEC':
        raise Blocker('OPENGREP_NETWORK_ISOLATION_UNPROVEN')
    try:
        payload = json.loads(outfile.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise Blocker('OPENGREP_JSON_UNREADABLE') from exc
    evidence = validate_opengrep_results(payload, target, expected_uris)
    evidence.update({'status': 'REAL_PINNED_OPENGREP_SCAN_PASS',
                     'opengrep_sha256': sha_file(opengrep),
                     'raw_json_sha256': sha_file(outfile),
                     'rule_sha256': sha_file(target/'opengrep_demo_rules.yml'),
                     'source_root': str(target.resolve()),
                     'network_policy': isolation['network'],
                     'metrics': 'DISABLED_BY_OFFLINE_INET_SECCOMP_AND_ENV',
                     'note': 'Real OpenGrep scan; rule is demo call-presence, not B29 benchmark.'})
    write_json(run/'OPENGREP_PREFLIGHT.json', evidence)
    return payload


def execute(argv, log: Path, *, cwd=None, timeout=900, extra_env=None):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GIT_OPTIONAL_LOCKS='0',
               HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1',
               SEMGREP_SEND_METRICS='off', OPENGREP_SEND_METRICS='off',
               SEMGREP_ENABLE_VERSION_CHECK='0', OPENGREP_ENABLE_VERSION_CHECK='0')
    if extra_env:
        env.update(extra_env)
    log.parent.mkdir(parents=True, exist_ok=True)
    write_json(log.with_suffix('.command.json'), {'argv': list(map(str, argv)), 'cwd': str(cwd),
                                                  'timeout_seconds': timeout})
    with log.open('w', encoding='utf-8') as f:
        p = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env, stdout=f,
                             stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(p.pid, signal.SIGKILL); p.wait()
            raise Blocker('COMMAND_TIMEOUT: ' + log.name) from exc
    if rc:
        raise Blocker('COMMAND_FAILED_%d: %s\n%s' % (rc, log, log.read_text(errors='replace')[-1800:]))
    return log.read_text(encoding='utf-8', errors='replace')


def extract_b33(path: Path, destination: Path):
    if not path.is_file() or sha_file(path) != B33_SHA:
        raise Blocker('B33_RESULT_MISSING_OR_SHA_MISMATCH: ' + str(path))
    with zipfile.ZipFile(path) as z:
        if sum(i.file_size for i in z.infolist()) > 128 * 1024 * 1024:
            raise Blocker('B33_ARCHIVE_SIZE_GUARD')
        names = z.namelist()
        if len(set(names)) != len(names):
            raise Blocker('DUPLICATE_ZIP_MEMBERS')
        for i in z.infolist():
            p = PurePosixPath(i.filename)
            if p.is_absolute() or '..' in p.parts or ((i.external_attr >> 16) & 0o170000) == 0o120000:
                raise Blocker('UNSAFE_ARCHIVE_ENTRY')
        z.extractall(destination)
    manifest = json.loads((destination / 'OUTPUT_MANIFEST.json').read_text())
    for name, expected in manifest.items():
        if sha_file(destination / name) != expected:
            raise Blocker('B33_MEMBER_SHA_MISMATCH: ' + name)
    summary = json.loads((destination / '00_SUMMARY.json').read_text())
    if summary['status'] != 'B33_NATIVE_STAGE3_INTEGRATION_COMPLETE' or not summary['frozen_unchanged']:
        raise Blocker('B33_CORE_EVIDENCE_NOT_COMPLETE')
    return summary


def local_pack_copy(repo: Path, out: Path):
    roots = [Path.home()/'.codeql/packages', repo/'codeql/qlpacks',
             repo/'codeql', Path.home()/'.codeql/qlpacks']
    override = os.environ.get('NTK_CODEQL_PACK_ROOT')
    if override:
        roots.insert(0, Path(override))
    report = {}
    for name, version in PACKS.items():
        found = None
        for root in roots:
            for p in (root/'codeql'/name/version, root/name/version):
                config = p/'qlpack.yml'
                if not config.is_file():
                    continue
                text = config.read_text(encoding='utf-8')
                if (re.search(r'^name:\s*[\"\x27]?codeql/' + re.escape(name) + r'[\"\x27]?\s*$', text, re.M)
                    and re.search(r'^version:\s*[\"\x27]?' + re.escape(version) + r'[\"\x27]?\s*$', text, re.M)):
                    found = p; break
            if found:
                break
        if found is None:
            raise Blocker('PINNED_LOCAL_CODEQL_PACK_MISSING: codeql/%s@%s; no network installation attempted' % (name, version))
        target = out/'codeql'/name/version
        shutil.copytree(found, target, symlinks=False,
                        ignore=shutil.ignore_patterns('.cache', '__pycache__', '.git'))
        files = {str(p.relative_to(target)): sha_file(p) for p in sorted(target.rglob('*')) if p.is_file()}
        report['codeql/'+name] = {'version': version, 'original_path': str(found),
                                 'copy_path': str(target), 'files': files, 'fingerprint': digest(files)}
    return report


def pack_result(run: Path, downloads: Path, summary: dict):
    # Large executable/cache/database assets remain local; the proof records identify exclusions.
    excluded_roots = {'snapshot', 'qlpacks', 'codeql-cache', 'database', 'cache', 'b33_evidence', 'query-compilation-cache', 'toolchain_recovery'}
    included, excluded = [], []
    for p in sorted(run.rglob('*')):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(run)
        if rel.parts[0] in excluded_roots or p.stat().st_size > 32 * 1024 * 1024:
            excluded.append({'path': str(rel), 'bytes': p.stat().st_size,
                             'reason': 'LARGE_OR_REPRODUCIBLE_LOCAL_ASSET_RETAINED_IN_RUN_DIR'})
            continue
        included.append(p)
    write_json(run/'EXCLUDED_FILES.json', excluded); included.append(run/'EXCLUDED_FILES.json')
    write_json(run/'OUTPUT_MANIFEST.json', {str(p.relative_to(run)): sha_file(p) for p in included})
    included.append(run/'OUTPUT_MANIFEST.json')
    dst = downloads/(run.name+'_result.zip')
    if dst.exists():
        raise Blocker('REFUSE_OVERWRITE_OUTPUT_ZIP')
    with zipfile.ZipFile(dst, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for p in included:
            z.write(p, str(p.relative_to(run)))
    checksum = sha_file(dst)
    dst.with_suffix('.zip.sha256').write_text(checksum+'  '+dst.name+'\n')
    print('\n===== BATCH 34R5 RESULT =====', flush=True)
    for key, val in [('REVISION',summary.get('revision','B34R5')), ('STATUS',summary['status']), ('CODEQL_DATAFLOW',summary.get('codeql_dataflow','NOT_EXECUTED')),
                     ('GATE_B',summary.get('gate_b','NOT_PROVEN')), ('FROZEN_REPO_UNCHANGED',summary.get('frozen_unchanged',False)),
                     ('RUN_DIR',run), ('OUTPUT_ZIP',dst), ('OUTPUT_SHA256',checksum)]:
        print(str(key)+'='+str(val), flush=True)
    if summary.get('blocker'):
        print('BLOCKER='+summary['blocker'], flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', type=Path, default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    ap.add_argument('--repo', type=Path, default=Path.home()/'iris')
    ap.add_argument('--downloads', type=Path, default=Path('/mnt/c/Users/HP/Downloads'))
    ap.add_argument('--b33-result', type=Path)
    ap.add_argument('--allow-codeql-download', action='store_true',
                    help='Allow GET of the SHA-pinned public CodeQL 2.25.6 Linux ZIP if Java is unavailable')
    ap.add_argument('--codeql-archive', type=Path,
                    help='Use an already downloaded official Linux ZIP (must match pinned SHA256)')
    args = ap.parse_args()
    run = args.work/'batch34_cwe89_dataflow_runs'/('batch34r5_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:6])
    run.mkdir(parents=True, exist_ok=False)
    began, before = time.monotonic(), None
    s = {'revision':'B34R5_EARLY_OFFLINE_OPENGREP_AND_DOWNSTREAM_GATES', 'status':'B34_BLOCKED', 'gate_a':'CORE_PASS_EXTENDED_REGRESSION_PENDING', 'gate_b':'NOT_PROVEN',
         'codeql_dataflow':'NOT_EXECUTED', 'training':'NOT_EXECUTED', 'full_SAPipeline_run':'NOT_EXECUTED',
         'stage4':'NOT_EXECUTED', 'original_IRIS_stage5_6':'NOT_EXECUTED_CUSTOM_EXACT_OVERLOAD_BRIDGE',
         'source_policy':SOURCE_POLICY, 'source_discovered_by_llm':False, 'independent_gold':False,
         'focused_20_B29_regression':'NOT_EXECUTED', 'rules':'B34_DEMO_RULES_NOT_B29_BENCHMARK_RULES',
         'scope':'ONE_CWE_JDK_ONLY_INTEGRATION_FIXTURE_NOT_FINAL_BENCHMARK', 'arms':{}}
    try:
        if args.repo.resolve() in run.resolve().parents or not args.downloads.is_dir():
            raise Blocker('INVALID_WORK_OR_DOWNLOADS_LOCATION')
        before = frozen_state(args.repo); write_json(run/'FROZEN_BEFORE.json', before)
        if before['head'] != COMMIT or before['status_porcelain']:
            raise Blocker('FROZEN_REPOSITORY_COMMIT_OR_CLEAN_STATUS_GUARD')
        print('===== B34: VERIFY B33 INPUTS AND LOCAL TOOLS =====', flush=True)
        b33 = run/'b33_evidence'
        old_summary = extract_b33(args.b33_result or args.downloads/B33_NAME, b33)
        old_frozen = json.loads((b33/'FROZEN_BEFORE.json').read_text())
        if before != old_frozen:
            raise Blocker('FROZEN_SOURCE_DRIFT_SINCE_B33')
        mlpy = args.work/'.ntk_v5_lora_venv/bin/python'
        if not mlpy.is_file():
            raise Blocker('LORA_PYTHON_MISSING')
        execute([mlpy,'-B','-m','unittest','discover','-s',ROOT/'tests','-v'], run/'SELFTEST.log',
                cwd=ROOT, timeout=180, extra_env={'NTK_REFERENCE_IRIS':str(args.repo/'src/iris.py')})
        codeql, og = args.repo/'codeql/codeql', Path.home()/'.opengrep/cli/v1.25.0/opengrep'
        if not codeql.is_file() or not og.is_file():
            raise Blocker('PINNED_CODEQL_OR_OPENGREP_EXECUTABLE_MISSING')
        cv = execute([codeql,'version'],run/'CODEQL_VERSION.log',timeout=60)
        if not re.search(r'\b2\.25\.6\b', cv):
            raise Blocker('CODEQL_EXPECTED_2_25_6')
        print('===== B34R1: RESOLVE JAVA EXTRACTOR BEFORE DATABASE CREATE =====', flush=True)
        selected = select_toolchain(codeql, args.work, args.downloads, run,
                                    allow_download=args.allow_codeql_download,
                                    archive_override=args.codeql_archive)
        codeql = selected.executable
        s['codeql_toolchain_mode'] = selected.mode
        s['java_extractor_resolved'] = True
        # Same resolver options are passed to database create. These options
        # are NOT the separately pinned QL-library search path below.
        extractor_options = selected.database_options
        if sha_file(og) != OPENGREP_SHA:
            raise Blocker('OPENGREP_BINARY_SHA_MISMATCH')
        execute([og,'--version'],run/'OPENGREP_VERSION.log',timeout=60)
        jv = execute(['javac','-version'],run/'JAVAC_VERSION.log',timeout=30)
        if not re.search(r'\b21\.', jv):
            raise Blocker('WSL_JDK21_EXPECTED_NO_AUTOMATIC_TOOLCHAIN_SWITCH')
        cfg0 = json.loads((b33/'CONFIG_epoch_1.json').read_text())
        base = Path(cfg0['base_dir'])
        expected_base = json.loads((b33/'inputs/BASE_MANIFEST.json').read_text())['files']
        actual_base = {str(p.relative_to(base)):sha_file(p) for p in sorted(base.rglob('*')) if p.is_file()}
        if actual_base != expected_base or digest(actual_base) != cfg0['base_fingerprint']:
            raise Blocker('LOCAL_BASE_BYTES_DIFFER_FROM_B33')
        write_json(run/'BASE_MANIFEST.json', {'files':actual_base,'fingerprint':digest(actual_base)})
        configs = {}
        for arm in ('base','epoch_1','epoch_2'):
            configs[arm] = json.loads((b33/('CONFIG_'+arm+'.json')).read_text())
            if arm != 'base':
                ad = Path(configs[arm]['adapter_dir'])
                for fn, expected in [('adapter_model.safetensors',ADAPTER_SHA[arm]),('adapter_config.json',ADAPTER_CONFIG_SHA)]:
                    if not (ad/fn).is_file() or sha_file(ad/fn) != expected:
                        raise Blocker('B33_LOCAL_ADAPTER_MISSING_OR_CHANGED: '+str(ad/fn))
        snapshot = run/'snapshot'; snapshot_from_git(args.repo,snapshot)
        print('===== B34R5: VERIFY FROZEN SCORER BEFORE DATABASE/GPU =====',flush=True)
        scorer_path = snapshot/'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py'
        scorer = load_scorer(scorer_path)
        shutil.copy2(scorer_path, run/'SCORER_ORIGINAL.py')
        # Minimal genuine invocation of the frozen scorer on a neutral, synthetic
        # preflight input. Not a finding and not used in experiment output.
        from dataclasses import asdict as _dataclass_asdict
        neutral = _dataclass_asdict(scorer.score_finding({
            'rule_id': 'ntk/b34/preflight', 'severity': 'ERROR',
            'metadata': {'cwe': ['CWE-89'], 'confidence': 'UNKNOWN'},
            'dataflow': [], 'ai_validation': {'api_role': 'unknown',
             'parse_status': 'NOT_APPLIED', 'verdict': 'NEEDS_REVIEW'},
        }))
        if not (0 <= float(neutral['final_score']) <= 100):
            raise Blocker('PINNED_SCORER_PREFLIGHT_INVALID_SCORE')
        write_json(run/'SCORER_PREFLIGHT.json', {
            'status': 'PINNED_FROZEN_SCORER_INVOCATION_PASS',
            'scorer_sha256': sha_file(scorer_path), 'neutral_synthetic_score': neutral,
            'evidence_status': 'SYNTHETIC_PREFLIGHT_NOT_A_VULNERABILITY_FINDING'})
        patch = apply(snapshot, ROOT)
        (run/'STAGE3_PATCH.diff').write_text(patch.pop('diff'))
        write_json(run/'PATCH_PROOF.json',patch)
        protocol = run/'runtime_protocol.json'
        shutil.copy2(b33/'inputs/runtime_protocol.json',protocol)
        write_json(run/'INPUT_PROVENANCE.json', {'b33_archive_sha256':B33_SHA,
                   'b33_original_run':old_summary.get('run_id'), 'protocol_sha256':sha_file(protocol),
                   'adapter_paths':{a:configs[a].get('adapter_dir') for a in configs}})
        target = run/'fixture'; shutil.copytree(ROOT/'fixture',target)
        expectations = json.loads((target/'expectations.json').read_text())
        write_json(run/'FIXTURE_SOURCE_LOCK.json',{str(p.relative_to(target)):sha_file(p) for p in sorted(target.rglob('*')) if p.is_file()})
        print('===== B34R5: REAL OFFLINE OPENGREP PRECHECK BEFORE DATABASE/GPU =====',flush=True)
        expected_uris = set(expectations['cases'])
        ogdata = run_opengrep_preflight(og, mlpy, target, run, expected_uris)


        print('===== B34: COPY PINNED LOCAL CODEQL PACKS =====', flush=True)
        # Stage verified pinned packs *inside* the run-specific CodeQL pack
        # download cache. B34R2 copied them to qlpacks/ and only gave the
        # compiler --search-path, which is ignored for locked dependencies.
        common_cache = run/'codeql-cache'
        packs = common_cache/'packages'
        pack_report = local_pack_copy(args.repo,packs)
        write_json(run/'QLPACK_MANIFEST.json',pack_report)
        additional_packs, resolution_proof = verify_and_options(
            pack_report, ROOT/'B34R2_OBSERVED_QLPACK_PINS.json',
            run=run, common_caches=common_cache)
        write_json(run/'CODEQL_PACK_RESOLUTION_PROOF.json',resolution_proof)
        qp = run/'queries'; shutil.copytree(ROOT/'queries',qp)
        lock = snapshot/'src/queries/codeql-pack.lock.yml'
        lock_text = lock.read_text()
        for name, version in PACKS.items():
            if not re.search(r'  codeql/'+re.escape(name)+r':\s*\n    version: '+re.escape(version)+r'\s*(?:\n|$)',lock_text):
                raise Blocker('FROZEN_CODEQL_LOCK_DRIFT: '+name)
        shutil.copy2(lock,qp/'codeql-pack.lock.yml')
        # B34R2: Restrict the CodeQL --no-pre-finalize exception to this exact
        # seven-file JDK-only fixture. Preserve the hash proof before create.
        finalize_policy = validate_java_only_fixture(target)
        write_json(run/'CODEQL_FINALIZE_POLICY.json', finalize_policy)
        s['codeql_finalize_policy'] = finalize_policy['mode']
        # This is compilation only. There is no Java application main/DB server execution.
        execute(['bash',target/'build.sh',run/'javac_preflight'],run/'JAVAC_BUILD.log',cwd=target)
        db = run/'database'
        build_command = 'bash '+__import__('shlex').quote(str(target/'build.sh'))+' '+__import__('shlex').quote(str(run/'javac_codeql'))
        cachearg = '--common-caches='+str(run/'codeql-cache')
        resources = ['--threads=1','--ram=3072']
        compilation = ['--no-default-compilation-cache', '--compilation-cache='+str(run/'query-compilation-cache')]
        # Fail fast: never rebuild the database if the exact locked QL graph
        # cannot be satisfied offline from the pinned run-local pack copies.
        print('===== B34R3: VERIFY PINNED LOCAL QUERY PACK DEPENDENCIES =====', flush=True)
        lock_before = sha_file(qp/'codeql-pack.lock.yml')
        execute([codeql,'pack','resolve-dependencies', '--mode=verify',
                 *additional_packs,cachearg,qp],
                run/'CODEQL_PACK_RESOLVE.log',cwd=run,timeout=180)
        if sha_file(qp/'codeql-pack.lock.yml') != lock_before:
            raise Blocker('B34R3_LOCK_FILE_MODIFIED_DURING_PREFLIGHT')
        resolution_proof['preflight'] = 'CODEQL_PACK_RESOLVE_DEPENDENCIES_VERIFY_PASS'
        resolution_proof['lock_sha256'] = lock_before
        write_json(run/'CODEQL_PACK_RESOLUTION_PROOF.json',resolution_proof)
        print('===== B34R4: COMPILE-CHECK ALL QUERY TYPES BEFORE DATABASE/GPU =====', flush=True)
        smoke_ql, smoke_proof = diagnostic_sink_preview(ROOT, qp)
        for name, file in (('APICALLS', qp/'ApiCalls.ql'),
                           ('ARGUMENT_SPANS', qp/'ArgumentSpans.ql'),
                           ('PATH_DIAGNOSTIC', smoke_ql)):
            check_ql_compilation(codeql, file, run, additional_packs, cachearg, resources, name)
        write_json(run/'PRE_DATABASE_QUERY_CHECKS.json', {
            'status': 'REAL_CODEQL_CHECK_ONLY_PASS',
            'queries': {p.name:sha_file(p) for p in (qp/'ApiCalls.ql', qp/'ArgumentSpans.ql', smoke_ql)},
            'codeql_version': '2.25.6', 'pack_lock_sha256': lock_before,
            'scope': 'COMPILER_CHECK_ONLY_NOT_QUERY_RESULT_NOT_DATAFLOW',
        })
        print('===== B34: CREATE REAL JAVA DATABASE =====', flush=True)
        execute(database_create_argv(codeql, db, target, build_command, cachearg,
                                     extractor_options, resources, finalize_policy),
                run/'DATABASE_CREATE.log',cwd=run,timeout=900)
        if not (db/'db-java').is_dir() or not (db/'codeql-database.yml').is_file() or not (db/'src.zip').is_file():
            raise Blocker('REAL_JAVA_DATABASE_ARTIFACTS_MISSING')
        write_json(run/'DATABASE_PROOF.json', {'created':True,'path':str(db),
            'java_only_no_pre_finalize_policy': finalize_policy['mode'],
            'source_zip_sha256':sha_file(db/'src.zip'),'metadata_sha256':sha_file(db/'codeql-database.yml'),
            'build_class_files':{str(p.relative_to(run/'javac_codeql')):sha_file(p) for p in (run/'javac_codeql').rglob('*.class')}})
        print('===== B34: EXTRACT COMPILER API IDENTITIES AND ARGUMENT SPANS =====', flush=True)
        for name in ('ApiCalls','ArgumentSpans'):
            bqrs = run/(name+'.bqrs'); csvpath = run/(name+'.csv')
            execute([codeql,'query','run',qp/(name+'.ql'),'--database='+str(db), '--output='+str(bqrs),
                     *additional_packs,cachearg,*compilation,*resources],run/(name+'_QUERY.log'),cwd=run,timeout=900)
            execute([codeql,'bqrs','decode',bqrs,'--format=csv','--output='+str(csvpath)],run/(name+'_DECODE.log'),timeout=120)
        cases,calls = read_calls(run/'ApiCalls.csv',target)
        arguments = read_arguments(run/'ArgumentSpans.csv',target)
        if set(c['uri'] for c in calls) != set(expectations['cases']):
            raise Blocker('DATABASE_MISSING_FIXTURE_CASES_OR_UNEXPECTED_SOURCE_FILES')
        write_json(run/'CANDIDATE_MANIFEST.json',cases);write_json(run/'CALLSITE_MANIFEST.json',calls)
        write_json(run/'ARGUMENT_MANIFEST.json',arguments)
        print('===== B34R4: RUN NON-LLM CODEQL SOURCE-SINK DIAGNOSTIC BEFORE GPU =====', flush=True)
        execute([codeql,'database','run-queries',db,smoke_ql,*additional_packs,
                 cachearg,*compilation,*resources], run/'MANUAL_DIAGNOSTIC_RUN.log', cwd=run, timeout=1200)
        diagnostic_sarif = run/'MANUAL_DIAGNOSTIC.sarif'
        execute([codeql,'database','interpret-results',db,smoke_ql,
                 '--format=sarifv2.1.0','--output='+str(diagnostic_sarif),
                 '--max-paths=4',*additional_packs,cachearg],
                run/'MANUAL_DIAGNOSTIC_INTERPRET.log', cwd=run, timeout=600)
        diag_flows = parse_flows(json.loads(diagnostic_sarif.read_text()),
                                 target, calls, arguments, smoke_proof)
        diag_matched = {uri: any(f['location']['uri'] == uri for f in diag_flows)
                        for uri in expectations['cases']}
        diag_expected = {uri: rule['expected_flow']
                         for uri,rule in expectations['cases'].items()}
        diag_ok = diag_matched == diag_expected
        write_json(run/'MANUAL_DIAGNOSTIC_RESULT.json', {
            'status': 'PASS' if diag_ok else 'FAIL',
            'observation': diag_matched, 'expected': diag_expected,
            'source_policy': SOURCE_POLICY,
            'flow_count': len(diag_flows),
            'label_provenance': 'MANUAL_DIAGNOSTIC_NOT_LLM',
            'not_included_in_fusion_or_scoring': True,
            'not_independent_gold': True,
        })
        if not diag_ok:
            raise Blocker('MANUAL_CODEQL_FLOW_FIXTURE_EXPECTATIONS_MISMATCH_REVIEW_REAL_QUERY_RESULTS')
        s['manual_codeql_diagnostic'] = 'PASSED_SEPARATE_FROM_LLM_EVIDENCE'
        s['codeql_dataflow'] = 'DIAGNOSTIC_ONLY_REAL_CODEQL_WITHOUT_LLM' 
        print('===== B34R5: REUSE VERIFIED REAL OPENGREP SCAN =====',flush=True)
        og_preflight = json.loads((run/'OPENGREP_PREFLIGHT.json').read_text())
        if (sha_file(run/'OPENGREP_RAW.json') != og_preflight['raw_json_sha256']
                or sha_file(target/'opengrep_demo_rules.yml') != og_preflight['rule_sha256']):
            raise Blocker('OPENGREP_PREFLIGHT_RAW_OR_RULE_DRIFT')
        # The evidence was created by a real offline scan earlier in this
        # same run. Do not rerun CLI or replace its findings with synthetic data.
        raw_report = fuse(ogdata,[],[],calls,target,scorer)
        if len(raw_report) != len(ogdata['results']) or not all(
                r['origin'] == 'OPENGREP' and r['retained'] is True and
                isinstance(r.get('score', {}).get('final_score'), (int, float)) and
                0 <= float(r['score']['final_score']) <= 100
                for r in raw_report):
            raise Blocker('OPENGREP_SCORER_OR_PRESERVATION_PREFLIGHT_FAILED')
        baseline_sarif = to_sarif(raw_report)
        if len(baseline_sarif['runs'][0]['results']) != len(raw_report):
            raise Blocker('OPENGREP_SARIF_PRESERVATION_PREFLIGHT_FAILED')
        write_json(run/'OPENGREP_ONLY.json', raw_report)
        write_json(run/'OPENGREP_ONLY.sarif', baseline_sarif)
        write_json(run/'OPENGREP_FUSION_PREFLIGHT.json', {
            'status': 'REAL_OPENGREP_FROZEN_SCORER_AND_SARIF_PASS',
            'raw_findings': len(ogdata['results']), 'preserved_findings': len(raw_report),
            'sarif_findings': len(baseline_sarif['runs'][0]['results']),
            'ai_evidence': 'NONE_AT_BASELINE', 'codeql_evidence': 'NONE_AT_BASELINE',
            'meaning': 'STATIC_CALL_PRESENCE_AND_PRIORITIZATION_NOT_DETECTION_ACCURACY',
        })
        host = old_summary.get('iris_host_python') or os.environ.get('NTK_IRIS_PYTHON') or str(mlpy)
        common = dict(cfg0, snapshot=str(snapshot), frozen_root=str(args.repo), ml_python=str(mlpy),
                      protocol_path=str(protocol), cases=cases, base_fingerprint=digest(actual_base))
        importcfg = run/'IMPORT_CONFIG.json';write_json(importcfg,common)
        candidates = list(dict.fromkeys([host,str(mlpy),os.environ.get('NTK_IRIS_PYTHON','')]))
        host = None
        for idx, candidate in enumerate(candidates):
            if not candidate:
                continue
            try:
                execute([candidate,'-B',ROOT/'run_native34.py',importcfg,'--import-only'],
                        run/('IRIS_IMPORT_%d.log'%idx),cwd=snapshot,timeout=180)
                host=candidate;break
            except Blocker:
                continue
        if host is None:
            raise Blocker('NO_AVAILABLE_PYTHON_CAN_IMPORT_COMPLETE_IRIS_MODULE')
        s['iris_host_python']=host
        for arm in ('base','epoch_1','epoch_2'):
            print('===== B34: LIVE IRIS STAGE3 '+arm+' =====',flush=True)
            output=run/'live'/arm
            cfg=dict(common,arm=arm,output_dir=str(output),cache_dir=str(run/'cache'/arm),
                     adapter_dir=configs[arm].get('adapter_dir'),adapter_sha256=configs[arm].get('adapter_sha256'),
                     adapter_config_sha256=configs[arm].get('adapter_config_sha256'))
            cfgpath=run/('CONFIG_'+arm+'.json');write_json(cfgpath,cfg)
            execute([host,'-B','-u',ROOT/'run_native34.py',cfgpath],run/('LIVE_'+arm+'.log'),cwd=snapshot,timeout=1800)
            stage3=json.loads((output/'SUMMARY.json').read_text())
            sinks=json.loads((output/'cold/cwe-89/llm_labelled_sink_apis.json').read_text())
            query,proof=emit_flow((qp/'Flow.template').read_text(),cases,sinks,arm)
            qfile=qp/('Flow_'+arm+'.ql');qfile.write_text(query)
            write_json(run/('SINK_BINDING_'+arm+'.json'),proof)
            print('===== B34R4: CHECK GENERATED QL BEFORE RUN '+arm+' =====', flush=True)
            check_ql_compilation(codeql, qfile, run, additional_packs, cachearg, resources, 'FLOW_'+arm)
            print('===== B34: REAL CODEQL PATH QUERY '+arm+' =====',flush=True)
            execute([codeql,'database','run-queries',db,qfile,*additional_packs,cachearg,*compilation,*resources],
                    run/('FLOW_'+arm+'_RUN.log'),cwd=run,timeout=1200)
            out=run/'analysis'/arm;out.mkdir(parents=True)
            sarifpath=out/'codeql.sarif'
            execute([codeql,'database','interpret-results',db,qfile,'--format=sarifv2.1.0',
                     '--output='+str(sarifpath),'--max-paths=4',*additional_packs,cachearg],
                    run/('FLOW_'+arm+'_INTERPRET.log'),cwd=run,timeout=600)
            s['codeql_dataflow']='PARTIALLY_EXECUTED_SEE_ARM_RESULTS'
            found=list((db/'results').rglob(qfile.stem+'.bqrs'))
            if len(found)!=1:
                raise Blocker('CANNOT_IDENTIFY_UNIQUE_STORED_FLOW_BQRS: '+arm)
            shutil.copy2(found[0],out/'flow.bqrs')
            flows=parse_flows(json.loads(sarifpath.read_text()),target,calls,arguments,proof)
            trace=[json.loads(line) for line in (output/'native_trace.jsonl').read_text().splitlines() if line.strip()]
            fused=fuse(ogdata,flows,trace,calls,target,scorer)
            write_json(out/'VERIFIED_PATHS.json',flows)
            write_json(out/'FUSED_FINDINGS.json',fused);write_json(out/'FUSED_FINDINGS.sarif',to_sarif(fused))
            matched={uri:any(f['location']['uri']==uri for f in flows) for uri in expectations['cases']}
            exact=all(matched[uri]==rule['expected_flow'] for uri,rule in expectations['cases'].items())
            s['arms'][arm]={'stage3':stage3, 'flow_count':len(flows), 'observed_case_flows':matched,
                           'fixture_expectations_match':exact, 'opengrep_findings_retained':sum(r['origin']=='OPENGREP' for r in fused),
                           'additional_codeql_findings':sum(r['origin']=='CODEQL_ADDITIONAL' for r in fused)}
            write_json(run/'00_PARTIAL_PROGRESS.json',s)
        s['codeql_dataflow']='EXECUTED_WITH_REAL_BQRS_AND_SARIF'
        s['opengrep_raw_findings']=len(ogdata['results'])
        passed=all(s['arms'][a]['fixture_expectations_match'] for a in ('epoch_1','epoch_2'))
        s['status']='B34_CWE89_DEMO_COMPLETE' if passed else 'B34_COMPLETED_NEEDS_REVIEW'
        s['gate_b']='ONE_CWE_FIXED_SOURCE_DEMO_ONLY' if passed else 'EXECUTED_RESULTS_REQUIRE_REVIEW'
    except Exception as exc:
        s['blocker']=str(exc)
        (run/'FAILURE.txt').write_text(traceback.format_exc())
    finally:
        try:
            after=frozen_state(args.repo);write_json(run/'FROZEN_AFTER.json',after)
            s['frozen_unchanged']=before is not None and before==after
            if not s['frozen_unchanged']:
                s['status']='B34_BLOCKED';s['gate_b']='NOT_PROVEN_FROZEN_STATE_CHANGED'
        except Exception as exc:
            s['frozen_unchanged']=False;s['frozen_error']=str(exc);s['status']='B34_BLOCKED'
        s['wall_time_s']=time.monotonic()-began
        write_json(run/'00_SUMMARY.json',s)
        if args.downloads.is_dir():
            pack_result(run,args.downloads,s)
        else:
            print('RUN_DIR='+str(run));print('BLOCKER='+s.get('blocker','Downloads unavailable'))
    return 0 if s['status']=='B34_CWE89_DEMO_COMPLETE' else 2 if s['status']=='B34_BLOCKED' else 3

if __name__=='__main__':
    sys.exit(main())
