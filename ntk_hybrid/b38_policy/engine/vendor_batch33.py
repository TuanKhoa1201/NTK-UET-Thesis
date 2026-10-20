#!/usr/bin/env python3
from __future__ import annotations
import argparse
import ast
from datetime import datetime, timezone
import io
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import time
import traceback
import uuid
import zipfile
from ntk_b33.common import (ADAPTER_CONFIG_SHA, ADAPTER_SHA, Blocker, COMMIT, IDENTITY,
                           candidate_from_record, digest, sha_file, walk, write_json)
from ntk_b33.patcher import apply, native_system_prompt

ROOT = Path(__file__).resolve().parent
ARCHIVES = {
    'b28': ('ntk-batch28_b21de8b3f3c10f42_a001.zip', '93f345ef4a55b75859da4e81464f357093480952c490e9f2dc2c7b5f67e72285'),
    'b32': ('batch32_20261016T110138Z_c1ff2ee6.zip', 'b5dbdb4c93aead9712c651af523365a9e7890ce959f327de6d2154f43ecd2d49'),
}
VERSIONS = {'torch': '2.5.1', 'transformers': '4.56.2', 'peft': '0.17.1', 'accelerate': '1.10.1'}


def command(args, *, cwd=None, timeout=120):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', PYTHONDONTWRITEBYTECODE='1',
               HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1')
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise Blocker('COMMAND_FAILED: %r\n%s\n%s' % (args, result.stdout[-2000:], result.stderr[-5000:]))
    return result.stdout


def frozen_state(repo):
    return {'head': command(['git', '-C', repo, 'rev-parse', 'HEAD']).strip(),
            'status_porcelain': command(['git', '-C', repo, 'status', '--porcelain']),
            'core_file_hashes': {p: sha_file(repo / p) for p in
                                ('src/iris.py', 'src/prompts.py', 'src/queries.py', 'src/models/llm.py',
                                 'simple_semgrepAI/semgrepai/scoring/sast_scoring_engine.py')}}


def find_named(root, names):
    found = []
    skip = {'.git', '.ntk_v5_lora_venv', '.venv', '__pycache__', 'node_modules',
            'benchmark_cached', 'immutable_adapters', 'batch33_native_integration_runs'}
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith('.ntk')]
        for name in files:
            if name in names:
                found.append(Path(current) / name)
    return found


def resolve_archive(tag, work, downloads):
    name, expected = ARCHIVES[tag]
    candidates = [downloads / name]
    if not candidates[0].is_file():
        candidates = find_named(work, {name})
    for path in candidates:
        if path.is_file() and sha_file(path) == expected:
            return path
    raise Blocker('MISSING_OR_SHA_MISMATCH_%s: expected %s ; sha256=%s' % (tag.upper(), name, expected))


def member_bytes(archive, suffix):
    with zipfile.ZipFile(archive) as z:
        matches = [n for n in z.namelist() if n == suffix or n.endswith('/' + suffix)]
        if not matches:
            raise Blocker('ARCHIVE_MEMBER_MISSING: ' + suffix)
        values = [z.read(n) for n in matches]
        if len({hashlib.sha256(v).hexdigest() for v in values}) != 1:
            raise Blocker('ARCHIVE_MEMBER_AMBIGUOUS: ' + suffix)
        return values[0], matches[0]


def snapshot_from_git(repo, snapshot):
    raw = subprocess.run(['git', '-C', str(repo), 'archive', '--format=tar', COMMIT],
                         check=True, capture_output=True).stdout
    snapshot.mkdir(exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for item in archive:
            relative = PurePosixPath(item.name)
            if relative.is_absolute() or '..' in relative.parts:
                raise Blocker('UNSAFE_GIT_ARCHIVE_PATH')
            path = snapshot.joinpath(*relative.parts)
            if item.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                resolved = path.resolve()
                if snapshot.resolve() not in resolved.parents:
                    raise Blocker('GIT_ARCHIVE_PATH_ESCAPE')
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as src, path.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                path.chmod(item.mode & 0o777)
            elif item.issym():
                target = (path.parent / item.linkname).resolve()
                if target != snapshot.resolve() and snapshot.resolve() not in target.parents:
                    raise Blocker('EXTERNAL_GIT_SYMLINK_REFUSED: ' + item.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(item.linkname)
            else:
                raise Blocker('UNSUPPORTED_GIT_ARCHIVE_ENTRY: ' + item.name)


def source_user_template(repo):
    tree = ast.parse((repo / 'src/prompts.py').read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id == 'API_LABELLING_USER_PROMPT' for t in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise Blocker('NATIVE_USER_TEMPLATE_NOT_LITERAL')


def resolve_protocol(archives, work, repo, inputs):
    candidates = []
    for tag, path in archives.items():
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if PurePosixPath(name).name == 'runtime_protocol.json':
                    candidates.append((z.read(name), {'origin': 'PINNED_RESULT_ARCHIVE',
                        'archive': str(path), 'member': name, 'archive_sha256': ARCHIVES[tag][1]}))
    if not candidates:
        for path in find_named(work, {'runtime_protocol.json'}):
            candidates.append((path.read_bytes(), {'origin': 'EXISTING_WORKROOT_PROTOCOL', 'path': str(path),
                'historical_archive_membership': 'NOT_PROVEN_BY_THIS_BATCH'}))
    system = native_system_prompt((repo / 'src/iris.py').read_text(encoding='utf-8'))
    user = source_user_template(repo)
    matches = []
    for raw, origin in candidates:
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeError):
            continue
        values = list(walk(obj))
        if system in values and user in values:
            matches.append((raw, origin, obj))
    if not matches:
        write_json(inputs / 'protocol_candidates.json', [origin for _, origin in candidates])
        raise Blocker('NO_EXISTING_RUNTIME_PROTOCOL_MATCHES_PINNED_NATIVE_PROMPT; not inventing a new protocol')
    # Prefer archive-pinned candidates. Equivalent JSON copies are safe; conflicts are not silently chosen.
    if len({digest(obj) for _, _, obj in matches}) != 1:
        write_json(inputs / 'protocol_candidates.json', [origin for _, origin, _ in matches])
        raise Blocker('MULTIPLE_DIFFERENT_MATCHING_PROTOCOL_SNAPSHOTS_REQUIRE_EXACT_INPUT')
    raw, origin, _ = matches[0]
    path = inputs / 'runtime_protocol.json'
    path.write_bytes(raw)
    return path, dict(origin, sha256=sha_file(path))


def pack_results(run, downloads, summary):
    zip_path = downloads / (run.name + '_result.zip')
    if zip_path.exists():
        raise Blocker('Refuse overwrite result archive')
    included = []
    for path in sorted(run.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(run)
        if relative.parts[0] in ('snapshot', 'cache') or 'adapters' in relative.parts:
            continue
        if path.stat().st_size > 16 * 1024 * 1024:
            continue
        included.append(path)
    manifest = {str(p.relative_to(run)): sha_file(p) for p in included}
    write_json(run / 'OUTPUT_MANIFEST.json', manifest)
    included.append(run / 'OUTPUT_MANIFEST.json')
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for path in included:
            z.write(path, str(path.relative_to(run)))
    digest_value = sha_file(zip_path)
    (downloads / (zip_path.name + '.sha256')).write_text(digest_value + '  ' + zip_path.name + '\n')
    print('\n===== BATCH 33 RESULT =====', flush=True)
    print('STATUS=' + summary['status'], flush=True)
    print('GATE_A=' + summary.get('gate_a', 'NOT_PROVEN'), flush=True)
    print('FROZEN_REPO_UNCHANGED=' + str(summary.get('frozen_unchanged', False)), flush=True)
    print('CODEQL_DATAFLOW=NOT_EXECUTED', flush=True)
    print('RUN_DIR=' + str(run), flush=True)
    print('OUTPUT_ZIP=' + str(zip_path), flush=True)
    print('OUTPUT_SHA256=' + digest_value, flush=True)
    if summary.get('blocker'):
        print('BLOCKER=' + summary['blocker'], flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, default=Path.home() / 'migration/ntk_stage3_verified_v5_work')
    parser.add_argument('--repo', type=Path, default=Path.home() / 'iris')
    parser.add_argument('--downloads', type=Path, default=Path('/mnt/c/Users/HP/Downloads'))
    args = parser.parse_args()
    run_id = 'batch33_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:6]
    run = args.work / 'batch33_native_integration_runs' / run_id
    run.mkdir(parents=True, exist_ok=False)
    inputs = run / 'inputs'
    inputs.mkdir()
    began = time.monotonic()
    summary = {'status': 'B33_BLOCKED', 'gate_a': 'NOT_PROVEN', 'run_id': run_id,
               'training': 'NOT_EXECUTED', 'codeql_dataflow': 'NOT_EXECUTED',
               'full_pipeline': 'NOT_EXECUTED', 'independent_gold': False,
               'focused_20_B29_weak_regression': 'NOT_EXECUTED_IN_THIS_RELEASE',
               'scope': 'NATIVE_STAGE3_INTEGRATION_16_B32_CASES_AND_SAFETY_TESTS'}
    before = None
    try:
        if not args.downloads.is_dir():
            raise Blocker('Windows Downloads path is unavailable')
        before = frozen_state(args.repo)
        write_json(run / 'FROZEN_BEFORE.json', before)
        if before['head'] != COMMIT or before['status_porcelain']:
            raise Blocker('FROZEN_REPO_HEAD_OR_CLEAN_STATUS_MISMATCH')
        ml_python = args.work / '.ntk_v5_lora_venv/bin/python'
        if not ml_python.is_file():
            raise Blocker('ML_PYTHON_MISSING: ' + str(ml_python))
        # Always run package safety tests before loading any model.
        test_env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', NTK_REFERENCE_IRIS=str(args.repo / 'src/iris.py'))
        test_result = subprocess.run([str(ml_python), '-B', '-m', 'unittest', 'discover', '-s', str(ROOT / 'tests'), '-v'],
                                     cwd=ROOT, env=test_env, capture_output=True, text=True)
        (run / 'SELFTEST.log').write_text(test_result.stdout + test_result.stderr, encoding='utf-8')
        if test_result.returncode:
            raise Blocker('PACKAGE_SELFTEST_FAILED; see SELFTEST.log')
        summary['selftests'] = 'PASS'
        env_json = command([ml_python, '-B', '-c',
            'import json,torch,transformers,peft,accelerate;print(json.dumps(dict(versions=dict('
            'torch=torch.__version__.split("+")[0],transformers=transformers.__version__,'
            'peft=peft.__version__,accelerate=accelerate.__version__),cuda=torch.cuda.is_available())))'])
        env = json.loads(env_json.strip().splitlines()[-1])
        if env['versions'] != VERSIONS or not env['cuda']:
            raise Blocker('PINNED_ML_ENV_OR_CUDA_MISMATCH: ' + repr(env))
        write_json(run / 'ENV_LOCK.json', env)
        archives = {tag: resolve_archive(tag, args.work, args.downloads) for tag in ARCHIVES}
        write_json(inputs / 'ARCHIVE_PROVENANCE.json', {tag: {'path': str(path), 'sha256': ARCHIVES[tag][1]}
                                                       for tag, path in archives.items()})
        for arm in ('epoch_1', 'epoch_2'):
            adapter_dir = inputs / 'adapters' / arm
            adapter_dir.mkdir(parents=True)
            for filename, expected in (('adapter_model.safetensors', ADAPTER_SHA[arm]),
                                       ('adapter_config.json', ADAPTER_CONFIG_SHA)):
                raw, member = member_bytes(archives['b28'], 'ml/checkpoint_' + arm + '/' + filename)
                target = adapter_dir / filename
                target.write_bytes(raw)
                if sha_file(target) != expected:
                    raise Blocker('ADAPTER_FILE_SHA_MISMATCH: ' + str(target))
        raw, member = member_bytes(archives['b32'], '04_FOUR_CWE_NATIVE_STAGE3_QUERIES_NOT_GOLD.jsonl')
        (inputs / 'B32_NATIVE_QUERIES_ORIGINAL.jsonl').write_bytes(raw)
        raw_records = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
        cases = [candidate_from_record(row) for row in raw_records]
        if len(cases) != 16 or {c: sum(r['cwe'] == c for r in cases) for c in ('22', '78', '79', '89')} != {
                '22': 4, '78': 5, '79': 2, '89': 5}:
            raise Blocker('B32_EXPECTED_16_CASE_DISTRIBUTION_MISMATCH')
        if len({digest([row['cwe']] + [row[k] for k in IDENTITY]) for row in cases}) != 16:
            raise Blocker('B32_DUPLICATE_IDENTITIES')
        write_json(inputs / 'CANDIDATE_MANIFEST.json', cases)
        protocol_path, origin = resolve_protocol(archives, args.work, args.repo, inputs)
        write_json(inputs / 'PROTOCOL_PROVENANCE.json', origin)
        base = Path.home() / '.cache/huggingface/hub/models--Qwen--Qwen2.5-Coder-0.5B-Instruct/snapshots/ea3f2471cf1b1f0db85067f1ef93848e38e88c25'
        if not base.is_dir() or not (base / 'config.json').is_file():
            raise Blocker('PINNED_LOCAL_BASE_SNAPSHOT_MISSING: ' + str(base))
        base_files = {str(p.relative_to(base)): sha_file(p) for p in sorted(base.rglob('*')) if p.is_file()}
        if not any(name.endswith('.safetensors') for name in base_files):
            raise Blocker('LOCAL_SAFETENSORS_BASE_WEIGHTS_MISSING')
        write_json(inputs / 'BASE_MANIFEST.json', {'files': base_files, 'b33_fingerprint': digest(base_files),
            'fingerprint_algorithm': 'sha256(canonical-json(relative-path->file-sha256))',
            'comparison_to_B29_fingerprint_algorithm': 'NOT_CLAIMED'})
        snapshot = run / 'snapshot'
        snapshot_from_git(args.repo, snapshot)
        report = apply(snapshot, ROOT)
        (run / 'STAGE3_PATCH.diff').write_text(report.pop('diff'), encoding='utf-8')
        write_json(run / 'PATCH_PROOF.json', report)
        patch_dir = run / 'patch'
        patch_dir.mkdir()
        shutil.copy2(snapshot / 'src/iris.py', patch_dir / 'iris.py')
        shutil.copytree(snapshot / 'src/ntk_stage3_native', patch_dir / 'ntk_stage3_native')
        write_json(snapshot / 'NTK_SNAPSHOT_ORIGIN.json', {'commit': COMMIT, 'source': str(args.repo),
                   'method': 'git archive; no worktree metadata or frozen source modification'})
        generation = dict(do_sample=False, max_new_tokens=256, max_input_tokens=4096,
                          seed=20261016, dtype='float16', attention='sdpa', generation_timeout_s=120)
        write_json(run / 'GENERATION_LOCK.json', {'settings': generation,
            'scope': 'EXPLICIT_B33_RUNTIME_SETTINGS_SAME_FOR_ALL_ARMS',
            'historical_B28_B32_generation_byte_parity': 'NOT_CLAIMED',
            'native_prompt_parity': 'REQUIRED_EXACT_BEFORE_LIVE_CALL'})
        common_cfg = dict(snapshot=str(snapshot), frozen_root=str(args.repo), ml_python=str(ml_python),
                          base_dir=str(base), base_fingerprint=digest(base_files),
                          protocol_path=str(protocol_path), native_system_prompt=report['native_system_prompt'],
                          runtime_versions=VERSIONS, generation=generation, cases=cases,
                          cache_mode='readwrite', load_timeout_s=300, request_timeout_s=180)
        import_cfg = run / 'IMPORT_CONFIG.json'
        write_json(import_cfg, common_cfg)
        possible = [str(ml_python), os.environ.get('NTK_IRIS_PYTHON'), shutil.which('python')]
        if os.environ.get('CONDA_PREFIX'):
            possible.append(str(Path(os.environ['CONDA_PREFIX']) / 'bin/python'))
        host_python = None
        for number, candidate in enumerate(dict.fromkeys(p for p in possible if p)):
            test = subprocess.run([candidate, '-B', str(ROOT / 'run_native.py'), str(import_cfg), '--import-only'],
                                  cwd=snapshot, capture_output=True, text=True,
                                  env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', HF_HUB_OFFLINE='1',
                                           TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1'))
            (run / ('IRIS_IMPORT_%d.log' % number)).write_text(test.stdout + test.stderr, encoding='utf-8')
            if test.returncode == 0:
                host_python = candidate
                break
        if host_python is None:
            raise Blocker('FULL_IRIS_MODULE_IMPORT_FAILED_IN_AVAILABLE_PYTHONS; no AST fallback or dependency auto-install')
        summary['iris_host_python'] = host_python
        arms = {}
        for arm in ('base', 'epoch_1', 'epoch_2'):
            arm_dir = run / 'live' / arm
            arm_dir.mkdir(parents=True)
            cfg = dict(common_cfg, arm=arm, output_dir=str(arm_dir),
                       cache_dir=str(run / 'cache' / arm),
                       adapter_dir=str(inputs / 'adapters' / arm) if arm != 'base' else None,
                       adapter_sha256=ADAPTER_SHA.get(arm),
                       adapter_config_sha256=ADAPTER_CONFIG_SHA if arm != 'base' else None)
            config_path = run / ('CONFIG_' + arm + '.json')
            write_json(config_path, cfg)
            argv = [host_python, '-B', '-u', str(ROOT / 'run_native.py'), str(config_path)]
            print('\n===== NATIVE STAGE 3 ARM: ' + arm + ' =====', flush=True)
            with open(run / ('LIVE_' + arm + '.log'), 'w', encoding='utf-8') as log:
                proc = subprocess.Popen(argv, cwd=snapshot, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                                        HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1'))
                for line in proc.stdout:
                    print(line, end='', flush=True)
                    log.write(line)
                    log.flush()
                rc = proc.wait()
            if rc:
                raise Blocker('NATIVE_ARM_FAILED: ' + arm + '; see LIVE_' + arm + '.log and worker_stderr.log')
            arms[arm] = json.loads((arm_dir / 'SUMMARY.json').read_text(encoding='utf-8'))
        summary['arms'] = arms
        if any(arms[arm]['strict_accepted'] == 0 for arm in ('epoch_1', 'epoch_2')):
            raise Blocker('BOTH_TUNED_ARMS_MUST_HAVE_AT_LEAST_ONE_ACCEPTED_NATIVE_LABEL')
        summary['status'] = 'B33_NATIVE_STAGE3_INTEGRATION_COMPLETE'
        summary['gate_a'] = 'CORE_PASS_EXTENDED_REGRESSION_PENDING'
        summary['protocol_origin'] = origin
        summary['remaining_limits'] = [
            'No full SAPipeline.run; Stage1/2 extraction and CodeQL database/dataflow not executed.',
            'B32 inputs are 16 prior compiler-attributed contracts; not newly CodeQL-extracted APIs.',
            'The 20 focused B29 weak regression cases are not executed in this release.',
            'Receiver this is ABSTAIN until API-specific receiver semantics are reviewed.',
            'No independent semantic API gold or vulnerability F1 is claimed.',
        ]
    except Exception as exc:
        summary['blocker'] = str(exc)
        (run / 'FAILURE.txt').write_text(traceback.format_exc(), encoding='utf-8')
    finally:
        try:
            after = frozen_state(args.repo)
            write_json(run / 'FROZEN_AFTER.json', after)
            summary['frozen_unchanged'] = before is not None and before == after
            if not summary['frozen_unchanged']:
                summary['status'] = 'B33_BLOCKED'
                summary['gate_a'] = 'NOT_PROVEN'
                summary['frozen_warning'] = 'Frozen state changed or initial state unavailable; inspect before/after.'
        except Exception as exc:
            summary['frozen_unchanged'] = False
            summary['frozen_check_error'] = str(exc)
            summary['status'] = 'B33_BLOCKED'
            summary['gate_a'] = 'NOT_PROVEN'
        summary['wall_time_s'] = time.monotonic() - began
        write_json(run / '00_SUMMARY.json', summary)
        if args.downloads.is_dir():
            pack_results(run, args.downloads, summary)
        else:
            print('RUN_DIR=' + str(run))
            print('BLOCKER=' + summary.get('blocker', 'Unknown'))
    return 0 if summary['status'] == 'B33_NATIVE_STAGE3_INTEGRATION_COMPLETE' else 2


if __name__ == '__main__':
    sys.exit(main())
