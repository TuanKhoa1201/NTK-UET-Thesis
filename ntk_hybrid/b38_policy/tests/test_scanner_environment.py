"""B38R1 regression: real subprocess and seccomp, deliberately FAKE scanner.

The fake executable reproduces the pinned scanner's startup precondition but
is not OpenGrep; its findings are fixture data, never detection evidence.
"""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bootstrap import ROOT
from ntk_b33.common import Blocker, COMMIT, sha_file
from ntk_b38 import scanner
from ntk_b38.scanner_environment import prepare_environment, PRIVATE_NAMES
import preflight_scanner
from run_batch38 import pack, verify_fixture_scanner, check_cases


FAKE = r'''
import errno,json,os,pathlib,socket,sys
MODE=__MODE__
# Corresponds to the startup precondition in the pinned upstream source.
config_dir=pathlib.Path(os.environ['XDG_CONFIG_HOME'])
assert config_dir.stat().st_mode, 'configuration directory must exist at startup'
for key in ('HOME','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_STATE_HOME','TMPDIR'):
    assert pathlib.Path(os.environ[key]).is_dir(), key
    probe=pathlib.Path(os.environ[key])/('mock-scanner-write-'+key)
    probe.write_text('FAKE SCANNER TEST ONLY')
    probe.unlink()
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        sock=socket.socket(family,socket.SOCK_STREAM)
    except OSError as exc:
        assert exc.errno==errno.EPERM
    else:
        sock.close(); raise RuntimeError('test scanner unexpectedly has Internet sockets')
if MODE=='exit2':
    print('FAKE_SCANNER_INTENTIONAL_FAILURE',flush=True);sys.exit(2)
argv=sys.argv[1:]
config=json.loads(pathlib.Path(argv[argv.index('--config')+1]).read_text())
out=pathlib.Path(argv[argv.index('--output')+1]);target=pathlib.Path(argv[-1])
index=json.loads(pathlib.Path(__INDEX__).read_text())
rows=[]
for rule in config['rules']:
    c=rule['metadata']['cwe'][0].split('-')[-1]
    for p in sorted(target.rglob('*.java')):
        uri=p.relative_to(target).as_posix()
        if MODE=='empty':continue
        if not index or uri in index.get(c,[]):
            rows.append({'check_id':'generated.test.'+rule['id'],'path':str(p),
              'start':{'line':1,'col':1},'end':{'line':1,'col':2},
              'extra':{'metadata':{'cwe':['CWE-'+c]}}})
if MODE=='missing_output':sys.exit(0)
out.write_text(json.dumps({'results':rows,'errors':[]}))
'''


def fake_binary(where: Path, mode='ok', fixture_index=False):
    index = {}
    if fixture_index:
        for value in json.loads((ROOT/'samples/MANIFEST.json').read_text()).values():
            for cwe, rows in value['scanner_expectations'].items():
                index.setdefault(cwe, set()).update(rows)
        index = {c: sorted(rows) for c, rows in index.items()}
    path = where/'fixture_index.json'; path.write_text(json.dumps(index))
    binary = where/'fake_opengrep'
    content = '#!' + sys.executable + '\n' + FAKE.replace('__MODE__', repr(mode)).replace('__INDEX__', repr(str(path)))
    binary.write_text(content); binary.chmod(0o700)
    return binary


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.work=self.root/'opengrep';self.work.mkdir()
    def tearDown(self):self.temp.cleanup()

    def test_all_directories_created_before_exec(self):
        env,proof=prepare_environment(self.work)
        for key in ('HOME','TMPDIR','TMP','TEMP','XDG_CACHE_HOME','XDG_CONFIG_HOME','XDG_STATE_HOME'):
            self.assertTrue(Path(env[key]).is_dir(),key)
            self.assertTrue(Path(env[key]).is_relative_to(self.work))
        self.assertTrue(all(p['write_probe']=='PASS' for p in proof['directories']))
        self.assertEqual(len(proof['directories']),len(PRIVATE_NAMES)+1)
    def test_modes_private_and_parent_config_untouched(self):
        parentmode=stat.S_IMODE(self.root.stat().st_mode)
        env,proof=prepare_environment(self.work)
        self.assertTrue(all(p['mode']=='0o700' for p in proof['directories']))
        self.assertEqual(parentmode,stat.S_IMODE(self.root.stat().st_mode))
    def test_existing_regular_directories_supported(self):
        (self.work/'.config').mkdir();(self.work/'.config'/'keep.txt').write_text('keep')
        prepare_environment(self.work);prepare_environment(self.work)
        self.assertEqual((self.work/'.config'/'keep.txt').read_text(),'keep')
    def test_symlink_config_rejected_without_external_write(self):
        outside=self.root/'outside';outside.mkdir();(self.work/'.config').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(Blocker,'SYMLINK'):prepare_environment(self.work)
        self.assertEqual(list(outside.iterdir()),[])
    def test_regular_file_config_rejected(self):
        (self.work/'.config').write_text('not a directory')
        with self.assertRaises(Blocker):prepare_environment(self.work)
    def test_tmp_symlink_rejected(self):
        (self.work/'.tmp').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(Blocker):prepare_environment(self.work)
    def test_nested_semgrep_symlink_rejected(self):
        (self.work/'.config').mkdir();(self.work/'.config'/'.semgrep').symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(Blocker,'SYMLINK'):prepare_environment(self.work)
    def test_missing_or_symlink_work_rejected(self):
        with self.assertRaises(Blocker):prepare_environment(self.root/'missing')
        (self.root/'link').symlink_to(self.work,target_is_directory=True)
        with self.assertRaises(Blocker):prepare_environment(self.root/'link')
    def test_write_failure_does_not_fallback_to_real_home(self):
        with mock.patch('ntk_b38.scanner_environment.tempfile.mkstemp',side_effect=PermissionError('test readonly')):
            with self.assertRaisesRegex(Blocker,'NOT_READY'):prepare_environment(self.work)
    def test_secrets_and_proxy_not_inherited(self):
        with mock.patch.dict(os.environ,{'HOME':'/test-real-home','XDG_CONFIG_HOME':'/test-real-config',
            'HF_TOKEN':'secret-a','OPENAI_API_KEY':'secret-b','HTTP_PROXY':'secret-proxy'}):
            env,proof=prepare_environment(self.work)
        self.assertNotIn('HF_TOKEN',env);self.assertNotIn('OPENAI_API_KEY',env);self.assertNotIn('HTTP_PROXY',env)
        text=(self.work/'ENVIRONMENT_PROOF.json').read_text()
        self.assertNotIn('secret-',text);self.assertNotIn('/test-real-',text)


class ChildScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.target=self.root/'uploaded_project';self.target.mkdir()
        (self.target/'Probe.java').write_text('class Probe {}\n')
    def tearDown(self):self.temp.cleanup()
    def call(self,mode='ok'):
        binary=fake_binary(self.root,mode)
        run=self.root/('run_'+mode);run.mkdir()
        with mock.patch.object(scanner,'OPENGREP_SHA',sha_file(binary)):
            value=scanner.scan(run,self.target,['22'],Path(sys.executable),binary=binary)
        return run,value
    def test_old_missing_xdg_directory_reproduced_by_fake_child(self):
        binary=fake_binary(self.root)
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(self.root),'XDG_CONFIG_HOME':str(self.root/'.config')}
        p=subprocess.run([str(binary)],env=env,text=True,capture_output=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('FileNotFoundError',p.stderr);self.assertIn('.config',p.stderr)
    def test_real_child_environment_and_inherited_seccomp_with_fake_scanner(self):
        run,result=self.call()
        self.assertEqual(len(result['results']),1)
        proof=json.loads((run/'opengrep/isolation.json').read_text())
        self.assertEqual(proof['network']['AF_INET'],'DENIED_EPERM')
        self.assertEqual(proof['network']['AF_INET6'],'DENIED_EPERM')
        final=json.loads((run/'opengrep/PROOF.json').read_text())
        self.assertEqual(final['environment_proof_sha256'],sha_file(run/'opengrep/ENVIRONMENT_PROOF.json'))
    def test_subprocess_failure_preserves_error_tail(self):
        with self.assertRaisesRegex(Blocker,'FAKE_SCANNER_INTENTIONAL_FAILURE'):self.call('exit2')
        d=self.root/'run_exit2/opengrep'
        self.assertEqual(json.loads((d/'PROCESS_RESULT.json').read_text())['returncode'],2)
        self.assertTrue((d/'FAILURE_DIAGNOSTIC.json').is_file())
        self.assertFalse((d/'PROOF.json').exists())
    def test_missing_raw_output_rejected(self):
        with self.assertRaisesRegex(Blocker,'SCANNER_OUTPUT_JSON_MISSING'):self.call('missing_output')
    def test_zero_findings_scanner_result_not_fabricated(self):
        _,result=self.call('empty');self.assertEqual(result,{'results':[]})
    def test_original_binary_pin_not_bypassed(self):
        binary=fake_binary(self.root);run=self.root/'untrusted';run.mkdir()
        with self.assertRaisesRegex(Blocker,'PINNED_OPENGREP_DRIFT'):
            scanner.scan(run,self.target,['22'],Path(sys.executable),binary=binary)
        self.assertFalse((run/'opengrep').exists())
    def test_archive_excludes_private_runtime_directories(self):
        run=self.root/'packed';run.mkdir();downloads=self.root/'downloads';downloads.mkdir()
        for relative in ('opengrep/.config/settings','opengrep/.cache/cachefile','opengrep/.tmp/native','opengrep/.state/state','opengrep/.semgrep/settings','opengrep/ENVIRONMENT_PROOF.json'):
            p=run/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('test')
        archive,_=pack(run,downloads,{})
        with zipfile.ZipFile(archive) as z:
            self.assertIn('opengrep/ENVIRONMENT_PROOF.json',z.namelist())
            self.assertFalse(any(any(x in Path(n).parts for x in ('.config','.cache','.tmp','.state','.semgrep')) for n in z.namelist()))


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.work=self.root/'work';self.work.mkdir();self.downloads=self.root/'downloads';self.downloads.mkdir()
        ml=self.work/'.ntk_v5_lora_venv/bin/python';ml.parent.mkdir(parents=True);ml.symlink_to(sys.executable)
        self.repo=self.root/'repo';self.repo.mkdir()
    def tearDown(self):self.temp.cleanup()
    def execute(self,mode='ok'):
        binary=fake_binary(self.root,mode,fixture_index=True)
        def real_process_call(run,target,cwes,mlpy):
            return scanner.scan(run,target,cwes,mlpy,binary=binary)
        output=io.StringIO()
        with mock.patch.object(scanner,'OPENGREP_SHA',sha_file(binary)), \
             mock.patch.object(preflight_scanner,'scan',side_effect=real_process_call), \
             mock.patch.object(preflight_scanner,'frozen_state',return_value={'head':COMMIT,'status_porcelain':''}), \
             contextlib.redirect_stdout(output):
            rc=preflight_scanner.main(['--work',str(self.work),'--downloads',str(self.downloads),'--repo',str(self.repo)])
        runs=list((self.work/'batch38_scanner_preflight_runs').iterdir());self.assertEqual(len(runs),1)
        return rc,runs[0],json.loads((runs[0]/'00_SUMMARY.json').read_text())
    def test_all_five_profiles_use_subprocess_scanner_mock_only(self):
        rc,run,s=self.execute()
        self.assertEqual(rc,0);self.assertEqual(s['status'],'B38R1_SCANNER_PREFLIGHT_PASS')
        self.assertEqual(set(s['profiles']),{'A','B','C','SQL','D'})
        self.assertEqual([s['profiles'][p]['findings'] for p in preflight_scanner.PROFILES],[4,4,4,4,16])
        self.assertFalse((self.work/'batch38_gates').exists())
        self.assertEqual(s['model_inference'],'NOT_EXECUTED');self.assertEqual(s['codeql_dataflow'],'NOT_EXECUTED')
        with zipfile.ZipFile(next(self.downloads.glob('*.zip'))) as z:
            manifest=json.loads(z.read('OUTPUT_MANIFEST.json'))
            import hashlib
            for name,h in manifest.items():self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),h)
            self.assertFalse(any('uploaded_project' in Path(n).parts for n in z.namelist()))
    def test_all_profiles_report_failures_without_model_fallback(self):
        rc,run,s=self.execute('exit2')
        self.assertEqual(rc,2);self.assertEqual(len(s['profiles']),5)
        self.assertTrue(all(r['status']=='BLOCKED' for r in s['profiles'].values()))
        self.assertFalse((self.work/'batch38_gates').exists())
    def test_missing_fixture_coverage_never_a_pass(self):
        rc,_,s=self.execute('empty')
        self.assertEqual(rc,2)
        self.assertTrue(all('COVERAGE_MISMATCH' in r['blocker'] for r in s['profiles'].values()))
    def test_scanner_preflight_before_abcd_loop(self):
        text=(ROOT/'run_all.sh').read_text()
        self.assertLess(text.index('preflight_scanner.py'),text.index('for PHASE in A B C D'))
        self.assertIn('set -euo pipefail',text)
        self.assertNotIn('pack install',text)



class CoverageContractTests(unittest.TestCase):
    def setUp(self):
        self.manifest=json.loads((ROOT/'samples/MANIFEST.json').read_text())
        self.combined=self.manifest['B38D_JAVA.zip']
    def rows(self):
        return {'results':[{'cwe':c,'path':p} for c,paths in self.combined['scanner_expectations'].items() for p in paths]}
    def test_D_scanner_four_per_cwe_while_dataflow_checks_all_sixteen(self):
        self.assertEqual(len(self.rows()['results']),16)
        proof=verify_fixture_scanner(self.rows(),self.combined,Path('/tmp'),'22 78 79 89'.split())
        for c in ('22','78','79','89'):
            self.assertTrue(proof[c]['match']);self.assertEqual(len(proof[c]['expected_files']),4)
            self.assertEqual(len(self.combined['expectations'][c]),16)
            self.assertEqual(sum(r['expected_flow'] for r in self.combined['expectations'][c].values()),2)
    def test_D_coverage_comes_from_each_original_profile_including_controls(self):
        for phase,c in (('A','22'),('B','78'),('C','79'),('SQL','89')):
            native=self.manifest['B38'+phase+'_JAVA.zip']['expectations'][c]
            self.assertEqual(set(self.combined['scanner_expectations'][c]),set(native))
            self.assertEqual(sum(not x['expected_flow'] for x in native.values()),2)
    def test_missing_control_callsite_still_blocks(self):
        rows=self.rows();c='22'
        control=next(p for p in self.combined['scanner_expectations'][c] if not self.combined['expectations'][c][p]['expected_flow'])
        rows['results']=[r for r in rows['results'] if not (r['cwe']==c and r['path']==control)]
        with self.assertRaisesRegex(Blocker,'COVERAGE_MISMATCH'):verify_fixture_scanner(rows,self.combined,Path('/tmp'),[c])
    def test_unexpected_cross_cwe_callsite_still_blocks(self):
        rows=self.rows();rows['results'].append({'cwe':'22','path':self.combined['scanner_expectations']['89'][0]})
        with self.assertRaisesRegex(Blocker,'COVERAGE_MISMATCH'):verify_fixture_scanner(rows,self.combined,Path('/tmp'),['22'])
    def test_cross_cwe_false_dataflow_still_fails_detection_contract(self):
        c='22';expect=self.combined['expectations'][c]
        paths=[{'location':{'uri':p}} for p,r in expect.items() if r['expected_flow']]
        self.assertTrue(check_cases(paths,expect)['match'])
        paths.append({'location':{'uri':self.combined['scanner_expectations']['89'][0]}})
        self.assertFalse(check_cases(paths,expect)['match'])


if __name__=='__main__':unittest.main()
