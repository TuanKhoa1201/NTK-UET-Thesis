from __future__ import annotations
import csv
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

from ntk_b33.common import Blocker
from ntk_b34.core import read_calls, read_arguments, emit_flow, SOURCE_POLICY
from ntk_b37.semantic import choose, adjudicate, POLICY, POLICY_SHA
from secure_intake import secure_unpack, IntakeError
from build_jdk_only import command as javac_cmd
from scanner import canonical_rule_id, ScanError
from run_batch37a import (ensure_safe_input, preserve_raw_opengrep, source_inventory,
                          assert_guarded_query, require_b37a_evidence, bundle)

ROOT=Path(__file__).resolve().parents[1]

class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.t=Path(self.tmp.name)
    def test_sample_is_not_old_fixture(self):
        with zipfile.ZipFile(ROOT/'sample_new_java_project.zip') as z:
            names=z.namelist()
            self.assertEqual(len(names),4)
            self.assertTrue(all('demo/orders' in n and 'ntk/b34' not in n for n in names))
    def test_sample_unpacks_only_java(self):
        proof=ensure_safe_input(ROOT/'sample_new_java_project.zip',self.t/'src')
        self.assertEqual(proof['java_files'],4)
        self.assertEqual(len(proof['java_source_hashes']),4)
    def test_relative_traversal_rejected(self):
        p=self.t/'bad.zip'
        with zipfile.ZipFile(p,'w') as z:z.writestr('../x.java','class X {}')
        with self.assertRaises(IntakeError):ensure_safe_input(p,self.t/'src')
    def test_absolute_path_rejected(self):
        p=self.t/'bad.zip'
        with zipfile.ZipFile(p,'w') as z:z.writestr('/etc/x.java','class X {}')
        with self.assertRaises(IntakeError):ensure_safe_input(p,self.t/'src')
    def test_symlink_rejected(self):
        p=self.t/'bad.zip'
        info=zipfile.ZipInfo('src/H.java');info.create_system=3
        info.external_attr=(stat.S_IFLNK|0o777)<<16
        with zipfile.ZipFile(p,'w') as z:z.writestr(info,'/tmp/evil')
        with self.assertRaises(IntakeError):ensure_safe_input(p,self.t/'src')
    def test_non_java_file_not_extracted(self):
        p=self.t/'prj.zip'
        with zipfile.ZipFile(p,'w') as z:
            z.writestr('bad.sh','#!/bin/sh\nexit 1')
            z.writestr('test/A.java','class A {}')
        proof=ensure_safe_input(p,self.t/'src')
        self.assertFalse((self.t/'src/bad.sh').exists())
        self.assertEqual(proof['java_files'],1)
    def test_more_than_24_java_refused(self):
        p=self.t/'prj.zip'
        with zipfile.ZipFile(p,'w') as z:
            for i in range(25):z.writestr(f'A{i}.java',f'class A{i} {{}}')
        with self.assertRaises(Blocker):ensure_safe_input(p,self.t/'src')
    def test_builder_disables_annotation_processing(self):
        secure_unpack((ROOT/'sample_new_java_project.zip').read_bytes(),self.t/'src')
        cmd=javac_cmd(self.t/'src',self.t/'out')
        self.assertIn('-proc:none',cmd)
        self.assertNotIn('mvn',cmd)
        self.assertNotIn('gradle',cmd)
        self.assertEqual(len([x for x in cmd if x.endswith('.java')]),4)
    def test_javac_real_build_if_available(self):
        if not shutil.which('javac'):
            self.skipTest('no local JDK')
        secure_unpack((ROOT/'sample_new_java_project.zip').read_bytes(),self.t/'src')
        cp=subprocess.run(javac_cmd(self.t/'src',self.t/'out'),capture_output=True,text=True)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(len(list((self.t/'out').rglob('*.class'))),4)

class QueryTests(unittest.TestCase):
    def test_queries_are_not_scoped_to_old_fixture(self):
        for name in ('ApiCalls.ql','ArgumentSpans.ql','Flow.template'):
            s=(ROOT/'queries'/name).read_text()
            self.assertNotIn('ntk.b34',s)
            self.assertNotIn('Case01',s)
            self.assertIn('java',s)
    def test_call_query_extracts_sql_and_source(self):
        s=(ROOT/'queries/ApiCalls.ql').read_text()
        for text in ('prepareStatement','executeQuery','setString','getenv','compiler_signature','m.getSignature()'):
            self.assertIn(text,s)
        self.assertIn('is_static',s)
    def test_exact_semantic_allows_sql_text_and_rejects_binding(self):
        stmt=dict(package='java.sql',**{'class':'Statement'},method='executeQuery',compiler_signature='executeQuery(java.lang.String)')
        binder=dict(package='java.sql',**{'class':'PreparedStatement'},method='setString',compiler_signature='setString(int,java.lang.String)')
        prepared=dict(package='java.sql',**{'class':'Connection'},method='prepareStatement',compiler_signature='prepareStatement(java.lang.String)')
        self.assertEqual(choose(stmt,0),'SQL_GRAMMAR_SINK_ELIGIBLE')
        self.assertEqual(choose(prepared,0),'SQL_GRAMMAR_SINK_ELIGIBLE')
        self.assertEqual(choose(binder,1),'PARAMETER_BINDING_VALUE_NOT_SQL_GRAMMAR_SINK')
        self.assertEqual(choose(dict(package='foo',**{'class':'Bar'},method='exec',compiler_signature='exec(int)'),0),'NEEDS_SEMANTIC_REVIEW_UNKNOWN_SINK')
    def test_policy_is_scoped_and_explicit_source(self):
        self.assertIn('JDK_ONLY',POLICY['scope'])
        self.assertIn('CodeQL database',POLICY['threat_model'])
        self.assertNotIn('FOUR_CASE_',POLICY['scope'])
    def test_adjudication_raw_label_immutable(self):
        base=dict(package='java.sql',**{'class':'PreparedStatement'},method='setString',signature='void setString(int p0, String p1)',
                  compiler_signature='setString(int,java.lang.String)',arity=2)
        label={k:base[k] for k in ('package','class','method','signature')}|{'type':'sink','sink_args':['p1']}
        old=deepcopy(label)
        accepted,decisions=adjudicate([base],[label])
        self.assertEqual(label,old)
        self.assertEqual(accepted,[])
        self.assertEqual(decisions[0]['decision'],'PARAMETER_BINDING_VALUE_NOT_SQL_GRAMMAR_SINK')
    def test_compiled_flow_template_exact_overload(self):
        base=dict(package='java.sql',**{'class':'Statement'},method='executeQuery',signature='ResultSet executeQuery(String p0)',
                  compiler_signature='executeQuery(java.lang.String)',arity=1)
        label={k:base[k] for k in ('package','class','method','signature')}|{'type':'sink','sink_args':['p0']}
        text,proof=emit_flow((ROOT/'queries/Flow.template').read_text(),[base],[label],'epoch_1')
        self.assertIn('getSignature() = "executeQuery(java.lang.String)"',text)
        self.assertIn('sink.asExpr() = call.getArgument(0)',text)
        self.assertEqual(proof[0]['argument_indices'],[0])
    def test_b34r5_real_evidence_semantic_guard_parity(self):
        # Archived user-observed real B34R5 model labels, not fabricated fixture labels.
        source=Path('/mnt/data/batch34r5_20261018T165902Z_5c5ec7_result.zip')
        if not source.is_file():
            self.skipTest('original B34R5 evidence unavailable in author environment')
        from ntk_b35.semantic import adjudicate as old_adjudicate
        with zipfile.ZipFile(source) as z:
            cases=json.loads(z.read('CANDIDATE_MANIFEST.json'))
            for arm in ('epoch_1','epoch_2'):
                raw=json.loads(z.read(f'live/{arm}/cold/cwe-89/llm_labelled_sink_apis.json'))
                before,_=old_adjudicate(cases,raw)
                after,records=adjudicate(cases,raw)
                self.assertEqual(after,before)
                self.assertTrue(any(x['decision']=='PARAMETER_BINDING_VALUE_NOT_SQL_GRAMMAR_SINK'
                                    for x in records))
                self.assertTrue(any(x['decision']=='SQL_GRAMMAR_SINK_ELIGIBLE'
                                    for x in records))

    def test_incorrect_generated_query_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'x.ql';f.write_text('ntk.b34 __SINK_BODY__')
            with self.assertRaises(Blocker):assert_guarded_query(f,f.read_text())
    def test_source_model_requires_real_compiler_call(self):
        x=dict(package='java.lang',**{'class':'System'},compiler_signature='getenv(java.lang.String)',uri='src/T.java')
        self.assertEqual(source_inventory([],[])['source_count'],0)
        self.assertEqual(source_inventory([], [x])['source_count'],1)
        self.assertFalse(source_inventory([], [x])['not_general_source_discovery'] is False)
    def test_no_query_without_positive_is_not_pass(self):
        result={'flow_count':0,'retained_opengrep':1}
        require_b37a_evidence(result,{'results':[{}]},[{'cwe':'89'}],{'source_count':0},'epoch_1')
        with self.assertRaises(Blocker):
            require_b37a_evidence({'flow_count':2,'retained_opengrep':1},{'results':[{}]},[{'cwe':'89'}],{'source_count':0},'epoch_1')

class ScannerTests(unittest.TestCase):
    def test_namespaced_id_normalization(self):
        self.assertEqual(canonical_rule_id('/tmp/a.b.ntk-b34-java-sql-call-review'.replace('/tmp/','tmp.')),
                         'ntk-b34-java-sql-call-review')
        with self.assertRaises(ScanError):canonical_rule_id('wrong-java-rule')
    def test_raw_scan_preserved_and_canonical_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            w=Path(tmp);p=w/'src';p.mkdir();(p/'Foo.java').write_text('class Foo {}')
            row={'check_id':'config.ntk-b34-java-sql-call-review','path':'src/Foo.java'}
            derived=preserve_raw_opengrep({'results':[row]},[{'uri':'Foo.java'}],p,w)
            self.assertEqual(derived['results'][0]['check_id'],'ntk-b34-java-sql-call-review')
            self.assertEqual(json.loads((w/'OPENGREP_ORIGINAL.json').read_text())['results'][0],row)

class BundleTests(unittest.TestCase):
    def test_report_excludes_upload_source_and_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);run=d/'run';run.mkdir();downloads=d/'dl';downloads.mkdir()
            (run/'uploaded_project').mkdir();(run/'uploaded_project/Sensitive.java').write_text('SECRET123')
            (run/'database').mkdir();(run/'database/internal.bin').write_text('SECRET456')
            (run/'visible.txt').write_text('ready')
            bundle(run,downloads,{'status':'B37A_BLOCKED'})
            z=zipfile.ZipFile(downloads/'run_result.zip')
            self.assertIn('visible.txt',z.namelist())
            self.assertNotIn('uploaded_project/Sensitive.java',z.namelist())
            self.assertNotIn('database/internal.bin',z.namelist())
            self.assertEqual(len(z.testzip() or ''),0)

if __name__=='__main__':unittest.main()
