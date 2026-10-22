"""CPU-only verified source-absence fast-path tests; never launch scanning, LLM or CodeQL."""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fastscan_v23_patch import GUARD, upgrade_text, upgrade_bytes, PatchRejected, BASE_SHA


def sha(raw):return hashlib.sha256(raw).hexdigest()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        self.qp=root/'queries';self.qp.mkdir()
        self.target=root/'upload';self.target.mkdir()
        self.pins={x:sha(x.encode()+b'-TEST') for x in ('NtkScope.qll','Source.template','Flow.template')}
        for name in self.pins:
            (self.qp/name).write_bytes(name.encode()+b'-TEST')
        ns={}
        exec(GUARD,ns)
        self.prove=ns['_ntkfast_source_absence_proof']
    def tearDown(self):self.tmp.cleanup()
    def put(self, content):
        (self.target/'Example.java').write_bytes(content)
    def test_no_getenv_with_exact_pinned_queries_can_skip(self):
        self.put(b'public class Example { void foo(){ Runtime.getRuntime().exec("ls"); } }')
        p=self.prove(self.target,self.qp,self.pins)
        self.assertTrue(p['query_pins_verified'])
        self.assertTrue(p['env_source_proven_absent'])
        self.assertTrue(p['no_source_is_not_safe'])
        self.assertEqual(p['verified_java_files'],1)
    def test_real_getenv_and_static_import_cannot_skip(self):
        for source in (b'public class Example { void f(){System.getenv("X");}}',
                       b'import static java.lang.System.getenv;class Example{void f(){getenv("X");}}'):
            with self.subTest(source=source):
                self.put(source)
                p=self.prove(self.target,self.qp,self.pins)
                self.assertFalse(p['env_source_proven_absent'])
    def test_unicode_escape_fail_closed(self):
        self.put(b'class Example {String s=System.\\u0067etenv("X");}')
        p=self.prove(self.target,self.qp,self.pins)
        self.assertFalse(p['env_source_proven_absent'])
    def test_query_hash_drift_fail_closed(self):
        self.put(b'class Example {}')
        (self.qp/'Flow.template').write_text('MISMATCH')
        p=self.prove(self.target,self.qp,self.pins)
        self.assertFalse(p['env_source_proven_absent'])
        self.assertFalse(p['query_pins_verified'])
    def test_missing_java_does_not_skip(self):
        self.assertFalse(self.prove(self.target,self.qp,self.pins)['env_source_proven_absent'])
    def test_linked_java_does_not_skip(self):
        original=self.target/'real.txt';original.write_text('class Example {}')
        (self.target/'A.java').symlink_to(original)
        self.assertFalse(self.prove(self.target,self.qp,self.pins)['env_source_proven_absent'])
    def test_more_than_24_java_fails_closed(self):
        for i in range(25):
            (self.target/f'{i}.java').write_text(f'class C{i}{{}}')
        self.assertFalse(self.prove(self.target,self.qp,self.pins)['env_source_proven_absent'])
    def test_transform_zero_candidate_bug_is_repaired(self):
        # Synthetic structural fixture only, not runtime simulation.
        fixture=Path(__file__).resolve().parents[1]/'tests'/'synthetic_v22_runner.txt'
        old=fixture.read_text()
        newer=upgrade_text(old)
        self.assertIn("raw_cases=native_inputs(flattened) if flattened else []",newer)
        self.assertNotIn("flattened=[x for c in CWES for x in cases[c]];raw_cases=native_inputs(flattened)",newer)
        self.assertEqual(newer.count('FAST_SOURCE_ABSENCE_PROOF.json'),1)
        self.assertEqual(newer.count('if c==\'79\' or not eligible or (fast_no_env'),1)
        ast.parse(newer)
    def test_byte_pin_rejects_synthetic_code(self):
        with self.assertRaises(PatchRejected):upgrade_bytes(b'#!/usr/bin/env python3\n')


if __name__=='__main__':unittest.main()
