"""Local unit tests for pinned Git blob checks and safe Java-only ZIP packaging."""
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec

f=Path(__file__).resolve().parents[1]/'tools'/'prepare_github_java_samples.py'
spec=spec_from_loader('ntk_github_prepare',SourceFileLoader('ntk_github_prepare',str(f)))
module=module_from_spec(spec);spec.loader.exec_module(module)

class PrepareTest(unittest.TestCase):
    def test_git_blob_sha(self):
        data=b'class Example {}\n'
        expected=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        self.assertEqual(module.blob_sha(data),expected)
    def test_safe_package(self):
        data=b'public class Example { public int answer() { return 42; } }\n'
        blob=module.blob_sha(data)
        spec={'name':'SampleFixtureOnly','repository':'example/source','commit':'0'*40,
              'branch':'fixture','note':'local test only',
              'files':(('Sample.java','src/Example.java',blob),)}
        with tempfile.TemporaryDirectory() as td:
            path,metadata=module.create_prepared_zip(spec,Path(td),fetcher=lambda *_:data)
            self.assertEqual(metadata['java_files'],1)
            self.assertEqual(metadata['javac_21_preflight'],'PASS')
            with zipfile.ZipFile(path) as z:
                self.assertEqual(z.namelist(),['src/Example.java'])
                self.assertEqual(z.read('src/Example.java'),data)
            # Idempotent when rerun with the same source.
            module.create_prepared_zip(spec,Path(td),fetcher=lambda *_:data)
    def test_fails_sha_mismatch(self):
        with self.assertRaisesRegex(ValueError,'checksum mismatch'):
            module.checked_source('a/b','0'*40,'A.java','0'*40,lambda *_:b'public class A{}')
if __name__=='__main__':unittest.main()
