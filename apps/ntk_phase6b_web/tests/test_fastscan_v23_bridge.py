"""CPU-only V2.3 proof validation: synthetic archive, no code scanning."""
from __future__ import annotations
from pathlib import Path
import json
import tempfile
import unittest
import zipfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fastscan_v23_patch import POLICY_PINS
from hashlib import sha256
RID='ntkfast_20261021T085514Z_e86a3942'
def sha(raw): return sha256(raw).hexdigest()
def raw(doc):return (json.dumps(doc,sort_keys=True,separators=(',',':'))+'\n').encode()

class SourceProofAuditTests(unittest.TestCase):
    def make_proof(self,svc,zp,run, *, tamper=False):
        with zipfile.ZipFile(zp) as z:
            contents={n:z.read(n) for n in z.namelist() if n!='SHA256SUMS'}
        proof={'env_source_proven_absent':True,'query_pins_verified':True,
               'no_source_is_not_safe':True,'skipped_source_queries':['78','89'],
               'query_sha256':dict(POLICY_PINS),
               'source_sha256':{'Example.java':'b'*64},'verified_java_files':1}
        if tamper:
            proof['skipped_source_queries']=['22']
        content=raw(proof)
        contents['FAST_SOURCE_ABSENCE_PROOF.json']=content
        (run/'FAST_SOURCE_ABSENCE_PROOF.json').write_bytes(content)
        sums=''.join(sha(b)+'  '+name+'\n' for name,b in sorted(contents.items()))
        with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
            for name,b in sorted(contents.items()):z.writestr(name,b)
            z.writestr('SHA256SUMS',sums)
        Path(str(zp)+'.sha256').write_text(sha(zp.read_bytes())+'  '+zp.name+'\n')
    def test_valid_v23_guard_proof_and_legacy_import(self):
        from test_fast_artifacts import ArtifactTests
        with tempfile.TemporaryDirectory() as tmp:
            svc,zp,run=ArtifactTests().make(tmp,True)
            self.assertEqual(svc.overview(RID)['summary']['status'],'NTK_FASTSCAN_EPOCH1_COMPLETE')
            self.make_proof(svc,zp,run)
            self.assertEqual(svc.overview(RID)['summary']['status'],'NTK_FASTSCAN_EPOCH1_COMPLETE')
    def test_forged_skip_list_rejected(self):
        from test_fast_artifacts import ArtifactTests
        with tempfile.TemporaryDirectory() as tmp:
            svc,zp,run=ArtifactTests().make(tmp,True)
            self.make_proof(svc,zp,run,tamper=True)
            with self.assertRaisesRegex(ValueError,'FAST_SOURCE_SKIP_PROVENANCE_CONFLICT'):
                svc.overview(RID)

if __name__=='__main__':unittest.main()
