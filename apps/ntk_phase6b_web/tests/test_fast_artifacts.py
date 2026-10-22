"""Offline artifact-contract test with synthetic data only; never executes an NTK scan."""
from __future__ import annotations
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fast_bridge import FastBridge

def raw(doc):return (json.dumps(doc,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
RID='ntkfast_20261021T085514Z_e86a3942'

class FakeWorkbench:
    @staticmethod
    def read(p,limit=64*1024*1024):
        p=Path(p)
        if not p.is_file() or p.is_symlink() or p.stat().st_size>limit:raise ValueError('READ_REJECTED')
        return p.read_bytes()
    @staticmethod
    def loads(b):return json.loads(b)
    @staticmethod
    def archive(b,expected):
        if sha(b)!=expected:raise ValueError('SHA_FAIL')
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            contents={p.filename:z.read(p) for p in z.infolist()}
        sums={x.split('  ')[1]:x.split('  ')[0] for x in contents['SHA256SUMS'].decode().splitlines()}
        if set(contents)!=(set(sums)|{'SHA256SUMS'}):raise ValueError('UNEXPECTED_MEMBER')
        for name,expected in sums.items():
            if sha(contents[name])!=expected:raise ValueError('SHA_MEMBER')
        return contents
    @staticmethod
    def verify_report(doc,summary,arm,input_sha):
        if doc['input_sha256']!=input_sha or doc['arm']!=arm or len(doc['findings'])!=summary['findings']:
            raise ValueError('REPORT_MISMATCH')

class ArtifactTests(unittest.TestCase):
    def make(self,home,has_candidates=True):
        work=Path(home)/'work';downloads=Path(home)/'downloads';downloads.mkdir();run=work/'ntk_fastscan_runs'/RID
        run.mkdir(parents=True);private=run/'private'
        status='NTK_FASTSCAN_EPOCH1_COMPLETE' if has_candidates else 'NTK_FASTSCAN_RAW_ONLY_NO_CANDIDATES'
        arms=['opengrep_only','epoch_1'] if has_candidates else ['opengrep_only']
        sha_input='c'*64
        top={
            '00_RESULT.json':{'status':status,'blockers':[],'new_training':False,'independent_gold':False,
                              'model_xss_gate_granted':False,'completed_arms':arms,'new_native_requests':2 if has_candidates else 0,
                              'input_sha256':sha_input,'elapsed_s':180.2,'raw_opengrep_findings':1},
            'COMPARISON.json':{'arms':{a:{'findings':1,'retained_opengrep':1} for a in arms}},
            'PROFILE_DISCOVERY.json':{'active_cwes':['78','89'] if has_candidates else [],
                                      'no_candidates_cwes':['22','79'] if has_candidates else ['22','78','79','89'],
                                      'candidates':{'22':0,'78':1 if has_candidates else 0,'79':0,'89':1 if has_candidates else 0},
                                      'no_candidates_is_not_safe':True},
            'BEFORE.json':{'git':'locked'},'AFTER.json':{'git':'locked'},
        }
        if has_candidates:top['NATIVE_epoch_1.json']={'new_requests':2,'accepted':1,'abstain':1}
        manifest={}
        for arm in arms:
            folder=private/'analysis'/arm;folder.mkdir(parents=True)
            score={'final_score':51.0,'risk_level':'MEDIUM'}
            alert={'id':'a','cwe':'89','origin':'OPENGREP','location':{'uri':'src/Test.java'},
                   'rule_id':'r','retained':True,'vulnerability_confirmed':False,'score':score,
                   'evidence_status':'REVIEW_REQUIRED','evidence_origin':'OPENGREP_ONLY','dataflow':[]}
            files={'result.json':{'arm':arm,'input_sha256':sha_input,'findings':[alert]},
                   'report.sarif':{'version':'2.1.0','runs':[{'results':[{'ruleId':'r'}]}]}}
            for leaf,doc in files.items():
                b=raw(doc);(folder/leaf).write_bytes(b)
                manifest['analysis/'+arm+'/'+leaf]=sha(b)
        top['PRIVATE_RESULT_MANIFEST.json']=manifest
        all_bytes={name:raw(obj) for name,obj in top.items()}
        for name,b in all_bytes.items():(run/name).write_bytes(b)
        totals=''.join(sha(b)+'  '+name+'\n' for name,b in sorted(all_bytes.items()))
        zp=downloads/(RID+'_result.zip')
        with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
            for name,b in sorted(all_bytes.items()):z.writestr(name,b)
            z.writestr('SHA256SUMS',totals)
        Path(str(zp)+'.sha256').write_text(sha(zp.read_bytes())+'  '+zp.name+'\n')
        s=FastBridge.__new__(FastBridge)
        s.workbench=FakeWorkbench
        s.cfg={'downloads':str(downloads)}
        s.runroot=work/'ntk_fastscan_runs'
        return s,zp,run
    def test_fast_e1_artifact_and_sanitized_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc,zp,run=self.make(tmp,True)
            detail=svc.overview(RID)
            self.assertEqual(set(detail['comparison']['arms']),{'opengrep_only','epoch_1'})
            self.assertEqual(detail['profile_discovery']['active_cwes'],['78','89'])
            view=svc.view(RID,'epoch_1')
            self.assertEqual(view['findings'][0]['score']['final_score'],51.0)
            self.assertFalse(view['findings'][0]['confirmed'])
            with self.assertRaises(ValueError):svc.file(RID,'base','result.json')
            self.assertEqual(svc.evidence(RID),zp.read_bytes())
    def test_raw_only_artifact_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc,zp,run=self.make(tmp,False)
            self.assertEqual(set(svc.overview(RID)['comparison']['arms']),{'opengrep_only'})
            with self.assertRaises(ValueError):svc.view(RID,'epoch_1')
            path=run/'private/analysis/opengrep_only/result.json'
            path.write_bytes(path.read_bytes()+b' ')  # cryptographic mismatch
            with self.assertRaises(ValueError):svc.overview(RID)

if __name__=='__main__':unittest.main()
