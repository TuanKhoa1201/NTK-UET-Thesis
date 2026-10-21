#!/usr/bin/env python3
"""Synthetic approval and temporary files only, never a real human-label audit."""
import contextlib, copy, importlib.util, io, json, os
from pathlib import Path
import pty, select, subprocess, sys, tempfile, time, unittest, zipfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import bulk_review as b
TOOL=Path(os.environ.get('NTK_B39B6_TEST_TOOL','/mnt/data/_bulk_b39b6'))
SOURCE_PACKAGE=Path(os.environ.get('NTK_B39B4_TEST_PACKAGE','/mnt/data/ntk_batch39b4_hybrid_cli_20261020.zip'))
cli=b.load_original(TOOL)
from eval_core import initial_labels, unit_id, PROTOCOL, ARMS
with zipfile.ZipFile(SOURCE_PACKAGE) as z:
    SOURCE_RAW=z.read('samples/B39B4_JDK_INTEGRATION.zip')
SOURCES=cli.zip_members(SOURCE_RAW)
PROPOSAL=b.strict_json((ROOT/'review_proposals.json').read_bytes())
UNITS=[{**{k:r[k] for k in ('uri','cwe','source_sha256')},'input_sha256':b.INPUT_SHA,
        'unit_id':unit_id(b.INPUT_SHA,r['uri'],r['cwe']),
        'source_line_count':len(SOURCES[r['uri']].decode().splitlines())}
       for r in PROPOSAL['records']]
WHEN='2026-10-20T10:00:00+00:00'

def prepared(proposal=None, labels=None, **kwargs):
    return b.prepare_updates(cli,UNITS,labels or initial_labels(UNITS),proposal or PROPOSAL,
        kwargs.get('sources',SOURCES),kwargs.get('reviewer','SYNTHETIC_TEST_REVIEWER'),
        'a'*64,kwargs.get('timestamp',WHEN))

def workspace_at(root):
    w=root/'workspace';w.mkdir();(w/'private').mkdir()
    cli.write_json(w/'private/units.json',UNITS)
    vectors={a:[{'unit_id':u['unit_id'],'cwe':u['cwe'],'score':50.0,
                 'raw_opengrep':True,'any_reported_alert':True,'qualified_evidence':False,
                 'qualified_model':False,'qualified_policy':False} for u in UNITS] for a in ARMS}
    cli.write_json(w/'private/vectors.json',vectors)
    (w/'private/review_sources.zip').write_bytes(SOURCE_RAW)
    cli.write_json(w/'EVAL_PROTOCOL.json',PROTOCOL)
    cli.write_jsonl(w/'private/labels.draft.jsonl',initial_labels(UNITS))
    lock={'schema':'NTK_B39B6_WORKSPACE_V1','input_sha256':b.INPUT_SHA,'scope':PROTOCOL['scope'],
          'code':cli.code_hashes(),'independent_gold':False,'original_inputs':{},
          'files':{n:b.sha((w/n).read_bytes()) for n in ('private/units.json','private/vectors.json','private/review_sources.zip','EVAL_PROTOCOL.json')}}
    cli.write_json(w/'WORKSPACE_LOCK.json',lock)
    return w

class Validation(unittest.TestCase):
    def test_all_16_validate_and_unknowns_stay(self):
        rows,changed=prepared();self.assertEqual(len(changed),16)
        self.assertEqual(dict(b.Counter(r['truth'] for r in rows)),{'POSITIVE':5,'NEGATIVE':8,'UNKNOWN':3})
        cli.validate_labels(UNITS,rows,for_lock=True)
    def test_proposals_have_no_reviewed_metadata(self):
        self.assertTrue(all('reviewer' not in r and 'review_status' not in r for r in PROPOSAL['records']))
    def test_schema_and_provenance(self):
        for field,value in [('schema','bad'),('scope','GOLD'),('origin','human_gold'),('already_exposed_to_predictions',False),('proposed_by','teacher'),('input_sha256','b'*64)]:
            with self.subTest(field=field):
                p=copy.deepcopy(PROPOSAL);p[field]=value
                with self.assertRaises(Exception):prepared(p)
    def test_bad_count(self):
        p=copy.deepcopy(PROPOSAL);p['records'].pop()
        with self.assertRaises(Exception):prepared(p)
    def test_duplicate_uri(self):
        p=copy.deepcopy(PROPOSAL);p['records'][0]=copy.deepcopy(p['records'][1])
        with self.assertRaises(Exception):prepared(p)
    def test_wrong_hash(self):
        p=copy.deepcopy(PROPOSAL);p['records'][0]['source_sha256']='0'*64
        with self.assertRaises(Exception):prepared(p)
    def test_source_drift(self):
        src=dict(SOURCES);src[UNITS[0]['uri']]+=b'\n'
        with self.assertRaises(Exception):prepared(sources=src)
    def test_cwe_drift(self):
        p=copy.deepcopy(PROPOSAL);p['records'][0]['cwe']='22'
        with self.assertRaises(Exception):prepared(p)
    def test_unknown_truth_rejected(self):
        p=copy.deepcopy(PROPOSAL);p['records'][0]['truth']='SAFE'
        with self.assertRaises(Exception):prepared(p)
    def test_empty_text(self):
        for field in ('rationale','assumptions'):
            p=copy.deepcopy(PROPOSAL);p['records'][0][field]=' '
            with self.assertRaises(Exception):prepared(p)
    def test_bad_line_types(self):
        for lines in ([],[True],[0],[999],[1,1],['4']):
            p=copy.deepcopy(PROPOSAL);p['records'][0]['evidence_lines']=lines
            with self.assertRaises(Exception):prepared(p)
    def test_duplicate_json(self):
        with self.assertRaises(Exception):b.strict_json('{"a":1,"a":2}')
    def test_nonfinite_json(self):
        with self.assertRaises(Exception):b.strict_json('{"a":NaN}')
    def test_extra_proposal_fields(self):
        p=copy.deepcopy(PROPOSAL);p['records'][0]['reviewer']='invented'
        with self.assertRaises(Exception):prepared(p)
    def test_assistance_explicit(self):
        rows,_=prepared()
        for r in rows:
            self.assertIn('AI-assisted',r['reviewer']);self.assertIn('AI-assisted',r['rationale'])
            self.assertFalse(r['human_review_independent']);self.assertTrue(r['predictions_exposed_before_review'])
    def test_preserve_existing(self):
        allrows,_=prepared();labels=initial_labels(UNITS);labels[2]=allrows[2]
        labels[2]['reviewer']='PREEXISTING_ACTUAL_REVIEWER'
        rows,changed=prepared(labels=labels)
        self.assertEqual(rows[2],labels[2]);self.assertEqual(len(changed),15)
    def test_no_pending(self):
        labels,_=prepared();rows,changed=prepared(labels=labels)
        self.assertEqual(rows,labels);self.assertEqual(changed,[])
    def test_no_reviewer(self):
        with self.assertRaises(Exception):prepared(reviewer='')
    def test_invalid_time(self):
        with self.assertRaises(Exception):prepared(timestamp='2026-10-20T10:00:00')
    def test_original_code_pin(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Exception):b.load_original(Path(d))

class Writes(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.w=workspace_at(self.root)
        self.draft=self.w/'private/labels.draft.jsonl';self.before=self.draft.read_bytes()
        self.rows,self.changed=prepared();self.praw=(ROOT/'review_proposals.json').read_bytes()
    def tearDown(self):self.temp.cleanup()
    def commit(self):return b.commit(cli,self.w,self.before,self.rows,self.praw,'TEST_ONLY',self.changed)
    def test_backup_exact_and_receipt(self):
        folder,r=self.commit();self.assertEqual((folder/'labels.before.jsonl').read_bytes(),self.before)
        self.assertEqual(b.sha(self.draft.read_bytes()),r['after_sha256']);self.assertFalse((self.w/'LABEL_LOCK.json').exists())
    def test_locked_refused(self):
        (self.w/'LABEL_LOCK.json').write_text('{}')
        with self.assertRaises(Exception):self.commit()
        self.assertEqual(self.draft.read_bytes(),self.before)
    def test_partial_lock_refused(self):
        (self.w/'private/labels.locked.jsonl').write_text('')
        with self.assertRaises(Exception):self.commit()
    def test_concurrent_change_refused(self):
        self.draft.write_bytes(self.before+b'\n')
        with self.assertRaises(Exception):self.commit()
    def test_before_backup_failure_leaves_draft(self):
        with patch.object(b,'save_new',side_effect=OSError('TEST_DISK_FAILURE')):
            with self.assertRaises(Exception):self.commit()
        self.assertEqual(self.draft.read_bytes(),self.before)
    def test_restore_exact(self):
        folder,r=self.commit()
        with contextlib.redirect_stdout(io.StringIO()):code=b.restore(cli,self.w,folder/'receipt.json',ask=lambda x:'KHOI_PHUC_DRAFT')
        self.assertEqual(code,0);self.assertEqual(self.draft.read_bytes(),self.before)
    def test_restore_cancel(self):
        folder,r=self.commit();after=self.draft.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):code=b.restore(cli,self.w,folder/'receipt.json',ask=lambda x:'NO')
        self.assertEqual(code,3);self.assertEqual(self.draft.read_bytes(),after)
    def test_restore_changed_draft_refused(self):
        folder,r=self.commit();self.draft.write_bytes(self.draft.read_bytes()+b'\n')
        with self.assertRaises(Exception):b.restore(cli,self.w,folder/'receipt.json',ask=lambda x:'KHOI_PHUC_DRAFT')
    def test_restore_after_lock_refused(self):
        folder,r=self.commit();(self.w/'LABEL_LOCK.json').write_text('{}')
        with self.assertRaises(Exception):b.restore(cli,self.w,folder/'receipt.json',ask=lambda x:'KHOI_PHUC_DRAFT')
    def test_original_lock_and_evaluate_compatibility(self):
        self.commit();sentinel=(self.w/'private/vectors.json').read_bytes()
        for action in ('lock','evaluate'):
            argv=[sys.executable,'-I','-B',str(TOOL/'cli.py'),action,'--workspace',str(self.w)]
            if action=='evaluate':argv+=['--downloads',str(self.root)]
            p=subprocess.run(argv,capture_output=True,text=True,timeout=20)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        results=list(self.root.glob('b39b6_eval_*_result.zip'));self.assertEqual(len(results),1)
        with zipfile.ZipFile(results[0]) as z:
            metrics=json.loads(z.read('METRICS.json'));self.assertFalse(metrics['independent_gold'])
            self.assertEqual(metrics['truth_counts']['UNKNOWN'],3)
            self.assertEqual(metrics['arms']['epoch_1']['scopes']['all']['ranking']['status'],'WITHHELD_UNREVIEWED_UNITS')
        self.assertEqual((self.w/'private/vectors.json').read_bytes(),sentinel)
    def test_cli_preview_no_labels_written(self):
        p=subprocess.run([sys.executable,'-I','-B',str(ROOT/'bulk_review.py'),'--tool-dir',str(TOOL),'--workspace',str(self.w),'--reviewer','TEST_ONLY'],capture_output=True,text=True,timeout=15)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr);self.assertEqual(self.draft.read_bytes(),self.before)
    def test_cli_pipe_apply_refused(self):
        p=subprocess.run([sys.executable,'-I','-B',str(ROOT/'bulk_review.py'),'--tool-dir',str(TOOL),'--workspace',str(self.w),'--reviewer','TEST_ONLY','--downloads',str(self.root),'--apply'],input=b.CONFIRM+'\n',capture_output=True,text=True,timeout=15)
        self.assertEqual(p.returncode,2);self.assertEqual(self.draft.read_bytes(),self.before)
    def test_cli_tty_single_confirmation(self):
        master,slave=pty.openpty()
        p=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/'bulk_review.py'),'--tool-dir',str(TOOL),'--workspace',str(self.w),'--reviewer','TEST_SYNTHETIC','--downloads',str(self.root),'--apply'],stdin=slave,stdout=slave,stderr=slave,close_fds=True)
        os.close(slave);data=b'';sent=False;deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try:chunk=os.read(master,65536)
                    except OSError:break
                    if not chunk:break
                    data+=chunk
                    if b'Type DONG_Y_NHAN_HO_TRO_AI' in data and not sent:
                        os.write(master,(b.CONFIRM+'\n').encode());sent=True
                if p.poll() is not None:
                    break
            p.wait(timeout=3)
            self.assertEqual(p.returncode,0,data.decode(errors='replace'))
            self.assertTrue(sent);self.assertNotEqual(self.draft.read_bytes(),self.before)
            provenance=list(self.root.glob('b39b6_bulk_review_*_provenance.json'))
            self.assertEqual(len(provenance),1);r=json.loads(provenance[0].read_bytes())
            self.assertEqual(r['draft_sha256'],b.sha(self.draft.read_bytes()));self.assertFalse(r['independent_gold'])
        finally:
            if p.poll() is None:p.kill();p.wait()
            os.close(master)

if __name__=='__main__':unittest.main(verbosity=2)
