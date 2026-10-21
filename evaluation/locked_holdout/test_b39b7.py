import hashlib,json,subprocess,tempfile,unittest,zipfile
from pathlib import Path
import metric_core
ROOT=Path(__file__).resolve().parent
class Tests(unittest.TestCase):
 def test_holdout_zip(self):
  p=ROOT/'samples/B39B7_HOLDOUT_JDK.zip';pins=json.loads((ROOT/'PINS.json').read_text())
  self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),pins['holdout_zip_sha256'])
  with zipfile.ZipFile(p) as z:
   self.assertIsNone(z.testzip()); names=[n for n in z.namelist() if n.endswith('.java')]
   self.assertEqual(len(names),24);self.assertEqual(len(names),len(set(names)))
 def test_proposals(self):
  xs=json.loads((ROOT/'HOLDOUT_PROPOSALS.json').read_text());self.assertEqual(len(xs),24)
  self.assertEqual(sum(x['truth']=='POSITIVE' for x in xs),12);self.assertEqual(sum(x['truth']=='NEGATIVE' for x in xs),12)
  self.assertEqual({x['cwe'] for x in xs},{'22','78','79','89'})
  for c in ('22','78','79','89'):
   self.assertEqual(sum(x['cwe']==c for x in xs),6)
  for x in xs:
   self.assertFalse(x['predictions_exposed_before_lock']);self.assertTrue(x['evidence_lines'])
 def test_detection(self):
  labels={'a':{'truth':'POSITIVE'},'b':{'truth':'NEGATIVE'},'c':{'truth':'POSITIVE'},'d':{'truth':'NEGATIVE'}}
  rows=[{'unit_id':'a','x':True},{'unit_id':'b','x':True},{'unit_id':'c','x':False},{'unit_id':'d','x':False}]
  m=metric_core.detection(rows,labels,'x');self.assertEqual((m['tp'],m['fp'],m['fn'],m['tn']),(1,1,1,1));self.assertAlmostEqual(m['f1'],0.5)
 def test_ranking_ties(self):
  labels={'a':{'truth':'POSITIVE'},'b':{'truth':'NEGATIVE'},'c':{'truth':'POSITIVE'},'d':{'truth':'NEGATIVE'}}
  rows=[{'unit_id':'a','score':10,'any_reported_alert':True},{'unit_id':'b','score':10,'any_reported_alert':True},{'unit_id':'c','score':5,'any_reported_alert':True},{'unit_id':'d','score':5,'any_reported_alert':True}]
  m=metric_core.ranking(rows,labels,(1,3));self.assertEqual(m['status'],'COMPUTED');self.assertEqual(m['positive_support'],2);self.assertIn('tie_expected_ap',m)
if __name__=='__main__':unittest.main()
