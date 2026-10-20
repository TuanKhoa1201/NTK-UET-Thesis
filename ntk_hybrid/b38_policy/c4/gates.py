"""Separate receipts. Never reads/writes the legacy model-derived C/D gates."""
import json
from pathlib import Path
from ntk_b33.common import Blocker,sha_file,write_json
KIND='CODEQL_CONTEXTUAL_POLICY_ASSISTED_V1'

def gate_path(work,phase,arm):
 return work/'batch38_policy_gates'/('C4.json' if phase=='C4' else 'DPA_'+arm+'.json')

def require_gate(work,phase,arm,impl):
 p=gate_path(work,phase,arm)
 if not p.is_file():raise Blocker('POLICY_GATE_MISSING_'+phase)
 g=json.loads(p.read_text());sfile=Path(g['summary_path']);mfile=Path(g['manifest_path'])
 if g.get('kind')!=KIND or g.get('implementation_sha256')!=impl:raise Blocker('POLICY_GATE_WRONG_IMPLEMENTATION_OR_KIND')
 if not sfile.is_file() or not mfile.is_file() or sha_file(sfile)!=g['summary_sha256'] or sha_file(mfile)!=g['manifest_sha256']:
  raise Blocker('POLICY_GATE_EVIDENCE_DRIFT')
 s=json.loads(sfile.read_text())
 if s.get('phase')!=phase or s.get('status')!='B38_'+phase+'_POLICY_SCOPED_COMPLETE' or not s.get('frozen_unchanged'):
  raise Blocker('POLICY_GATE_NOT_ACCEPTED')
 if s.get('model_derived_xss_gate')!='NOT_GRANTED' or s.get('old_gate_D')!='UNCHANGED_NOT_GRANTED':
  raise Blocker('POLICY_GATE_MUST_NOT_UPGRADE_MODEL_GATE')
 if phase=='DPA' and arm not in s.get('arms',{}):raise Blocker('POLICY_GATE_ARM_MISMATCH')
 for name,h in json.loads(mfile.read_text()).items():
  pp=sfile.parent/name
  if not pp.resolve().is_relative_to(sfile.parent.resolve()) or pp.is_symlink() or not pp.is_file() or sha_file(pp)!=h:raise Blocker('POLICY_GATE_ARTIFACT_DRIFT_'+name)
 return g

def issue_gate(work,phase,arm,impl,run,manifest):
 write_json(gate_path(work,phase,arm),{'kind':KIND,'phase':phase,'arm':arm,'implementation_sha256':impl,
  'summary_path':str(run/'00_SUMMARY.json'),'summary_sha256':sha_file(run/'00_SUMMARY.json'),
  'manifest_path':str(manifest),'manifest_sha256':sha_file(manifest)})
