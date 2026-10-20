"""Real pinned OpenGrep with strict CWE/rule provenance, inherited INET blocking."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from ntk_b33.common import Blocker,digest,sha_file,write_json
from ntk_b34.core import normalized_uri
from b34_helpers import OPENGREP_SHA
from .profiles import RULE_IDS
from .scanner_environment import prepare_environment
ROOT=Path(__file__).resolve().parents[1]
PATTERNS={
 '22':['Files.readString(...)','Files.readAllBytes(...)','Files.newInputStream(...)'],
 '78':['$R.exec(...)'],
 '79':['$STREAM.write(...)'],
 '89':['$S.executeQuery($SQL)','$S.execute($SQL)','$C.prepareStatement($SQL)']}

def rules(cwes):
 return {'rules':[{'id':RULE_IDS[c],'languages':['java'],'severity':'ERROR',
 'message':('SQL-text API call for integration review; call presence alone is not a confirmed vulnerability.' if c=='89' else
           'CWE-'+c+' API call for integration review; not by itself a vulnerability.'),
 'metadata':{'cwe':['CWE-'+c],'confidence':'UNKNOWN','scope':'integration-demo-only-not-b29-benchmark-rules'},
 'pattern-either':[{'pattern':p} for p in PATTERNS[c]]} for c in cwes]}

def canonical_rule(check,cwes):
 if not isinstance(check,str) or len(check)>2048:raise Blocker('INVALID_SCANNER_RULE_ID')
 matched=[c for c in cwes if check==RULE_IDS[c] or check.endswith('.'+RULE_IDS[c])]
 if len(matched)!=1 or not all(x.isascii() and (x.isalnum() or x in '._/-') for x in check):
  raise Blocker('UNEXPECTED_SCANNER_RULE_ID: '+repr(check[:180]))
 return matched[0],RULE_IDS[matched[0]]

def validate(raw,target,cwes):
 if not isinstance(raw,dict) or not isinstance(raw.get('results'),list) or raw.get('errors'):
  raise Blocker('SCANNER_JSON_INVALID_OR_ERRORS')
 if len(raw['results'])>5000:raise Blocker('FINDING_LIMIT_EXCEEDED')
 records=[]
 for row in raw['results']:
  cwe,rid=canonical_rule(row.get('check_id'),cwes)
  uri=normalized_uri(row.get('path',''),target)
  path=(target/uri).resolve()
  if not path.is_relative_to(target.resolve()) or not path.is_file() or path.suffix!='.java':
   raise Blocker('SCANNER_RESULT_NOT_IN_UPLOADED_JAVA')
  for key in ('start','end'):
   loc=row.get(key,{})
   if any(type(loc.get(k)) is not int or loc[k]<1 for k in ('line','col')):
    raise Blocker('SCANNER_LOCATION_INVALID')
  if (row['end']['line'],row['end']['col'])<(row['start']['line'],row['start']['col']):
   raise Blocker('REVERSED_SCANNER_SPAN')
  extra=row.get('extra',{});cwe_meta=extra.get('metadata',{}).get('cwe',[])
  if cwe_meta!=['CWE-'+cwe]:raise Blocker('RULE_CWE_METADATA_MISMATCH')
  records.append({**row,'scanner_check_id':row['check_id'],'check_id':rid,'cwe':cwe,'path':str(path)})
 return {'results':records}

def scan(run,target,cwes,mlpy,binary=None):
 binary=Path(binary or Path.home()/'.opengrep/cli/v1.25.0/opengrep')
 if not binary.is_file() or sha_file(binary)!=OPENGREP_SHA:raise Blocker('PINNED_OPENGREP_DRIFT')
 work=run/'opengrep';work.mkdir()
 config=work/'rules.json';write_json(config,rules(cwes))
 output=work/'raw.json';proof=work/'isolation.json'
 cmd=[str(mlpy),'-B',str(ROOT/'engine/offline_opengrep.py'),str(proof),str(binary.resolve()),
      'scan','--config',str(config),'--json','--output',str(output),str(target)]
 env,environment=prepare_environment(work)
 write_json(work/'command.json',cmd);start=time.monotonic()
 with (work/'scanner.log').open('wb') as f:
  p=subprocess.Popen(cmd,cwd=work,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
  try:code=p.wait(timeout=300)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);p.wait();raise Blocker('OPENGREP_TIMEOUT')
 write_json(work/'PROCESS_RESULT.json',{'returncode':code,'duration_s':time.monotonic()-start,
  'environment_revision':environment['revision'],'rules_sha256':sha_file(config)})
 if code!=0:
  log_tail=(work/'scanner.log').read_text(encoding='utf-8',errors='replace')[-3500:]
  write_json(work/'FAILURE_DIAGNOSTIC.json',{'returncode':code,'log_tail':log_tail,
   'environment_proof':'ENVIRONMENT_PROOF.json','rules_sha256':sha_file(config)})
  raise Blocker('OPENGREP_FAILED_'+str(code)+': '+str(work/'scanner.log')+'\n'+log_tail)
 if not proof.is_file():raise Blocker('SCANNER_ISOLATION_PROOF_MISSING')
 if not output.is_file():raise Blocker('SCANNER_OUTPUT_JSON_MISSING')
 isolation=json.loads(proof.read_text())
 if any(isolation.get('network',{}).get(k)!='DENIED_EPERM' for k in ('AF_INET','AF_INET6')):
  raise Blocker('SCANNER_ISOLATION_UNPROVEN')
 raw=json.loads(output.read_text());validated=validate(raw,target,cwes)
 write_json(work/'canonical_derived.json',validated)
 write_json(work/'PROOF.json',{'binary_sha256':sha_file(binary),'rules_sha256':sha_file(config),
  'raw_sha256':sha_file(output),'duration_s':time.monotonic()-start,'findings':len(validated['results']),
  'scope':'REAL_OPENGREP_CALL_PRESENCE_ONLY_NOT_B29_RULESET','isolation':isolation,
  'environment_revision':environment['revision'],'environment_proof_sha256':sha_file(work/'ENVIRONMENT_PROOF.json')})
 return validated
