"""Narrow compiler-certified output encoding; no global taint suppression.
Raw CodeQL paths and all OpenGrep findings are retained. No name-only sanitizer.
"""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import dataclasses
import json
from bootstrap import ROOT
from ntk_b33.common import Blocker,digest,sha_file,write_json
from ntk_b34.core import normalized_uri,contains,label_key
from ntk_b38.core import same_call,to_sarif as baseline_sarif
from ntk_b38.profiles import SOURCE_POLICY,manual_labels

ORIGIN='CODEQL_CONTEXTUAL_POLICY_ASSISTED'
MODEL='MODEL_DERIVED'
POLICY={'id':'NTK_C4_OUTPUT_ENCODING_PROOF_V1',
 'source_sink_origin':ORIGIN,'http_context':'INHERITED_DIRECT_HTTP_EXCHANGE_HTML_HEADER_LINE_ORDER_NOT_GENERAL_CFG',
 'proof':'JAVAC_RESOLVED_SINGLE_RETURN_STATIC_HELPER_OR_INLINE_LITERAL_STRING_REPLACE_CHAIN',
 'encoding':'AMPERSAND_FIRST_THEN_LT_GT_AND_THE_SURROUNDING_QUOTE_WHEN_APPLICABLE',
 'scope':'SINGLE_DYNAMIC_SLOT_FIXED_HTML_TEXT_OR_QUOTED_ORDINARY_ATTRIBUTE_UTF8_STRAIGHT_LINE',
 'text_tags':['p','div','span','h1','h2','b','section'],
 'attributes':['div.title','div.data-note','input.value_double_quoted'],
 'unknown':'REVIEW_REQUIRED_NOT_SAFE_NOT_SUPPRESSED',
 'raw_paths':'RETAINED_NO_CODEQL_BARRIER_OR_GLOBAL_SANITIZER_NAME_RULE',
 'scoring':'FROZEN_V22_NEUTRAL_AI_POLICY_QUALIFIED_PATH_ONLY',
 'model_xss_gate':'NOT_GRANTED'}
POLICY_SHA=digest(POLICY)

def tagged(records,cwe=None):
 out=deepcopy(records)
 for row in out:
  for key in ('cwe','source_record_sha256','case_key','compiler_record_sha256'):row.pop(key,None)
  if cwe:row['cwe']=cwe
  row['compiler_record_sha256']=digest(row)
 return out

def tag_paths(flows,cwe):
 out=deepcopy(flows)
 for f in out:
  f['cwe']=cwe;f['callsite']=tagged([f['callsite']],cwe)[0]
  f['evidence_origin']=ORIGIN if cwe=='79' else MODEL
 return out

def bind_ast(ast,calls,source_hashes):
 if ast.get('schema')!='NTK_C4_JAVAC_ENCODING_PROOF_V1' or ast.get('source_application_executed') is not False:
  raise Blocker('INVALID_COMPILER_ENCODING_PROOF_SCHEMA')
 if ast.get('source_hashes')!=source_hashes:raise Blocker('COMPILER_PROOF_NOT_SAME_UPLOADED_SOURCES')
 out=[];seen=set()
 for row in ast['findings']:
  loc=row['location'];key=(loc['uri'],loc['start_line'],loc['start_column'])
  if key in seen:raise Blocker('DUPLICATE_COMPILER_PROOF_CALLSITE')
  seen.add(key)
  match=[c for c in calls if all(c.get(k)==loc[k] for k in ('uri','start_line','start_column')) and
         c['package']== 'java.io' and c['class']=='OutputStream' and c['compiler_signature']=='write(byte[])']
  if len(match)!=1:raise Blocker('JAVAC_CODEQL_CALL_IDENTITY_DISAGREEMENT')
  out.append(dict(deepcopy(row),callsite=tagged(match,'79')[0],compiler_binding_verified=True))
 return out

def assess_paths(raw,proofs):
 qualified=[];assessments=[]
 for f in raw:
  hits=[p for p in proofs if same_call(p['callsite'],f['callsite'])]
  if len(hits)!=1:raise Blocker('POLICY_PATH_WITHOUT_UNIQUE_JAVAC_OUTPUT_PROOF')
  p=hits[0]
  if not f.get('http_context_verified') or f.get('cwe')!='79':raise Blocker('UNSCOPED_POLICY_FLOW')
  a=p['assessment']
  eligible=a=='UNENCODED_SUPPORTED_CONTEXT'
  enc=a=='ENCODING_VERIFIED_SCOPED'
  status='POLICY_QUALIFIED_UNENCODED_HTML_PATH' if eligible else 'ENCODING_VERIFIED_SCOPED_REVIEW_RETAINED' if enc else 'REVIEW_REQUIRED_UNSUPPORTED_OR_INCOMPLETE_ENCODING'
  row={'flow_id':f['id'],'callsite':f['callsite'],'status':status,'qualified_for_vulnerability_priority':eligible,
    'encoder_proof':p,'origin':ORIGIN,'policy_sha256':POLICY_SHA,'vulnerability_confirmed':False,'safe_verdict':False}
  assessments.append(row)
  if eligible:qualified.append(deepcopy(f))
 return qualified,assessments

def policy_fusion(og,raw,qualified,assessments,proofs,calls,target,scorer,trace):
 from ntk_b38.profiles import api_key,SINKS
 wanted={x[:3] for x in SINKS['79']};out=[];consumed=set()
 byid={a['flow_id']:a for a in assessments};qids={f['id'] for f in qualified}
 observations={label_key(t['candidate']):t for t in trace if t.get('phase')=='cold' and t['candidate']['cwe']=='79'}
 def complete(r,linked):
  accepted=[f for f in linked if f['id'] in qids]
  r['raw_policy_flow_ids']=[f['id'] for f in linked];r['linked_codeql_flow_ids']=[f['id'] for f in accepted]
  r['raw_policy_paths']=deepcopy(linked);r['sanitizer_assessments']=[byid[f['id']] for f in linked]
  pp=[p for p in proofs if r.get('callsite') and same_call(p['callsite'],r['callsite'])]
  r['compiler_output_assessment']=pp[0] if len(pp)==1 else None
  r['model_observation']=observations.get(label_key(r['callsite'])) if r.get('callsite') else None
  r['model_observation_usage']='RECORDED_ONLY_NOT_SINK_AUTHORITY_NOT_AI_SCORE_UPGRADE'
  r['evidence_origin']=ORIGIN;r['sink_origin']=ORIGIN;r['source_policy']=SOURCE_POLICY['79']
  r['ai_validation']={'api_role':'unknown','parse_status':'NOT_APPLIED','verdict':'NEEDS_REVIEW'}
  r['dataflow']=[]
  if accepted:
   path=accepted[0]['paths'][0]
   r['dataflow']=[dict(n,type='source' if i==0 else 'sink' if i==len(path)-1 else 'intermediate',origin='CODEQL_SARIF_THREADFLOW') for i,n in enumerate(path)]
   r['evidence_status']='POLICY_QUALIFIED_UNENCODED_HTML_PATH'
  elif linked:r['evidence_status']='ENCODING_VERIFIED_SCOPED_REVIEW_RETAINED' if all(byid[f['id']]['status']=='ENCODING_VERIFIED_SCOPED_REVIEW_RETAINED' for f in linked) else 'REVIEW_REQUIRED_ENCODING_OR_CONTEXT'
  else:r['evidence_status']='REVIEW_ONLY_NO_QUALIFIED_POLICY_PATH'
  r['score']=dataclasses.asdict(scorer.score_finding(r));r['retained']=True;r['vulnerability_confirmed']=False
  r['score_semantics']='PRIORITY_ONLY_NOT_PROBABILITY_OR_CVSS';r['semantic_policy_sha256']=POLICY_SHA
  if r['score']['ai_confidence_score']!=0.5:raise Blocker('POLICY_PATH_MUST_NOT_BECOME_LLM_CONFIDENCE')
 for i,row in enumerate(og.get('results',[])):
  if row['cwe']!='79':continue
  uri=normalized_uri(row['path'],target);s,e=row['start'],row['end'];extra=row.get('extra',{})
  loc={'uri':uri,'start_line':s['line'],'start_column':s.get('col',1),'end_line':e['line'],'end_column':e.get('col',1)}
  match=[c for c in calls if c['uri']==uri and api_key(c) in wanted and contains(loc,c['start_line'],c['start_column'])]
  call=tagged(match,'79')[0] if len(match)==1 else None
  linked=[f for f in raw if call is not None and same_call(call,f['callsite'])];consumed.update(f['id'] for f in linked)
  r={'id':'opengrep:'+str(i),'origin':'OPENGREP','cwe':'79','rule_id':row['check_id'],
     'severity':extra.get('severity','ERROR'),'message':extra.get('message','API call requires review'),
     'metadata':extra.get('metadata',{'cwe':['CWE-79']}),'location':loc,'callsite':call,'original_opengrep':deepcopy(row)}
  complete(r,linked);out.append(r)
 for f in raw:
  if f['id'] in consumed:continue
  r={'id':'codeql-policy:'+f['id'],'origin':'CODEQL_POLICY_ADDITIONAL','cwe':'79','rule_id':'java/ntk-c4-policy',
    'severity':'ERROR','message':'Policy path retained; inspect context/encoding assessment. Not an LLM sink prediction.',
    'metadata':{'cwe':['CWE-79'],'confidence':'UNKNOWN'},'location':f['location'],'callsite':f['callsite']}
  complete(r,[f]);out.append(r)
 if sum(r['origin']=='OPENGREP' for r in out)!=sum(r['cwe']=='79' for r in og['results']):raise Blocker('POLICY_MERGER_LOST_OPENGREP_FINDING')
 return out

def to_sarif(records):
 sarif=baseline_sarif(records);run=sarif['runs'][0]
 run['tool']['driver']['name']='NTK B38D policy-assisted research prototype'
 run['properties'].update(mode='MIXED_MODEL_DERIVED_AND_CONTEXTUAL_POLICY',model_xss_gate_granted=False)
 for r,x in zip(records,run['results']):
  x['properties'].update(evidence_origin=r.get('evidence_origin',MODEL),sink_origin=r.get('sink_origin','LOCAL_LIVE_STAGE3'),
   raw_policy_flow_ids=r.get('raw_policy_flow_ids',[]),sanitizer_assessments=r.get('sanitizer_assessments',[]),
   model_role_used_for_xss_score=False if r['cwe']=='79' else True)
 return sarif

def check_policy_fixture(raw,qualified,proofs,expected):
 checks={};rawfiles={f['location']['uri'] for f in raw};qfiles={f['location']['uri'] for f in qualified}
 for uri,rule in expected.items():
  pp=[p for p in proofs if p['location']['uri']==uri]
  observed={'raw_policy_flow':uri in rawfiles,'qualified_policy_flow':uri in qfiles,
            'ast_assessment':pp[0]['assessment'] if len(pp)==1 else 'NON_UNIQUE_PROOF'}
  checks[uri]={'expected':rule,'observed':observed,'match':observed==rule}
 unexpected=sorted((rawfiles|qfiles)-set(expected))
 return {'checks':checks,'unexpected_paths':unexpected,'match':not unexpected and all(x['match'] for x in checks.values()),
    'scope':'DEVELOPMENT_POLICY_FIXTURE_NOT_MODEL_ACCURACY_NOT_INDEPENDENT_GOLD'}
