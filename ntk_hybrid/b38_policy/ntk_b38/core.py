"""Compiler bindings, real path validation, and per-CWE evidence-conditioned scoring."""
from copy import deepcopy
import dataclasses
import json
from pathlib import Path
from ntk_b33.common import Blocker, IDENTITY, digest
from ntk_b34.core import (read_calls as legacy_read_calls, emit_flow as legacy_emit_flow,
    normalized_uri, contains, physical_location, label_key)
from .profiles import SOURCE_POLICY, POLICY_SHA, RULE_IDS, api_key


def read_calls(path, target):
 # Header-only query output is a legitimate empty set, not a successful detection.
 import csv
 with open(path,newline='',encoding='utf-8-sig') as f:
  rows=list(csv.DictReader(f))
 if not rows: return [],[]
 return legacy_read_calls(path,target)


def emit_flow(template,cases,labels,cwe,arm,kind='live'):
 if cwe not in RULE_IDS or arm not in ('base','epoch_1','epoch_2') or kind not in ('live','diagnostic','compile'):
  raise Blocker('INVALID_QL_REQUEST_CONTEXT')
 for c in cases:
  if c['cwe']!=cwe:raise Blocker('CROSS_CWE_QUERY_CANDIDATE')
 # Reuse the exact owner + overload + argument binding that passed B37.
 text,proof=legacy_emit_flow(template,cases,labels,arm)
 text=text.replace('exists(MethodCall call |\n','exists(MethodCall call |\n      ntkSinkContext(call, "'+cwe+'") and\n')
 text=text.replace('__CWE__',cwe).replace('__PADDED__',cwe.zfill(3)).replace('__KIND__',kind)
 # legacy_emit_flow substituted underscores in ARM; avoid CodeQL @id warning.
 text=text.replace('cwe'+cwe+'-'+kind+'-'+arm,'cwe'+cwe+'-'+kind+'-'+arm.replace('_','-'))
 if '__' in text:raise Blocker('UNEXPANDED_QUERY_TOKEN')
 for p in proof:
  p['cwe']=cwe;p['policy_sha256']=POLICY_SHA;p['label_origin']='LOCAL_LIVE_STAGE3' if kind=='live' else 'MANUAL_DIAGNOSTIC_ONLY_NOT_LLM'
 return text,proof


def parse_flows(sarif,target,calls,arguments,proof,sources,cwe,contexts=None):
 flows=[];allowed={(p['candidate']['package'],p['candidate']['class'],p['candidate']['compiler_signature'],n)
                    for p in proof for n in p['argument_indices']}
 for run in sarif.get('runs',[]):
  for index,result in enumerate(run.get('results',[])):
   loc=physical_location(result['locations'][0],run,target)
   matches=[a for a in arguments if a['uri']==loc['uri'] and contains(a,loc['start_line'],loc['start_column'])
            and (a['package'],a['clazz'],a['compiler_signature'],a['argument_index']) in allowed]
   if len(matches)!=1:raise Blocker('SINK_NOT_UNIQUELY_BOUND_TO_COMPILER_ARGUMENT')
   arg=matches[0]
   cs=[c for c in calls if c['uri']==arg['uri'] and c['start_line']==arg['call_line'] and
       c['start_column']==arg['call_column'] and c['compiler_signature']==arg['compiler_signature'] and
       c['package']==arg['package'] and c['class']==arg['clazz']]
   if len(cs)!=1:raise Blocker('SINK_OWNER_OVERLOAD_CALLSITE_AMBIGUOUS')
   call=cs[0];paths=[]
   if cwe=='79' and not any(same_call(call,x) for x in (contexts or [])):
    raise Blocker('XSS_SINK_WITHOUT_CODEQL_HTTP_HTML_CONTEXT')
   for cf in result.get('codeFlows',[]):
    for tf in cf.get('threadFlows',[]):
     nodes=[physical_location(x['location'],run,target) for x in tf.get('locations',[])]
     if len(nodes)<2:continue
     first,last=nodes[0],nodes[-1]
     if not any(s['uri']==first['uri'] and contains(s,first['start_line'],first['start_column']) for s in sources):
      raise Blocker('PATH_SOURCE_NOT_IN_THIS_DATABASE_SOURCE_INVENTORY')
     if last['uri']!=arg['uri'] or not contains(arg,last['start_line'],last['start_column']):
      raise Blocker('PATH_END_NOT_THE_BOUND_SINK_ARGUMENT')
     paths.append(nodes)
   if not paths:raise Blocker('SARIF_RESULT_WITHOUT_VERIFIABLE_PATH')
   flows.append({'id':digest([cwe,result.get('ruleId'),index,loc]),'cwe':cwe,'location':loc,
     'callsite':call,'argument_index':arg['argument_index'],'paths':paths,'raw_result':result,
     'source_policy':SOURCE_POLICY[cwe],'source_discovered_by_llm':False,
     'origin':'REAL_CODEQL_PATH_QUERY','http_context_verified':cwe=='79'})
 return flows


def same_call(a,b):
 return all(a.get(k)==b.get(k) for k in ('uri','start_line','start_column','package','class','compiler_signature'))


def calibrated_fusion(og,flows,trace,calls,target,scorer,cwe,decisions):
 verdicts={label_key(x['candidate']):x for x in trace if x.get('phase')=='cold' and x['candidate']['cwe']==cwe}
 allowed={(label_key(x['candidate']),x['argument_index']) for x in decisions if x['decision']=='ELIGIBLE_EXACT_CWE_ARGUMENT'}
 out=[];consumed=set()
 for i,raw in enumerate(og.get('results',[])):
  if raw['cwe']!=cwe:continue
  uri=normalized_uri(raw['path'],target);s,e=raw['start'],raw['end']
  loc={'uri':uri,'start_line':s['line'],'start_column':s.get('col',1),'end_line':e['line'],'end_column':e.get('col',1)}
  # Match only APIs that are permitted as sinks or yielded the actual flow.
  from .profiles import SINKS
  wanted={x[:3] for x in SINKS[cwe]}
  matched=[c for c in calls if c['uri']==uri and api_key(c) in wanted and contains(loc,c['start_line'],c['start_column'])]
  call=matched[0] if len(matched)==1 else None
  linked=[f for f in flows if call is not None and same_call(f['callsite'],call)]
  consumed.update(f['id'] for f in linked)
  extra=raw.get('extra') or {}
  r={'id':'opengrep:'+str(i),'origin':'OPENGREP','cwe':cwe,'rule_id':raw['check_id'],
    'severity':extra.get('severity','ERROR'),'message':extra.get('message','API call requires review'),
    'metadata':extra.get('metadata',{'cwe':['CWE-'+cwe]}),'location':loc,
    'original_opengrep':deepcopy(raw),'callsite':call,'linked_codeql_flow_ids':[f['id'] for f in linked]}
  score_record(r,linked,verdicts,scorer,cwe,allowed);out.append(r)
 for flow in flows:
  if flow['id'] in consumed:continue
  r={'id':'codeql:'+flow['id'],'origin':'CODEQL_ADDITIONAL','cwe':cwe,
     'rule_id':flow['raw_result'].get('ruleId','java/ntk-b38/cwe'+cwe),'severity':'ERROR',
     'message':'CodeQL path to accepted local-model sink under explicit CWE semantics.',
     'metadata':{'cwe':['CWE-'+cwe],'confidence':'UNKNOWN'},'location':flow['location'],
     'callsite':flow['callsite'],'linked_codeql_flow_ids':[flow['id']]}
  score_record(r,[flow],verdicts,scorer,cwe,allowed);out.append(r)
 expected=sum(r['cwe']==cwe for r in og.get('results',[]))
 if sum(r['origin']=='OPENGREP' for r in out)!=expected:raise Blocker('OPENGREP_LOST_DURING_FUSION')
 return out


def score_record(r,flows,verdicts,scorer,cwe,allowed):
 observation=verdicts.get(label_key(r['callsite'])) if r['callsite'] else None
 r['model_observation']=observation;r['dataflow']=[]
 if flows:
  if any((label_key(f['callsite']),f['argument_index']) not in allowed or f['cwe']!=cwe for f in flows):
   raise Blocker('UNQUALIFIED_CWE_FLOW_IN_SCORER')
  if not observation or observation.get('status')!='ACCEPTED' or observation.get('label',{}).get('type')!='sink':
   raise Blocker('POSITIVE_SCORE_WITHOUT_ACCEPTED_LIVE_MODEL_SINK')
  path=flows[0]['paths'][0]
  r['dataflow']=[dict(n,type='source' if i==0 else 'sink' if i==len(path)-1 else 'intermediate',
                    origin='CODEQL_SARIF_THREADFLOW') for i,n in enumerate(path)]
  r['ai_validation']={'api_role':'sink','parse_status':'OK','verdict':'API_ROLE_PLUS_CWE_QUALIFIED_CODEQL_PATH'}
 else:r['ai_validation']={'api_role':'unknown','parse_status':'NOT_APPLIED','verdict':'NEEDS_REVIEW'}
 r['score']=dataclasses.asdict(scorer.score_finding(r));r['retained']=True
 r['evidence_status']='CODEQL_CWE_'+cwe+'_QUALIFIED_PATH' if flows else 'REVIEW_ONLY'
 r['score_semantics']='PRIORITY_ONLY_NOT_PROBABILITY_OR_CVSS'
 r['vulnerability_confirmed']=False;r['semantic_policy_sha256']=POLICY_SHA
 r['source_policy']=SOURCE_POLICY[cwe]


def to_sarif(records):
 results=[]
 for r in records:
  loc=r['location']
  def physical(n):return {'physicalLocation':{'artifactLocation':{'uri':n['uri']},
    'region':{'startLine':n['start_line'],'startColumn':n.get('start_column',1)}}}
  s={'ruleId':r['rule_id'],'level':'warning','message':{'text':r['message']},'locations':[physical(loc)],
     'properties':{'ntk_id':r['id'],'cwe':'CWE-'+r['cwe'],'priority_score':r['score'],
       'retained':True,'evidence_status':r['evidence_status'],'origin':r['origin'],
       'source_policy':r['source_policy'],'vulnerability_confirmed':False}}
  if r['dataflow']:s['codeFlows']=[{'threadFlows':[{'locations':[{'location':physical(n)} for n in r['dataflow']]}]}]
  results.append(s)
 return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
  'runs':[{'tool':{'driver':{'name':'NTK B38 scoped multi-CWE hybrid','version':'0.1.0'}},
           'properties':{'mode':'NEW_JAVA_LOCAL_STAGE3_PLUS_CODEQL','score_is_probability':False},'results':results}]}
