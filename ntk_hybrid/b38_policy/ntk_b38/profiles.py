"""Explicit, narrow CWE semantics. Never manufacture model labels or gold."""
from copy import deepcopy
from ntk_b33.common import IDENTITY, Blocker, digest, parameter_names
from ntk_b37.semantic import POLICY as SQL_POLICY

GETENV = ('java.lang', 'System', 'getenv(java.lang.String)')
SINKS = {
 '22': [
  ('java.nio.file', 'Files', 'readString(java.nio.file.Path)', 0),
  ('java.nio.file', 'Files', 'readString(java.nio.file.Path,java.nio.charset.Charset)', 0),
  ('java.nio.file', 'Files', 'readAllBytes(java.nio.file.Path)', 0),
  ('java.nio.file', 'Files', 'newInputStream(java.nio.file.Path,java.nio.file.OpenOption[])', 0),
 ],
 '78': [('java.lang', 'Runtime', 'exec('+args+')', 0) for args in (
  'java.lang.String', 'java.lang.String,java.lang.String[]',
  'java.lang.String,java.lang.String[],java.io.File',
  'java.lang.String[]', 'java.lang.String[],java.lang.String[]',
  'java.lang.String[],java.lang.String[],java.io.File')],
 '79': [('java.io', 'OutputStream', 'write(byte[])', 0),
        ('java.io', 'OutputStream', 'write(byte[],int,int)', 0)],
 '89': [(x['package'],x['class'],x['compiler_signature'],x['argument_index'])
        for x in SQL_POLICY['allow_sql_text']],
}
SOURCE_APIS = {
 '22': [GETENV], '78': [GETENV], '89': [GETENV],
 '79': [('java.net','URI','getRawQuery()'),('java.net','URI','getQuery()')],
}
REVIEW_APIS = {
 '22': [('java.nio.file','Path','normalize()'),('java.nio.file','Path','resolve(java.lang.String)')],
 '78': [('java.lang','ProcessBuilder','start()')],
 '79': [('com.sun.net.httpserver','HttpExchange','getRequestURI()'),
        ('com.sun.net.httpserver','HttpExchange','getResponseBody()')],
 '89': [('java.sql','PreparedStatement','setString(int,java.lang.String)'),
        ('java.sql','PreparedStatement','executeQuery()')],
}
TITLES = {'22':'Path traversal', '78':'OS command injection', '79':'HTTP reflected XSS', '89':'SQL injection'}
RULE_IDS = {'22':'ntk-b38-cwe22-path-call-review','78':'ntk-b38-cwe78-command-call-review',
            '79':'ntk-b38-cwe79-output-call-review','89':'ntk-b34-java-sql-call-review'}
SOURCE_POLICY = {
 '22':'CODEQL_LOCATED_SYSTEM_GETENV_DECLARED_UNTRUSTED_NOT_LLM',
 '78':'CODEQL_LOCATED_SYSTEM_GETENV_DECLARED_UNTRUSTED_NOT_LLM',
 '79':'CODEQL_HTTP_EXCHANGE_REQUEST_URI_QUERY_DECLARED_REMOTE_SOURCE_NOT_LLM',
 '89':'CODEQL_DISCOVERED_LOCAL_GETENV_CALL_UNTRUSTED_BY_EXPLICIT_DEMO_POLICY_NOT_LLM',
}
POLICY = {'id':'NTK_B38_EXACT_ARGUMENT_AND_HTTP_CONTEXT_V1',
 'sinks':SINKS,'source_apis':SOURCE_APIS,'source_policy':SOURCE_POLICY,
 'xss_context':'DIRECT_HttpExchange_RESPONSE_BODY_WRITE_WITH_SAME_PARAMETER_HTML_HEADER_AND_RESPONSE_HEADERS_SENT',
 'transfers':'ANALYST_AUTHORED_JDK_MODELS_AND_CODEQL_LIBRARY_NOT_LLM_LEARNED',
 'unknown_sink':'NEEDS_SEMANTIC_REVIEW_DO_NOT_OVERRIDE_NONE_OR_ABSTAIN',
 'score':'ONLY_ACCEPTED_MODEL_SINK_PLUS_PROVEN_CWE_FLOW_UPGRADES_AI_EVIDENCE',
 'no_path':'PRESERVE_FINDING_NEUTRAL_AI_NOT_SAFE',
 'scope':'JDK21_ONLY_MAX24_JAVA_LOCAL_RESEARCH_NOT_FULL_IRIS_OR_GENERAL_CWE_COVERAGE'}
POLICY_SHA = digest(POLICY)
PHASE_CWES = {'A':['22'], 'B':['78'], 'C':['79'], 'D':['22','78','79','89']}

def api_key(c):
 return (c['package'],c['class'],c['compiler_signature'])

def identity(c):
 return tuple(c[k] for k in IDENTITY)

def select_candidates(cases, cwe):
 wanted={x[:3] for x in SINKS[cwe]}|set(SOURCE_APIS[cwe])|set(REVIEW_APIS[cwe])
 chosen=[]
 for case in cases:
  if api_key(case) not in wanted: continue
  c=deepcopy(case);c['cwe']=cwe;c.pop('source_record_sha256',None)
  c['source_record_sha256']=digest(c);chosen.append(c)
 return chosen

def adjudicate(candidates, labels, cwe):
 keyed={identity(c):c for c in candidates}
 if len(keyed)!=len(candidates):raise Blocker('DUPLICATE_CWE_API_IDENTITY')
 eligible=[];records=[];seen=set()
 for raw in labels:
  key=identity(raw)
  if key not in keyed or key in seen or raw.get('type')!='sink':
   raise Blocker('INVALID_STAGE3_SINK_ARTIFACT')
  seen.add(key); c=keyed[key];params=parameter_names(c['signature'])
  if c['cwe']!=cwe:raise Blocker('CROSS_CWE_LABEL_REJECTED')
  if not isinstance(raw.get('sink_args'),list) or not raw['sink_args']:
   raise Blocker('EMPTY_SINK_ARGUMENTS')
  args=[];arg_seen=set()
  for name in raw['sink_args']:
   if name not in params or name in arg_seen:raise Blocker('INVALID_SINK_ARGUMENT')
   arg_seen.add(name);index=params.index(name)
   ok=(*api_key(c),index) in SINKS[cwe]
   decision='ELIGIBLE_EXACT_CWE_ARGUMENT' if ok else 'WITHHELD_UNKNOWN_OR_IRRELEVANT_ARGUMENT'
   if cwe=='89' and api_key(c)==('java.sql','PreparedStatement','setString(int,java.lang.String)'):
    decision='WITHHELD_BOUND_VALUE_NOT_SQL_GRAMMAR'
   records.append({'cwe':cwe,'candidate':deepcopy(c),'raw_label':deepcopy(raw),'argument_index':index,
    'decision':decision,'policy_sha256':POLICY_SHA,
    'requires_http_context':cwe=='79','not_gold':True})
   if ok:args.append(name)
  if args:eligible.append({**deepcopy(raw),'sink_args':args})
 return eligible,records

def manual_labels(cases,cwe):
 """Diagnostic labels only; never feed these to the model arm or scoring."""
 out=[]
 for c in cases:
  args=['p'+str(x[3]) for x in SINKS[cwe] if x[:3]==api_key(c)]
  if args:out.append({**{k:c[k] for k in IDENTITY},'type':'sink','sink_args':args})
 return out
