"""Bounded, checksum-verified local B39B4 result store. No ML/project imports."""
from __future__ import annotations
from collections import Counter
from pathlib import Path, PurePosixPath
import hashlib, io, json, math, os, re, stat, subprocess, tempfile, time, zipfile

ARMS=('opengrep_only','base','epoch_1','epoch_2')
CWES=('22','78','79','89')
POLICY='CODEQL_CONTEXTUAL_POLICY_ASSISTED'
B4_NAME='b39b4_20261020T061240Z_9533627d_result.zip'
B4_SHA='d081411e2aa5b461d682bda06725cb134dd5761deda1775190ce73e598e69798'
ENGINE_SHA='e30a7fc1434b083c87bda80da1667bd2e9d64664d8cb2bf80d00534efaf3791c'
RUN_RE=re.compile(r'b39b4_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}\Z')
JOB_RE=re.compile(r'[0-9a-f]{20}\Z')
MAX_FILE=32*1024**2
class Blocked(RuntimeError): pass

def need(ok,why):
    if not ok: raise Blocked(why)
def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def loads(data):
    def unique(pairs):
        d={}
        for k,v in pairs:
            need(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
        return d
    def constant(value): raise Blocked('NONFINITE_JSON')
    return json.loads(data,object_pairs_hook=unique,parse_constant=constant)
def write_json(path,obj,exclusive=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    data=(canonical(obj)+'\n').encode()
    if exclusive:
        with path.open('xb') as f:f.write(data)
        os.chmod(path,0o600);return
    fd,temp=tempfile.mkstemp(prefix='.write-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)
def read(path,limit=MAX_FILE):
    p=Path(path);need(p.is_file() and not p.is_symlink(),'FILE_MISSING_OR_SYMLINK:'+p.name)
    a=p.stat();need(a.st_size<=limit,'FILE_TOO_LARGE:'+p.name)
    with p.open('rb') as f:data=f.read(limit+1)
    b=p.stat();need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'FILE_CHANGED_DURING_READ')
    need(len(data)==a.st_size,'SHORT_OR_OVERSIZE_READ');return data

def safe_name(name):
    need(isinstance(name,str) and name and len(name)<2048,'INVALID_PATH')
    p=PurePosixPath(name)
    need(not p.is_absolute() and not any(c in name for c in ('\\',':','\x00')) and not any(ord(c)<32 for c in name),'UNSAFE_PATH')
    need(all(x not in ('','..','.') for x in name.rstrip('/').split('/')),'UNSAFE_PATH')
    return p

def under(root,relative):
    root=Path(root).resolve();p=safe_name(relative);q=root
    for part in p.parts:
        q=q/part;need(not q.is_symlink(),'SYMLINK_NOT_ALLOWED:'+relative)
    need(q.resolve().is_relative_to(root),'PATH_ESCAPE');return q

def archive(data,expected=None,max_total=64*1024**2):
    if expected:need(sha(data)==expected,'ARCHIVE_SHA_MISMATCH')
    need(len(data)<=max_total,'ARCHIVE_SIZE_LIMIT')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            info=z.infolist();need(len(info)<=3000 and len({i.filename for i in info})==len(info),'ZIP_ENTRY_LIMIT_OR_DUPLICATE')
            need(sum(i.file_size for i in info)<=max_total,'ZIP_UNCOMPRESSED_LIMIT')
            for i in info:
                safe_name(i.filename);need(not i.is_dir(),'UNEXPECTED_DIRECTORY_IN_EVIDENCE')
                need(not i.flag_bits&1 and stat.S_IFMT(i.external_attr>>16) not in (stat.S_IFLNK,stat.S_IFIFO,stat.S_IFSOCK),'ZIP_SPECIAL_OR_ENCRYPTED')
            contents={i.filename:z.read(i) for i in info}
    except (zipfile.BadZipFile,RuntimeError) as e:raise Blocked('INVALID_ZIP:'+type(e).__name__) from None
    need('SHA256SUMS' in contents,'MANIFEST_MISSING');sums={}
    for line in contents['SHA256SUMS'].decode('ascii').splitlines():
        need(bool(re.fullmatch(r'[0-9a-f]{64}  .+',line)),'MANIFEST_LINE_INVALID')
        h,n=line.split('  ',1);safe_name(n);need(n not in sums,'MANIFEST_DUPLICATE');sums[n]=h
    need(set(contents)==set(sums)|{'SHA256SUMS'},'UNMANIFESTED_FILE')
    for n,h in sums.items():need(sha(contents[n])==h,'MEMBER_SHA_MISMATCH:'+n)
    return contents

def audit_metadata(contents):
    get=lambda name:loads(contents[name])
    s=get('00_RESULT.json');c=get('COMPARISON.json');pr=get('RUN_PROTOCOL.json')
    need(s['status']=='B39B4_FOUR_ARM_HYBRID_EXECUTION_COMPLETE' and s['blockers']==[],'B4_NOT_COMPLETE')
    need(s['completed_arms']==list(ARMS) and set(c['arms'])==set(ARMS),'ARM_SET')
    need(get('BEFORE.json')==get('AFTER.json'),'RELEASE_CHANGED')
    need(s['new_training'] is False and s['independent_gold'] is False and s['model_xss_gate_granted'] is False and s['web_gate_changed_by_runner'] is False,'SCOPE_CHANGED')
    need(pr['input_sha256']==s['input_sha256'] and get('DATABASE_PROOF.json')['input_sha256']==s['input_sha256'],'INPUT_PROVENANCE')
    need(get('DATABASE_PROOF.json')['created_in_this_run'] is True and get('DATABASE_PROOF.json')['count']==1,'DB_PROVENANCE')
    n=s['raw_opengrep_findings'];native={};tok={x['case_key']:x for x in get('TOKENIZER_PREFLIGHT.json')['rows']}
    for arm in ARMS:
        v=c['arms'][arm];own=get('OPENGREP_ONLY.json' if arm=='opengrep_only' else 'FUSION_'+arm+'.json')
        need(v==own and v['retained_opengrep']==n and v['scorer_replay_checked']==v['findings'],'FUSION_SUMMARY_MISMATCH')
        need(sum(v['per_cwe'][k]['findings'] for k in CWES)==v['findings'],'CWE_TOTAL')
        if arm=='opengrep_only':need(v['qualified_paths']==0,'BASELINE_FLOW');continue
        a=get('NATIVE_'+arm+'.json');rows=a['details'];ids=[r['case_key'] for r in rows]
        need(len(rows)==len(set(ids))==a['candidates']==a['new_requests']==a['cache_hits']==pr['model_candidates'],'NATIVE_COUNT')
        need(set(ids)==set(tok),'NATIVE_TOKEN_SET')
        need(a['accepted']==sum(r['status']=='ACCEPTED' for r in rows) and a['abstain']==sum(r['status']=='ABSTAIN' for r in rows),'ACCEPTED_COUNT')
        need(dict(Counter(r['reason'] for r in rows))==a['reasons'],'ABSTAIN_REASONS')
        w=a['worker'];need(w['arm']==arm and w['ready'] is True and w['trainable_parameters']==0 and w['training_executed'] is False,'WORKER_IDENTITY')
        need(w['versions']==pr['runtime']['runtime_versions'],'WORKER_VERSIONS')
        need(w['isolation']['AF_INET']=='DENIED_EPERM' and w['isolation']['AF_INET6']=='DENIED_EPERM','WORKER_NETWORK')
        need(a['cleanup']['worker_returncode']==0 and a['cleanup']['worker_still_running'] is False,'WORKER_CLEANUP')
        for row in rows:
            t=tok[row['case_key']]
            need(all(row[k]==t[k] for k in ('prompt_sha256','input_tokens','input_token_ids_sha256')),'TOKEN_PARITY')
            need(math.isfinite(row['generation_s']) and row['generation_s']>=0,'BAD_TIME')
        need(math.isclose(a['performance']['generation_total_s'],sum(r['generation_s'] for r in rows),abs_tol=1e-8),'TIME_SUM')
        need(v['qualified_paths']==sum(v['evidence_by_cwe'][k]['qualified_paths'] for k in CWES),'FLOW_TOTAL')
        x=v['evidence_by_cwe']['79'];need(x['evidence_origin']==POLICY and x['raw_policy_paths']==get('POLICY79.json')['raw_paths'] and x['qualified_paths']==get('POLICY79.json')['qualified_paths'],'POLICY_PROVENANCE')
        native[arm]=a
    need(sum(a['new_requests'] for a in native.values())==s['new_native_requests']==pr['planned_model_requests']==c['parity']['new_native_requests'],'REQUEST_TOTAL')
    need(sum(a['cache_hits'] for a in native.values())==s['warm_cache_hits']==c['parity']['warm_cache_hits'],'CACHE_TOTAL')
    for ident in tok:
        same=[next(x for x in native[a]['details'] if x['case_key']==ident) for a in ARMS[1:]]
        need(len({x['cache_key'] for x in same})==3,'CACHE_COLLISION')
    commands=get('COMMAND_TIMINGS.json')
    need(all(x['returncode']==0 and not x['timed_out'] and not x['still_running'] and not x['process_group_still_running'] for x in commands),'CHILD_PROCESS_FAILURE')
    return {'archive_members_verified':len(contents),'manifest_entries_verified':len(contents)-1,'commands_completed':len(commands),
            'status':s['status'],'raw_opengrep_findings':n,'new_native_requests':s['new_native_requests'],'warm_cache_hits':s['warm_cache_hits'],
            'elapsed_s':s['elapsed_s'],'arms':{a:{'retained_opengrep':c['arms'][a]['retained_opengrep'],'qualified_paths':c['arms'][a]['qualified_paths'],
              'model_derived_paths':sum(c['arms'][a].get('evidence_by_cwe',{}).get(k,{}).get('qualified_paths',0) for k in ('22','78','89')),
              'policy_assisted_paths':c['arms'][a].get('evidence_by_cwe',{}).get('79',{}).get('qualified_paths',0),
              'accepted':native[a]['accepted'] if a in native else None,'abstain':native[a]['abstain'] if a in native else None} for a in ARMS},
            'limits':'ARCHIVE_BYTES_AND_INTERNAL_METADATA_CONSISTENCY; ORIGINAL_WEIGHTS_RAW_RESPONSES_DB_AND_SARIF_NOT_IN_UPLOAD; NO_INDEPENDENT_GOLD'}

def verify_report(data,summary,arm,input_sha):
    need(data.get('arm')==arm and data.get('input_sha256')==input_sha,'REPORT_IDENTITY')
    need(data.get('model_xss_gate_granted') is False and data.get('independent_gold') is False,'REPORT_SCOPE')
    rows=data['findings'];need(len(rows)==summary['findings'] and len({r['id'] for r in rows})==len(rows),'FINDING_COUNT')
    need(sum(r['origin']=='OPENGREP' for r in rows)==summary['retained_opengrep'],'RETENTION_COUNT')
    for c in CWES:
        chosen=[r for r in rows if r['cwe']==c];given=summary['per_cwe'][c]
        need(len(chosen)==given['findings'] and sorted({r['score']['final_score'] for r in chosen})==given['score_values'],'CWE_SCORE_SUMMARY')
    for r in rows:
        need(r['retained'] is True and r['vulnerability_confirmed'] is False,'CONFIRMED_OR_DROPPED_FINDING')
        v=r['score']['final_score'];need(type(v) in (int,float) and math.isfinite(v) and 0<=v<=100,'SCORE_RANGE')
        if arm=='opengrep_only':need(not r['dataflow'] and r['score']['ai_confidence_score']==0.5,'BASELINE_EVIDENCE')
        elif r['cwe']=='79':need(r['evidence_origin']==POLICY and r['score']['ai_confidence_score']==0.5,'XSS_AUTHORITY_CHANGED')
    return rows

class Store:
    def __init__(self,state,work):
        self.state=Path(state).resolve();self.work=Path(work).resolve();self.runroot=self.work/'batch39b4_hybrid_runs'
        self.state.mkdir(parents=True,exist_ok=True);self.catalog_path=self.state/'catalog.json'
        self.catalog=loads(read(self.catalog_path)) if self.catalog_path.exists() else {}
    def save(self):write_json(self.catalog_path,self.catalog)
    def register(self,run_id,zip_path,expected,origin):
        need(bool(RUN_RE.fullmatch(run_id)),'RUN_ID_INVALID');raw=read(zip_path)
        content=archive(raw,expected);audit_metadata(content);data=loads(content['00_RESULT.json']);mapping=loads(content['PRIVATE_RESULT_MANIFEST.json'])
        root=under(self.runroot,run_id);need(root.is_dir(),'LOCAL_RUN_MISSING')
        # Metadata must match the same original run, not only a name supplied by the UI.
        for name in ('00_RESULT.json','PRIVATE_RESULT_MANIFEST.json','COMPARISON.json','BEFORE.json','AFTER.json'):
            need(read(under(root,name))==content[name],'LOCAL_METADATA_MISMATCH:'+name)
        facts=[]
        for arm in ARMS:
            for leaf in ('result.json','report.sarif'):
                relative='analysis/'+arm+'/'+leaf;need(relative in mapping,'PRIVATE_MANIFEST_KEY_MISSING')
                b=read(under(root/'private',relative));need(sha(b)==mapping[relative],'LOCAL_RESULT_HASH_DRIFT:'+relative)
                if leaf=='result.json':verify_report(loads(b),loads(content['COMPARISON.json'])['arms'][arm],arm,data['input_sha256'])
                else:
                    sarif=loads(b);need(sarif['version']=='2.1.0','SARIF_VERSION')
                    need(sum(len(r['results']) for r in sarif['runs'])==loads(content['COMPARISON.json'])['arms'][arm]['findings'],'SARIF_COUNT')
                facts.append({'path':relative,'sha256':sha(b),'bytes':len(b)})
        if run_id in self.catalog:
            need(self.catalog[run_id]['audit_sha256']==expected,'RUN_ID_EVIDENCE_CONFLICT');return facts
        dst=under(self.state,'evidence/'+run_id+'_result.zip');dst.parent.mkdir(parents=True,exist_ok=True)
        with dst.open('xb') as f:f.write(raw)
        self.catalog[run_id]={'run_id':run_id,'audit_sha256':expected,'origin':origin,'registered_at':time.time(),'input_sha256':data['input_sha256']}
        self.save();return facts
    def evidence(self,run_id):
        need(run_id in self.catalog and bool(RUN_RE.fullmatch(run_id)),'RUN_NOT_REGISTERED')
        entry=self.catalog[run_id];raw=read(under(self.state,'evidence/'+run_id+'_result.zip'))
        return raw,archive(raw,entry['audit_sha256'])
    def full_file(self,run_id,arm,leaf):
        need(arm in ARMS and leaf in ('result.json','report.sarif'),'DOWNLOAD_NOT_ALLOWED')
        _,e=self.evidence(run_id);relative='analysis/'+arm+'/'+leaf;mapping=loads(e['PRIVATE_RESULT_MANIFEST.json'])
        b=read(under(self.runroot,run_id+'/private/'+relative));need(sha(b)==mapping[relative],'LOCAL_RESULT_HASH_DRIFT:'+relative)
        return b
    def overview(self,run_id):
        _,e=self.evidence(run_id);s=loads(e['00_RESULT.json']);c=loads(e['COMPARISON.json'])
        return {'registration':self.catalog[run_id],'summary':s,'comparison':c,'native':{a:{k:v for k,v in loads(e['NATIVE_'+a+'.json']).items() if k in ('accepted','abstain','candidates','reasons','performance')} for a in ARMS[1:]},'mode':'VIEW_EXISTING_RESULT_NO_NEW_SCAN'}
    def listing(self):
        out=[]
        for rid in sorted(self.catalog,reverse=True):
            try:
                o=self.overview(rid);out.append({**o['registration'],'status':o['summary']['status'],'elapsed_s':o['summary']['elapsed_s'],'raw_opengrep_findings':o['summary']['raw_opengrep_findings']})
            except (Blocked,OSError,ValueError,KeyError) as exc:out.append({'run_id':rid,'status':'EVIDENCE_UNAVAILABLE','error':str(exc)})
        return out
    def view(self,run_id,arm):
        raw=self.full_file(run_id,arm,'result.json');r=loads(raw);o=self.overview(run_id)
        rows=verify_report(r,o['comparison']['arms'][arm],arm,o['summary']['input_sha256']);out=[]
        for x in rows:
            model=x.get('model_observation') or {};label=model.get('label') or {};call=x.get('callsite') or {}
            out.append({'id':x['id'],'cwe':x['cwe'],'location':x['location'],'rule_id':x['rule_id'],'origin':x['origin'],
              'score':{k:v for k,v in x['score'].items() if k!='risk_description'},'evidence_status':x['evidence_status'],
              'evidence_origin':x.get('evidence_origin','OPENGREP_ONLY' if arm=='opengrep_only' else 'MODEL_DERIVED'),
              'confirmed':False,'retained':True,'callsite':{k:call[k] for k in ('package','class','method','signature','compiler_signature') if k in call},
              'model':{'status':model.get('status','NOT_APPLIED'),'role':label.get('type'),'reason':model.get('reason')},
              'dataflow':[{k:n[k] for k in ('uri','start_line','start_column','type') if k in n} for n in x.get('dataflow',[])],
              'raw_policy_path_count':len(x.get('raw_policy_flow_ids',[])),
              'encoding_assessments':[a.get('status','UNKNOWN') for a in x.get('sanitizer_assessments',[])]})
        return {'run_id':run_id,'arm':arm,'input_sha256':r['input_sha256'],'findings':out,
                'scope':'READ_ONLY_SANITIZED_VIEW; NO_RAW_PROMPTS_OR_MODEL_COMPLETIONS','independent_gold':False,
                'score_is_probability':False,'original_result_sha256':sha(raw)}
