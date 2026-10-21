#!/usr/bin/env python3
"""Import one pinned B4 run and test real localhost read-only persistence; NEVER scan."""
from __future__ import annotations
import argparse, http.client, os, signal, socket, subprocess, sys, time, uuid, zipfile
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from store import *
from workbench import release_state,verify_engine,offline_env


def request(port,path):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
    try:
        c.request('GET',path,headers={'Host':'127.0.0.1:'+str(port)});r=c.getresponse();b=r.read(32*1024**2+1)
        need(len(b)<=32*1024**2,'HTTP_RESPONSE_LIMIT');return r.status,b
    finally:c.close()

def cycle(state,host,port,run_id,log,overview_hash):
    proc=None;responses=[]
    with log.open('xb') as out:
        try:
            proc=subprocess.Popen([host,'-I','-B','-u',str(ROOT/'workbench.py'),'--state',str(state),'--port',str(port)],
                                  stdout=out,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,cwd=ROOT,env=offline_env(),start_new_session=True)
            deadline=time.monotonic()+120
            while True:
                need(proc.poll() is None,'SERVER_EXITED_BEFORE_READY_SEE_'+log.name)
                try:
                    code,b=request(port,'/api/health')
                    if code==200:break
                except (ConnectionError,TimeoutError,OSError):pass
                need(time.monotonic()<deadline,'SERVER_READY_TIMEOUT');time.sleep(0.3)
            paths=['/api/health','/','/app.js','/style.css','/api/runs','/api/jobs','/api/runs/'+run_id]
            paths += ['/api/runs/'+run_id+'/'+a for a in ARMS]
            paths += ['/api/runs/'+run_id+'/'+a+'/'+f for a in ARMS for f in ('result.json','report.sarif')]
            paths += ['/api/runs/'+run_id+'/evidence.zip']
            for path in paths:
                code,b=request(port,path);need(code==200,'HTTP_FAILED:'+path)
                if path=='/api/health':
                    h=loads(b);need(h['mode']=='B39B5_PERSISTENT_COMPARISON_WORKBENCH' and h['scan_enabled'] is False and h['active_job'] is None,'UNEXPECTED_SERVICE_OR_MODE')
                if path=='/api/jobs':need(loads(b)==[],'SMOKE_MUST_NOT_START_JOBS')
                if path=='/api/runs':need([x['run_id'] for x in loads(b)]==[run_id],'HISTORY_MISSING_AFTER_START')
                if path=='/api/runs/'+run_id:need(sha(b)==overview_hash,'HISTORY_CONTENT_CHANGED_ON_RESTART')
                responses.append({'path':path,'status':code,'sha256':sha(b),'bytes':len(b)})
        finally:
            if proc and proc.poll() is None:proc.send_signal(signal.SIGTERM)
            if proc:
                try:proc.wait(timeout=120)
                except subprocess.TimeoutExpired:raise Blocked('OWN_SERVER_STOP_UNCONFIRMED_NO_BROAD_KILL') from None
    need(proc.returncode==0,'SERVER_SHUTDOWN_FAILED')
    return {'responses':responses,'pid':proc.pid,'returncode':proc.returncode,'own_server_still_running':proc.poll() is None,'post_requests':0}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,default=Path.home()/'migration/ntk_stage3_verified_v5_work')
    p.add_argument('--repo',type=Path,default=Path.home()/'iris');p.add_argument('--github',type=Path,default=Path.home()/'migration/ntk_github_publish_20261020')
    p.add_argument('--downloads',type=Path,default=Path('/mnt/c/Users/HP/Downloads'));p.add_argument('--host-python',default=os.environ.get('NTK_IRIS_PYTHON',''))
    a=p.parse_args(argv)
    for k in ('work','repo','github','downloads'):setattr(a,k,getattr(a,k).resolve())
    need(a.work.is_dir() and a.downloads.is_dir(),'WORK_OR_DOWNLOADS_MISSING');need(a.host_python and Path(a.host_python).is_file(),'HOST_PYTHON_REQUIRED')
    need(not a.work.is_relative_to(a.repo) and not a.work.is_relative_to(a.github),'WORK_INSIDE_REPO')
    name='b39b5_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    root=a.work/'batch39b5_workbench'/name;root.mkdir(parents=True,mode=0o700);state=root/'state';state.mkdir(mode=0o700)
    evidence=root/'audit';evidence.mkdir();s={'status':'B39B5_BLOCKED','blockers':[],'new_scan_requests':0,'new_model_inference_requested':False,
      'new_codeql_database_requested':False,'live_upload_e2e':'NOT_EXECUTED','default_scan_enabled':False,'production_b38_web_changed':False}
    before=None;config=None;cycles=[]
    try:
        print('B39B5_STAGE=VERIFY_B39B4_METADATA_AND_ORIGINAL_BACKEND',flush=True)
        zip_path=a.downloads/B4_NAME;content=archive(read(zip_path),B4_SHA);audit=audit_metadata(content);write_json(evidence/'INPUT_B39B4_AUDIT.json',audit)
        backend=archive(read(ROOT/'backend_b39b4.zip'),ENGINE_SHA);engine=root/'backend';engine.mkdir()
        for n,data in backend.items():q=under(engine,n);q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(data)
        config={'work':str(a.work),'repo':str(a.repo),'github':str(a.github),'downloads':str(a.downloads),'host_python':a.host_python,
                'engine':str(engine),'engine_manifest_sha256':verify_engine(engine),'baseline':loads(content['BEFORE.json'])}
        write_json(state/'config.json',config,exclusive=True)
        before=release_state(config);write_json(evidence/'BEFORE.json',before)
        oldruns=sorted(p.name for p in (a.work/'batch39b4_hybrid_runs').iterdir() if p.is_dir())
        print('B39B5_STAGE=VERIFY_EIGHT_LOCAL_RESULT_EXPORTS_AND_REGISTER_HISTORY',flush=True)
        run_id=B4_NAME.removesuffix('_result.zip');store=Store(state,a.work)
        records=store.register(run_id,zip_path,B4_SHA,'EXISTING_VERIFIED_RUN_IMPORTED_WITHOUT_RESCAN')
        write_json(evidence/'LOCAL_EXPORTS_VERIFIED.json',records)
        overview_hash=sha(canonical(store.overview(run_id)).encode())
        print('B39B5_STAGE=FIRST_START_READ_ONLY_GET_AND_STOP',flush=True)
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:sock.bind(('127.0.0.1',8767))
            except OSError:raise Blocked('PORT_8767_BUSY_EXISTING_SERVICE_NOT_TOUCHED') from None
        cycles.append(cycle(state,a.host_python,8767,run_id,root/'FIRST_SERVER.log',overview_hash))
        print('B39B5_STAGE=RESTART_AND_VERIFY_PERSISTED_HISTORY_NO_SCAN',flush=True)
        cycles.append(cycle(state,a.host_python,8767,run_id,root/'SECOND_SERVER.log',overview_hash))
        need(oldruns==sorted(p.name for p in (a.work/'batch39b4_hybrid_runs').iterdir() if p.is_dir()),'NEW_BACKEND_RUN_APPEARED_DURING_GET_SMOKE')
        need(Store(state,a.work).register(run_id,zip_path,B4_SHA,'VERIFY_AGAIN')==records,'LOCAL_EXPORTS_CHANGED')
        s.update(status='B39B5_HISTORY_IMPORT_AND_HTTP_RESTART_COMPLETE',verified_original_exports=len(records),registered_existing_runs=1,
          persistence_restart='PASS',live_backend_implementation='BYTE_IDENTICAL_B39B4_NOT_REEXECUTED',state_dir=str(state))
    except (Exception,KeyboardInterrupt) as exc:s['blockers'].append(type(exc).__name__+': '+str(exc));s['status']='B39B5_BLOCKED'
    finally:
        if before is not None:
            try:
                after=release_state(config);write_json(evidence/'AFTER.json',after);need(after==before,'BASELINE_CHANGED')
            except Exception as e:s['blockers'].append(str(e));s['status']='B39B5_BLOCKED'
        write_json(evidence/'HTTP_CYCLES.json',cycles)
        if s['status']=='B39B5_HISTORY_IMPORT_AND_HTTP_RESTART_COMPLETE':
            install={'state':str(state),'work':str(a.work),'host_python':a.host_python,'source_tool_root':str(ROOT)}
            write_json(ROOT/'INSTALL.json',install,exclusive=True)
            pointer=a.work/'NTK_B39B5_TOOL_PATH.txt'
            if not pointer.exists():
                with pointer.open('x') as f:f.write(str(ROOT)+'\n')
            elif pointer.read_text().strip()!=str(ROOT):s['existing_pointer_not_overwritten']=str(pointer)
        write_json(evidence/'00_RESULT.json',s)
        files=sorted(evidence.glob('*.json'));sums=''.join(sha(read(f))+'  '+f.name+'\n' for f in files)
        (evidence/'SHA256SUMS').write_text(sums,encoding='ascii')
        dst=a.downloads/(name+'_result.zip')
        with zipfile.ZipFile(dst,'x',zipfile.ZIP_DEFLATED) as z:
            for f in files+[evidence/'SHA256SUMS']:z.write(f,f.name)
        h=sha(read(dst));Path(str(dst)+'.sha256').write_text(h+'  '+dst.name+'\n')
        print('\n===== B39B.5 RESULT =====',flush=True)
        for k,v in [('STATUS',s['status']),('BLOCKERS',len(s['blockers'])),('REGISTERED_EXISTING_RUNS',s.get('registered_existing_runs',0)),
          ('VERIFIED_ORIGINAL_EXPORTS',s.get('verified_original_exports',0)),('PERSISTENCE_RESTART',s.get('persistence_restart','NOT_COMPLETED')),
          ('NEW_SCAN_REQUESTS',0),('LIVE_UPLOAD_E2E','NOT_EXECUTED'),('DEFAULT_SCAN_ENABLED',False),('RUN_DIR',root),('OUTPUT_ZIP',dst),('OUTPUT_SHA256',h),
          ('START_SCRIPT',ROOT/'serve.sh')]:print(str(k)+'='+str(v),flush=True)
        for b in s['blockers']:print('BLOCKER='+b,flush=True)
    return 0 if s['status']=='B39B5_HISTORY_IMPORT_AND_HTTP_RESTART_COMPLETE' else 2
if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:print('B39B5_EARLY_BLOCKED='+str(e),flush=True);sys.exit(2)
