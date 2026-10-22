'use strict';
/* New source upload and new job IDs only; prior Phase5.1 viewer is untouched. */
(() => {
  const id = x => document.getElementById(x);
  const text = (tag, value, cls) => { const e=document.createElement(tag);e.textContent=String(value??'');if(cls)e.className=cls;return e; };
  const csrf = document.querySelector('meta[name="ntk-csrf"]').content;
  let active=null, timer=null, findings=[];
  const summaryFields = [
    ['opengrep','OpenGrep'], ['codeql_db','CodeQL database'], ['codeql_security','CodeQL Security'],
    ['api_inventory','Compiler API'], ['native_lora','IRIS / LoRA E1'],
    ['exact_binding','Argument dataflow'], ['score','SAST V2.2']
  ];
  async function request(path, init={}) {
    const res=await fetch(path,{credentials:'same-origin',cache:'no-store',...init});
    const ty=res.headers.get('content-type')||'';
    const content=ty.includes('application/json')?await res.json():await res.text();
    if(!res.ok)throw Error(content?.error||`HTTP ${res.status}`);
    return content;
  }
  function renderStatus(job) {
    const target=id('fp6b-status');if(!target)return;
    target.replaceChildren(text('strong',`Job ${job.id} | ${job.status}`),text('p',`Stage: ${job.stage} | ${job.elapsed_s??0} s`));
    const sum=job.summary||{};
    const info=text('div','', 'fp6b-stages');
    for(const [key,label] of summaryFields)info.append(text('div',`${label}: ${sum[key]||'NOT_RUN'}`));
    target.append(info);
    if(job.error)target.append(text('p',`Blocker: ${job.error}`,'fp6b-error'));
    if(sum.opengrep_findings!==undefined)target.append(text('p',`OpenGrep: ${sum.opengrep_findings} findings | CodeQL: ${sum.codeql_findings??'not complete'} | Exact AI links: ${sum.exact_model_links??0}`));
    const stop=id('fp6b-stop');stop.disabled=!['STARTING','RUNNING','STOPPING'].includes(job.status);
    if(['COMPLETE','PARTIAL'].includes(job.status))showResult(job.id);
  }
  async function showResult(jobId) {
    try {
      const j=await request(`/api/fullproject/live/jobs/${jobId}/result.json`);
      if(j.status!=='PHASE6B_NEW_SCAN_EVIDENCE_REPORT'||j.new_scan!==true)throw Error('Not a verified new scan result');
      findings=j.findings||[];
      const box=id('fp6b-results');box.replaceChildren();
      box.append(text('h3',`New scan: ${j.project} (${findings.length} findings)`));
      box.append(text('p',`OpenGrep ${j.summary?.opengrep||0} | CodeQL ${j.summary?.codeql||0} | Exact AI paths ${j.summary?.exact_model_links||0}. Review priority 0-100 is not a CVE probability.`));
      const dl=text('div','', 'fp6b-links');
      for(const [n,label] of [['result.json','JSON report'],['report.sarif','SARIF 2.1.0'],['SCAN_SUMMARY.json','Stage receipts']]){
        const a=text('a',label);a.href=`/api/fullproject/live/jobs/${jobId}/${n}`;a.download='';dl.append(a);
      }
      box.append(dl);
      const tbl=document.createElement('table');tbl.className='fp6b-table';
      const head=document.createElement('thead');const tr=document.createElement('tr');
      for(const title of ['CWE','Engine','Rule','Location','Priority','AI join'])tr.append(text('th',title));
      head.append(tr);tbl.append(head);
      const body=document.createElement('tbody');
      for(const item of findings.slice(0,350)){
        const row=document.createElement('tr');row.tabIndex=0;
        const loc=item.location||{};
        for(const value of [item.cwe||'--',item.origin==='OPENGREP'?'OpenGrep':'CodeQL',
          item.rule_id||'--',`${loc.uri||'--'}:${loc.line||loc.start_line||'?'}`,
          item.score?.final_score??'--',item.model_qualified_dataflow_path?'Exact':'Not linked'])row.append(text('td',value));
        const show=()=>{
          const detail=id('fp6b-inspect');detail.replaceChildren(text('strong',item.rule_id||'Finding'),
            text('p',item.message||'Needs review'),text('p',`Evidence: ${item.model_qualified_dataflow_path?'exact model sink argument + CodeQL dataflow':'CodeQL / OpenGrep only'}`));
          if(item.dataflow?.length){const ol=document.createElement('ol');
            for(const pos of item.dataflow.slice(0,25))ol.append(text('li',`${pos.uri}:${pos.line}`));detail.append(ol);}
        };
        row.addEventListener('click',show);row.addEventListener('keydown',e=>{if(e.key==='Enter'){show();}});
        body.append(row);
      }
      tbl.append(body);const scroll=text('div','','fp6b-scroll');scroll.append(tbl);box.append(scroll);
      id('fp6b-inspect').replaceChildren(text('p','Click a finding to see the CodeQL path.'));
    }catch(e){id('fp6b-error').textContent=`Report unavailable: ${e.message}`;}
  }
  async function poll() {
    if(!active)return;
    try {
      const j=await request(`/api/fullproject/live/jobs/${active}`);
      renderStatus(j);
      if(['COMPLETE','PARTIAL','BLOCKED','STOPPED','INTERRUPTED_UNCONFIRMED'].includes(j.status)){
        clearInterval(timer);timer=null;id('fp6b-run').disabled=false;active=null;
      }
    } catch(e){id('fp6b-error').textContent=e.message;}
  }
  async function submit(file,name,fromLegacy=false) {
    if(active)throw Error('A full-project job is already running');
    if(!file||!file.name.toLowerCase().endsWith('.zip'))throw Error('Choose a project ZIP');
    if(!file.size||file.size>64*1024*1024)throw Error('Compressed ZIP must be at most 64 MiB');
    if(fromLegacy ? !id('scan-consent').checked : !id('fp6b-consent').checked)
      throw Error('Confirm that you are permitted to scan this project');
    if(!window.confirm('Start a REAL local full-project scan? CodeQL uses no-build mode. Complex repositories can take many minutes.'))return;
    id('fp6b-run').disabled=true;id('fp6b-error').textContent='';
    id('fp6b-results').replaceChildren();id('fp6b-inspect').replaceChildren();
    try {
      const body=await request('/api/fullproject/live/jobs',{method:'POST',
        headers:{'X-NTK-CSRF':csrf,'X-NTK-Consent':'TRUSTED_FULLPROJECT_ZIP_NO_BUILD',
          'Content-Type':'application/zip','X-NTK-Project-Name':encodeURIComponent(name)},body:file});
      active=body.job_id;
      window.location.hash='full-project-scan';
      renderStatus({id:active,status:'STARTING',stage:'ZIP_INTAKE',elapsed_s:0});
      await poll();timer=setInterval(poll,1800);
    } catch(e){id('fp6b-error').textContent=e.message;id('fp6b-run').disabled=false;throw e;}
  }
  window.NTKFullProjectB={submit};
  function init() {
    if(!id('fp6b-run'))return;
    const sel=id('scan-mode');
    if(sel) {
      sel.addEventListener('change',()=>{
        const live=sel.value==='fullproject';
        const desc=id('scan-mode-note');if(desc){desc.textContent=live?
          'Full Project: up to 64 MiB ZIP, many Java files, real OpenGrep + CodeQL Java no-build + local IRIS/LoRA when eligible. No project build scripts executed. No 120 s guarantee.':
          'Fast/JDK-only mode: up to 24 Java files. Not compatible with a full Maven/Gradle GitHub repository.';}
        const note=document.querySelector('#dropzone span');if(note)note.textContent=live?
          'GitHub ZIP, many Java files | CodeQL no-build | max 64 MiB ZIP':
          '1-24 Java files | JDK 21 | no Maven/Gradle';
      });
    }
    id('fp6b-run').addEventListener('click',async()=>{
      try{const f=id('fp6b-file').files?.[0];await submit(f,f?.name||'project.zip');}catch(e){id('fp6b-error').textContent=e.message;}
    });
    id('fp6b-stop').addEventListener('click',async()=>{
      if(!active)return;
      try{await request(`/api/fullproject/live/jobs/${active}/stop`,{method:'POST',headers:{'X-NTK-CSRF':csrf}});await poll();}
      catch(e){id('fp6b-error').textContent=e.message;}
    });
    id('fp6b-refresh').addEventListener('click',loadHistory);
    loadHistory();
  }
  async function loadHistory() {
    try {
      const jobs=await request('/api/fullproject/live/jobs');
      const root=id('fp6b-history');root.replaceChildren();
      for(const j of jobs.slice(0,12)){
        const b=text('button',`${j.project} | ${j.status} | ${j.id}`,'fp6b-history-button');b.type='button';
        b.onclick=()=>{if(['COMPLETE','PARTIAL'].includes(j.status))showResult(j.id);else renderStatus(j);};root.append(b);
      }
    } catch(e){id('fp6b-error').textContent=e.message;}
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
