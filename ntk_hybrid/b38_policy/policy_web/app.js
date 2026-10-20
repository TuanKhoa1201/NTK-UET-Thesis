'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="ntk-csrf"]').content;
let busy = false;
function textNode(tag,text){const el=document.createElement(tag);el.textContent=String(text);return el;}
async function api(url,options={}){const r=await fetch(url,options);const j=await r.json();if(!r.ok)throw Error(j.error||r.status);return j;}
async function start(){
  const health=await api('/api/health');
  health.accepted_arms.forEach(arm=>{const o=textNode('option','Qwen2.5-Coder-0.5B + LoRA '+arm);o.value=arm;$('arm').append(o);});
}
$('zip').addEventListener('change',()=>{$('filename').textContent=$('zip').files[0]?.name||'Select .zip';});
function links(id,ready){$('links').replaceChildren();for(const leaf of ['engine.log',...(ready?['result.json','report.sarif','evidence.zip']:[])]){const a=textNode('a',leaf);a.href='/api/jobs/'+id+'/'+leaf;a.download='ntk-b38-'+id+'-'+leaf;$('links').append(a);}}
function render(report){
 $('results').classList.remove('hidden');$('rows').replaceChildren();$('paths').replaceChildren();$('counts').replaceChildren();
 const arm=report.summary.arms[report.arm];
 Object.entries(arm.cwes).forEach(([c,r])=>{$('counts').append(textNode('div','CWE-'+c+' | paths '+r.flow_count+' | retained '+r.opengrep_preserved+' | model-only paths '+r.model_only_flow_count+' | origin '+r.evidence_origin));});
 [...report.findings].sort((a,b)=>b.score.final_score-a.score.final_score).forEach(f=>{const tr=document.createElement('tr');[f.location.uri,f.location.start_line,'CWE-'+f.cwe,Number(f.score.final_score).toFixed(1),f.score.risk_level,f.evidence_status,f.evidence_origin||'MODEL_DERIVED'].forEach(t=>tr.append(textNode('td',t)));$('rows').append(tr);});
 report.paths.forEach(f=>{const d=document.createElement('div');d.className='trace';d.append(textNode('strong','CWE-'+f.cwe+' | '+(f.evidence_origin||'MODEL_DERIVED')+' | '+f.callsite.method+' | '+f.location.uri+':'+f.location.start_line));f.paths.forEach(path=>d.append(textNode('div',path.map(n=>n.uri+':'+n.start_line).join(' -> '))));$('paths').append(d);});
 if(!report.paths.length)$('paths').append(textNode('p','No qualified path under the selected source/sink policy. This is NOT a safety verdict.'));
}
$('scan').addEventListener('click',async()=>{
 if(busy)return;const file=$('zip').files[0];if(!file){$('problem').textContent='Select a ZIP first.';return;}
 busy=true;$('scan').disabled=true;$('problem').textContent='';$('results').classList.add('hidden');$('state').className='status';
 try{
  const j=await api('/api/jobs',{method:'POST',headers:{'Content-Type':'application/zip','X-NTK-CSRF':token,'X-NTK-Arm':$('arm').value,'X-NTK-CWE':$('cwe').value},body:file});
  $('job').textContent=j.job_id;links(j.job_id,false);
  while(true){
   const state=await api('/api/jobs/'+j.job_id);$('state').textContent=state.status;$('stage').textContent=state.stage;$('elapsed').textContent=(state.elapsed_s||0)+' s';
   if(state.status!=='RUNNING'){
    $('problem').textContent=state.blocker||'';$('state').className='status '+(state.status==='COMPLETE'?'good':'bad');
    links(j.job_id,state.status!=='BLOCKED'||Boolean(state.evidence_file));
    if(state.status!=='BLOCKED')render(await api('/api/jobs/'+j.job_id+'/result.json'));
    break;
   }
   await new Promise(r=>setTimeout(r,1500));
  }
 }catch(e){$('problem').textContent=e.message;$('state').textContent='BLOCKED';$('state').className='status bad';}
 finally{busy=false;$('scan').disabled=false;}
});
start().catch(e=>{$('problem').textContent=e.message;$('scan').disabled=true;});
