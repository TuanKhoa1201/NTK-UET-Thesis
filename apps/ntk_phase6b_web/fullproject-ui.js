'use strict';
/* Only displays SHA-verified Phase 5.1 results already computed on this machine.
   It never starts a scanner or sends Java source to any endpoint. */
(() => {
  const byId = id => document.getElementById(id);
  const text = (tag, cls, content) => { const e = document.createElement(tag); if (cls) e.className=cls; e.textContent = String(content ?? ''); return e; };
  const priority = f => { const n=f?.score?.final_score; return typeof n==='number'?n.toFixed(1):'—'; };
  const safeLocalProject = p => /^[a-zA-Z0-9._-]+$/.test(p);
  let all=[];
  async function get(path) {
    const r=await fetch(path,{cache:'no-store',credentials:'same-origin'});
    const j=await r.json();
    if(!r.ok) throw Error(j?.error || `HTTP ${r.status}`);
    return j;
  }
  function count(root,n,label) {const b=text('div','fp-metric','');b.append(text('strong','',n),text('span','',label));root.append(b);}
  function showFinding(f) {
    const area=byId('fp-inspect');area.replaceChildren();
    area.append(text('h4','',f.rule_id || f.id || 'Finding'));
    area.append(text('p','',f.message || 'Cảnh báo cần kiểm tra thủ công.'));
    const source=f.location || {};
    area.append(text('p','fp-mono',`${source.uri || '—'}:${source.line || source.start_line || '?'}:${source.column || source.start_column || '?'}`));
    area.append(text('p','',`CWE ${f.cwe || 'chưa xác định'} · ${f.origin || '—'} · Điểm ${priority(f)}/100`));
    const a=f.model_annotation;
    if(f.model_qualified_dataflow_path === true && a && a.status==='ACCEPTED') {
      area.append(text('p','fp-exact','Có liên kết chính xác API/overload/đối số sink với CodeQL dataflow và nhãn LoRA. Không phải xác nhận lỗ hổng độc lập.'));
    } else {
      area.append(text('p','fp-muted','Chưa có liên kết AI–CodeQL đủ điều kiện. Nhãn AI không tự xác nhận lỗ hổng.'));
    }
    if(Array.isArray(f.dataflow) && f.dataflow.length) {
      area.append(text('h4','','CodeQL dataflow'));
      const list=text('ol','fp-path','');
      for (const pos of f.dataflow.slice(0,20)) list.append(text('li','',`${pos.uri || '—'}:${pos.line || '?'}`));
      area.append(list);
    }
  }
  function renderList() {
    const tbody=byId('fp-finding-body');tbody.replaceChildren();
    const scope=byId('fp-filter').value;
    const found=all.filter(f=>scope==='all'||(scope==='exact'&&f.model_qualified_dataflow_path===true)||
      (scope==='opengrep'&&f.origin==='OPENGREP')||(scope==='codeql'&&f.origin==='CODEQL_SECURITY_EXTENDED'));
    byId('fp-find-count').textContent=`${found.length}/${all.length} cảnh báo`;
    for(const f of found.slice(0,250)) {
      const row=document.createElement('tr');
      const loc=f.location || {};
      const brief=`${loc.uri || '—'}:${loc.line || loc.start_line || '?'}`;
      for(const cell of [f.cwe || '—', f.origin==='OPENGREP'?'OpenGrep':'CodeQL', f.rule_id || '—',brief,priority(f),f.model_qualified_dataflow_path?'Exact AI link':'Chưa linked']) {
        row.append(text('td','',cell));
      }
      row.tabIndex=0;
      row.addEventListener('click',()=>showFinding(f));
      row.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();showFinding(f);}});
      tbody.append(row);
    }
    if(!found.length) {
      const row=document.createElement('tr');const cell=text('td','','Không có finding trong bộ lọc này.');cell.colSpan=6;row.append(cell);tbody.append(row);
    }
  }
  async function selectProject() {
    const p=byId('fp-select').value;
    if(!safeLocalProject(p)) return;
    byId('fp-error').textContent='';
    try {
      const result=await get(`/api/fullproject/${encodeURIComponent(p)}/result`);
      if(result.status!=='PHASE51_EXACT_BINDING_AUDITED') throw Error('Trạng thái Phase 5.1 không hợp lệ');
      all=result.findings || [];
      const summary=byId('fp-stats');summary.replaceChildren();
      const og=all.filter(x=>x.origin==='OPENGREP').length;
      const ql=all.filter(x=>x.origin==='CODEQL_SECURITY_EXTENDED').length;
      const linked=all.filter(x=>x.model_qualified_dataflow_path===true).length;
      count(summary,all.length,'Findings giữ lại');
      count(summary,og,'OpenGrep');count(summary,ql,'CodeQL');count(summary,linked,'Exact AI–CodeQL');
      const downloads=byId('fp-downloads');downloads.replaceChildren();
      for(const [leaf,label] of [['result.json','JSON đầy đủ'],['report.sarif','SARIF 2.1.0']]) {
        const a=text('a','fp-link',label);a.href=`/api/fullproject/${encodeURIComponent(p)}/${leaf}`;a.download='';downloads.append(a);
      }
      byId('fp-inspect').replaceChildren(text('p','fp-muted','Chọn một finding trong bảng để xem chi tiết.'));
      renderList();
    } catch(e) {byId('fp-error').textContent=`Không thể nạp kết quả đã kiểm chứng: ${e.message}`;}
  }
  async function start() {
    const select=byId('fp-select'); if(!select) return;
    try {
      const list=await get('/api/fullproject');
      if(list.mode!=='READ_ONLY_PRIOR_PHASE51_EVIDENCE') throw Error('Backend không ở chế độ Phase 6A');
      for (const item of list.projects) {
        if(!safeLocalProject(item.project)) continue;
        const opt=text('option','',item.project);opt.value=item.project;select.append(opt);
      }
      select.addEventListener('change',selectProject);
      byId('fp-filter').addEventListener('change',renderList);
      if(select.options.length) {select.selectedIndex=0;await selectProject();}
    } catch(e) {
      byId('fp-error').textContent=`Chưa cấu hình nguồn bằng chứng Full-Project: ${e.message}`;
    }
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
