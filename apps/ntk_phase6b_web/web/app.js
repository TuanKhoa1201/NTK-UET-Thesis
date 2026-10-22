'use strict';
/* NTK SAST single-port UI. Every request is same-origin localhost. */
const $ = id => document.getElementById(id);
const csrf = document.querySelector('meta[name="ntk-csrf"]').content;
const arms = {opengrep_only:'OpenGrep', base:'Qwen cơ sở', epoch_1:'LoRA - Epoch 1', epoch_2:'LoRA - Epoch 2'};
const cwes = {'22':'Truy cập đường dẫn không an toàn','78':'Chèn lệnh hệ thống','79':'Cross-site scripting (XSS)','89':'SQL injection'};
const bands = {
  CRITICAL:['Ưu tiên rất cao','Nên kiểm tra cảnh báo này trước tiên. Đối chiếu đường dữ liệu và điều kiện khai thác trước khi quyết định sửa mã.'],
  HIGH:['Ưu tiên cao','Nên rà soát sớm vì bộ chấm điểm xếp cảnh báo vào nhóm cần quan tâm cao.'],
  MEDIUM:['Ưu tiên trung bình','Cần kiểm tra thêm bối cảnh xử lý dữ liệu, ràng buộc đầu vào và các điều kiện bảo vệ.'],
  LOW:['Ưu tiên thấp','Có thể rà soát sau các cảnh báo ưu tiên cao hơn, nhưng không được hiểu là mã an toàn.']
};
const state={connected:false,enabled:false,fastAvailable:false,selectedRun:null,rows:[],runOverview:null,
  datasets:{train:null,validation:null},datasetInfo:{},activeSplit:'train',datasetPage:0,
  jobId:null,pollBusy:false,lastJobStatus:null,flowTimer:[],activeProject:''};
function el(tag,cls,content){const out=document.createElement(tag);if(cls)out.className=cls;if(content!==undefined)out.textContent=String(content);return out;}
function empty(target,message){target.replaceChildren(el('div','empty-state',message));}
function number(v){return typeof v==='number'&&Number.isFinite(v)?v.toLocaleString('vi-VN',{maximumFractionDigits:1}):String(v??'—');}
function glyph(id){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');const use=document.createElementNS('http://www.w3.org/2000/svg','use');use.setAttribute('href','#'+id);svg.append(use);return svg;}
let noticeTimer;
function notice(text,error=false){const t=$('toast');t.textContent=text;t.classList.toggle('problem',error);t.classList.add('visible');clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>t.classList.remove('visible'),6000);}
async function api(path,init={}){
  const response=await fetch(path,{cache:'no-store',...init});
  const type=response.headers.get('content-type')||'';
  const result=type.includes('application/json')?await response.json():await response.text();
  if(!response.ok)throw Error((result&&result.error)||`Có lỗi kết nối (HTTP ${response.status}).`);
  return result;
}
function addDownload(target,path,title){const a=el('a','link-button');a.href=path;a.download='';a.append(glyph('i-download'),el('span','',title));target.append(a);}
function metric(value,title,wide=false){const d=el('div','summary-item'+(wide?' wide':''));d.append(el('strong','',value),el('span','',title));return d;}
function stageReset(){for(const t of state.flowTimer)clearTimeout(t);state.flowTimer=[];document.querySelectorAll('.pipe-step').forEach(d=>{d.classList.remove('in-action','done');d.querySelector('.pipe-state').textContent='·';});}
function stageMark(index,all=false){[...document.querySelectorAll('.pipe-step')].forEach((d,i)=>{const done=all||i<index,active=!all&&i===index;d.classList.toggle('done',done);d.classList.toggle('in-action',active);d.querySelector('.pipe-state').textContent=done?'✓':active?'●':'·';});}
function resetReports(message='Chưa có kết quả phân tích. Hãy chọn gói Java và nhấn “Bắt đầu phân tích”.'){
  state.selectedRun=null;state.rows=[];state.runOverview=null;state.jobId=null;state.lastJobStatus=null;
  $('run-select').replaceChildren(el('option','','Chưa có dự án đã quét'));
  $('run-status').textContent='0 dự án';empty($('run-summary'),message);
  const body=$('arms-comparison');body.replaceChildren();const tr=el('tr');const td=el('td','placeholder-cell','Bảng so sánh sẽ có dữ liệu sau lần quét đầu tiên.');td.colSpan=5;tr.append(td);body.append(tr);
  $('findings-total').textContent='0 cảnh báo';empty($('findings-list'),'Danh sách cảnh báo hiện đang trống.');empty($('inspect'),'Chọn một cảnh báo để xem chi tiết.');
  $('arm-downloads').replaceChildren();$('run-downloads').replaceChildren();
  empty($('score-overview'),'Chưa có điểm chấm SAST. Mỗi cảnh báo sẽ được xếp mức ưu tiên sau khi có kết quả quét.');
  $('score-explainer').replaceChildren(el('strong','','Chưa có điểm phân tích'),
    el('p','','Điểm ưu tiên sẽ xuất hiện khi phân tích dự án Java. Mỗi cảnh báo có điểm riêng từ 0–100.'));
}
async function checkBackend(){
  const data=await api('/api/connect');state.connected=!!data.connected;state.enabled=!!data.backend?.scan_enabled;state.fastAvailable=!!data.backend?.fast_available;
  $('scan-mode').querySelector('option[value=fast]').disabled=!state.fastAvailable;
  if(!state.fastAvailable)$('scan-mode').value='deep';
  const c=$('connection');c.classList.toggle('offline',!state.connected);c.classList.toggle('readonly',state.connected&&!state.enabled);
  c.replaceChildren(el('span','dot'),document.createTextNode(!state.connected?'Không kết nối được engine':state.enabled?'Hệ thống sẵn sàng quét':'Chế độ xem kết quả'));
  $('scan-gate').textContent=state.enabled?'Sẵn sàng phân tích':state.connected?'Chỉ xem dữ liệu':'Đang ngắt kết nối';
  $('run-scan').disabled=!state.enabled;
  $('sample-link').style.display=state.connected?'inline-flex':'none';
  $('scan-message').textContent=!state.connected?'Không truy cập được bộ phân tích cục bộ. Hãy kiểm tra terminal chạy ứng dụng.':
    state.enabled?'Sẵn sàng phân tích. Mã nguồn và kết quả được xử lý trên máy này.':
    'Ứng dụng đang ở chế độ xem. Muốn phân tích mã Java mới, khởi động bằng tùy chọn --enable-scan.';
  return state.connected;
}
$('simulate-flow').addEventListener('click',()=>{
  if(state.jobId&&['RUNNING','STARTING','STOPPING'].includes(state.lastJobStatus))return notice('Đang có lượt quét thật. Vui lòng chờ kết quả.',true);
  stageReset();stageMark(0);
  $('job-card').replaceChildren(el('strong','job-title','Giới thiệu quy trình phân tích'),el('p','','Đang minh họa thứ tự xử lý. Chưa chạy engine và không tạo cảnh báo.'));
  for(let i=1;i<6;i++)state.flowTimer.push(setTimeout(()=>stageMark(i),i*650));
  state.flowTimer.push(setTimeout(()=>{stageMark(5,true);notice('Đã giới thiệu toàn bộ quy trình. Chưa thực hiện quét mã nguồn.');},6*650));
});
$('project-zip').addEventListener('change',()=>{
  const f=$('project-zip').files[0];$('file-label').textContent=f?`${f.name} (${number(Math.round(f.size/1024))} KB)`:'Chọn tệp ZIP hoặc kéo thả vào đây';
});
const drop=$('dropzone');
drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('dragover');});
drop.addEventListener('dragleave',()=>drop.classList.remove('dragover'));
drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('dragover');
  const f=e.dataTransfer?.files?.[0];if(!f)return;
  if(!f.name.toLowerCase().endsWith('.zip'))return notice('Hãy chọn gói ZIP Java.',true);
  const dt=new DataTransfer();dt.items.add(f);$('project-zip').files=dt.files;
  $('project-zip').dispatchEvent(new Event('change'));
});
$('run-scan').addEventListener('click',async()=>{
  if(!state.enabled)return notice('Ứng dụng chưa được bật chế độ phân tích.',true);
  const f=$('project-zip').files[0];
  if(!f||!f.name.toLowerCase().endsWith('.zip'))return notice('Chọn gói ZIP có các tệp Java trước.',true);
  if($('scan-mode').value==='fullproject') {
    try {await window.NTKFullProjectB.submit(f,f.name,true);}
    catch(error) {notice(error.message,true);}
    return;
  }
  if(f.size<1||f.size>16*1024*1024)return notice('Kích thước tệp ZIP cần nhỏ hơn hoặc bằng 16 MiB.',true);
  if(!$('scan-consent').checked)return notice('Vui lòng xác nhận quyền phân tích mã nguồn.',true);
  const mode=$('scan-mode').value;
  if(mode==='fast'&&!state.fastAvailable)return notice('Quét nhanh chưa được cài đặt. Hãy kiểm tra terminal.',true);
  if(!confirm((mode==='fast'?'Quét nhanh Epoch 1':'Phân tích chuyên sâu')+' sẽ chạy OpenGrep, CodeQL và mô hình AI cục bộ trên máy này. Có thể mất nhiều phút. Bắt đầu?'))return;
  $('run-scan').disabled=true;stageReset();stageMark(0);
  try{
    const job=await api('/api/jobs',{method:'POST',headers:{'X-NTK-CSRF':csrf,
      'X-NTK-Consent':mode==='fast'?'TRUSTED_JDK_ONLY_RUN_FAST_E1':'TRUSTED_JDK_ONLY_RUN_ALL_FOUR_ARMS',
      'X-NTK-Scan-Mode':mode,'Content-Type':'application/zip',
      'X-NTK-Project-Name':encodeURIComponent(f.name)},body:f});
    state.jobId=job.job_id;state.activeProject=f.name;state.lastJobStatus=null;
    notice('Đã bắt đầu quét dự án. Có thể theo dõi tiến trình ngay trên trang này.');
    await pollJobs();
  }catch(error){$('run-scan').disabled=!state.enabled;notice(error.message,true);}
});
function shortStage(raw){
  const stage=String(raw||'').toUpperCase();
  if(/INSPECT_LOCAL_ENGINE_LOG|CHECK_LOCAL_ENGINE_LOG|BLOCKED/.test(stage))return {at:0,label:'Phân tích chưa hoàn tất; kiểm tra thông tin lỗi'};
  if(/REPORT|FUSION|SCORE|EXPORT|PACK/.test(stage))return {at:5,label:'Đang tổng hợp cảnh báo và tạo báo cáo'};
  if(/POLICY|QUALIF|GUARD/.test(stage))return {at:4,label:'Đang đối chiếu bằng chứng và điều kiện bảo vệ'};
  if(/MODEL|GPU|NATIVE|INFER/.test(stage))return {at:3,label:'Đang phân tích API bằng mô hình AI cục bộ'};
  if(/CODEQL|IRIS|CANDIDATE/.test(stage))return {at:2,label:'Đang xác định ngữ nghĩa API và luồng dữ liệu'};
  if(/OPENGREP/.test(stage))return {at:1,label:'Đang phát hiện cảnh báo bằng OpenGrep'};
  return {at:0,label:'Đang chuẩn bị dữ liệu đầu vào'};
}
async function pollJobs(){
  if(!state.connected||state.pollBusy)return;
  state.pollBusy=true;
  try{
    const jobs=await api('/api/jobs');
    const current=state.jobId?jobs.find(j=>j.id===state.jobId):jobs.find(j=>['STARTING','RUNNING','STOPPING'].includes(j.status));
    const box=$('job-card');
    if(!current){$('run-scan').disabled=!state.enabled;return;}
    state.jobId=current.id;
    const status=current.status;
    const stage=shortStage(current.stage);
    const title=status==='COMPLETE'?'Đã hoàn tất phân tích':status==='BLOCKED'?'Phân tích chưa hoàn tất':
      status==='STOPPING'?'Đang yêu cầu dừng':status==='INTERRUPTED_UNCONFIRMED'?'Phân tích bị gián đoạn':'Đang phân tích mã nguồn';
    box.replaceChildren(el('strong','job-title',title),el('p','',status==='COMPLETE'?
      `${current.project||'Dự án Java'} đã có báo cáo.${current.imported_prior_cli?' Đây là kết quả đã phân tích trước.':''}`:
      status==='BLOCKED'?`Không hoàn tất · ${number(current.elapsed_s||0)} giây`:
      `${stage.label} · ${number(current.elapsed_s||0)} giây`));
    if(['STARTING','RUNNING','STOPPING'].includes(status)){
      stageMark(stage.at);$('run-scan').disabled=true;
      const stop=el('button','btn small secondary','Yêu cầu dừng phân tích');stop.type='button';
      stop.addEventListener('click',async()=>{
        if(!confirm('Gửi yêu cầu dừng phân tích đang chạy?'))return;
        try{await api('/api/jobs/'+current.id+'/stop',{method:'POST',headers:{'X-NTK-CSRF':csrf}});notice('Đã gửi yêu cầu dừng; đang chờ engine xác nhận.');}
        catch(err){notice(err.message,true);}
      });box.append(stop);
    }else{
      $('run-scan').disabled=!state.enabled;
      if(status==='COMPLETE'){
        stageMark(5,true);
        if(state.lastJobStatus!=='COMPLETE'&&current.run_id){
          notice('Phân tích hoàn tất. Báo cáo đã sẵn sàng.');
          await refreshRuns(current.run_id);
        }
      }else if(status==='BLOCKED'||status==='INTERRUPTED_UNCONFIRMED'||status==='STOP_UNCONFIRMED'){
        stageReset();box.append(el('p','fine-print','Không có báo cáo thành công từ lần chạy này. '+
          (current.error?'Chi tiết: '+current.error:'Kiểm tra log cục bộ để xác định nguyên nhân.')));
        if(state.lastJobStatus!==status)notice('Quá trình phân tích chưa hoàn tất. Không tạo kết quả thay thế.',true);
      }
    }
    state.lastJobStatus=status;
  }catch(e){notice('Không thể cập nhật tiến trình: '+e.message,true);}finally{state.pollBusy=false;}
}
async function refreshRuns(selected=null){
  if(!state.connected)return;
  const runs=await api('/api/runs');const dropdown=$('run-select');
  const prev=selected||state.selectedRun;
  dropdown.replaceChildren();
  if(!runs.length){resetReports();return;}
  for(const [i,r] of runs.entries()){
    const type=r.mode==='fast'?' · Quét nhanh':' · Chuyên sâu';
    const origin=r.imported_prior_cli?' · Đã phân tích trước':'';
    const o=el('option','',(r.project||`Dự án ${runs.length-i}`)+type+origin);
    o.value=r.run_id;dropdown.append(o);
  }
  $('run-status').textContent=`${runs.length} dự án đã phân tích`;
  const found=runs.find(r=>r.run_id===prev)||runs[0];
  dropdown.value=found.run_id;
  await selectRun(found.run_id);
}
$('refresh-runs').addEventListener('click',()=>refreshRuns().catch(e=>notice(e.message,true)));
$('run-select').addEventListener('change',e=>selectRun(e.target.value).catch(x=>notice(x.message,true)));
async function selectRun(rid){
  if(!rid)return;
  state.selectedRun=rid;
  const detail=await api('/api/runs/'+rid);
  state.runOverview=detail;
  const activeArms=Object.keys(detail.comparison?.arms||{});
  const isFast=detail.mode?.startsWith('FAST_');
  $('run-summary').replaceChildren(
    metric(number(detail.summary?.raw_opengrep_findings??0),'Cảnh báo OpenGrep'),
    metric(number(detail.summary?.elapsed_s??0)+' giây','Thời gian phân tích thực'),
    metric(String(activeArms.length),'Nhánh có kết quả'),
    metric((detail.summary?.input_sha256||'—').slice(0,20)+'…','Mã nhận dạng đầu vào',true));
  if(isFast){
    const profile=detail.profile_discovery||{};
    const no=profile.no_candidates_cwes||[];
    $('run-summary').append(el('p','fine-print',
      'Quét nhanh Epoch 1 · '+(no.length?'Không có API candidates trong phạm vi: '+no.map(x=>'CWE-'+x).join(', ')+'.':'Có ứng viên trong cả bốn nhóm CWE.')+
      ' Không phát hiện ứng viên không đồng nghĩa mã nguồn an toàn.'));
  }
  const armSelector=$('finding-arm'),previous=armSelector.value;armSelector.replaceChildren();
  for(const key of ['epoch_1','epoch_2','base','opengrep_only'])if(activeArms.includes(key)){
    const option=el('option','',arms[key]);option.value=key;armSelector.append(option);
  }
  armSelector.value=activeArms.includes(previous)?previous:activeArms.includes('epoch_1')?'epoch_1':activeArms[0]||'opengrep_only';
  const tbody=$('arms-comparison');tbody.replaceChildren();
  for(const [key,label] of Object.entries(arms)){
    const result=detail.comparison?.arms?.[key];if(!result)continue;
    const m=['22','78','89'].reduce((acc,c)=>acc+(result.evidence_by_cwe?.[c]?.qualified_paths||0),0);
    const p=result.evidence_by_cwe?.['79']?.qualified_paths||0;
    const native=detail.native?.[key];const tr=el('tr');
    [label,result.retained_opengrep,native?native.accepted+' / '+native.abstain:'Không áp dụng',m,p].forEach(v=>tr.append(el('td','',v)));
    tbody.append(tr);
  }
  const downloads=$('run-downloads');downloads.replaceChildren();
  addDownload(downloads,'/api/runs/'+rid+'/evidence.zip','Báo cáo kiểm tra tính toàn vẹn');
  await loadArm();
}
$('finding-arm').addEventListener('change',()=>loadArm().catch(e=>notice(e.message,true)));
$('finding-cwe').addEventListener('change',renderFindings);
$('finding-evidence').addEventListener('change',renderFindings);
async function loadArm(){
  if(!state.selectedRun)return;
  const arm=$('finding-arm').value;
  const report=await api('/api/runs/'+state.selectedRun+'/'+arm);
  state.rows=Array.isArray(report.findings)?report.findings:[];
  const dl=$('arm-downloads');dl.replaceChildren();
  addDownload(dl,'/api/runs/'+state.selectedRun+'/'+arm+'/result.json','Xuất JSON');
  addDownload(dl,'/api/runs/'+state.selectedRun+'/'+arm+'/report.sarif','Xuất SARIF');
  updateProjectScore();renderFindings();
}
function originOf(r){const s=String(r.evidence_origin||'').toUpperCase();return s.includes('POLICY')?'policy':s.includes('MODEL')?'model':'other';}
function evidenceName(r){
  const c=originOf(r),path=Array.isArray(r.dataflow)&&r.dataflow.length>0;
  if(c==='model')return path?'Luồng dữ liệu được AI hỗ trợ':'Thông tin từ AI · cần rà soát';
  if(c==='policy')return path?'Đối chiếu theo chính sách':'XSS · cần kiểm tra ngữ cảnh';
  return 'Cảnh báo phân tích tĩnh';
}
function riskLabel(r){return bands[String(r.score?.risk_level||'').toUpperCase()]?.[0]||'Cần rà soát';}
function riskText(r){return bands[String(r.score?.risk_level||'').toUpperCase()]?.[1]||'Cần kiểm tra ngữ cảnh mã nguồn để xác định mức ưu tiên xử lý.';}
function updateProjectScore(){
  const target=$('score-overview');
  if(!state.rows.length){empty(target,'Không có cảnh báo được báo cáo ở phương án phân tích đã chọn. Không thể từ đó kết luận dự án không có lỗ hổng.');
    $('score-explainer').replaceChildren(el('strong','','Chưa có điểm từ phương án này'),el('p','','Không được coi là bằng chứng mã an toàn.'));return;}
  const top=[...state.rows].sort((a,b)=>(b.score?.final_score||0)-(a.score?.final_score||0))[0];
  const box=el('div','project-score-grid');
  box.append(metric(number(top.score?.final_score)+'/100','Điểm ưu tiên cao nhất'),metric(riskLabel(top),'Mức ưu tiên tương ứng'),
    metric(state.rows.length+'','Cảnh báo cần xem xét'));
  const distribution={};
  for(const r of state.rows){const key=String(r.score?.risk_level||'OTHER').toUpperCase();distribution[key]=(distribution[key]||0)+1;}
  const summary=Object.entries(distribution).map(([level,count])=>`${count} ${bands[level]?.[0]?.toLowerCase()||'cần rà soát'}`).join(' · ');
  target.replaceChildren(box,el('p','score-meaning',riskText(top)),
    el('p','fine-print','Phân bố cảnh báo: '+summary+'. Đây là điểm của cảnh báo được ưu tiên cao nhất, KHÔNG phải điểm an toàn của toàn bộ dự án hoặc xác suất tồn tại lỗ hổng.'));
  $('score-explainer').replaceChildren(el('strong','',number(top.score?.final_score)+'/100 — '+riskLabel(top)),
    el('p','',riskText(top)));
}
function renderFindings(){
  const cwe=$('finding-cwe').value, source=$('finding-evidence').value;
  const result=state.rows.filter(r=>(cwe==='all'||r.cwe===cwe)&&(source==='all'||originOf(r)===source))
    .sort((a,b)=>(b.score?.final_score||0)-(a.score?.final_score||0)||String(a.id).localeCompare(String(b.id)));
  $('findings-total').textContent=`${result.length} / ${state.rows.length} cảnh báo`;
  const list=$('findings-list');list.replaceChildren();
  if(!result.length){empty(list,'Không có cảnh báo phù hợp với bộ lọc. Kết quả này không chứng minh mã nguồn an toàn.');
    empty($('inspect'),'Chọn cảnh báo khác để xem chi tiết.');return;}
  result.forEach((r,index)=>{
    const btn=el('button','finding-item');btn.type='button';
    const first=el('div','finding-first');first.append(el('span','finding-id',`CWE-${r.cwe} · ${cwes[r.cwe]||'Cảnh báo Java'}`),
      el('span','finding-score',number(r.score?.final_score)+'/100'));
    const origin=el('div','finding-meta');origin.append(el('span','finding-tag'+(originOf(r)==='policy'?' policy':''),evidenceName(r)),
      el('span','finding-tag',riskLabel(r)));
    btn.append(first,el('div','finding-location',(r.location?.uri||'Tệp không xác định')+':'+(r.location?.start_line||'?')),origin);
    btn.addEventListener('click',()=>{list.querySelectorAll('.finding-item').forEach(x=>x.classList.remove('active'));btn.classList.add('active');inspectFinding(r);});
    list.append(btn);
    if(index===0){btn.classList.add('active');inspectFinding(r);}
  });
}
function pair(dl,title,value){dl.append(el('dt','',title),el('dd','',value===undefined||value===null||value===''?'—':String(value)));}
function detailSection(title){const node_=el('div','inspect-block');node_.append(el('div','inspect-title',title));return node_;}
function inspectFinding(r){
  const target=$('inspect');target.replaceChildren();
  const score=detailSection('MỨC ƯU TIÊN XỬ LÝ');
  score.append(el('h3','',`CWE-${r.cwe} · ${cwes[r.cwe]||'Cảnh báo bảo mật'}`));
  const scoreDisplay=el('div','score-display');scoreDisplay.append(el('strong','',number(r.score?.final_score)+'/100'),
    el('span','',riskLabel(r)));score.append(scoreDisplay);
  score.append(el('p','score-meaning',riskText(r)));
  score.append(el('p','fine-print','Điểm được tính từ các tín hiệu đã đánh giá và quy tắc điều chỉnh bảo thủ; không phải xác suất lỗ hổng. Trạng thái: chưa được xác nhận thủ công.'));
  target.append(score);
  const detail=detailSection('THÔNG TIN CẢNH BÁO');const dl=el('dl','inspect-pairs');
  pair(dl,'Vị trí',`${r.location?.uri||'—'}:${r.location?.start_line||'?'}`);
  pair(dl,'Phương thức phát hiện',evidenceName(r));
  pair(dl,'Trạng thái bằng chứng',r.evidence_status||'Cần xác minh');
  pair(dl,'Quy tắc phân tích',r.rule_id||'—');
  detail.append(dl);target.append(detail);
  const factors=detailSection('TẠI SAO CẢNH BÁO CÓ ĐIỂM NÀY?');
  factors.append(el('p','fine-print','Các thông tin bên dưới là thành phần đầu vào do hệ thống trả về; tổng điểm đã bao gồm chính sách và điều chỉnh, không đơn thuần cộng tuyến tính các tỷ lệ.'));
  const values=el('dl','inspect-pairs');const s=r.score||{};
  const keys=[['effective_severity','Mức ảnh hưởng đã điều chỉnh'],['ai_confidence_score','Tín hiệu từ mô hình'],
    ['exploitability','Khả năng khai thác / luồng dữ liệu'],['exploitability_score','Khả năng khai thác / luồng dữ liệu'],
    ['rule_precision_score','Độ chính xác quy tắc'],['rule_precision','Độ chính xác quy tắc'],
    ['penalty_factor','Hệ số giảm điểm thận trọng'],['safety_floor_applied','Áp dụng giới hạn an toàn']];
  const seen=new Set();
  for(const [key,label] of keys){if(!(key in s)||seen.has(label))continue;seen.add(label);pair(values,label,typeof s[key]==='number'?number(s[key]):String(s[key]));}
  if(!seen.size)pair(values,'Thông tin','Các thành phần kỹ thuật được lưu trong báo cáo JSON.');
  factors.append(values);target.append(factors);
  const apiPart=detailSection('API VÀ KẾT QUẢ PHÂN TÍCH AI');
  const apis=el('dl','inspect-pairs');const m=r.model||{},call=r.callsite||{};
  pair(apis,'Lớp / thư viện',`${call.package||''}${call.package?'.':''}${call.class||'—'}`);
  pair(apis,'Phương thức',call.method||'—');pair(apis,'Khai báo hàm',call.compiler_signature||call.signature||'—');
  pair(apis,'Kết quả mô hình',m.status==='ACCEPTED'?'Định dạng phản hồi hợp lệ (không đảm bảo chính xác)':m.status||'Chưa áp dụng');
  pair(apis,'Vai trò API',m.role||'Chưa xác định');
  if(m.reason)pair(apis,'Ghi chú mô hình',m.reason);
  apiPart.append(apis);target.append(apiPart);
  const flow=detailSection('ĐƯỜNG TRUYỀN DỮ LIỆU');
  if(Array.isArray(r.dataflow)&&r.dataflow.length){
    const lines=r.dataflow.map((p,i)=>`${i+1}. ${p.type||'Bước'} · ${p.uri||'—'}:${p.start_line||'?'}`);
    flow.append(el('pre','codepath',lines.join('\n')));
  }else flow.append(el('p','fine-print','Chưa có đường truyền dữ liệu đáp ứng điều kiện hiện tại. Không thể kết luận mã nguồn an toàn.'));
  if(r.cwe==='79')flow.append(el('p','policy-explain','Cảnh báo XSS sử dụng phân tích ngữ cảnh HTML/HTTP theo chính sách đã công bố; không coi đây là sink do LoRA học được.'));
  target.append(flow);
}
function clearUi(){
  state.activeProject='';state.jobId=null;state.lastJobStatus=null;
  $('project-zip').value='';$('file-label').textContent='Chọn tệp ZIP hoặc kéo thả vào đây';$('scan-consent').checked=false;
  stageReset();$('job-card').replaceChildren(el('strong','job-title','Sẵn sàng phân tích dự án'),
    el('p','','Chọn tệp ZIP Java để bắt đầu lượt quét mới.'));
  resetReports();
  $('finding-arm').value='epoch_1';$('finding-cwe').value='all';$('finding-evidence').value='all';
}
for(const button of document.querySelectorAll('[data-clear-session]')){
  button.addEventListener('click',async()=>{
    if(!confirm('Xóa lịch sử và kết quả đang hiển thị trên giao diện này? Tác vụ đang chạy không thể xóa. Bằng chứng kỹ thuật gốc sẽ được giữ nguyên.'))return;
    try{
      await api('/api/session/clear',{method:'POST',headers:{'X-NTK-CSRF':csrf,'Content-Type':'application/json'},
        body:JSON.stringify({confirm:'HIDE_LOCAL_UI_SCAN_HISTORY'})});
      clearUi();notice('Đã làm sạch kết quả và lịch sử trên giao diện. Không xóa dữ liệu nghiên cứu gốc.');
    }catch(e){notice(e.message,true);}
  });
}
// Training data is served from the original local filesystem when it can be identified.
// An optional user-selected file is visually distinguished from pinned training data.
async function loadDatasetCatalog(){
  try{
    const sources=await api('/api/dataset/info');state.datasetInfo=sources;
    await ensureDataset(state.activeSplit);
  }catch(error){notice('Không thể xem nguồn dữ liệu huấn luyện: '+error.message,true);renderDataset();}
}
async function ensureDataset(split){
  if(state.datasets[split]){renderDataset();return;}
  const item=state.datasetInfo[split];
  if(item?.available){
    try{
      const data=await api('/api/dataset/'+split);
      state.datasets[split]={...data, origin:'original'};
    }catch(err){notice('Chưa tải được bộ dữ liệu '+split+': '+err.message,true);}
  }
  renderDataset();
}
const datasetTabs=[...document.querySelectorAll('.tab')];
datasetTabs.forEach(t=>t.addEventListener('click',async()=>{
  state.activeSplit=t.dataset.split;state.datasetPage=0;
  datasetTabs.forEach(x=>x.classList.toggle('active',x===t));
  await ensureDataset(state.activeSplit);
}));
$('dataset-file').addEventListener('change',async()=>{
  const file=$('dataset-file').files[0];if(!file)return;
  const fmt=file.name.split('.').pop().toLowerCase();
  if(!['jsonl','csv','tsv','xlsx'].includes(fmt))return notice('Định dạng tệp chưa được hỗ trợ.',true);
  if(file.size>16*1024*1024)return notice('Tệp vượt giới hạn 16 MiB.',true);
  const split=state.activeSplit;
  try{
    const data=await api('/api/dataset/parse',{method:'POST',headers:{'X-NTK-CSRF':csrf,
      'X-NTK-Format':fmt,'Content-Type':'application/octet-stream'},body:file});
    state.datasets[split]={...data, filename:file.name,origin:'manual'};state.datasetPage=0;
    notice('Đã mở '+data.count+' mẫu từ tệp đã chọn.');renderDataset();
  }catch(err){notice(err.message,true);}finally{$('dataset-file').value='';}
});
$('dataset-search').addEventListener('input',()=>{state.datasetPage=0;renderDataset();});
function filteredRows(d){
  const query=$('dataset-search').value.trim().toLowerCase();
  return query?d.rows.filter(r=>r.some(v=>String(v??'').toLowerCase().includes(query))):d.rows;
}
function renderDataset(){
  const d=state.datasets[state.activeSplit];const table=$('dataset-table');
  const count=$('dataset-count');const provenance=$('dataset-provenance');
  $('export-xlsx').disabled=!d;
  if(!d){
    table.replaceChildren();const head=el('thead'),tr=el('tr');tr.append(el('th','row-num','#'),el('th','','Chưa thể mở dữ liệu'));head.append(tr);
    const body=el('tbody'),r=el('tr');
    const msg=state.datasetInfo[state.activeSplit]?.message||'Chưa tìm thấy bộ dữ liệu gốc trên máy.';
    r.append(el('td','row-num','1'),el('td','',msg+' Bạn có thể chọn tệp dữ liệu đã dùng để huấn luyện.'));
    body.append(r);table.append(head,body);
    $('dataset-status').textContent='Chưa kết nối được tệp gốc';
    provenance.textContent='Không tạo mẫu thay thế khi thiếu tệp gốc.';
    count.textContent='0 bản ghi';$('dataset-page').textContent='Trang 1/1';
    $('data-prev').disabled=true;$('data-next').disabled=true;return;
  }
  const subset=filteredRows(d);const maxPage=Math.max(1,Math.ceil(subset.length/25));
  state.datasetPage=Math.min(state.datasetPage,maxPage-1);
  const offset=state.datasetPage*25;
  table.replaceChildren();const header=el('thead'),headrow=el('tr');headrow.append(el('th','row-num','#'));
  d.columns.forEach(x=>headrow.append(el('th','',x)));header.append(headrow);table.append(header);
  const body=el('tbody');
  subset.slice(offset,offset+25).forEach((row,i)=>{
    const tr=el('tr');tr.append(el('td','row-num',String(offset+i+1)));
    row.forEach(cell=>{const text=String(cell??'');const td=el('td','dataset-cell',text);td.title='Bấm để xem đầy đủ';
      td.addEventListener('click',()=>openCell(text));tr.append(td);});
    body.append(tr);
  });
  if(!body.childNodes.length){const tr=el('tr'),td=el('td','placeholder-cell','Không có bản ghi phù hợp.');td.colSpan=d.columns.length+1;tr.append(td);body.append(tr);}
  table.append(body);
  count.textContent=`${subset.length} / ${d.count} bản ghi`;
  $('dataset-status').textContent=d.origin==='original'?`Đã nạp ${d.count} mẫu đã sử dụng để huấn luyện`:`Đã mở ${d.count} bản ghi từ tệp được chọn`;
  provenance.textContent=d.origin==='original'?`Nguồn: dữ liệu huấn luyện trên máy · SHA-256: ${d.sha256}`:
    'Nguồn: tệp do người sử dụng chọn · chưa đối chiếu với bản dữ liệu huấn luyện đã khóa';
  $('dataset-page').textContent=`Trang ${state.datasetPage+1}/${maxPage}`;
  $('data-prev').disabled=state.datasetPage===0;$('data-next').disabled=state.datasetPage>=maxPage-1;
}
function openCell(content){
  const dlg=$('cell-dialog');if(!dlg){notice(content.slice(0,300));return;}
  $('cell-content').textContent=content;
  dlg.showModal();
}
$('close-cell').addEventListener('click',()=>$('cell-dialog').close());
$('data-prev').addEventListener('click',()=>{if(state.datasetPage>0){state.datasetPage--;renderDataset();}});
$('data-next').addEventListener('click',()=>{state.datasetPage++;renderDataset();});
$('export-xlsx').addEventListener('click',async()=>{
  const d=state.datasets[state.activeSplit];if(!d)return;
  try{
    const r=await fetch('/api/dataset/export',{method:'POST',headers:{'X-NTK-CSRF':csrf,
      'Content-Type':'application/json'},body:JSON.stringify({columns:d.columns,rows:d.rows,
      sheet:state.activeSplit==='train'?'Training':'Validation'})});
    if(!r.ok){const err=await r.json();throw Error(err.error||'Xuất file thất bại.');}
    const url=URL.createObjectURL(await r.blob());const a=el('a');
    a.href=url;a.download=state.activeSplit==='train'?'NTK_training_dataset.xlsx':'NTK_validation_dataset.xlsx';
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),3000);
    notice('Đã tạo file Excel chứa '+d.count+' bản ghi.');
  }catch(e){notice(e.message,true);}
});
$('present-btn').addEventListener('click',()=>{
  document.body.classList.toggle('presentation');
  $('present-btn').textContent=document.body.classList.contains('presentation')?'Thoát chế độ tập trung':'Chế độ tập trung';
});
const nav=[...document.querySelectorAll('.nav a')];
nav.forEach(a=>a.addEventListener('click',()=>nav.forEach(x=>x.classList.toggle('active',x===a))));
if('IntersectionObserver' in window){
  const observer=new IntersectionObserver(entries=>{for(const e of entries){if(!e.isIntersecting)continue;
    nav.forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#'+e.target.id));}
  },{rootMargin:'-15% 0px -65% 0px'});
  document.querySelectorAll('main section[id]').forEach(s=>observer.observe(s));
}
(async()=>{
  resetReports();renderDataset();
  try{if(await checkBackend()){await refreshRuns();await pollJobs();}}
  catch(err){notice('Không thể kết nối bộ phân tích: '+err.message,true);}
  await loadDatasetCatalog();
  setInterval(async()=>{
    try{if(!state.connected){if(await checkBackend())await refreshRuns();}
      if(state.connected)await pollJobs();
    }catch(err){/* Preserve UI and do not fabricate any scan status when offline. */}
  },3500);
})();
