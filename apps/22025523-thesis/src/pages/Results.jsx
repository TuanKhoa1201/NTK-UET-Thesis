import {useCallback,useEffect,useMemo,useState} from 'react';
import {Link,useLocation,useSearchParams} from 'react-router-dom';
import {Card,PageHeader,StatCard,Badge,SectionTitle,DataNotice,EmptyState,BarRow,Icon} from '../components/common/Ui';
import {demoFindings} from '../data/research';
import {useScanSelection,scanQuery,ACTIVE_KEY} from '../services/liveScan';
import {api} from '../services/api';
import {normalizeFinding} from '../services/scanData';
import {LiveGate,LiveResultsBody} from './LiveResults';

const PAGE_SIZE=50;
const num=(value)=> (value===undefined || value===null || value==='' || !Number.isFinite(Number(value)) ? null : Number(value));
const fmt=(value)=> (value===null ? '—' : value.toLocaleString());
const toneOf=(decision)=> (decision==='REPORT' ? 'red' : decision==='REVIEW' ? 'amber' : decision==='SUPPRESS' ? 'green' : 'neutral');

function useActiveScanId() {
  const [params]=useSearchParams();
  return params.get('scan_id') || window.sessionStorage.getItem(ACTIVE_KEY) || '';
}

function useRemote(load,deps) {
  const [state,setState]=useState({status:'loading',data:null,error:''});
  const [attempt,setAttempt]=useState(0);
  useEffect(()=> {
    const controller=new AbortController();
    setState({status:'loading',data:null,error:''});
    load(controller.signal)
      .then((data)=> setState({status:'success',data,error:''}))
      .catch((error)=> {
        if (!controller.signal.aborted) setState({status:'error',data:null,error:error?.message || 'Không thể tải dữ liệu từ backend.'});
      });
    return ()=> controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[...deps,attempt]);
  const retry=useCallback(()=> setAttempt((value)=> value+1),[]);
  return [state,retry];
}

function SummaryStats({scanId,summary,pageData}) {
  const total=num(pageData?.total_count ?? summary?.total_count ?? summary?.total_findings);
  const matching=num(pageData?.total_matching);
  const by=summary?.triage_totals || summary?.decision_counts || summary?.triage_counts || summary || {};
  const pick=(key)=> num(by[`${key.toLowerCase()}_count`] ?? by[key] ?? by[key.toLowerCase()]);
  return (
    <div className="stats-grid">
      <StatCard label="Tổng findings (total_count)" value={fmt(total)} note={`LIVE · ${scanId}`} icon="Bug" />
      <StatCard label="Khớp bộ lọc (total_matching)" value={fmt(matching)} note="Theo API phân trang" icon="Filter" tone="blue" />
      <StatCard label="REPORT" value={fmt(pick('REPORT'))} note="Từ summary backend" icon="ShieldAlert" tone="amber" />
      <StatCard label="REVIEW / SUPPRESS" value={`${fmt(pick('REVIEW'))} / ${fmt(pick('SUPPRESS'))}`} note="Từ summary backend" icon="Eye" tone="green" />
    </div>
  );
}

function LiveFindings({scanId}) {
  const [page,setPage]=useState(1);
  const [summaryState,retrySummary]=useRemote((signal)=> api.scanSummary(scanId,{signal}),[scanId]);
  const [pageState,retryPage]=useRemote((signal)=> api.findingsPage(scanId,page,PAGE_SIZE,{signal}),[scanId,page]);
  useEffect(()=> { setPage(1); },[scanId]);
  const pageData=pageState.data;
  const rows=useMemo(()=> {
    const list=pageData?.findings ?? pageData?.items ?? pageData?.results ?? [];
    return Array.isArray(list) ? list.map((item)=> ({...normalizeFinding(item),detailUrl:item?.detail_url})) : [];
  },[pageData]);
  const totalMatching=num(pageData?.total_matching);
  const totalPages=num(pageData?.total_pages) ?? (totalMatching!==null ? Math.max(1,Math.ceil(totalMatching/PAGE_SIZE)) : null);
  const hasNext=totalPages!==null ? page<totalPages : rows.length===PAGE_SIZE;
  return (
    <>
      <PageHeader eyebrow="PHIÊN PHÂN TÍCH" title="Kết quả phát hiện" description={`Scan LIVE: ${scanId}`} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />
      <DataNotice>Dữ liệu LIVE theo trang từ backend (page_size={PAGE_SIZE}). Heuristic score không phải xác suất đã hiệu chuẩn; REPORT chưa đồng nghĩa chuyên gia đã xác nhận.</DataNotice>
      {summaryState.status==='error' && <DataNotice>Không tải được summary (không chặn danh sách): {summaryState.error} <button className="button-secondary" onClick={retrySummary}>Thử lại</button></DataNotice>}
      <SummaryStats scanId={scanId} summary={summaryState.data} pageData={pageData} />
      <section className="section-block">
        <SectionTitle title="Danh sách findings" text="Evidence đầy đủ chỉ được tải khi mở chi tiết một finding." />
        <Card className="table-card">
          {pageState.status==='loading' && <DataNotice>Đang tải trang {page} từ backend…</DataNotice>}
          {pageState.status==='error' && <EmptyState title="Không tải được findings" text={pageState.error} icon="AlertTriangle" />}
          {pageState.status==='error' && <button className="button-secondary" onClick={retryPage}>Thử lại</button>}
          {pageState.status==='success' && !rows.length && <EmptyState title="Scan không có finding" text="Backend trả về 0 findings cho scan này. Điều này không có nghĩa ứng dụng an toàn." />}
          {pageState.status==='success' && rows.length>0 && (
            <div className="table-wrap"><table><thead><tr><th>Finding</th><th>CWE</th><th>File · line</th><th>Severity</th><th>Heuristic score</th><th>Triage</th><th></th></tr></thead><tbody>
              {rows.map((row)=> <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe||'—'}</Badge></td><td className="mono" title={row.file}>{String(row.file).split('/').slice(-1)}:{row.line}</td><td>{row.severity||'—'}</td><td className="mono">{row.score===null ? '—' : row.score.toFixed(2)}</td><td><Badge tone={toneOf(row.decision)}>{row.decision||'—'}</Badge></td><td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`} state={{detailUrl:row.detailUrl}}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>)}
            </tbody></table></div>
          )}
          <div className="table-toolbar">
            <button className="button-secondary" disabled={page<=1 || pageState.status==='loading'} onClick={()=> setPage((value)=> Math.max(1,value-1))}>Trước</button>
            <span>Trang {page}{totalPages!==null ? ` / ${totalPages}` : ''}</span>
            <button className="button-secondary" disabled={!hasNext || pageState.status==='loading'} onClick={()=> setPage((value)=> value+1)}>Sau</button>
          </div>
        </Card>
      </section>
    </>
  );
}

function LiveDetailPage({scanId,id,detailUrl}) {
  const [state,retry]=useRemote((signal)=> api.findingDetail(scanId,id,detailUrl,{signal}),[scanId,id]);
  const row=state.data ? normalizeFinding(state.data.finding && typeof state.data.finding==='object' ? {...state.data.finding,...state.data} : state.data) : null;
  const back=`/findings${scanQuery(scanId)}`;
  return (
    <>
      <PageHeader eyebrow={`FINDING · ${id}`} title={row?.title || id} description={`Scan ${scanId}`} actions={<Link to={back} className="button-secondary">Danh sách</Link>} />
      {state.status==='loading' && <DataNotice>Đang tải evidence của finding…</DataNotice>}
      {state.status==='error' && <><EmptyState title="Không tải được chi tiết finding" text={state.error} icon="AlertTriangle" /><button className="button-secondary" onClick={retry}>Thử lại</button></>}
      {row && <>
        <div className="finding-summary">
          <StatCard label="Severity" value={row.severity || '—'} note="Từ backend" icon="ShieldAlert" tone="amber" />
          <StatCard label="Heuristic score" value={row.score===null ? '—' : row.score.toFixed(2)} note="Không phải xác suất" icon="Gauge" />
          <StatCard label="Triage" value={row.decision || '—'} note="Chưa có xác nhận chuyên gia" icon="ScanEye" tone="violet" />
        </div>
        <Card title="Bản ghi backend nguyên bản"><pre><code>{JSON.stringify(state.data,null,2)}</code></pre></Card>
      </>}
    </>
  );
}

export function Results() {
  const scanId=useActiveScanId();
  if (scanId) return <LiveFindings scanId={scanId} />;
  return <LegacyResults />;
}

function LegacyResults() {
  const sel=useScanSelection();
  if (sel.mode==='live') {
    return <LiveGate sel={sel} title="Kết quả phát hiện">{(data)=> <LiveResultsBody data={data} table={<FindingsTable rows={data.rows} scanId={data.scanId} />} />}</LiveGate>;
  }
  const demo=sel.mode==='demo';
  const rows=demo ? demoFindings : [];
  const severity=['Critical','High','Medium','Low','Informational'];
  return (
    <>
      <PageHeader eyebrow="PHIЁN PHÂN TÍCH" title={demo ? 'Kết quả minh họa' : 'Kết quả phát hiện'} description={demo ? 'Bộ dữ liệu synthetic dùng để minh họa cách trình bày; không phải kết quả quét thực tế.' : 'Chưa có scan LIVE được nạp trong phiên này.'} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />
      {demo && <DataNotice>Dữ liệu mô phỏng — không phải kết quả quét thực tế. Các findings bên dưới chỉ minh họa giao diện, không xuất phát từ backend.</DataNotice>}
      {!demo ? <EmptyState title="Chưa có kết quả scan" text="Bắt đầu phân tích hoặc mở scan LIVE bằng scan_id từ backend." icon="ScanSearch" /> : <>
        <div className="stats-grid">
          <StatCard label="Candidate findings" value={rows.length} note="Synthetic demo" icon="Bug" />
          <StatCard label="REPORT" value="1" note="Ưu tiên kiểm tra" icon="ShieldAlert" tone="amber" />
          <StatCard label="REVIEW" value="2" note="Cần xem xét" icon="Eye" tone="blue" />
          <StatCard label="SUPPRESS" value="1" note="Giữ trong audit trail" icon="ShieldCheck" tone="green" />
        </div>
        <section className="section-block">
          <SectionTitle title="Tổng quan phân bố" text="Các biểu đồ dựa trên bộ findings minh họa ở trang này." />
          <div className="results-grid">
            <Card title="Findings by severity">{severity.map((level)=> <BarRow key={level} label={level} value={rows.filter((row)=> row.severity===level).length} max={4} color={level==='High' ? 'red' : level==='Medium' ? 'amber' : 'blue'} />)}</Card>
            <Card title="Phân bố CWE">{['CWE-022','CWE-078','CWE-079','CWE-089'].map((cwe)=> <BarRow key={cwe} label={cwe} value={rows.filter((row)=> row.cwe===cwe).length} max={2} />)}</Card>
            <Card title="Alert triage"><div className="donut-wrap"><div className="donut-chart"><div><b>4</b><span>DEMO</span></div></div><div className="donut-legend"><span><i className="legend-red" />REPORT · 1</span><span><i className="legend-amber" />REVIEW · 2</span><span><i className="legend-green" />SUPPRESS · 1</span></div></div></Card>
          </div>
        </section>
        <FindingsTable rows={rows} />
      </>}
    </>
  );
}

export function FindingsTable({rows=demoFindings,scanId=''}) {
  const [query,setQuery]=useState('');
  const [decision,setDecision]=useState('Tất cả quyết định');
  const filtered=useMemo(()=> rows.filter((row)=> `${row.id} ${row.title} ${row.file} ${row.cwe}`.toLowerCase().includes(query.toLowerCase())).filter((row)=> decision==='Tất cả quyết định' || row.decision===decision),[rows,query,decision]);
  return (
    <section className="section-block">
      <SectionTitle title="Danh sách findings" text="Candidate finding cần được đọc cùng evidence, policy và trạng thái review." />
      <Card className="table-card">
        <div className="table-toolbar"><input placeholder="Tìm ID, CWE, file..." value={query} onChange={(event)=> setQuery(event.target.value)} /><select value={decision} onChange={(event)=> setDecision(event.target.value)}><option>Tất cả quyết định</option><option>REPORT</option><option>REVIEW</option><option>SUPPRESS</option></select></div>
        {filtered.length ? <div className="table-wrap"><table><thead><tr><th>Finding</th><th>CWE / loại vấn đề</th><th>File · line</th><th>Severity</th><th>Heuristic score</th><th>Triage</th><th></th></tr></thead><tbody>{filtered.map((row)=> <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe||'—'}</Badge><br />{row.title}</td><td className="mono">{String(row.file).split('/').slice(-1)}:{row.line}</td><td><Badge tone={row.severity==='High' ? 'red' : 'amber'}>{row.severity||'—'}</Badge></td><td className="mono">{row.score===null||row.score===undefined ? '—' : row.score.toFixed(2)}</td><td><Badge tone={toneOf(row.decision)}>{row.decision||'—'}</Badge></td><td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>)}</tbody></table></div> : <EmptyState title="Không tìm thấy finding" text="Thay đổi bộ lọc hoặc từ khóa tìm kiếm." />}
      </Card>
    </section>
  );
}

export function FindingDetail() {
  const scanId=useActiveScanId();
  const location=useLocation();
  const id=decodeURIComponent(window.location.hash.split('?')[0].split('/').pop());
  if (scanId) return <LiveDetailPage scanId={scanId} id={id} detailUrl={location.state?.detailUrl} />;
  return <DemoFindingDetail id={id} />;
}

function DemoFindingDetail({id}) {
  const finding=demoFindings.find((item)=> item.id===id);
  const [tab,setTab]=useState('OpenGrep');
  if (!finding) return <><PageHeader title="Chi tiết finding" description="Không có finding LIVE được nạp." /><EmptyState title="Không tìm thấy dữ liệu" text="Finding này chưa có trong dữ liệu demo hoặc backend chưa được kết nối." /></>;
  const tabs=['OpenGrep','IRIS','Language Model','Scoring','Decision'];
  return (
    <>
      <PageHeader eyebrow={`FINDING · ${finding.id}`} title={finding.title} description={`${finding.file}:${finding.line} · ${finding.cwe}`} actions={<Badge tone="amber">BẢN GHI MINH HỌA</Badge>} />
      <DataNotice>Finding synthetic minh họa — không phải kết quả phát hiện thực tế.</DataNotice>
      <div className="finding-summary"><StatCard label="Severity" value={finding.severity} note="Mức độ từ dữ liệu demo" icon="ShieldAlert" tone="amber" /><StatCard label="Heuristic score" value={finding.score.toFixed(2)} note="Không phải xác suất" icon="Gauge" /><StatCard label="Triage" value={finding.decision} note="Chưa có chuyên gia xác nhận" icon="ScanEye" tone="violet" /></div>
      <Card title="Evidence explorer">
        <div className="evidence-tabs">{tabs.map((item)=> <button className={tab===item ? 'active' : ''} key={item} onClick={()=> setTab(item)}>{item}</button>)}</div>
        <div className="evidence-panel"><h3>{tab}</h3><p>{tab==='OpenGrep' ? 'Rule match candidate và vị trí code trong dữ liệu synthetic.' : tab==='IRIS' ? 'Chưa có verified dataflow trace trong ví dụ này.' : tab==='Language Model' ? `API role minh họa: ${finding.role}. Đây không phải xác nhận lỗ hổng.` : tab==='Scoring' ? `Base score 0.70 cùng policy minh họa; score cuối ${finding.score.toFixed(2)}.` : finding.reason}</p></div>
      </Card>
      <section className="section-block"><SectionTitle title="Code context" text="Đoạn mã minh họa, không phải source code từ repository thật." /><Card className="code-card"><div className="code-header"><span className="mono">{finding.file}</span><Badge>JAVA · SAMPLE</Badge></div><pre><code>{` 81 public List<User> findUser(String input) {\n 82 String query="SELECT * FROM users WHERE name='" + input + "'";\n 83 // Candidate location for review\n 84 return statement.executeQuery(query);\n 85}`}</code></pre></Card></section>
    </>
  );
}