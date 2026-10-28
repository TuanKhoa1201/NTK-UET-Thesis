import {useCallback,useEffect,useMemo,useState} from 'react';
import {Link, useOutletContext, useSearchParams} from 'react-router-dom';
import {Card,PageHeader,SectionTitle,Badge,DataNotice,EmptyState,Icon} from '../components/common/Ui';
import UETLogo from '../components/common/UETLogo';
import {demoFindings} from '../data/research';
import {api} from '../services/api';
import {normalizeFinding} from '../services/scanData';
import {useScanSelection,scanQuery,evidenceText,ACTIVE_KEY} from '../services/liveScan';
import {LiveGate} from './LiveResults';

const REVIEW_PAGE_SIZE=50;
const toNum=(value)=> (value===undefined || value===null || value==='' || !Number.isFinite(Number(value)) ? null : Number(value));
const showNum=(value)=> (value===null ? '—' : value.toLocaleString());

function saveJson(name,payload) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
  const anchor=document.createElement('a');
  anchor.href=url;
  anchor.download=name;
  anchor.click();
  URL.revokeObjectURL(url);
}

function useReviewRemote(load,deps) {
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

function PagedReview({scanId}) {
  const [tab,setTab]=useState('REPORT');
  const [page,setPage]=useState(1);
  const [summaryState,retrySummary]=useReviewRemote((signal)=> api.scanSummary(scanId,{signal}),[scanId]);
  const [pageState,retryPage]=useReviewRemote((signal)=> api.findingsPage(scanId,page,REVIEW_PAGE_SIZE,{signal,decision:tab}),[scanId,tab,page]);
  useEffect(()=> { setPage(1); },[scanId,tab]);
  const totals=summaryState.data?.triage_totals || {};
  const globalCount=(key)=> toNum(totals[`${key.toLowerCase()}_count`]);
  const pageData=pageState.data;
  const rows=useMemo(()=> {
    const list=pageData?.findings ?? pageData?.items ?? pageData?.results ?? [];
    return Array.isArray(list) ? list.map((item)=> ({...normalizeFinding(item),detailUrl:item?.detail_url})) : [];
  },[pageData]);
  const matching=toNum(pageData?.total_matching);
  const totalPages=toNum(pageData?.total_pages) ?? (matching!==null ? Math.max(1,Math.ceil(matching/REVIEW_PAGE_SIZE)) : null);
  const hasNext=totalPages!==null ? page<totalPages : rows.length===REVIEW_PAGE_SIZE;
  const tone=tab==='REPORT' ? 'red' : tab==='REVIEW' ? 'amber' : 'green';
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Xác minh cảnh báo" description="Hàng đợi hỗ trợ analyst review. Không tự xác nhận findings trong giao diện." />
      <DataNotice>Số liệu tab lấy từ summary.triage_totals của scan {scanId}; danh sách được lọc phía server theo decision (page_size={REVIEW_PAGE_SIZE}). Trạng thái chuyên gia chỉ có thể thay đổi khi backend cung cấp reviewer workflow.</DataNotice>
      {summaryState.status==='error' && <DataNotice>Không tải được summary (không chặn danh sách): {summaryState.error} <button className="button-secondary" onClick={retrySummary}>Thử lại</button></DataNotice>}
      <div className="review-tabs">{['REPORT','REVIEW','SUPPRESS'].map((item)=> <button className={tab===item ? 'active' : ''} key={item} onClick={()=> setTab(item)}>{item}<span>{showNum(globalCount(item))}</span></button>)}</div>
      <Card className="review-list">
        {pageState.status==='loading' && <DataNotice>Đang tải {tab} trang {page} từ backend…</DataNotice>}
        {pageState.status==='error' && <EmptyState title="Không tải được danh sách" text={pageState.error} icon="AlertTriangle" />}
        {pageState.status==='error' && <button className="button-secondary" onClick={retryPage}>Thử lại</button>}
        {pageState.status==='success' && !rows.length && <EmptyState title={`Không có finding ${tab}`} text="Backend trả về 0 finding cho bộ lọc này." />}
        {pageState.status==='success' && rows.map((row)=> <div className="review-row" key={row.id}><div><Badge tone={tone}>{row.decision || tab}</Badge><h3>{row.title}</h3><p className="mono">{row.id} · {row.cwe} · {row.file}:{row.line}{row.score===null || row.score===undefined ? '' : ` · score ${row.score.toFixed(2)}`}</p><p>{evidenceText(row)}</p></div><Link to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`} state={{detailUrl:row.detailUrl}} className="button-secondary">Xem evidence <Icon name="ArrowRight" /></Link></div>)}
        <div className="table-toolbar">
          <button className="button-secondary" disabled={page<=1 || pageState.status==='loading'} onClick={()=> setPage((value)=> Math.max(1,value-1))}>Trước</button>
          <span>Trang {page}{totalPages!==null ? ` / ${totalPages}` : ''} · khớp bộ lọc: {showNum(matching)}</span>
          <button className="button-secondary" disabled={!hasNext || pageState.status==='loading'} onClick={()=> setPage((value)=> value+1)}>Sau</button>
        </div>
      </Card>
    </>
  );
}

function LiveReview({data}) {
  const [tab,setTab]=useState('REPORT');
  const rows=data.rows.filter((row)=> row.decision===tab);
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Xác minh cảnh báo" description="Hàng đợi hỗ trợ analyst review. Không tự xác nhận findings trong giao diện." />
      <DataNotice>Danh sách lấy từ backend cho scan {data.scanId}. Trạng thái chuyên gia chỉ có thể thay đổi khi backend cung cấp reviewer workflow.</DataNotice>
      <div className="review-tabs">{['REPORT','REVIEW','SUPPRESS'].map((item)=> <button className={tab===item ? 'active' : ''} key={item} onClick={()=> setTab(item)}>{item}<span>{data.rows.filter((row)=> row.decision===item).length}</span></button>)}</div>
      <Card className="review-list">{rows.map((row)=> <div className="review-row" key={row.id}><div><Badge tone={tab==='REPORT' ? 'red' : tab==='REVIEW' ? 'amber' : 'green'}>{tab}</Badge><h3>{row.title}</h3><p className="mono">{row.id} · {row.cwe} · {row.file}:{row.line}</p><p>{evidenceText(row)}</p></div><Link to={`/finding/${encodeURIComponent(row.id)}${scanQuery(data.scanId)}`} className="button-secondary">Xem evidence <Icon name="ArrowRight" /></Link></div>)}</Card>
    </>
  );
}

function LiveReport({data}) {
  const [error,setError]=useState('');
  const [summaryState,retrySummary]=useReviewRemote((signal)=> api.scanSummary(data.scanId,{signal}),[data.scanId]);
  const totals=summaryState.data?.triage_totals;
  const totalCandidates=toNum(totals?.total_candidates);
  const reportCount=toNum(totals?.report_count);
  const reviewCount=toNum(totals?.review_count);
  const suppressCount=toNum(totals?.suppress_count);
  const fetchReport=async()=> {
    setError('');
    try {
      saveJson(`${data.scanId}-report.json`,await api.report(data.scanId,{timeoutMs:60000}));
    } catch (failure) {
      setError(`Không tải được báo cáo từ backend: ${failure.message}`);
    }
  };
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Trung tâm báo cáo" description="Báo cáo của scan LIVE đang chọn." />
      <DataNotice>Dữ liệu LIVE từ backend cho scan {data.scanId}. Thống kê bên dưới là tổng scan từ summary; xuất dữ liệu đã nạp chỉ bao gồm payload findings hiện có, không thay thế báo cáo đầy đủ từ backend.</DataNotice>
      {summaryState.status==='loading' && <DataNotice>Đang tải thống kê tổng scan từ backend…</DataNotice>}
      {summaryState.status==='error' && <DataNotice>Không tải được thống kê tổng scan: {summaryState.error} <button className="button-secondary" onClick={retrySummary}>Thử lại</button></DataNotice>}
      <Card className="report-row"><div><Badge tone="blue">LIVE</Badge><h3>{data.scanId}</h3><p>{showNum(totalCandidates)} findings · REPORT {showNum(reportCount)} · REVIEW {showNum(reviewCount)} · SUPPRESS {showNum(suppressCount)}</p></div>
        <div>
          <Link to={`/findings${scanQuery(data.scanId)}`} className="button-secondary">Xem kết quả <Icon name="ArrowRight" /></Link>
          <button className="button-secondary" onClick={()=> saveJson(`${data.scanId}-fetched.json`,{scan:data.scan,findings:data.findingsPayload})}><Icon name="Download" />Xuất dữ liệu đã nạp ({data.rows.length} finding)</button>
          <button className="button-secondary" onClick={fetchReport}><Icon name="FileText" />Báo cáo từ backend</button>
        </div>
      </Card>
      {error && <div className="inline-error" role="alert"><Icon name="AlertTriangle" />{error}</div>}
    </>
  );
}

export function Review() {
  const [params]=useSearchParams();
  const scanId=params.get('scan_id') || window.sessionStorage.getItem(ACTIVE_KEY) || '';
  if (scanId) return <PagedReview scanId={scanId} />;
  return <DemoReview />;
}

function DemoReview() {
  const [tab,setTab]=useState('REPORT');
  const rows=demoFindings.filter((row)=> row.decision===tab);
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Xác minh cảnh báo" description="Hàng đợi hỗ trợ analyst review. Không tự xác nhận findings trong giao diện." />
      <DataNotice>Danh sách là dữ liệu minh họa. Trạng thái chuyên gia chỉ có thể thay đổi khi backend cung cấp reviewer workflow.</DataNotice>
      <div className="review-tabs">{['REPORT','REVIEW','SUPPRESS'].map((item)=> <button className={tab===item ? 'active' : ''} key={item} onClick={()=> setTab(item)}>{item}<span>{demoFindings.filter((row)=> row.decision===item).length}</span></button>)}</div>
      <Card className="review-list">{rows.map((row)=> <div className="review-row" key={row.id}><div><Badge tone={tab==='REPORT' ? 'red' : tab==='REVIEW' ? 'amber' : 'green'}>{tab}</Badge><h3>{row.title}</h3><p className="mono">{row.id} · {row.cwe} · {row.file}:{row.line}</p><p>{row.reason}</p></div><Link to={`/finding/${row.id}`} className="button-secondary">Xem evidence <Icon name="ArrowRight" /></Link></div>)}</Card>
      <div className="section-block"><SectionTitle title="Trạng thái chuyên gia" /><div className="status-grid">{['NOT_REVIEWED','CONFIRMED_TRUE_POSITIVE','CONFIRMED_FALSE_POSITIVE'].map((item)=> <Card key={item} title={item}><p>Chưa có thao tác reviewer được kết nối. Frontend không tự xác nhận hoặc ghi đè trạng thái.</p></Card>)}</div></div>
    </>
  );
}

export function Reports() {
  const sel=useScanSelection();
  if (sel.mode==='live') return <LiveGate sel={sel} title="Trung tâm báo cáo">{(data)=> <LiveReport data={data} />}</LiveGate>;
  return <DemoReports />;
}

function DemoReports() {
  const demo=window.sessionStorage.getItem('22025523-demo-result')==='true';
  const download=()=> {
    const payload={data_origin:'synthetic_demo',note:'Không phải báo cáo scan thực tế',findings:demoFindings};
    const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
    const anchor=document.createElement('a');
    anchor.href=url;
    anchor.download='22025523-synthetic-report.json';
    anchor.click();
    URL.revokeObjectURL(url);
  };
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Trung tâm báo cáo" description="Lịch sử và bản xuất báo cáo sẽ lấy từ backend khi API report sẵn sàng." actions={demo && <button onClick={download} className="button-secondary"><Icon name="Download" />Xuất JSON minh họa</button>} />
      <DataNotice>{demo ? 'Bản ghi báo cáo hiện tại là minh họa synthetic.' : 'Chưa có phiên phân tích thực để hiển thị. Nút xuất được bật khi có dữ liệu demo.'}</DataNotice>
      {demo ? <Card className="report-row"><div><Badge tone="amber">DEMO</Badge><h3>Java Security Sample · Synthetic</h3><p>Sample scan · Findings minh họa · Không phải kết quả backend</p></div><Link to="/results" className="button-secondary">Xem report <Icon name="ArrowRight" /></Link></Card> : <EmptyState title="Chưa có báo cáo" text="Các phiên scan và báo cáo sẽ xuất hiện tại đây khi backend cung cấp dữ liệu." icon="FileText" />}
    </>
  );
}

export function History() {
  const demo=window.sessionStorage.getItem('22025523-demo-result')==='true';
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Lịch sử phân tích" description="Danh sách scan thực sẽ được nạp qua API backend." />
      {demo ? (
        <>
          <DataNotice>Phiên bên dưới là kịch bản minh họa, không phải scan thực.</DataNotice>
          <Card className="report-row"><div><Badge tone="amber">MINH HỌA</Badge><h3>Java Security Sample</h3><p>Synthetic demo · 4 findings minh họa · Trạng thái hoàn tất demo</p></div><Link to="/results" className="button-secondary">Mở kết quả <Icon name="ArrowRight" /></Link></Card>
        </>
      ) : (
        <EmptyState title="Chưa có phiên phân tích" text="Chạy demo hoặc kết nối backend để xem lịch sử scan." icon="Clock" />
      )}
    </>
  );
}

export function Status() {
  const backend = useOutletContext()?.backend ?? {status: 'CHECKING', health: null};
  const backendLabel = {
    CHECKING: 'Đang kiểm tra backend',
    CONNECTED: 'Backend đã kết nối',
    DISCONNECTED: 'Backend chưa kết nối',
    ERROR: 'Lỗi kiểm tra backend'
  }[backend.status] || 'Chưa xác minh';
  const backendTone = backend.status === 'CONNECTED' ? 'green' : backend.status === 'CHECKING' ? 'blue' : 'amber';
  const rows=[['Backend API',backendLabel,backendTone],['OpenGrep','Chưa xác minh qua backend','neutral'],['IRIS','Chưa xác minh qua backend','neutral'],['Model · EO06 LoRA','Qwen2.5-Coder-0.5B-Instruct','blue'],['Scoring policy','Metadata chưa được nạp','neutral'],['Ruleset version','Metadata chưa được nạp','neutral']];
  return (
    <>
      <PageHeader eyebrow="HỆ THỐNG" title="Trạng thái hệ thống" description="Trạng thái runtime thực tế chỉ được xác nhận từ API health và metadata backend." />
      <DataNotice>{backend.status === 'CONNECTED' ? `Backend đã được xác minh qua API health${backend.health?.service ? ` · ${backend.health.service}` : ''}. Các thành phần khác chưa được xác minh.` : `Backend chưa được xác minh (${backend.status}). Không hiển thị trạng thái All Systems Operational.`}</DataNotice>
      <Card className="status-table">{rows.map(([name,value,tone])=> <div className="system-row" key={name}><div><span className={`status-dot ${name === 'Backend API' && backend.status === 'CONNECTED' ? 'online' : ''}`} /><strong>{name}</strong></div><Badge tone={tone}>{value}</Badge></div>)}</Card>
      <Card className="model-card" title="Model card"><div className="model-card-grid"><div><span>MODEL</span><strong>Qwen2.5-Coder-0.5B-Instruct + EO06 LoRA</strong></div><div><span>TRẠNG THÁNG RUNTIME</span><strong>Chưa xác minh</strong></div><div><span>CHECKPOINT DIGEST</span><strong>Chưa được API cung cấp</strong></div></div></Card>
    </>
  );
}

export function About() {
  return (
    <>
      <PageHeader eyebrow="THÔNG TIN HỌC THUẬT" title="Giới thiệu đề tài" description="Nền tảng nghiên cứu kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ để hỗ trợ đánh giá mã nguồn Java." />
      <div className="university-card">
        <UETLogo variant="about" />
        <div className="university-details">
          <Badge tone="blue">ĐỒ ÁN TỐT NGHIỆP</Badge>
          <h2>Trường Đại học Công nghệ<br />Đại học Quốc gia Hà Nội</h2>
          <p>VNU University of Engineering and Technology (VNU-UET)</p>
          <span className="academic-disclaimer">Website giới thiệu sản phẩm đồ án; không phải cổng thông tin chính thức của nhà trường.</span>
        </div>
      </div>
      <Card className="thesis-card" title="Thông tin đề tài">
        <div className="thesis-grid">
          <div><span>TÊN ĐỀ TÀI</span><strong>Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn</strong></div>
          <div><span>SINH VIÊN THỰC HIỆN</span><strong>Nguyễn Tuấn Khoa</strong></div>
          <div><span>MÃ SINH VIÊN</span><strong className="mono">22025523</strong></div>
          <div><span>GIẢNG VIÊN HƯỚNG DẪN</span><strong>TS. Nguyễn Đại Thọ</strong></div>
          <div><span>LỚP</span><strong>K67-I-CN</strong></div>
          <div><span>TRƯỜNG</span><strong>Trường Đại học Công nghệ — Đại học Quốc gia Hà Nội</strong></div>
          <div><span>LĨNH VỰC</span><strong>An toàn thông tin, phân tích mã nguồn và ứng dụng mô hình ngôn ngữ lớn</strong></div>
        </div>
      </Card>
      <section className="section-block">
        <SectionTitle title="Đóng góp nghiên cứu" />
        <div className="contribution-grid">{['Tích hợp các thành phần phân tích mã nguồn.','Xây dựng và kiểm soát chất lượng dữ liệu API role.','Fine-tuning mô hình chuyên biệt bằng LoRA.','Hợp nhất bằng chứng và chấm điểm heuristic.','Phân loại cảnh báo để hỗ trợ xác minh.','Triển khai giao diện có khả năng kết nối API.'].map((item,index)=> <div className="contribution" key={item}><span>0{index+1}</span><p>{item}</p></div>)}</div>
      </section>
      <DataNotice>Giới hạn: khả năng phát hiện phụ thuộc ruleset, phạm vi phân tích và bằng chứng backend. Không khẳng định phát hiện mọi lỗ hổng hoặc loại bỏ hoàn toàn false positive.</DataNotice>
    </>
  );
}