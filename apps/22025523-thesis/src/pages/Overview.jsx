import {useEffect, useState} from 'react';
import {Link, useOutletContext} from 'react-router-dom';
import {motion} from 'framer-motion';
import {Icon,Card,StatCard,SectionTitle,Badge,DataNotice} from '../components/common/Ui';
import {pipelinePhases} from '../data/research';
import {api} from '../services/api';

const pillars=[
  ['ScanSearch','OpenGrep','Phát hiện các mẫu mã nguồn có dấu hiệu rủi ro dựa trên quy tắc phân tích tĩnh.'],
  ['GitBranch','IRIS','Phân tích cấu trúc Java, ngữ cảnh và luồng dữ liệu trong phạm vi được hỗ trợ.'],
  ['Cpu','Mô hình ngôn ngữ','Phân loại vai trò API và bổ sung tín hiệu ngữ nghĩa cho quá trình đánh giá.']
];

function readLatestScan() {
  try {
    return JSON.parse(window.sessionStorage.getItem('22025523-live-scans') || '[]')[0] || null;
  } catch {
    return null;
  }
}

function listRows(result) {
  return result?.supported && Array.isArray(result.items) ? result.items : [];
}

function getId(record) {
  return record?.scan_id ?? record?.id ?? record?.job_id ?? '';
}

function getState(record) {
  return String(record?.state ?? record?.status ?? '').toUpperCase();
}

function extractFindingList(payload) {
  const keys = ['findings', 'alerts', 'candidates', 'reported_findings', 'review_queue_findings', 'suppressed_findings_audit_log'];
  if (!payload || typeof payload !== 'object') return null;
  for (const key of keys) if (Array.isArray(payload[key])) return payload[key];
  for (const key of ['data', 'result', 'scan', 'payload']) {
    const nested = extractFindingList(payload[key]);
    if (nested) return nested;
  }
  return null;
}

async function fetchOverviewStats(signal) {
  const responses = await Promise.allSettled([api.listScanJobs({signal}), api.listScans({signal})]);
  const lists = responses
    .filter((response) => response.status === 'fulfilled' && response.value.supported)
    .map((response) => response.value.items);
  if (!lists.length) return {supported: false, records: [], report: null, projectCount: null, latestMs: null};
  const byId = new Map();
  lists.flat().forEach((item) => {
    const id = getId(item);
    if (id) byId.set(id, {...byId.get(id), ...item});
  });
  const records = [...byId.values()];
  const completed = records.filter((item) => getState(item) === 'COMPLETED');
  const projects = new Set(records.map((item) => item.repo_url ?? item.repository_url).filter(Boolean));
  const latest = completed
    .filter((item) => item.total_e2e_duration_ms !== null && item.total_e2e_duration_ms !== undefined && Number.isFinite(Number(item.total_e2e_duration_ms)))
    .sort((a, b) => Date.parse(b.completed_at ?? b.finished_at ?? b.created_at ?? '') - Date.parse(a.completed_at ?? a.finished_at ?? a.created_at ?? ''))[0];
  const reportCounts = [];
  for (let offset = 0; offset < completed.length; offset += 4) {
    const batch = await Promise.all(completed.slice(offset, offset + 4).map(async (item) => {
      const scanId = item.scan_id ?? item.id;
      if (!scanId) return null;
      try {
        const payload = await api.findings(scanId, {signal, timeoutMs: 30000});
        const findings = extractFindingList(payload);
        return findings ? findings.filter((finding) => String(finding?.triage_decision ?? finding?.decision ?? finding?.policy_decision ?? '').toUpperCase() === 'REPORT').length : null;
      } catch {
        return null;
      }
    }));
    reportCounts.push(...batch);
  }
  return {
    supported: true,
    records,
    report: reportCounts.length === completed.length && reportCounts.every((value) => value !== null)
      ? reportCounts.reduce((sum, value) => sum + value, 0)
      : null,
    projectCount: projects.size,
    latestMs: latest ? Number(latest.total_e2e_duration_ms) : null
  };
}

export default function Overview() {
  const backend = useOutletContext()?.backend ?? {status: 'CHECKING', health: null};
  const latest = readLatestScan();
  const liveFindings = latest?.findings?.findings || latest?.findings?.alerts || latest?.findings?.candidates || latest?.findings?.data?.findings || [];
  const countDecision = (decision) => liveFindings.filter((item) => String(item.triage_decision || item.decision || '').toUpperCase() === decision).length;
  const [stats, setStats] = useState({loading: true, supported: false, records: [], report: null, projectCount: null, latestMs: null});

  useEffect(() => {
    const controller = new AbortController();
    fetchOverviewStats(controller.signal)
      .then((result) => { if (!controller.signal.aborted) setStats({...result, loading: false}); })
      .catch(() => { if (!controller.signal.aborted) setStats((current) => ({...current, loading: false})); });
    return () => controller.abort();
  }, []);

  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> 22025523 · NỀN TẢNG NGHIÊN CỨU BẢO MẬT MÃ NGUỒN</div>
          <h1>Phân tích mã nguồn.<br /><em>Kết nối bằng chứng.</em></h1>
          <p>Nền tảng nghiên cứu kết hợp phân tích tĩnh, ngữ cảnh chương trình và mô hình ngôn ngữ để hỗ trợ nhận diện rủi ro trong mã nguồn Java.</p>
          <div className="hero-actions">
            <Link to="/scanner" className="button-primary"><Icon name="ScanSearch" />Bắt đầu phân tích<Icon name="ArrowRight" /></Link>
            <Link to="/architecture" className="button-secondary">Khám phá kiến trúc</Link>
          </div>
          <div className="hero-footnote"><Icon name="ShieldCheck" /> Công cụ hỗ trợ phân tích — kết luận cần được xem xét theo bằng chứng.</div>
        </div>
        <motion.div className="hero-visual" initial={{opacity:0,scale:.96}} animate={{opacity:1,scale:1}} transition={{duration:.6}}>
          <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" />
          <div className="visual-core"><Icon name="ScanSearch" /><span>22025523</span></div>
          <div className="visual-node node-open"><Icon name="ScanSearch" /><span>OpenGrep</span></div>
          <div className="visual-node node-iris"><Icon name="GitBranch" /><span>IRIS</span></div>
          <div className="visual-node node-llm"><Icon name="Cpu" /><span>Qwen + LoRA</span></div>
          <div className="visual-link link-a" /><div className="visual-link link-b" /><div className="visual-link link-c" />
          <div className="visual-caption">EVIDENCE FUSION <span>→</span> FINDINGS</div>
        </motion.div>
      </section>
      <DataNotice>{backend.status === 'CONNECTED' ? `Backend: CONNECTED · ${backend.health?.service || 'health OK'} · kết quả bên dưới chỉ phản ánh scan thực đã nhận trong session.` : `Backend: ${backend.status}. Chỉ số scan thực sẽ xuất hiện sau khi API trả dữ liệu.`}</DataNotice>
      <section className="section-block">
        <SectionTitle title="Ba nguồn tín hiệu. Một kết luận có thể giải thích." text="Không có thành phần đơn lẻ nào được xem là bằng chứng tuyệt đối." />
        <div className="pillar-grid">{pillars.map(([icon,title,text],index)=> <motion.div key={title} className="pillar-card" whileHover={{y:-4}} transition={{duration:.2}}><div className={`pillar-icon pillar-${index}`}><Icon name={icon} /></div><h3>{title}</h3><p>{text}</p><span className="pillar-index">0{index+1}</span></motion.div>)}</div>
      </section>
      <section className="section-block">
        <SectionTitle title="Nghiên cứu và vận hành" text="Hai giai đoạn riêng biệt, cùng hướng tới kết quả phân tích có căn cứ." />
        <div className="journey-grid">
          <Card className="journey-card" title="01 / Xây dựng mô hình">
            <div className="journey-flow">{['Dataset','Quality gates','LoRA','Đánh giá','Model release'].map((item,index)=> <span key={item}>{item}{index<4 && <Icon name="ChevronRight" />}</span>)}</div>
            <p>Chuẩn hóa dữ liệu API role, kiểm soát chất lượng nhãn, fine-tuning và lựa chọn checkpoint.</p>
            <Link to="/training">Xem quy trình huấn luyện <Icon name="ArrowRight" /></Link>
          </Card>
          <Card className="journey-card" title="02 / Phân tích mã nguồn">
            <div className="journey-flow">{pipelinePhases.slice(1,6).map(([name],index)=> <span key={name}>{['Java','OpenGrep','IRIS','Qwen','Fusion'][index]}{index<4 && <Icon name="ChevronRight" />}</span>)}</div>
            <p>Từ source Java đến candidate, bằng chứng, scoring và triage cảnh báo.</p>
            <Link to="/architecture">Khám phá kiến trúc <Icon name="ArrowRight" /></Link>
          </Card>
        </div>
      </section>
      <section className="section-block">
        <SectionTitle title="Thông tin nghiên cứu" text={stats.supported ? 'Thống kê chỉ bao phủ các bản ghi backend có thể truy xuất; không mặc định là tổng lifetime.' : 'Chưa có API tổng hợp thống kê; không thay bằng số liệu giả.'} />
        <div className="stats-grid">
          <StatCard label="Các phiên có thể truy xuất" value={stats.loading ? '…' : stats.supported ? stats.records.length.toLocaleString() : '—'} note={stats.supported ? 'Job/scan khử trùng lặp theo ID' : 'Chưa có API tổng hợp thống kê'} icon="ScanSearch" />
          <StatCard label="Dự án trong lịch sử hiện có" value={stats.loading ? '…' : stats.projectCount === null ? '—' : stats.projectCount.toLocaleString()} note="Repository trong các bản ghi truy xuất được" icon="FolderGit2" tone="violet" />
          <StatCard label="REPORT trong các phiên đã nạp" value={stats.loading ? '…' : stats.report === null ? '—' : `${stats.report} REPORT`} note={stats.report === null ? 'Findings chưa thể truy xuất đầy đủ' : 'Đếm từ findings API các scan đã nạp'} icon="ShieldAlert" tone="amber" />
          <StatCard label="Thời gian backend của phiên gần nhất" value={stats.loading ? '…' : Number.isFinite(stats.latestMs) ? `${(stats.latestMs / 1000).toFixed(3)}s` : '—'} note="total_e2e_duration_ms; không dùng browser timer" icon="Clock" tone="green" />
        </div>
      </section>
      <section className="research-banner">
        <div><Badge tone="blue">ĐỒ ÁN TỐT NGHIỆP</Badge><h2>Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn</h2><p>Trường Đại học Công nghệ — Đại học Quốc gia Hà Nội</p></div>
        <Link to="/about" className="button-secondary">Thông tin đề tài <Icon name="ArrowRight" /></Link>
      </section>
    </>
  );
}