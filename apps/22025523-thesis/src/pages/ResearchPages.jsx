import { useMemo, useState } from 'react';
import { Card, PageHeader, SectionTitle, Badge, BarRow, DataNotice, EmptyState } from '../components/common/Ui';
import { Icon } from '../components/common/Ui';
import { datasetSamples, roleLabels, trainingResults, benchmarkRows } from '../data/research';

const workflowTraining = ['Nguồn dữ liệu', 'Provenance', 'Quality gates', 'Role annotation', 'LoRA fine-tuning', 'Evaluation', 'Checkpoint'];
const workflowRuntime = ['Java repository / ZIP', 'Source inventory', 'OpenGrep', 'IRIS context & dataflow', 'Qwen role inference', 'Evidence fusion', 'Scoring & triage', 'Findings'];

export function Architecture() {
  const [selected, setSelected] = useState('OpenGrep');
  const [simple, setSimple] = useState(false);
  const steps = ['OpenGrep', 'IRIS', 'Qwen2.5-Coder + LoRA', 'Evidence Fusion', 'Alert Triage'];
  const descriptions = {
    OpenGrep: ['Tìm dấu hiệu đáng nghi.', 'Rule matches và candidate findings.', 'Có thể bỏ sót lỗ hổng; candidate chưa phải kết luận.'],
    IRIS: ['Kiểm tra ngữ cảnh và đường đi dữ liệu.', 'Java context, cấu trúc và dataflow trong phạm vi hỗ trợ.', 'Không mặc định chứng minh được dataflow liên thủ tục.'],
    'Qwen2.5-Coder + LoRA': ['Phân loại vai trò API.', 'source, sink, taint-propagator hoặc none.', 'Role classification không tự xác nhận vulnerability.'],
    'Evidence Fusion': ['Tổng hợp các tín hiệu.', 'Evidence và score theo policy hệ thống.', 'Heuristic score không phải xác suất đã hiệu chuẩn.'],
    'Alert Triage': ['Hỗ trợ ưu tiên kiểm tra.', 'REPORT, REVIEW hoặc SUPPRESS cùng reason codes.', 'REPORT không đồng nghĩa chuyên gia đã xác nhận.']
  };
  return (
    <>
      <PageHeader eyebrow="NỀN TẢNG" title="Kiến trúc hệ thống" description="Hai luồng nghiên cứu và vận hành, được trình bày riêng để làm rõ vai trò từng thành phần." actions={<button className={`button-secondary ${simple ? 'selected' : ''}`} onClick={() => setSimple(!simple)}><Icon name="BookOpen" />{simple ? 'Giải thích kỹ thuật' : 'Giải thích đơn giản'}</button>} />
      <ArchitectureFlow title="A · Giai đoạn nghiên cứu và huấn luyện" steps={workflowTraining} accent="violet" />
      <ArchitectureFlow title="B · Giai đoạn phân tích mã nguồn" steps={workflowRuntime} />
      <section className="section-block"><SectionTitle title="Vai trò và giới hạn" text="Chọn một thành phần để xem input, output và giới hạn phân tích." />
        <div className="architecture-layout"><div className="architecture-nodes">{steps.map((step, i) => <button key={step} className={`architecture-node ${selected === step ? 'active' : ''}`} onClick={() => setSelected(step)}><span>0{i + 1}</span><strong>{step}</strong><Icon name="ArrowRight" /></button>)}</div>
          <Card className="node-detail" title={selected}><div className="detail-grid"><div><span>VAI TRÒ</span><p>{simple ? descriptions[selected][0] : `Thành phần ${selected} bổ sung một lớp tín hiệu vào quy trình phân tích.`}</p></div><div><span>OUTPUT</span><p>{descriptions[selected][1]}</p></div><div><span>GIỚI HẠN</span><p>{descriptions[selected][2]}</p></div></div></Card>
        </div>
      </section>
    </>
  );
}

function ArchitectureFlow({ title, steps, accent = 'blue' }) {
  return <Card className={`flow-card flow-${accent}`} title={title}><div className="flow-scroll">{steps.map((step, index) => <div className="flow-step" key={step}><div className="flow-step-box"><span>0{index + 1}</span><strong>{step}</strong></div>{index < steps.length - 1 && <div className="flow-connector"><i /></div>}</div>)}</div></Card>;
}

export function Dataset() {
  const [query, setQuery] = useState('');
  const [cwe, setCwe] = useState('Tất cả CWE');
  const [role, setRole] = useState('Tất cả role');
  const [page, setPage] = useState(0);
  const rows = useMemo(() => datasetSamples.filter((item) => `${item.id} ${item.className} ${item.method} ${item.package}`.toLowerCase().includes(query.toLowerCase())).filter((item) => cwe === 'Tất cả CWE' || item.cwe === cwe).filter((item) => role === 'Tất cả role' || item.role === role), [query, cwe, role]);
  const download = async () => {
    const XLSX = await import('xlsx');
    const book = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(book, XLSX.utils.json_to_sheet([{ origin: 'synthetic_demo', note: 'Dữ liệu minh họa, không phải dataset nghiên cứu chính thức' }]), 'Overview');
    XLSX.utils.book_append_sheet(book, XLSX.utils.json_to_sheet(datasetSamples), 'Samples');
    XLSX.writeFile(book, 'vulnscope-synthetic-demo.xlsx');
  };
  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · DỮ LIỆU" title="Dữ liệu nghiên cứu và kiểm soát chất lượng" description="Theo dõi cấu trúc dataset, provenance và quality gates trước khi sử dụng trong fine-tuning." actions={<button className="button-primary" onClick={download}><Icon name="Download" />Tải Excel minh họa</button>} />
      <DataNotice>Data Explorer hiện dùng một tập mẫu nhỏ có nhãn <b>Dữ liệu minh họa</b>. Dataset chính thức chưa được nạp vào giao diện; nút tải dataset nghiên cứu sẽ được kích hoạt khi có artifact thật.</DataNotice>
      <div className="dataset-cards">
        <DatasetCard title="Track A · Trusted Gold Pilot" count="275" note="Tập đáng tin cậy trong quá trình phát triển." />
        <DatasetCard title="Track B · Audited Full" count="781" note="Fine-tuning EO06: 275 Trusted Gold + 506 multi-tool SAST audited." />
        <DatasetCard title="Development Set" count="166" note="Được dùng trong đánh giá và lựa chọn mô hình." />
        <DatasetCard title="Quarantine / Review" count="137" note="Tách riêng để kiểm tra; không tự động cộng vào training." />
      </div>
      <DataNotice>Track A là một phần thuộc Track B; không cộng 275 và 781 như hai tập độc lập. Track B không được gọi toàn bộ là independently human-verified gold.</DataNotice>
      <section className="section-block">
        <SectionTitle title="Data Explorer · dữ liệu minh họa" text="Các trường bên dưới mô phỏng cấu trúc bản ghi. Không đại diện cho phân bố chính thức." />
        <Card className="table-card">
          <div className="table-toolbar"><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} placeholder="Tìm sample, class, method..." /><select value={cwe} onChange={(event) => setCwe(event.target.value)}><option>Tất cả CWE</option>{['CWE-022', 'CWE-078', 'CWE-079', 'CWE-089'].map((value) => <option key={value}>{value}</option>)}</select><select value={role} onChange={(event) => setRole(event.target.value)}><option>Tất cả role</option>{roleLabels.map((value) => <option key={value}>{value}</option>)}</select></div>
          <div className="table-wrap"><table><thead><tr><th>Sample ID</th><th>CWE</th><th>Package / Class</th><th>Method</th><th>Signature</th><th>Role</th><th>Split</th></tr></thead><tbody>{rows.slice(page * 5, page * 5 + 5).map((row) => <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe}</Badge></td><td className="mono">{row.package}<br />{row.className}</td><td className="mono">{row.method}</td><td className="mono">{row.signature}</td><td><Badge tone="violet">{row.role}</Badge></td><td>{row.split}</td></tr>)}</tbody></table>{!rows.length && <EmptyState title="Không có bản ghi phù hợp" text="Thử điều chỉnh từ khóa hoặc bộ lọc." />}</div>
          <div className="pagination"><span>{rows.length} bản ghi minh họa</span><button disabled={page === 0} onClick={() => setPage(0)}>Trang trước</button><button disabled={rows.length <= (page + 1) * 5} onClick={() => setPage(page + 1)}>Trang sau</button></div>
        </Card>
      </section>
    </>
  );
}

function DatasetCard({ title, count, note }) {
  return <Card className="dataset-stat"><span className="dataset-count">{count}</span><h3>{title}</h3><p>{note}</p></Card>;
}

export function Training() {
  const timeline = ['Xác định bài toán API role', 'Thu thập dữ liệu & provenance', 'Chuẩn hóa schema', 'Kiểm tra leakage và nhãn', 'Chuẩn bị split đánh giá', 'Chọn base model', 'Cấu hình LoRA', 'Fine-tuning', 'Đánh giá mô hình', 'Chọn best checkpoint', 'Đưa vào pipeline vận hành'];
  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · MÔ HÌNH" title="Quy trình huấn luyện" description="Từ xây dựng dữ liệu đến lựa chọn checkpoint, tách biệt kết quả phân loại API role với hiệu quả end-to-end." />
      <Card className="model-card" title="Model card · EO06"><div className="model-card-grid"><div><span>BASE MODEL</span><strong>Qwen2.5-Coder-0.5B-Instruct</strong></div><div><span>FINE-TUNING</span><strong>LoRA · rank 16 · alpha 32 · dropout 0.05</strong></div><div><span>TRAINING</span><strong>4 epochs · 784 optimizer steps</strong></div><div><span>CHECKPOINT</span><strong>Best checkpoint · Epoch 3</strong></div></div></Card>
      <div className="timeline">{timeline.map((item, index) => <div className="timeline-item" key={item}><span className="timeline-marker">{String(index + 1).padStart(2, '0')}</span><div><strong>{item}</strong><p>{index < 4 ? 'Xây dựng đầu vào có provenance và kiểm soát chất lượng dữ liệu.' : index < 9 ? 'Cấu hình và đánh giá mô hình phân loại vai trò API.' : 'Chọn checkpoint theo kết quả phát triển; không đồng nhất với xác nhận vulnerability.'}</p></div></div>)}</div>
      <section className="section-block"><SectionTitle title="Kết quả API Role Classification" text="Các chỉ số này đo phân loại vai trò API, không phải độ chính xác phát hiện lỗ hổng end-to-end." />
        <Card className="chart-card" title="Accuracy và Macro-F1 theo split"><div className="metric-chart">{trainingResults.map((item) => <div className="metric-group" key={item.split}><div className="metric-bars"><div className="metric-bar accuracy" style={{ height: `${item.accuracy}%` }} /><div className="metric-bar f1" style={{ height: `${item.f1}%` }} /></div><strong>{item.accuracy.toFixed(2)}% / {item.f1.toFixed(2)}%</strong><span>{item.split}</span></div>)}</div><div className="chart-legend"><span className="legend-blue">Accuracy</span><span className="legend-violet">Macro-F1</span></div></Card>
      </section>
      <DataNotice>Development Set đã được dùng trong quá trình phát triển. Historical Holdout V2/V3 không phải blind test hoàn toàn mới; kết quả trên dữ liệu lịch sử khó hơn thấp hơn kết quả Dev. EO03 Primary Macro-F1: 91,31%; EO06: 98,28% trên Development Set.</DataNotice>
    </>
  );
}

export function Scoring() {
  return (
    <>
      <PageHeader eyebrow="PHƯƠNG PHÁP" title="Chấm điểm dựa trên bằng chứng" description="Score, severity và triage decision là ba khái niệm riêng biệt." />
      <DataNotice>SAST Scoring là chính sách heuristic được thiết kế trong hệ thống nghiên cứu. Không gán công thức cho CVSS hoặc một nguồn ngoài khi chưa có tài liệu xác nhận.</DataNotice>
      <div className="evidence-grid">{[['OpenGrep', 'Rule, CWE, severity, vị trí và matched code.', 'blue'], ['IRIS', 'Ngữ cảnh Java, dataflow, AST và sanitizer evidence.', 'violet'], ['LLM', 'Vai trò API được dự đoán và provenance nếu backend cung cấp.', 'cyan']].map(([name, text, tone]) => <Card key={name} className={`evidence-source source-${tone}`} title={name}><p>{text}</p></Card>)}</div>
      <div className="fusion-arrow"><Icon name="ArrowDown" /><strong>Evidence Fusion & SAST Scoring</strong><Icon name="ArrowDown" /><span>Alert Verification & Triage</span></div>
      <div className="scoring-grid">
        <Card title="Điều chỉnh minh họa"><div className="formula">Score_raw = clamp(Base_score + LLM_adjustment, 0, 1)</div><ul className="clean-list"><li>Base score: 0.70</li><li>Role `sink`: +0.15 → 0.85</li><li>Role `none`: −0.35 → intermediate 0.35</li><li>`source` hoặc thiếu bằng chứng: không điều chỉnh phần LLM</li></ul><p className="muted-text">Safety floor 0.55 có thể áp dụng theo điều kiện policy, ví dụ severity cao nhưng chưa đủ AST evidence để xác nhận an toàn.</p></Card>
        <Card title="Ví dụ score breakdown"><div className="score-example"><div><span>BASE SCORE</span><b>0.70</b></div><div className="score-adjust">+0.15 <small>LLM role = sink</small></div><div className="score-meter"><i style={{ width: '85%' }} /></div><strong>0.85 <small>heuristic score minh họa</small></strong></div><p className="muted-text">Ví dụ không phải kết quả scan trực tiếp và không thể diễn giải thành xác suất vulnerability 85%.</p></Card>
      </div>
      <section className="section-block"><SectionTitle title="Score ≠ Severity ≠ Triage" text="Một mức severity cao không tự động đồng nghĩa cảnh báo đã được xác nhận." />
        <div className="triage-cards"><Card title="REPORT"><Badge tone="red">Ưu tiên xử lý</Badge><p>Có bằng chứng hỗ trợ nghi ngờ lỗ hổng. Chưa tương đương chuyên gia xác nhận.</p></Card><Card title="REVIEW"><Badge tone="amber">Cần xem xét</Badge><p>Thiếu bằng chứng hoặc tín hiệu mâu thuẫn; cần kiểm tra thủ công.</p></Card><Card title="SUPPRESS"><Badge tone="green">Giảm ưu tiên</Badge><p>Có bằng chứng theo policy; vẫn giữ trong audit trail, không đồng nghĩa an toàn tuyệt đối.</p></Card></div>
      </section>
    </>
  );
}

export function Evaluation() {
  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · ĐÁNH GIÁ" title="Đánh giá thực nghiệm" description="Phân biệt đánh giá API role classification với benchmark phát hiện SAST end-to-end." />
      <DataNotice>Kết quả dưới đây thuộc controlled benchmark gồm 18 vị trí Java: 10 vulnerable theo ground truth. Không suy rộng thành chất lượng trên mọi GitHub repository.</DataNotice>
      <Card className="table-card" title="Ablation trên controlled benchmark"><div className="table-wrap"><table><thead><tr><th>Phương pháp</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>{benchmarkRows.map((row) => <tr key={row.name}><td>{row.name}</td><td>{row.tp}</td><td>{row.fp}</td><td>{row.fn}</td><td>{row.precision.toFixed(2)}%</td><td>{row.recall.toFixed(2)}%</td><td>{row.f1.toFixed(2)}%</td></tr>)}</tbody></table></div></Card>
      <section className="section-block"><SectionTitle title="Những gì kết quả chứng minh — và chưa thể kết luận" />
        <div className="two-column"><Card title="Có thể kết luận"><ul className="clean-list"><li>OpenGrep-only tạo nhiều FP hơn trong controlled set.</li><li>IRIS giảm false positive trong ablation này.</li><li>Full Triage đưa 9 finding vào REPORT; 1 vị trí chưa đủ bằng chứng được REVIEW.</li></ul></Card><Card title="Không thể kết luận"><ul className="clean-list"><li>Không khẳng định mọi repository có cùng metrics.</li><li>1 REVIEW không phải True Negative đã xác nhận.</li><li>Benchmark không cho thấy LLM trực tiếp tăng F1 so với IRIS.</li></ul></Card></div>
      </section>
    </>
  );
}