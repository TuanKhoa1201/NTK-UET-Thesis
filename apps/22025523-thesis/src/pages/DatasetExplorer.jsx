import {useEffect, useState} from 'react';
import {Card, PageHeader, SectionTitle, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import {api} from '../services/api';

const DATASETS = [
  ['track_a_trusted_gold', 'Track A · Trusted Gold Pilot'],
  ['track_b_audited_full', 'Track B · Audited Full'],
  ['dev_vnext_3_1', 'Development · VNext.3.1'],
  ['quarantine_review_queue', 'Quarantine · Review Queue']
];
const RELEASE_META = {
  base: 'Qwen/Qwen2.5-Coder-0.5B-Instruct',
  adapter: 'eo06_vnext31_trackb_main',
  checkpoint: 'eo06_vnext31_trackb_main_epoch3'
};

function DatasetCard({item}) {
  return <Card className="dataset-stat"><span className="dataset-count">{Number(item.row_count ?? 0).toLocaleString()}</span><h3>{item.title || item.dataset_id}</h3><p>{item.dataset_id}</p><p>SHA-256 {item.sha256_verified ? 'đã xác minh' : 'chưa xác minh'} · row count {item.row_count_verified ? 'đã xác minh' : 'chưa xác minh'}</p><p>{item.training_eligibility_status || (item.training_eligible ? 'Đủ điều kiện huấn luyện' : 'Không dùng huấn luyện')}</p></Card>;
}

function Cell({value, children, className = ''}) {
  const text = value === undefined || value === null ? '' : String(value);
  return <td className={`cell-trunc ${className}`} title={text}>{children ?? (text || '—')}</td>;
}

function fieldRows(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).map(([key, item]) => [
    key.replaceAll('_', ' '),
    item && typeof item === 'object' ? JSON.stringify(item) : String(item)
  ]);
}

function downloadName(disposition, datasetId, format) {
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return match?.[1] || `${datasetId}.${format}`;
}

export default function DatasetExplorer() {
  const [manifest, setManifest] = useState(null);
  const [manifestError, setManifestError] = useState('');
  const [datasetId, setDatasetId] = useState(DATASETS[1][0]);
  const [records, setRecords] = useState([]);
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [cwe, setCwe] = useState('');
  const [role, setRole] = useState('');
  const [split, setSplit] = useState('');
  const [provenance, setProvenance] = useState('');
  const [goldOnly, setGoldOnly] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [pageInfo, setPageInfo] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [exportError, setExportError] = useState('');
  const [exporting, setExporting] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    api.datasetManifest({signal: controller.signal})
      .then(setManifest)
      .catch((failure) => {
        if (!controller.signal.aborted) setManifestError(failure.message || 'Không tải được manifest.');
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query.trim()), 350);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    const controller = new AbortController();
    const params = {page, page_size: pageSize, q: debouncedQuery, cwe, role, split, provenance_tier: provenance, in_track_a_gold_subset: goldOnly};
    setLoading(true);
    setError('');
    api.datasetRecords(datasetId, params, {signal: controller.signal})
      .then((response) => {
        if (controller.signal.aborted) return;
        setRecords(Array.isArray(response?.records) ? response.records : []);
        setPageInfo(response || {});
      })
      .catch((failure) => {
        if (!controller.signal.aborted) {
          setRecords([]);
          setError(failure.message || 'Không thể tải dữ liệu từ backend.');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [datasetId, page, pageSize, debouncedQuery, cwe, role, split, provenance, goldOnly]);

  const changeFilter = (setter) => (event) => {
    setter(event.target.value);
    setPage(1);
  };

  const exportDataset = async (format) => {
    setExporting(format);
    setExportError('');
    let objectUrl = '';
    try {
      const result = await api.datasetExport(datasetId, format);
      objectUrl = URL.createObjectURL(result.blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = downloadName(result.disposition, datasetId, format);
      link.click();
    } catch (failure) {
      setExportError(failure.message || `Không tải được ${format}.`);
    } finally {
      if (objectUrl) window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setExporting('');
    }
  };

  const entries = Array.isArray(manifest?.datasets) ? manifest.datasets : [];
  const selected = entries.find((item) => item.dataset_id === datasetId);
  const totalPages = Number(pageInfo.total_pages || 0);
  const training = manifest?.eo06_training_provenance || {};
  const privacyRows = fieldRows(manifest?.privacy_and_redistribution_audit);

  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · DỮ LIỆU" title="Dữ liệu nghiên cứu và kiểm soát chất lượng" description="Manifest, bản ghi phân trang và artifact tải xuống được lấy trực tiếp từ backend." actions={
        <div className="guided-actions">{['csv', 'jsonl', 'xlsx'].map((format) => <button key={format} className="button-secondary" disabled={Boolean(exporting)} onClick={() => exportDataset(format)}><Icon name="Download" />{exporting === format ? 'Đang tải…' : `Tải ${format.toUpperCase()}`}</button>)}</div>
      } />
      {manifestError && <div className="inline-error" role="alert">{manifestError}</div>}
      <DataNotice>Track A là tập con của Track B; không cộng hai tập như dữ liệu độc lập. Track B là dữ liệu fine-tuning EO06; Development phục vụ validation/checkpoint selection; Quarantine bị loại khỏi training.</DataNotice>
      <div className="dataset-cards">{(entries.length ? entries : DATASETS.map(([dataset_id, title]) => ({dataset_id, title, row_count: '—'}))).map((item) => <DatasetCard key={item.dataset_id} item={item} />)}</div>
      <Card className="model-card" title="Fine-tuning provenance">
        <div className="model-card-grid"><div><span>BASE MODEL</span><strong>{manifest?.eo06_training_provenance?.base_model || RELEASE_META.base}</strong></div><div><span>ADAPTER</span><strong>{manifest?.eo06_training_provenance?.adapter || RELEASE_META.adapter}</strong></div><div><span>CHECKPOINT</span><strong>{manifest?.eo06_training_provenance?.selected_checkpoint || RELEASE_META.checkpoint}</strong></div><div><span>RELEASE</span><strong>{manifest?.dataset_release_version || '—'}</strong></div></div>
        <h4>Model and Training</h4>
        <div className="model-card-grid">
          <div><span>TRAINING DATASET</span><strong>{training.training_dataset || training.source_artifact || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>TRAINING SPLIT</span><strong>{training.training_split || training.split || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>TRAINING RUN ID</span><strong>{training.training_run_id || training.run_id || 'Manifest chưa cung cấp'}</strong></div>
        </div>
        <h4>API Role Taxonomy</h4>
        <div className="role-badges">{['source', 'sink', 'taint-propagator', 'none'].map((value) => <Badge tone="blue" key={value}>{value}</Badge>)}</div>
        <p className="panel-note">Sanitizer không phải role LLM thứ năm.</p>
        {manifest?.api_role_taxonomy && <details className="technical-details"><summary>Chi tiết taxonomy từ manifest</summary><pre><code>{JSON.stringify(manifest.api_role_taxonomy, null, 2)}</code></pre></details>}
        <h4>Data Quality and Provenance</h4>
        <div className="model-card-grid">
          <div><span>VERIFIED PROVENANCE</span><strong>{training.provenance_status || training.verified_provenance || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>SPDX LICENSING</span><strong>{training.spdx_license || training.spdx_licensing || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>SOURCE JSONL SHA-256</span><strong>{training.source_jsonl_sha256 || training.source_artifact_sha256 || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>TRAINING ELIGIBILITY</span><strong>{training.training_eligibility_status || training.training_eligible || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>TRACK A INCLUSION POLICY</span><strong>{training.track_a_inclusion_policy || manifest?.track_a_inclusion_policy || 'Manifest chưa cung cấp'}</strong></div>
          <div><span>ADAPTER SHA-256</span><strong>{training.adapter_sha256 || training.adapter_digest || 'Manifest chưa cung cấp'}</strong></div>
        </div>
        <p className="panel-note">Source JSONL SHA-256 và XLSX tải xuống là hai file khác nhau. Export Excel tự nó không chứng minh file nguồn đã được dùng trong fine-tuning; cần đối chiếu training manifest và execution receipt.</p>
        <h4>Privacy Audit</h4>
        {privacyRows.length
          ? <div className="model-card-grid">{privacyRows.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>
          : <p>Manifest chưa cung cấp privacy and redistribution audit.</p>}
        {manifest?.privacy_and_redistribution_audit && <details className="technical-details"><summary>Privacy audit JSON từ manifest</summary><pre><code>{JSON.stringify(manifest.privacy_and_redistribution_audit, null, 2)}</code></pre></details>}
        <h4>Export formats</h4>
        <div className="role-badges">{['CSV', 'JSONL', 'XLSX'].map((format) => <Badge tone="violet" key={format}>{format}</Badge>)}</div>
      </Card>
      <section className="section-block">
        <SectionTitle title="Data Explorer · bản ghi từ backend" text="Bộ lọc và phân trang được gửi tới API; giá trị dài được cắt hiển thị (rê chuột để xem đầy đủ) nhưng tệp xuất không bị cắt." />
        <Card className="table-card">
          <div className="table-toolbar">
            <select value={datasetId} onChange={(event) => {setDatasetId(event.target.value); setPage(1);}}>{DATASETS.map(([id, label]) => <option value={id} key={id}>{label}</option>)}</select>
            <input value={query} onChange={(event) => {setQuery(event.target.value); setPage(1);}} placeholder="Tìm sample, class, method..." />
            <input value={cwe} onChange={changeFilter(setCwe)} placeholder="CWE, ví dụ CWE-089" />
            <input value={role} onChange={changeFilter(setRole)} placeholder="API role" />
            <input value={split} onChange={changeFilter(setSplit)} placeholder="Split" />
            <input value={provenance} onChange={changeFilter(setProvenance)} placeholder="Provenance tier" />
            <select value={goldOnly} onChange={changeFilter(setGoldOnly)}><option value="">Track A subset: tất cả</option><option value="true">Chỉ Track A gold</option><option value="false">Ngoại trừ Track A gold</option></select>
          </div>
          {exportError && <div className="inline-error" role="alert">{exportError}</div>}
          {error && <div className="inline-error" role="alert">{error}</div>}
          <div className="table-wrap">
            <table><thead><tr><th>Sample ID</th><th>CWE</th><th>API</th><th>Signature</th><th>Role</th><th>Provenance</th><th>Split</th></tr></thead>
              <tbody>{records.map((row) => (
                <tr key={row.sample_id}>
                  <Cell value={row.sample_id} className="mono" />
                  <Cell value={row.cwe}><Badge tone="blue">{row.cwe}</Badge></Cell>
                  <Cell value={`${row.package_name} ${row.class_name}.${row.method_name}`} className="mono" />
                  <Cell value={row.signature} className="mono" />
                  <Cell value={row.role}><Badge tone="violet">{row.role}</Badge></Cell>
                  <Cell value={row.provenance_tier || row.evidence_tier} />
                  <Cell value={`${row.split ?? ''}${row.in_track_a_gold_subset ? ' · Track A' : ''}`} />
                </tr>
              ))}</tbody>
            </table>
            {loading && <DataNotice>Đang tải trang từ backend…</DataNotice>}
            {!loading && !error && !records.length && <EmptyState title="Không có bản ghi phù hợp" text="Không có dữ liệu thay thế minh họa; kiểm tra dataset hoặc bộ lọc." />}
          </div>
          <div className="pagination"><span>{Number(pageInfo.total_matching_rows ?? 0).toLocaleString()} kết quả · {Number(pageInfo.total_dataset_rows ?? selected?.row_count ?? 0).toLocaleString()} dòng trong dataset · Trang {pageInfo.page || page}/{totalPages || '—'}</span><select value={pageSize} onChange={(event) => {setPageSize(Number(event.target.value)); setPage(1);}}><option value={20}>20 / trang</option><option value={50}>50 / trang</option><option value={100}>100 / trang</option></select><button disabled={!pageInfo.has_prev_page} onClick={() => setPage((value) => Math.max(1, value - 1))}>Trang trước</button><button disabled={!pageInfo.has_next_page} onClick={() => setPage((value) => value + 1)}>Trang sau</button></div>
        </Card>
      </section>
      {selected?.distribution && <Card title="Phân bố backend"><pre><code>{JSON.stringify(selected.distribution, null, 2)}</code></pre></Card>}
      {selected?.quality_gate_summary && <Card title="Quality gate summary"><pre><code>{JSON.stringify(selected.quality_gate_summary, null, 2)}</code></pre></Card>}
    </>
  );
}