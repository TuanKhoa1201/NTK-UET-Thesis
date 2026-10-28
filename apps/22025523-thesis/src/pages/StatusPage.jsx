import {useCallback, useEffect, useState} from 'react';
import {Card, PageHeader, Badge, DataNotice} from '../components/common/Ui';
import {api} from '../services/api';
import {findKey, findKeyLike} from '../services/jobModel';
import {readHistory} from '../services/scanHistory';

const MISSING = 'API không cung cấp trường này';
const yesNo = (value, yes, no) => (value === undefined ? [MISSING, 'neutral'] : value ? [yes, 'green'] : [no, 'amber']);

function traceStageFive(payload) {
  const stages = payload?.stages ?? payload?.pipeline_trace?.stages ?? payload?.trace?.stages ?? payload?.events;
  if (!Array.isArray(stages)) return null;
  return stages.find((stage, index) => {
    const key = String(stage?.stage_key ?? stage?.key ?? stage?.stage_id ?? stage?.name ?? '').toUpperCase();
    const number = Number(stage?.stage_number ?? stage?.stage_no ?? stage?.number);
    return key.includes('IRIS_PROGRAM_ANALYSIS') || number === 5 || (!key && !number && index === 4);
  }) || null;
}

function buildRows(health, model, lastScan, irisTrace) {
  const both = {health, model};
  const get = (key) => findKey(both, key);
  const loadState = get('model_load_state');
  const device = get('actual_model_device');
  const dtype = get('actual_model_dtype');
  const cudaAvail = get('torch_cuda_available');
  const digest = get('best_adapter_sha256');
  const policy = findKeyLike(both, /scoring.*policy|policy.*(version|name)/i);
  const ruleset = findKeyLike(both, /ruleset|rule_set/i);
  const iris = findKeyLike(both, /iris/i);
  const irisState = String(irisTrace?.state ?? irisTrace?.status ?? '').toUpperCase();
  const irisEvidence = irisTrace?.summary_metadata ?? irisTrace?.summary ?? irisTrace?.evidence ?? irisTrace?.metadata;
  const onGpu = typeof device === 'string' && /cuda|gpu/i.test(device) && String(loadState).toUpperCase() === 'LOADED';
  return [
    ['Backend API', health ? `Có thể truy cập · ${get('service') ?? 'service ?'} · api ${get('api_version') ?? '?'} · arch ${get('architecture_version') ?? '?'} · status ${get('status') ?? '?'}` : 'Chưa nhận health', health ? 'green' : 'amber'],
    ['OpenGrep (binary)', ...yesNo(get('opengrep_available'), 'Đã cài / khả dụng (chưa xác minh bằng scan)', 'Không khả dụng')],
    ['javac', ...yesNo(get('javac_available'), 'Khả dụng', 'Không khả dụng')],
    ['git', ...yesNo(get('git_available'), 'Khả dụng', 'Không khả dụng')],
    ['AST parser engine', get('ast_parser_engine') ?? MISSING, get('ast_parser_engine') ? 'blue' : 'neutral'],
    ['IRIS', iris ? `${iris.key}: ${iris.value}` : 'API health/model không có trường IRIS riêng', iris ? 'blue' : 'neutral'],
    ['IRIS · Stage 05 trace', irisTrace ? `${irisState || 'Có stage trong trace'} · ${lastScan?.scanId}${irisEvidence ? ' · metadata/evidence có trong trace' : ' · không có evidence chi tiết'}` : 'Chưa có Stage 05 trace để xác minh; health/model không có trường IRIS riêng', irisTrace && /COMPLETED|SUCCESS|DONE/.test(irisState) ? 'green' : irisTrace ? 'amber' : 'neutral'],
    ['Base model', ...yesNo(get('base_model_available'), 'Có sẵn', 'Không có')],
    ['LoRA adapter', ...yesNo(get('best_adapter_available'), 'Có sẵn', 'Không có')],
    ['Trạng thái nạp model', loadState === undefined ? MISSING : String(loadState).toUpperCase() === 'NOT_LOADED' ? 'NOT_LOADED — bình thường trước lần inference đầu tiên' : String(loadState), loadState === undefined ? 'neutral' : 'blue'],
    ['Thiết bị cấu hình', get('configured_device') ?? MISSING, 'blue'],
    ['Thiết bị thực thi / dtype', device || dtype ? `${device ?? '—'} · ${dtype ?? '—'}${onGpu ? ' · đã chạy GPU' : ''}` : 'Chưa nạp model hoặc API chưa cung cấp', onGpu ? 'green' : 'neutral'],
    ['CUDA (torch)', ...yesNo(cudaAvail, 'torch.cuda khả dụng', 'torch.cuda không khả dụng')],
    ['Adapter SHA-256', digest ?? 'API không cung cấp trong phản hồi hiện tại', digest ? 'green' : 'neutral'],
    ['Scoring policy', policy ? `${policy.key}: ${policy.value}` : 'Không có trường scoring policy trong health/model', policy ? 'blue' : 'neutral'],
    ['Ruleset version', ruleset ? `${ruleset.key}: ${ruleset.value}` : 'Không có trường ruleset trong health/model', ruleset ? 'blue' : 'neutral'],
    ['Xác minh bằng scan thực', lastScan ? `Có scan hoàn tất gần nhất: ${lastScan.scanId}` : 'Chưa có scan hoàn tất trong bộ nhớ trình duyệt', lastScan ? 'green' : 'neutral']
  ];
}

export default function StatusPage() {
  const [health, setHealth] = useState(null);
  const [model, setModel] = useState(null);
  const [irisTrace, setIrisTrace] = useState(null);
  const [errors, setErrors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshedAt, setRefreshedAt] = useState(null);
  const [stale, setStale] = useState(false);
  const lastScan = readHistory().find((record) => record.status === 'COMPLETED');

  const load = useCallback(async () => {
    setLoading(true);
    const [h, m] = await Promise.allSettled([api.health(), api.model()]);
    const failures = [h, m].map((item, index) => (item.status === 'rejected' ? `${index ? '/api/model' : '/api/health'}: ${item.reason?.message}` : null)).filter(Boolean);
    if (h.status === 'fulfilled') setHealth(h.value);
    if (m.status === 'fulfilled') setModel(m.value);
    if (h.status === 'fulfilled' || m.status === 'fulfilled') setRefreshedAt(new Date().toLocaleString('vi-VN'));
    if (lastScan?.scanId) {
      try {
        const trace = await api.pipelineTrace(lastScan.scanId);
        setIrisTrace(traceStageFive(trace));
      } catch (failure) {
        failures.push(`/api/scans/${lastScan.scanId}/pipeline-trace: ${failure.message}`);
      }
    }
    setErrors(failures);
    setStale(failures.length > 0);
    setLoading(false);
  }, [lastScan?.scanId]);

  useEffect(() => { load(); }, [load]);

  const rows = buildRows(health, model, lastScan, irisTrace);
  return (
    <>
      <PageHeader eyebrow="HỆ THỐNG" title="Trạng thái hệ thống" description="Giá trị lấy từ GET /api/health và GET /api/model, kể cả trường lồng nhau." actions={<button className="button-secondary" onClick={load} disabled={loading}>{loading ? 'Đang tải…' : 'Làm mới metadata'}</button>} />
      <DataNotice>Phân biệt: API truy cập được · thành phần có sẵn · model đã nạp · model chạy GPU · đã xác minh bằng scan thực. Sự tồn tại của binary không đồng nghĩa thành phần đã hoạt động đầy đủ.</DataNotice>
      {refreshedAt && <p className="panel-note">{stale ? 'Dữ liệu hiển thị là giá trị gần nhất; refresh hiện tại có lỗi.' : 'Cập nhật gần nhất'} {refreshedAt}</p>}
      {errors.map((message) => <div className="inline-error" role="alert" key={message}>{message}</div>)}
      <Card className="status-table">{rows.map(([name, value, tone]) => <div className="system-row" key={name}><div><span className={`status-dot ${tone === 'green' ? 'online' : ''}`} /><strong>{name}</strong></div><Badge tone={tone}>{value}</Badge></div>)}</Card>
    </>
  );
}