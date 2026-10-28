import {useEffect, useRef, useState} from 'react';
import {Link, useOutletContext} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, Icon} from '../components/common/Ui';
import SecurityAnalysisScene from '../components/scanner/SecurityAnalysisScene';
import {CoveragePanel, FailureDetails, StageOverview} from '../components/scanner/JobPanels';
import {api} from '../services/api';
import {currentStageIndex, resolveStages, skipNote} from '../services/jobModel';
import {loadLiveScan, scanQuery} from '../services/liveScan';
import {readHistory, upsertHistory} from '../services/scanHistory';

const phaseCount = 10;
const JOB_KEY = '22025523-active-job';
const STAGE_KEYS = [
  'PROJECT_INTAKE', 'SOURCE_INVENTORY', 'OPENGREP_DETECTION', 'CONTEXT_EXTRACTION',
  'IRIS_PROGRAM_ANALYSIS', 'LLM_INFERENCE', 'EVIDENCE_FUSION', 'SAST_SCORING',
  'ALERT_VERIFICATION', 'REPORT_SYNTHESIS'
];

function stageNumber(stage, index) {
  const value = Number(stage?.stage_number ?? stage?.stage_no ?? stage?.number);
  if (Number.isInteger(value) && value >= 1 && value <= 10) return value;
  const key = String(stage?.stage_key ?? stage?.key ?? stage?.stage_id ?? '').toUpperCase();
  const found = STAGE_KEYS.indexOf(key);
  return found >= 0 ? found + 1 : index + 1;
}

function formatMs(value) {
  return value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value))
    ? `${Number(value).toLocaleString('vi-VN', {minimumFractionDigits: 3, maximumFractionDigits: 3})} ms`
    : '—';
}

function StageTiming({job, counts}) {
  const stages = Array.isArray(job?.stages) ? job.stages : [];
  const resolved = resolveStages(job);
  const byNumber = new Map(stages.map((stage, index) => [stageNumber(stage, index), stage]));
  const durations = [...byNumber.values()].map((stage) => Number(stage.duration_ms)).filter(Number.isFinite);
  const sum = durations.reduce((total, value) => total + value, 0);
  const total = Number(job?.total_e2e_elapsed_ms ?? job?.total_e2e_duration_ms);
  const longest = [...byNumber.entries()]
    .filter(([, stage]) => stage.duration_ms !== null && stage.duration_ms !== undefined && Number.isFinite(Number(stage.duration_ms)))
    .sort((a, b) => Number(b[1].duration_ms) - Number(a[1].duration_ms))[0];

  return (
    <section className="section-block">
      <h3>THỜI GIAN THỰC THI 10 GIAI ĐOẠN</h3>
      <Card className="table-card">
        <div className="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Stage</th><th>Backend state</th><th>Duration</th><th>Tỷ lệ</th><th>Metadata</th></tr></thead>
            <tbody>{Array.from({length: phaseCount}, (_, index) => {
              const stage = byNumber.get(index + 1);
              const current = resolved[index];
              const active = current.cat === 'RUNNING';
              const status = current.label;
              const elapsed = Number(stage?.running_elapsed_ms);
              const note = skipNote(current, counts);
              return (
                <tr key={index}>
                  <td>{String(index + 1).padStart(2, '0')}</td>
                  <td>{stage?.stage_name || stage?.name || STAGE_KEYS[index]}</td>
                  <td>{status}{active && Number.isFinite(elapsed) ? ` · elapsed ${formatMs(elapsed)}` : ''}{note ? ` · ${note}` : ''}</td>
                  <td>{formatMs(stage?.duration_ms)}</td>
                  <td>{stage?.duration_ms !== null && stage?.duration_ms !== undefined && Number.isFinite(Number(stage?.duration_ms)) && sum > 0 ? `${(Number(stage.duration_ms) / sum * 100).toFixed(2)}%` : '—'}</td>
                  <td className="mono">{stage?.summary_metadata ? JSON.stringify(stage.summary_metadata) : '—'}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
        <div className="model-card-grid">
          <div><span>TỔNG E2E BACKEND</span><strong>{formatMs(total)}</strong></div>
          <div><span>TỔNG DURATION CÁC STAGE</span><strong>{formatMs(sum)}</strong></div>
          <div><span>OVERHEAD</span><strong>{Number.isFinite(total) && total >= sum ? formatMs(total - sum) : '—'}</strong></div>
          <div><span>STAGE DÀI NHẤT</span><strong>{longest ? `${longest[1].stage_name || longest[1].name || STAGE_KEYS[longest[0] - 1]} · ${formatMs(longest[1].duration_ms)}` : '—'}</strong></div>
        </div>
      </Card>
    </section>
  );
}

export default function Scanner() {
  const backend = useOutletContext()?.backend ?? {status: 'CHECKING', health: null};
  const [tab, setTab] = useState('github');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [elapsedMs, setElapsedMs] = useState(0);
  const [liveStatus, setLiveStatus] = useState('');
  const [liveStage, setLiveStage] = useState('IDLE');
  const [backendMs, setBackendMs] = useState(null);
  const [liveScanId, setLiveScanId] = useState('');
  const [liveCounts, setLiveCounts] = useState(null);
  const [liveJob, setLiveJob] = useState(null);
  const [interrupted, setInterrupted] = useState(false);
  const [jobId, setJobId] = useState(() => window.sessionStorage.getItem(JOB_KEY) || '');
  const timerRef = useRef(null);
  const startRef = useRef(Number(window.sessionStorage.getItem(JOB_KEY + '-started')) || 0);
  const requestRef = useRef(null);
  const pendingRef = useRef(false);
  const inputRef = useRef(null);
  const simulationRef = useRef(null);

  useEffect(() => () => {
    window.clearInterval(timerRef.current);
    requestRef.current?.abort();
  }, []);

  const scrollToSimulation = () => {
    requestAnimationFrame(() => simulationRef.current?.scrollIntoView({behavior: 'smooth', block: 'start'}));
  };

  useEffect(() => {
    if (!jobId) return undefined;
    const controller = new AbortController();
    let stopped = false;
    let pollTimer;

    const poll = async () => {
      try {
        const job = await api.scanJob(jobId, {signal: controller.signal});
        if (stopped) return;
        setInterrupted(false);
        setLiveJob(job);
        const state = String(job?.state || '').toUpperCase();
        setLiveStage(state || 'IDLE');
        if (job?.scan_id) {
          window.sessionStorage.setItem('22025523-scan-id', job.scan_id);
          setLiveScanId(job.scan_id);
        }
        if (state === 'QUEUED' || state === 'RUNNING') {
          setLiveStatus(state === 'QUEUED' ? 'Backend đã xếp job vào hàng chờ' : `Backend đang thực thi${job.active_stage ? ` · stage ${job.active_stage}` : ''}`);
          pollTimer = window.setTimeout(poll, 750);
          return;
        }
        if (state === 'COMPLETED' && job.scan_id) {
          setLiveStatus('Đang tải metadata và findings của scan từ backend');
          window.clearInterval(timerRef.current);
          setElapsedMs(Date.now() - startRef.current);
          try {
            const data = await loadLiveScan(job.scan_id, controller.signal);
            if (stopped) return;
            setLiveCounts(data.counts);
            const total = Number(data.scan?.total_e2e_duration_ms);
            setBackendMs(Number.isFinite(total) ? total : null);
            setLiveStage('COMPLETED');
            setLiveStatus('Hoàn tất: đã nhận và đối chiếu scan_id, metadata và findings từ backend');
          } catch (failure) {
            if (!stopped && !controller.signal.aborted) setError(`Job đã hoàn tất nhưng không tải được findings: ${failure.message}`);
          }
          setBusy(false);
          return;
        }
        if (state === 'FAILED') {
          window.clearInterval(timerRef.current);
          if (startRef.current) setElapsedMs(Date.now() - startRef.current);
          setBusy(false);
          setLiveStatus('Backend đã dừng job với trạng thái FAILED');
          setError(job.error_message || (typeof job.error === 'string' ? job.error : job.error?.message) || job.message || 'Backend đã đánh dấu job là FAILED.');
          if (job.scan_id) upsertHistory({scanId: job.scan_id, status: 'FAILED'});
          return;
        }
        setLiveStatus('Backend trả về trạng thái job chưa xác định; sẽ thử GET lại.');
        pollTimer = window.setTimeout(poll, 1500);
      } catch (failure) {
        if (!stopped && !controller.signal.aborted) {
          setInterrupted(true);
          setLiveStatus(`Mất kết nối khi polling; sẽ thử GET lại. ${failure.message}`);
          pollTimer = window.setTimeout(poll, 1500);
        }
      }
    };

    poll();
    return () => {
      stopped = true;
      window.clearTimeout(pollTimer);
      controller.abort();
    };
  }, [jobId]);

  useEffect(() => {
    if (jobId) return undefined;
    const scanId = window.sessionStorage.getItem('22025523-scan-id');
    if (!scanId) return undefined;
    const controller = new AbortController();
    setLiveScanId(scanId);
    loadLiveScan(scanId, controller.signal)
      .then((data) => {
        setLiveCounts(data.counts);
        setLiveStage('COMPLETED');
        const total = Number(data.scan?.total_e2e_duration_ms);
        setBackendMs(Number.isFinite(total) ? total : null);
      })
      .catch((failure) => {
        if (!controller.signal.aborted) setError(failure.message);
      });
    return () => controller.abort();
  }, [jobId]);

  const startLive = async () => {
    if (pendingRef.current) return;
    setError('');
    if (backend.status !== 'CONNECTED') {
      const statusMessage = backend.status === 'CHECKING'
        ? 'Đang kiểm tra backend. Vui lòng thử lại sau khi kiểm tra hoàn tất.'
        : 'Backend chưa được xác nhận kết nối. Hãy kiểm tra trạng thái API trước khi chạy LIVE.';
      setError(statusMessage);
      setLiveStatus(statusMessage);
      return;
    }
    if (tab !== 'github') {
      setError('API tải ZIP trực tiếp chưa được đối chiếu với hợp đồng backend. Vui lòng dùng URL GitHub trong lúc chờ xác nhận.');
      return;
    }
    if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(url.trim())) {
      setError('Nhập URL repository GitHub công khai hợp lệ.');
      return;
    }
    pendingRef.current = true;
    const controller = new AbortController();
    requestRef.current = controller;
    const startedAt = new Date().toISOString();
    let submittedId = '';
    setBusy(true);
    setLiveJob(null);
    setJobId('');
    setLiveCounts(null);
    setLiveScanId('');
    setLiveStatus('Đang gửi yêu cầu phân tích');
    setLiveStage('SUBMITTING');
    setBackendMs(null);
    setElapsedMs(0);
    startRef.current = Date.now();
    window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => setElapsedMs(Date.now() - startRef.current), 250);
    scrollToSimulation();
    try {
      setLiveStage('WAITING_FOR_RESPONSE');
      setLiveStatus('Đang chờ backend tạo job phân tích');
      const result = await api.createScanJob(url.trim(), undefined, {signal: controller.signal});
      if (typeof result?.job_id !== 'string' || !result.job_id) {
        throw new Error('Backend chưa trả về job_id theo hợp đồng hiện tại. Không thể theo dõi job này.');
      }
      submittedId = result.scan_id || '';
      window.sessionStorage.setItem(JOB_KEY, result.job_id);
      window.sessionStorage.setItem(JOB_KEY + '-started', String(startRef.current));
      if (submittedId) {
        window.sessionStorage.setItem('22025523-scan-id', submittedId);
        setLiveScanId(submittedId);
        upsertHistory({scanId: submittedId, jobId: result.job_id, repoUrl: url.trim(), inputMode: 'GITHUB', startedAt, status: result.state || 'QUEUED'});
      }
      setJobId(result.job_id);
      setLiveJob(result);
      setLiveStage(String(result.state || 'QUEUED').toUpperCase());
      setLiveStatus('Đã nhận job từ backend');
    } catch (failure) {
      if (!controller.signal.aborted) {
        setError(failure.message?.startsWith('Backend') ? failure.message : `Không thể kết nối máy chủ phân tích. Vui lòng kiểm tra dịch vụ backend trước khi chạy quét trực tiếp. ${failure.message || ''}`);
        setLiveStatus('Không thể xác nhận trạng thái quét');
        setLiveStage('FAILED');
        setBusy(false);
        window.clearInterval(timerRef.current);
      }
    } finally {
      pendingRef.current = false;
      requestRef.current = null;
    }
  };

  const backendStatusMessage = {
    CHECKING: 'Đang kiểm tra backend',
    CONNECTED: `Backend đã kết nối${backend.health?.service ? ` · ${backend.health.service}` : ''}`,
    DISCONNECTED: 'Backend chưa kết nối',
    ERROR: 'Không thể xác minh backend'
  }[backend.status] || 'Chưa xác minh trạng thái backend';

  const latest = readHistory().find((record) => record.status === 'COMPLETED');
  const resultId = liveScanId || latest?.scanId || '';
  const stageIndex = currentStageIndex(liveJob);
  const activeStage = stageIndex === null ? null : stageIndex + 1;
  const livePhase = activeStage || 0;
  const jobFailed = String(liveJob?.state || '').toUpperCase() === 'FAILED';

  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Phân tích dự án" description="Phân tích mã nguồn Java bằng OpenGrep, IRIS và Qwen LoRA. Tiến trình 10 giai đoạn được đồng bộ theo dữ liệu thực từ backend." actions={<Badge tone="green">LIVE API</Badge>} />
      <div className="scanner-layout">
        <div className="scanner-main">
          <div className="tab-switcher">
            <button className={tab === 'github' ? 'active' : ''} onClick={() => setTab('github')}><Icon name="Github" />GitHub Repository</button>
            <button className={tab === 'zip' ? 'active' : ''} onClick={() => setTab('zip')}><Icon name="Archive" />Tải tệp ZIP</button>
          </div>
          <Card className="scanner-input-card">
            {tab === 'github' ? (
              <div className="input-section">
                <label htmlFor="repo-url">URL repository Java công khai</label>
                <div className="input-with-icon">
                  <Icon name="Github" />
                  <input id="repo-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://github.com/owner/repository" />
                  <Badge>HTTPS</Badge>
                </div>
                <p>Branch hoặc commit có thể cấu hình khi API backend hỗ trợ.</p>
              </div>
            ) : (
              <button className={`dropzone ${file ? 'has-file' : ''}`} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => {event.preventDefault(); setFile(event.dataTransfer.files[0] || null);}}>
                <input ref={inputRef} type="file" accept=".zip,application/zip" hidden onChange={(event) => setFile(event.target.files[0] || null)} />
                <span className="drop-icon"><Icon name={file ? 'FileArchive' : 'UploadCloud'} /></span>
                <strong>{file?.name || 'Kéo thả tệp ZIP vào đây'}</strong>
                <span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : 'hoặc chọn tệp từ thiết bị · chỉ hỗ trợ .zip'}</span>
                <span className="button-secondary">{file ? 'Chọn tệp khác' : 'Chọn tệp ZIP'}</span>
              </button>
            )}
            {tab === 'zip' && <div className="inline-warning"><Icon name="AlertTriangle" />Tải ZIP LIVE đang chờ xác nhận hợp đồng API.</div>}
            {error && <div className="inline-error" role="alert"><Icon name="AlertTriangle" />{error}</div>}
            <div className="scanner-submit">
              <div><strong>Phạm vi phân tích</strong><span>Java source · OpenGrep · IRIS · Qwen LoRA</span></div>
              <button className="button-primary" disabled={busy} onClick={startLive}>
                <Icon name="ScanSearch" />{busy ? 'Đang phân tích…' : 'Bắt đầu phân tích'}<Icon name="ArrowRight" />
              </button>
            </div>
          </Card>
        </div>
        <aside className="scanner-aside">
          <StageOverview job={liveJob} />
          <Card title="Phạm vi và tính minh bạch">
            <ul className="clean-list">
              <li>Giải nén an toàn và kiểm tra archive thuộc backend.</li>
              <li>ZIP LIVE chỉ hoạt động khi API chính thức sẵn sàng.</li>
              <li>Mọi kết quả và tiến trình đều lấy từ backend; không có dữ liệu giả.</li>
              <li>REPORT chưa đồng nghĩa chuyên gia đã xác nhận.</li>
            </ul>
          </Card>
        </aside>
      </div>
      <div ref={simulationRef} className="simulation-anchor">
        <SecurityAnalysisScene live={{stage: liveStage, state: String(liveJob?.state || liveStage).toUpperCase(), activeStage: liveStage === 'COMPLETED' ? 10 : activeStage, stages: liveJob?.stages || [], counts: liveCounts, interrupted}} phase={livePhase} elapsedMs={elapsedMs} running={busy} />
        <section className="card live-scan-status" aria-live="polite">
          <span className="eyebrow">LIVE API · TRẠNG THÁI TỪ BACKEND</span>
          <h2>Phiên phân tích trực tiếp</h2>
          <p>{liveStatus || backendStatusMessage}</p>
          <p>Trạng thái vòng đời: <code>{liveStage}</code></p>
          {interrupted && <p className="inline-warning">Gián đoạn kết nối: đang giữ trạng thái đã xác minh gần nhất và thử GET lại.</p>}
          <p>Thời gian kể từ lúc gửi yêu cầu (đo tại trình duyệt, không phải thời gian thực thi backend): <strong>{Math.floor(elapsedMs / 1000)} giây</strong></p>
          {backendMs !== null && <p>Thời gian xử lý do backend báo cáo (total_e2e_duration_ms): <strong>{(backendMs / 1000).toFixed(2)} giây</strong></p>}
          {liveScanId && <p>Mã phiên: <code>{liveScanId}</code></p>}
          {liveStage === 'COMPLETED' && liveCounts && liveCounts.total === 0 && <p>Không phát hiện finding nào trong ruleset hiện tại và phạm vi mã nguồn đã phân tích. Điều này không khẳng định ứng dụng Java an toàn.</p>}
          {busy && <p>Đang phân tích — chưa có thời gian hoàn tất dự kiến.</p>}
          {resultId && <Link className="button-secondary" to={`/findings${scanQuery(resultId)}`}>{liveScanId ? 'Mở trang kết quả' : `Mở phiên gần nhất · ${resultId}`}</Link>}
          {liveScanId && !busy && <Link className="button-secondary" to={`/replay?scan=${encodeURIComponent(liveScanId)}`}>Phát lại trace đã ghi</Link>}
        </section>
        {jobFailed && <FailureDetails job={liveJob} />}
        {liveJob && <StageTiming job={liveJob} counts={liveCounts} />}
        {liveJob && <CoveragePanel job={liveJob} counts={liveCounts} />}
      </div>
    </>
  );
}