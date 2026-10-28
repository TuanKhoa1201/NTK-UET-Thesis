import {useEffect, useState} from 'react';
import {Link} from 'react-router-dom';
import {Card, PageHeader, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import {ApiError, api} from '../services/api';
import {scanQuery} from '../services/liveScan';
import {readHistory, upsertHistory, hideHistoryRecord, readHiddenHistory, restoreHistoryRecord} from '../services/scanHistory';

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString('vi-VN') : '—');
const fmtMs = (ms) => (Number.isFinite(ms) ? `${(ms / 1000).toFixed(2)} giây` : '—');

function useAvailability(records) {
  const [map, setMap] = useState({});
  const ids = records.map((item) => item.scanId).join('|');
  useEffect(() => {
    const controller = new AbortController();
    records.forEach((item) => {
      api.scan(item.scanId, {signal: controller.signal, timeoutMs: 15000})
        .then(() => setMap((prev) => ({...prev, [item.scanId]: 'ok'})))
        .catch((error) => {
          if (controller.signal.aborted) return;
          setMap((prev) => ({...prev, [item.scanId]: error instanceof ApiError && error.status === 404 ? 'gone' : 'unknown'}));
        });
    });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids]);
  return map;
}

function Row({record, availability, onDelete}) {
  const gone = availability === 'gone';
  const traceOnly = String(record.restoration || '').includes('TRACE_ONLY');
  const tone = record.status === 'COMPLETED' ? 'green' : record.status === 'FAILED' ? 'red' : 'amber';
  const running = ['RUNNING', 'QUEUED'].includes(String(record.status).toUpperCase());
  return (
    <Card className="report-row">
      <div>
        <Badge tone={tone}>{record.status === 'COMPLETED' ? 'HOÀN TẤT' : record.status === 'FAILED' ? 'THẤT BẠI' : 'CHƯA XÁC NHẬN'}</Badge>
        {record.restoration && <Badge tone="blue">{record.restoration}</Badge>}
        <h3 className="mono">{record.scanId}</h3>
        <p>{record.repoUrl || record.fileName || '—'}{record.commit ? ` · ${record.commit.slice(0, 12)}` : ''} · {record.inputMode || 'GITHUB'}</p>
        <p>Bắt đầu: {fmtDate(record.startedAt || record.savedAt)} · Hoàn tất: {fmtDate(record.completedAt)} · Backend: {fmtMs(record.backendMs)}</p>
        {traceOnly && <p>Chỉ khôi phục trace: không có chi tiết findings và hệ thống không dựng lại findings.</p>}
        {record.status === 'COMPLETED'
          ? <p>{record.candidates ?? '—'} ứng viên · REPORT {record.report ?? '—'} · REVIEW {record.review ?? '—'} · SUPPRESS {record.suppress ?? '—'}{record.verification ? ` · Nguồn: ${record.verification}` : ''}</p>
          : record.status === 'FAILED'
            ? <p>Backend báo job thất bại; mở trace để xem stage lỗi và duration đã ghi.</p>
            : <p>Phiên đã gửi nhưng kết quả chưa được tải thành công.</p>}
        {gone && <p className="inline-error">Phiên này không còn khả dụng trên backend hiện tại.</p>}
        {availability === 'unknown' && <p>Chưa kiểm tra được trạng thái trên backend.</p>}
      </div>
      <div className="history-actions">
        {!traceOnly && <Link to={`/findings${scanQuery(record.scanId)}`} className="button-secondary">Xem findings <Icon name="ArrowRight" /></Link>}
        {!traceOnly && <Link to={`/reports${scanQuery(record.scanId)}`} className="button-secondary"><Icon name="FileText" />Báo cáo</Link>}
        <Link to={`/replay?scan=${encodeURIComponent(record.scanId)}`} className="button-secondary"><Icon name="Play" />Phát lại trace</Link>
        <button className="button-secondary history-delete" type="button" disabled={running} aria-label={`Ẩn ${record.scanId} khỏi lịch sử`} onClick={() => onDelete(record)}><Icon name="Trash2" />Xóa</button>
      </div>
    </Card>
  );
}

function ConfirmHide({record, onCancel, onConfirm}) {
  if (!record) return null;
  const source = record.inputMode === 'ZIP' ? (record.fileName || 'Tệp ZIP') : (record.repoUrl || '—');
  return (
    <div className="history-dialog-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <section className="history-dialog card" role="dialog" aria-modal="true" aria-labelledby="history-delete-title">
        <span className="eyebrow">ẨN PHIÊN TRÊN TRÌNH DUYỆT NÀY</span>
        <h2 id="history-delete-title">Xác nhận xóa khỏi lịch sử</h2>
        <p>Scan ID: <code>{record.scanId}</code></p>
        <p>Repository / tệp ZIP: <span className="wrap-value">{source}</span></p>
        <p>Ngày: {fmtDate(record.startedAt || record.savedAt)}</p>
        <p>Trạng thái: {record.status || 'Chưa xác nhận'}</p>
        <p className="history-dialog-warning">Thao tác này chỉ ẩn phiên trong lịch sử của trình duyệt hiện tại; không xóa dữ liệu hoặc artifact trên backend.</p>
        <p>Bạn có chắc chắn muốn xóa phiên phân tích này khỏi lịch sử?</p>
        <div className="history-dialog-actions">
          <button className="button-secondary" type="button" onClick={onCancel}>Hủy</button>
          <button className="button-secondary history-delete" type="button" onClick={onConfirm}><Icon name="Trash2" />Xóa</button>
        </div>
      </section>
    </div>
  );
}

export default function HistoryPage() {
  const [records, setRecords] = useState(() => readHistory());
  const [hiddenRecords, setHiddenRecords] = useState(() => readHiddenHistory());
  const [gap, setGap] = useState('');
  const [pendingDelete, setPendingDelete] = useState(null);
  const [notice, setNotice] = useState('');
  const availability = useAvailability(records);
  const demo = window.sessionStorage.getItem('22025523-demo-result') === 'true';

  useEffect(() => {
    const controller = new AbortController();
    (async () => {
      let supported = false;
      for (const load of [api.listScanJobs, api.listScans]) {
        try {
          const result = await load({signal: controller.signal});
          if (!result.supported) continue;
          supported = true;
          result.items.forEach((item) => {
            const scanId = item.scan_id ?? item.id;
            if (!scanId) return;
            upsertHistory({
              scanId,
              jobId: item.job_id,
              repoUrl: item.repo_url,
              fileName: item.file_name,
              inputMode: item.input_mode,
              status: String(item.state ?? item.status ?? '').toUpperCase() || undefined,
              startedAt: item.created_at ?? item.started_at,
              completedAt: item.completed_at ?? item.finished_at,
              backendMs: item.total_e2e_duration_ms,
              restoration: item.restoration_type ?? item.restoration_status
            });
          });
        } catch {
          /* list endpoint unavailable or network error; cached IDs still shown */
        }
      }
      if (controller.signal.aborted) return;
      if (!supported) setGap('API gap: backend chưa công bố endpoint danh sách (GET /api/scan-jobs, GET /api/scans không khả dụng hoặc lỗi). Chỉ hiển thị các scan_id đã biết và đối chiếu từng ID với backend.');
      setRecords(readHistory());
      setHiddenRecords(readHiddenHistory());
    })();
    return () => controller.abort();
  }, []);

  const confirmHide = () => {
    if (!pendingDelete) return;
    hideHistoryRecord(pendingDelete);
    setRecords(readHistory());
    setHiddenRecords(readHiddenHistory());
    setNotice(`Đã ẩn ${pendingDelete.scanId} khỏi lịch sử trên trình duyệt này. Không có dữ liệu backend nào bị xóa.`);
    setPendingDelete(null);
  };

  const restore = (scanId) => {
    restoreHistoryRecord(scanId);
    setRecords(readHistory());
    setHiddenRecords(readHiddenHistory());
    setNotice(`Đã khôi phục ${scanId} vào lịch sử trên trình duyệt này.`);
  };

  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Lịch sử phân tích" description="Danh sách scan được nạp từ backend khi API hỗ trợ, đối chiếu với các scan_id đã xem trên trình duyệt này." />
      <DataNotice>{gap || 'Lịch sử được đối chiếu với backend theo danh sách job/scan đã lưu bền vững; localStorage chỉ là cache các scan_id đã xem. Xóa chỉ ẩn cục bộ, không xóa scan backend.'}</DataNotice>
      {notice && <div className="inline-success" role="status">{notice}</div>}
      {records.length === 0
        ? <EmptyState title="Chưa có phiên phân tích" text="Chạy một scan LIVE để phiên được ghi lại tại đây." icon="Clock" />
        : records.map((record) => <Row key={record.scanId} record={record} availability={availability[record.scanId]} onDelete={setPendingDelete} />)}
      {hiddenRecords.length > 0 && (
        <section className="section-block">
          <h2>Đã ẩn trên trình duyệt này</h2>
          <p className="muted-text">Các phiên vẫn còn trên backend. Khôi phục sẽ bỏ tùy chọn ẩn cục bộ.</p>
          {hiddenRecords.map((record) => (
            <Card className="report-row" key={record.scanId}>
              <div><Badge tone="neutral">ĐÃ ẨN CỤC BỘ</Badge><h3 className="mono">{record.scanId}</h3><p>{record.repoUrl || record.fileName || '—'} · {record.status || 'Chưa xác nhận'}</p></div>
              <button className="button-secondary" type="button" onClick={() => restore(record.scanId)}><Icon name="RotateCcw" />Khôi phục</button>
            </Card>
          ))}
        </section>
      )}
      {demo && <Card className="report-row"><div><Badge tone="amber">MINH HỌA</Badge><h3>Java Security Sample</h3><p>Phiên demo synthetic, tách biệt khỏi lịch sử LIVE.</p></div><Link to="/results" className="button-secondary">Mở kết quả <Icon name="ArrowRight" /></Link></Card>}
      <ConfirmHide record={pendingDelete} onCancel={() => setPendingDelete(null)} onConfirm={confirmHide} />
    </>
  );
}