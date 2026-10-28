import {useEffect, useState} from 'react';
import {Link, useSearchParams} from 'react-router-dom';
import {Card, PageHeader, DataNotice, Icon} from '../components/common/Ui';
import ScanStageVisual from '../components/scanner/ScanStageVisual';
import {scanGuide} from '../data/scanGuide';
import {api} from '../services/api';
import {fmtMs, resolveStages} from '../services/jobModel';
import {scanQuery} from '../services/liveScan';

function traceStages(trace) {
  const list = trace?.stages ?? trace?.pipeline_trace?.stages ?? trace?.trace?.stages ?? trace?.events;
  return Array.isArray(list) ? list : [];
}

export default function TraceReplay() {
  const [params, setParams] = useSearchParams();
  const scanId = params.get('scan') || '';
  const [input, setInput] = useState(scanId);
  const [trace, setTrace] = useState(null);
  const [error, setError] = useState('');
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  useEffect(() => {
    if (!scanId) return undefined;
    const controller = new AbortController();
    setTrace(null);
    setError('');
    setIndex(0);
    api.pipelineTrace(scanId, {signal: controller.signal})
      .then(setTrace)
      .catch((failure) => { if (!controller.signal.aborted) setError(failure.message || 'Không tải được trace.'); });
    return () => controller.abort();
  }, [scanId]);

  useEffect(() => {
    if (!playing) return undefined;
    const timer = window.setTimeout(() => {
      if (index >= 9) setPlaying(false);
      else setIndex(index + 1);
    }, 1400 / speed);
    return () => window.clearTimeout(timer);
  }, [playing, index, speed]);

  const stages = resolveStages({state: 'COMPLETED', stages: traceStages(trace)});
  const step = scanGuide[index];
  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Phát lại trace đã ghi" description="Chế độ Recorded Replay: chỉ đọc trace đã lưu (GET), không tạo scan mới." />
      <DataNotice>Thời gian phát lại chỉ là thời lượng trình diễn. Duration trong bảng là số liệu backend đã ghi.</DataNotice>
      <Card className="scanner-input-card">
        <div className="table-toolbar">
          <input value={input} onChange={(event) => setInput(event.target.value)} placeholder="SCAN-..." />
          <button className="button-secondary" onClick={() => setParams(input ? {scan: input.trim()} : {})}>Tải trace</button>
          {scanId && <Link className="button-secondary" to={`/findings${scanQuery(scanId)}`}>Xem findings</Link>}
        </div>
      </Card>
      {error && <div className="inline-error" role="alert">{error}</div>}
      {trace && (
        <>
          <div className="guided-actions">
            <button className="button-secondary" onClick={() => setPlaying((value) => !value)}><Icon name={playing ? 'Pause' : 'Play'} />{playing ? 'Tạm dừng' : 'Phát'}</button>
            <button className="button-secondary" disabled={index === 0} onClick={() => setIndex(index - 1)}>Trước</button>
            <button className="button-secondary" disabled={index === 9} onClick={() => setIndex(index + 1)}>Sau</button>
            <button className="button-secondary" onClick={() => { setIndex(0); setPlaying(false); }}>Về đầu</button>
            {[0.5, 1, 2].map((value) => <button key={value} className={`button-secondary ${speed === value ? 'active' : ''}`} onClick={() => setSpeed(value)}>{value}×</button>)}
          </div>
          <ScanStageVisual step={step} index={index} previous={index > 0 ? scanGuide[index - 1] : null} next={index < 9 ? scanGuide[index + 1] : null} live />
          <Card className="table-card">
            <div className="table-wrap">
              <table>
                <thead><tr><th>#</th><th>Stage</th><th>Backend state</th><th>Duration (backend)</th></tr></thead>
                <tbody>{stages.map((stage) => <tr key={stage.key} className={index === stage.number - 1 ? 'active' : ''} onClick={() => setIndex(stage.number - 1)}><td>{String(stage.number).padStart(2, '0')}</td><td>{stage.name}</td><td>{stage.label}{stage.reason ? ` · ${stage.reason}` : ''}</td><td>{fmtMs(stage.duration)}</td></tr>)}</tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </>
  );
}