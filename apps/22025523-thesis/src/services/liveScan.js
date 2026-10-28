import {useEffect, useState} from 'react';
import {useSearchParams} from 'react-router-dom';
import {api, ApiError} from './api';
import {normalizeFinding, saveScanRecord} from './scanData';
import {pick, upsertHistory} from './scanHistory';

export const ACTIVE_KEY = '22025523-scan-id';
const DEMO_KEY = '22025523-demo-result';
const CACHE_PREFIX = '22025523-live-dataset:';
const DECISIONS = ['REPORT', 'REVIEW', 'SUPPRESS'];
const COLLECTIONS = [
  ['findings', ''],
  ['reported_findings', 'REPORT'],
  ['review_queue_findings', 'REVIEW'],
  ['suppressed_findings_audit_log', 'SUPPRESS']
];
export const DURATION_FIELDS = [
  ['latency_ms', 'Độ trễ API'],
  ['javac_duration_ms', 'javac'],
  ['opengrep_duration_ms', 'OpenGrep'],
  ['ast_analysis_duration_ms', 'AST / IRIS'],
  ['llm_inference_duration_ms', 'LLM inference'],
  ['source_verification_duration_ms', 'Xác minh nguồn'],
  ['total_e2e_duration_ms', 'Tổng E2E (backend)']
];

export function buildDataset(scanId, scan, findingsPayload) {
  const map = new Map();
  COLLECTIONS.forEach(([key, fallback]) => {
    const list = Array.isArray(findingsPayload?.[key]) ? findingsPayload[key] : [];
    list.forEach((item, index) => {
      const flat = item && typeof item.finding === 'object' ? {...item.finding, ...item} : item;
      const row = normalizeFinding(flat);
      const own = String(row.decision || '').toUpperCase();
      row.decision = DECISIONS.includes(own) ? own : fallback;
      row.collections = [key];
      if (!row.id) row.id = `${key}#${index}`;
      const existing = map.get(row.id);
      if (existing) {
        if (!existing.decision && row.decision) existing.decision = row.decision;
        existing.collections.push(key);
      } else {
        map.set(row.id, row);
      }
    });
  });
  const rows = [...map.values()];
  const count = (decision) => rows.filter((row) => row.decision === decision).length;
  return {
    scanId,
    scan,
    findingsPayload,
    rows,
    counts: {total: rows.length, report: count('REPORT'), review: count('REVIEW'), suppress: count('SUPPRESS'), unclassified: rows.filter((row) => !row.decision).length}
  };
}

function writeCache(scanId, scan, findingsPayload) {
  try {
    window.sessionStorage.setItem(CACHE_PREFIX + scanId, JSON.stringify({scan, findingsPayload}));
  } catch {
    /* cache is optional */
  }
}

function readCache(scanId) {
  try {
    const cached = JSON.parse(window.sessionStorage.getItem(CACHE_PREFIX + scanId) || 'null');
    return cached ? buildDataset(scanId, cached.scan, cached.findingsPayload) : null;
  } catch {
    return null;
  }
}

function recordHistory(dataset) {
  const {scanId, scan, counts} = dataset;
  const verification = scan?.source_provenance_verification;
  const backendDuration = scan?.total_e2e_duration_ms;
  const backendMs = backendDuration === null || backendDuration === undefined ? undefined : Number(backendDuration);
  upsertHistory({
    scanId,
    status: 'COMPLETED',
    completedAt: scan?.completed_at ?? scan?.finished_at ?? new Date().toISOString(),
    candidates: counts.total,
    report: counts.report,
    review: counts.review,
    suppress: counts.suppress,
    backendMs: Number.isFinite(backendMs) ? backendMs : undefined,
    repoUrl: pick(scan?.repository_provenance, ['repo_url', 'repository_url', 'url']),
    commit: pick(scan?.repository_provenance, ['commit_sha', 'resolved_commit_sha', 'commit']),
    verification: typeof verification === 'string' ? verification : pick(verification, ['status', 'verification_status'])
  });
}

export async function loadLiveScan(scanId, signal) {
  const options = {signal, timeoutMs: 60000};
  const [scan, findingsPayload] = await Promise.all([api.scan(scanId, options), api.findings(scanId, options)]);
  if (scan?.scan_id !== scanId) throw new Error('Phản hồi metadata không khớp scan_id đã chọn.');
  if (findingsPayload?.scan_id !== scanId) throw new Error('Phản hồi findings không khớp scan_id đã chọn.');
  writeCache(scanId, scan, findingsPayload);
  window.sessionStorage.setItem(ACTIVE_KEY, scanId);
  window.sessionStorage.removeItem(DEMO_KEY);
  saveScanRecord({sessionKey: scanId, scanId, raw: scan, findingsPayload, savedAt: new Date().toISOString()});
  const dataset = buildDataset(scanId, scan, findingsPayload);
  recordHistory(dataset);
  return dataset;
}

function describe(error) {
  if (error instanceof ApiError && error.status === 404) return 'Scan này không còn tồn tại trên backend (HTTP 404). Không có dữ liệu thay thế nào được hiển thị.';
  if (error instanceof ApiError && error.timedOut) return 'Backend không phản hồi trong thời gian cho phép.';
  return error?.message || 'Không thể tải scan từ backend.';
}

export function useScanSelection() {
  const [params] = useSearchParams();
  const queryId = params.get('scan_id') || '';
  const scanId = queryId || window.sessionStorage.getItem(ACTIVE_KEY) || '';
  const demo = window.sessionStorage.getItem(DEMO_KEY) === 'true';
  const mode = scanId ? 'live' : demo ? 'demo' : 'none';
  const [state, setState] = useState({id: '', status: 'idle', data: null, error: ''});

  useEffect(() => {
    if (!scanId) return undefined;
    window.sessionStorage.setItem(ACTIVE_KEY, scanId);
    const cached = readCache(scanId);
    if (cached) {
      setState({id: scanId, status: 'ready', data: cached, error: ''});
      return undefined;
    }
    const controller = new AbortController();
    setState({id: scanId, status: 'loading', data: null, error: ''});
    loadLiveScan(scanId, controller.signal)
      .then((data) => setState({id: scanId, status: 'ready', data, error: ''}))
      .catch((error) => {
        if (!controller.signal.aborted) setState({id: scanId, status: 'error', data: null, error: describe(error)});
      });
    return () => controller.abort();
  }, [scanId]);

  const current = state.id === scanId ? state : {status: scanId ? 'loading' : 'idle', data: null, error: ''};
  return {mode, scanId, status: current.status, data: current.data, error: current.error};
}

export const scanQuery = (scanId) => (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '');

export function evidenceText(row) {
  const evidence = row.evidence;
  if (evidence === undefined || evidence === null) return 'Backend không cung cấp evidence tóm tắt cho finding này.';
  const text = typeof evidence === 'string' ? evidence : JSON.stringify(evidence);
  return text.length > 400 ? `${text.slice(0, 400)}…` : text;
}