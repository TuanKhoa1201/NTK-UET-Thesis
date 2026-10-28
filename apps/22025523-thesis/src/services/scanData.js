const STORAGE_KEY = '22025523-live-scan-history';
const MAX_RECORDS = 20;

const firstValue = (object, keys) => {
  if (!object || typeof object !== 'object') return undefined;
  for (const key of keys) {
    if (object[key] !== undefined && object[key] !== null && object[key] !== '') return object[key];
  }
  return undefined;
};

function findArray(payload, keys, depth = 0) {
  if (depth > 5 || !payload || typeof payload !== 'object') return null;
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  for (const key of ['data', 'result', 'scan', 'payload', 'response']) {
    const found = findArray(payload[key], keys, depth + 1);
    if (found) return found;
  }
  return null;
}

function findValue(payload, keys, depth = 0) {
  if (depth > 5 || !payload || typeof payload !== 'object') return undefined;
  const value = firstValue(payload, keys);
  if (value !== undefined) return value;
  for (const key of ['data', 'result', 'scan', 'payload', 'response', 'summary', 'metrics']) {
    const found = findValue(payload[key], keys, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

export function normalizeFinding(item) {
  const location = item?.location || item?.source_location || {};
  const scoreValue = firstValue(item, ['final_heuristic_score', 'confidence_score', 'final_score', 'sast_score', 'heuristic_score', 'score'])
    ?? firstValue(item?.evidence_fusion, ['final_heuristic_score', 'confidence_score', 'final_score', 'score']);
  const score = scoreValue === undefined ? null : Number(scoreValue);

  return {
    id: firstValue(item, ['finding_id', 'candidate_id', 'id', 'key']) ?? '',
    title: firstValue(item, ['title', 'name', 'rule_name', 'message', 'type']) ?? '',
    cwe: firstValue(item, ['cwe', 'cwe_id', 'weakness_id']) ?? '',
    file: firstValue(item, ['file_path', 'source_file', 'path', 'file']) ?? location.file ?? location.path ?? '',
    line: firstValue(item, ['line_number', 'source_line', 'line']) ?? location.line ?? '',
    severity: firstValue(item, ['severity', 'priority', 'risk_level']) ?? '',
    score: Number.isFinite(score) ? score : null,
    scoreBreakdown: firstValue(item, ['score_breakdown']) ?? firstValue(item?.evidence_fusion, ['score_breakdown']),
    decision: firstValue(item, ['triage_decision', 'decision', 'policy_decision', 'triage']) ?? '',
    role: firstValue(item, ['api_role', 'role', 'classification']) ?? '',
    evidence: firstValue(item, ['evidence', 'evidence_summary', 'dataflow', 'ast_evidence']),
    raw: item
  };
}

export function extractFindings(payload) {
  const rows = findArray(payload, ['findings', 'alerts', 'candidates', 'results', 'items']);
  return Array.isArray(rows) ? rows.map(normalizeFinding) : [];
}

export function getScanMetrics(payload, findings = extractFindings(payload)) {
  const candidateTotal = findValue(payload, ['total_candidates', 'candidate_count', 'total_findings', 'findings_count']);
  const retained = findValue(payload, ['retained_alerts', 'retained_count', 'alerts_retained']);
  const countByDecision = (decision) => findings.filter((item) => String(item.decision).toUpperCase() === decision).length;

  return {
    candidates: Number.isFinite(Number(candidateTotal)) ? Number(candidateTotal) : findings.length || null,
    retained: retained === undefined ? null : Number(retained),
    report: countByDecision('REPORT'),
    review: countByDecision('REVIEW'),
    suppress: countByDecision('SUPPRESS')
  };
}

export function getScanId(payload) {
  const value = findValue(payload, ['scan_id', 'scanId', 'id']);
  return typeof value === 'string' || typeof value === 'number' ? String(value) : '';
}

export function readScanHistory() {
  try {
    const records = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) || '[]');
    return Array.isArray(records) ? records : [];
  } catch {
    return [];
  }
}

export function saveScanRecord(record) {
  const history = readScanHistory();
  const records = [record, ...history.filter((item) => item.sessionKey !== record.sessionKey)].slice(0, MAX_RECORDS);
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(records));
  } catch {
    return records;
  }
  return records;
}

export function removeScanRecord(scanId) {
  const records = readScanHistory().filter((item) => item?.scanId !== scanId && item?.sessionKey !== scanId);
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(records));
  } catch {
    return records;
  }
  return records;
}

export function getLatestLiveScan() {
  return readScanHistory()[0] || null;
}

export function getRecordFindings(record) {
  if (!record) return [];
  const payload = record.findingsPayload ?? record.raw;
  return extractFindings(payload);
}

export function getRecordMetrics(record) {
  return getScanMetrics(record?.findingsPayload ?? record?.raw, getRecordFindings(record));
}