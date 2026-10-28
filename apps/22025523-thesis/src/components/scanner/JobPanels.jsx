import {useEffect, useState} from 'react';
import {Card, DataNotice} from '../common/Ui';
import {api} from '../../services/api';
import {errorInfo, fmtMs, resolveStages, skipNote} from '../../services/jobModel';

function JsonDetails({summary, title}) {
  if (summary === null || summary === undefined) return null;
  return (
    <details className="technical-details">
      <summary>{title}</summary>
      <pre><code>{typeof summary === 'string' ? summary : JSON.stringify(summary, null, 2)}</code></pre>
    </details>
  );
}

export function StageOverview({job}) {
  const stages = resolveStages(job);
  return (
    <Card title="10 giai đoạn của backend">
      <div className="mini-pipeline">
        {stages.map((stage) => (
          <div key={stage.key} className={`stage-cat-${stage.cat}`} title={stage.key}>
            <span>{String(stage.number).padStart(2, '0')}</span>{stage.name}{stage.number < 10 && <i />}
          </div>
        ))}
      </div>
      <p className="panel-note">Trạng thái từng giai đoạn chỉ được cập nhật theo telemetry backend.</p>
    </Card>
  );
}

export function FailureDetails({job}) {
  const info = errorInfo(job);
  const failed = resolveStages(job).find((stage) => stage.cat === 'FAILED');
  return (
    <section className="card failure-details" role="alert">
      <span className="eyebrow">JOB FAILED · CHẨN ĐOÁN TỪ BACKEND</span>
      <h2>{failed ? `Thất bại tại Stage ${String(failed.number).padStart(2, '0')} · ${failed.name}` : 'Backend báo job FAILED'}</h2>
      <dl className="kv-list">
        <dt>error_code</dt><dd className="mono">{info.code || 'Backend không cung cấp'}</dd>
        <dt>error_message</dt><dd>{info.message || 'Backend không cung cấp'}</dd>
        {failed && <><dt>Stage key</dt><dd className="mono">{failed.key}</dd><dt>Duration đã đo</dt><dd>{fmtMs(failed.duration)}</dd></>}
        {failed?.error && <><dt>Lỗi của stage</dt><dd>{failed.error}</dd></>}
      </dl>
      {failed?.summary && <><h3>Summary metadata của stage</h3><JsonDetails summary={failed.summary} title="Mở metadata stage" /></>}
      {info.limits && <><h3>Giới hạn tài nguyên / chi tiết do backend báo</h3><JsonDetails summary={info.limits} title="Mở chi tiết giới hạn" /></>}
      {info.steps.length > 0 && <><h3>Hướng xử lý do backend đề xuất</h3><ul className="clean-list">{info.steps.map((step) => <li key={String(step)}>{typeof step === 'string' ? step : JSON.stringify(step)}</li>)}</ul></>}
    </section>
  );
}

export function StageTiming({job, counts}) {
  const stages = resolveStages(job);
  const durations = stages.map((stage) => stage.duration).filter((value) => value !== null);
  const sum = durations.reduce((total, value) => total + value, 0);
  const raw = job?.total_e2e_duration_ms ?? job?.total_e2e_elapsed_ms ?? job?.pipeline_duration_ms;
  const total = raw === null || raw === undefined ? NaN : Number(raw);
  const longest = stages.filter((stage) => stage.duration !== null).sort((a, b) => b.duration - a.duration)[0];
  return (
    <section className="section-block">
      <h3>THỜI GIAN THỰC THI 10 GIAI ĐOẠN (DO BACKEND ĐO)</h3>
      <Card className="table-card">
        <div className="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Stage</th><th>Backend state</th><th>Duration</th><th>Tỷ lệ</th><th>Ghi chú / metadata</th></tr></thead>
            <tbody>{stages.map((stage) => {
              const note = skipNote(stage, counts);
              return (
                <tr key={stage.key} className={`stage-cat-${stage.cat}`}>
                  <td>{String(stage.number).padStart(2, '0')}</td>
                  <td>{stage.name}<br /><small className="mono">{stage.key}</small></td>
                  <td>{stage.label}{stage.cat === 'RUNNING' && Number.isFinite(Number(stage.elapsed)) ? ` · elapsed ${fmtMs(stage.elapsed)}` : ''}</td>
                  <td>{fmtMs(stage.duration)}</td>
                  <td>{stage.duration !== null && sum > 0 ? `${(stage.duration / sum * 100).toFixed(3)}%` : '—'}</td>
                  <td>{note && <p>{note}</p>}<JsonDetails summary={stage.summary} title="Mở stage summary metadata" /></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </Card>
      <Card className="timing-summary-card">
        <div className="model-card-grid">
          <div><span>TỔNG PIPELINE BACKEND (MONOTONIC)</span><strong>{fmtMs(total)}</strong></div>
          <div><span>TỔNG DURATION CÁC STAGE</span><strong>{fmtMs(sum)}</strong></div>
          <div><span>CHÊNH LỆCH BACKEND (OVERHEAD)</span><strong>{Number.isFinite(total) && total >= sum ? fmtMs(total - sum) : '—'}</strong></div>
          <div><span>STAGE DÀI NHẤT</span><strong>{longest ? `${longest.name} · ${fmtMs(longest.duration)}` : '—'}</strong></div>
        </div>
      </Card>
    </section>
  );
}

function unwrapPayload(payload) {
  return payload?.data?.summary ?? payload?.summary ?? payload?.data ?? payload;
}

function findField(source, keys, depth = 0) {
  if (!source || typeof source !== 'object' || depth > 7) return undefined;
  if (!Array.isArray(source)) {
    for (const key of keys) {
      if (source[key] !== undefined && source[key] !== null) return source[key];
    }
  }
  for (const value of Object.values(source)) {
    const found = findField(value, keys, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

function stageMatches(stage, number, canonicalKey) {
  const text = [
    stage?.stage_key, stage?.key, stage?.stage_id, stage?.stage_name, stage?.name
  ].filter(Boolean).join(' ').toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  const declaredNumber = Number(stage?.stage_number ?? stage?.stage_no ?? stage?.number);
  return declaredNumber === number
    || text.includes(canonicalKey)
    || new RegExp(`(?:^|_)STAGE_?0?${number}(?:_|$)`).test(text);
}

function findStage(source, number, canonicalKey, depth = 0) {
  if (!source || typeof source !== 'object' || depth > 7) return null;
  if (Array.isArray(source)) {
    for (const item of source) {
      if (stageMatches(item, number, canonicalKey)) return item;
    }
    for (const item of source) {
      const found = findStage(item, number, canonicalKey, depth + 1);
      if (found) return found;
    }
    return null;
  }
  if (stageMatches(source, number, canonicalKey)) return source;
  for (const value of Object.values(source)) {
    const found = findStage(value, number, canonicalKey, depth + 1);
    if (found) return found;
  }
  return null;
}

function valueFrom(sources, keys) {
  for (const source of sources) {
    const value = findField(source, keys);
    if (value !== undefined) return value;
  }
  return undefined;
}

function displayValue(value) {
  if (value === undefined || value === null || value === '') return null;
  if (Array.isArray(value)) return value.join(', ');
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function triageTotal(summary, stage10) {
  const totals = summary?.triage_totals ?? findField(summary, ['triage_totals']);
  if (totals?.total_candidates !== null && totals?.total_candidates !== undefined) {
    return totals.total_candidates;
  }
  const stageTotals = findField(stage10, ['triage_totals']);
  return stageTotals?.total_candidates;
}

function formatE2e(value) {
  if (value === undefined || value === null || value === '') return null;
  const milliseconds = Number(value);
  return Number.isFinite(milliseconds)
    ? `${String(value)} ms (${(milliseconds / 1000).toFixed(3)} s)`
    : String(value);
}

function parseCache(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') return {data: value, raw: JSON.stringify(value, null, 2), error: ''};
  try {
    const data = JSON.parse(value);
    return {data, raw: JSON.stringify(data, null, 2), error: ''};
  } catch {
    return {data: null, raw: value, error: 'Cache statistics không phải JSON hợp lệ; hiển thị nguyên văn.'};
  }
}

function cacheLeaves(value, prefix = '', depth = 0) {
  if (!value || typeof value !== 'object' || depth > 6) return [];
  return Object.entries(value).flatMap(([key, item]) => {
    const path = prefix ? `${prefix} · ${key}` : key;
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return cacheLeaves(item, path, depth + 1);
    }
    const label = path.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
    return [[label, Array.isArray(item) ? JSON.stringify(item) : String(item)]];
  });
}

function coverageRows(job, counts, summaryPayload, tracePayload) {
  const summary = unwrapPayload(summaryPayload);
  const trace = unwrapPayload(tracePayload);
  const stage02 = findStage(trace, 2, 'SOURCE_INVENTORY')
    || findStage(job, 2, 'SOURCE_INVENTORY');
  const stage03 = findStage(trace, 3, 'OPENGREP_DETECTION')
    || findStage(job, 3, 'OPENGREP_DETECTION');
  const stage04 = findStage(trace, 4, 'CONTEXT_EXTRACTION')
    || findStage(job, 4, 'CONTEXT_EXTRACTION');
  const stage05 = findStage(trace, 5, 'IRIS_PROGRAM_ANALYSIS')
    || findStage(job, 5, 'IRIS_PROGRAM_ANALYSIS');
  const stage06 = findStage(trace, 6, 'QWEN_LORA_INFERENCE')
    || findStage(job, 6, 'LLM_INFERENCE');
  const stage10 = findStage(trace, 10, 'REPORT_SYNTHESIS')
    || findStage(job, 10, 'REPORT_SYNTHESIS');
  const totals = summary?.triage_totals ?? findField(summary, ['triage_totals']);
  const accumulated = valueFrom([stage03, summary, job], ['accumulated_candidates']);
  const deduplicated = valueFrom([stage03, summary, job], ['raw_opengrep_candidates']);
  const duplicateCount = Number.isFinite(Number(accumulated)) && Number.isFinite(Number(deduplicated))
    ? Math.max(0, Number(accumulated) - Number(deduplicated))
    : undefined;
  const cacheStatistics = parseCache(valueFrom([summary, stage06, job, trace], ['cache_statistics']));
  const e2e = formatE2e(valueFrom(
    [summary, trace, job],
    ['total_e2e_duration_ms', 'total_e2e_elapsed_ms']
  ));
  const rows = [
    ['Java files phát hiện', valueFrom([summary, stage02, job], ['java_files_discovered'])],
    ['Java files đã phân tích', valueFrom([summary, stage02, job], ['java_files_scanned'])],
    ['Java files bị bỏ qua', valueFrom([summary, stage02, job], ['java_files_skipped'])],
    ['Java files đủ điều kiện', valueFrom([summary, stage02, job], ['eligible_java_files'])],
    ['Java files loại trừ', valueFrom([summary, job, trace], ['excluded_java_files'])],
    ['Trạng thái coverage', valueFrom([summary, stage02, job], ['coverage_status', 'analysis_coverage_status'])],
    ['Phạm vi CWE hỗ trợ', valueFrom([summary, stage03, job], ['supported_cwe_categories'])],
    ['OpenGrep ruleset', valueFrom([summary, stage03, job], ['ruleset_version'])],
    ['Số rule đã áp dụng', valueFrom([summary, stage03, job], ['rules_applied_count'])],
    ['Pattern matches tích lũy trước deduplication', valueFrom([stage03, summary, job], ['accumulated_candidates'])],
    ['Ứng viên OpenGrep đã deduplicate', valueFrom([stage03, summary, job], ['raw_opengrep_candidates'])],
    ['Pattern matches trùng đã loại bỏ', duplicateCount],
    ['Ứng viên cuối cùng (triage total)', totals?.total_candidates ?? triageTotal(summary, stage10)],
    ['Candidate contexts', valueFrom([stage04, summary, job], ['candidate_contexts', 'candidate_context_count', 'contexts_extracted'])],
    ['AST parser identity', valueFrom([stage04, summary, job], ['ast_parser', 'ast_parser_identity', 'parser_identity'])],
    ['AST files processed', valueFrom([stage04, summary, job], ['ast_files_processed'])],
    ['AST files reused', valueFrom([stage04, summary, job], ['ast_files_reused'])],
    ['IRIS / taint evidence', valueFrom([stage05, summary, job], ['taint_evidence_count', 'iris_taint_findings', 'taint_paths_found'])],
    ['API identities đã phân loại', valueFrom([summary, stage06, job], ['unique_api_identities_classified'])],
    ['Ứng viên được phân loại bởi LLM', valueFrom([summary, stage06, job], ['llm_inference_count'])],
    ['GPU inference thực tế', valueFrom([summary, stage06, job], ['actual_gpu_inference_calls'])],
    ['LLM cache hits', valueFrom([summary, stage06, job], ['llm_cache_hits', 'cache_hits'])],
    ['LLM cache misses', valueFrom([summary, stage06, job], ['llm_cache_misses', 'cache_misses'])],
    ['Cache statistics', valueFrom([summary, stage06, job, trace], ['cache_statistics'])],
    ['Lý do phân tích chưa đầy đủ', valueFrom([summary, stage02, job], ['incomplete_analysis_reasons'])],
    ['Thời gian E2E backend', e2e]
  ].map(([label, value]) => [
    label,
    label === 'Cache statistics' ? parseCache(value) : displayValue(value)
  ]);
  if (counts) {
    rows.push(['REPORT / REVIEW / SUPPRESS (từ findings backend)', `${counts.report} / ${counts.review} / ${counts.suppress}`]);
  }
  return rows;
}

function coverageGroup(label) {
  if (label.startsWith('Java files') || label === 'Trạng thái coverage' || label === 'Lý do phân tích chưa đầy đủ') {
    return 'A. Source Coverage';
  }
  if (label.includes('OpenGrep') || label.includes('Pattern matches') || label.includes('rule') || label.includes('CWE') || label.includes('triage total')) {
    return 'B. OpenGrep Detection';
  }
  if (label.includes('Candidate contexts') || label.includes('AST') || label.includes('IRIS') || label.includes('API identities') || label.includes('LLM') || label.includes('GPU inference')) {
    return 'C. IRIS and Qwen LoRA';
  }
  return 'D. Execution and Cache';
}

function CacheStatistics({cache}) {
  if (!cache) return <em>Backend chưa cung cấp metadata này</em>;
  const metrics = cache.data ? cacheLeaves(cache.data) : [];
  return (
    <div className="ntk-coverage-cache">
      {cache.error && <p>{cache.error}</p>}
      {metrics.length > 0
        ? <dl>{metrics.map(([label, value], index) => <div key={`${label}-${index}`}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
        : !cache.error && <p>Backend không cung cấp cache layer chi tiết.</p>}
      <details>
        <summary>Xem JSON cache gốc</summary>
        <pre>{cache.raw}</pre>
      </details>
    </div>
  );
}

export function CoveragePanel({job, counts}) {
  const scanId = job?.scan_id ?? job?.scanId ?? '';
  const state = String(job?.state ?? '').toUpperCase();
  const [summary, setSummary] = useState(null);
  const [trace, setTrace] = useState(null);
  const [loading, setLoading] = useState(false);
  const [requestError, setRequestError] = useState('');

  useEffect(() => {
    if (!scanId || state === 'RUNNING' || state === 'QUEUED') {
      setSummary(null);
      setTrace(null);
      setLoading(false);
      setRequestError('');
      return undefined;
    }

    const controller = new AbortController();
    setSummary(null);
    setTrace(null);
    setLoading(true);
    setRequestError('');

    const loadMetadata = async () => {
      const errors = [];
      try {
        setSummary(await api.scanSummary(scanId, {signal: controller.signal}));
      } catch (error) {
        if (controller.signal.aborted) return;
        errors.push(`summary: ${error.message}`);
      }
      try {
        setTrace(await api.pipelineTrace(scanId, {signal: controller.signal}));
      } catch (error) {
        if (controller.signal.aborted) return;
        errors.push(`pipeline trace: ${error.message}`);
      }
      if (!controller.signal.aborted) {
        setRequestError(errors.join(' · '));
        setLoading(false);
      }
    };

    loadMetadata();
    return () => controller.abort();
  }, [scanId, state]);

  const rows = coverageRows(job, counts, summary, trace);
  const groupedRows = rows.reduce((groups, row) => {
    const group = coverageGroup(row[0]);
    groups[group] = groups[group] || [];
    groups[group].push(row);
    return groups;
  }, {});
  const finalCandidates = rows.find(([label]) => label === 'Ứng viên cuối cùng (triage total)')?.[1];
  const coverageStatus = rows.find(([label]) => label === 'Trạng thái coverage')?.[1];
  const incompleteReasons = rows.find(([label]) => label === 'Lý do phân tích chưa đầy đủ')?.[1];
  const cache = rows.find(([label]) => label === 'Cache statistics')?.[1];
  const none = rows.every(([, value]) => value === null);
  const completed = ['COMPLETED', 'FAILED'].includes(state);
  const zeroCandidates = finalCandidates !== null
    && finalCandidates !== undefined
    && Number(finalCandidates) === 0;
  const coverageText = String(coverageStatus ?? '').toUpperCase();
  const partialCoverage = Boolean(coverageText && coverageText !== 'FULL_SOURCE_COVERAGE');

  return (
    <section className="section-block ntk-coverage-section">
      <style>{`
        .ntk-coverage-section,.ntk-coverage-card,.ntk-coverage-groups,.ntk-coverage-group,
        .ntk-coverage-row,.ntk-coverage-row dd,.ntk-coverage-value,.ntk-coverage-cache {
          min-width:0;max-width:100%;
        }
        .ntk-coverage-groups{display:grid;grid-template-columns:minmax(0,1fr);gap:18px}
        .ntk-coverage-group{padding-top:14px;border-top:1px solid #26374d}
        .ntk-coverage-group:first-child{padding-top:0;border-top:0}
        .ntk-coverage-group h4{margin:0 0 10px;color:#d8e8f4;font-size:14px}
        .ntk-coverage-grid{display:grid;grid-template-columns:minmax(220px,280px) minmax(0,1fr);margin:0}
        .ntk-coverage-row{display:grid;grid-column:1/-1;grid-template-columns:minmax(220px,280px) minmax(0,1fr);gap:16px;padding:10px 12px;border-bottom:1px solid #1e3043}
        .ntk-coverage-row dt,.ntk-coverage-row dd{margin:0;white-space:normal;overflow-wrap:anywhere;word-break:break-word}
        .ntk-coverage-row dt{color:#9cb0c3;line-height:1.55}
        .ntk-coverage-row dd{color:#e0eaf3;line-height:1.6}
        .ntk-coverage-value{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
        .ntk-coverage-cache{display:grid;gap:10px}
        .ntk-coverage-cache dl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:0}
        .ntk-coverage-cache dl>div{min-width:0;padding:9px;border:1px solid #22354a;border-radius:6px}
        .ntk-coverage-cache dt,.ntk-coverage-cache dd{overflow-wrap:anywhere;word-break:break-word}
        .ntk-coverage-cache dt{color:#8fa6ba;font-size:12px}
        .ntk-coverage-cache dd{margin:4px 0 0;color:#dbe8f2;white-space:pre-wrap}
        .ntk-coverage-cache summary{cursor:pointer;color:#82d9fb}
        .ntk-coverage-cache pre{max-width:100%;max-height:480px;overflow-x:hidden;overflow-y:auto;padding:12px;border:1px solid #26374d;border-radius:8px;background:#08111b;color:#cad8e5;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
        @media(max-width:640px){.ntk-coverage-grid,.ntk-coverage-row{grid-template-columns:minmax(0,1fr)}.ntk-coverage-row{gap:4px;padding:10px 4px}.ntk-coverage-cache dl{grid-template-columns:minmax(0,1fr)}}
      `}</style>
      <h3>PHẠM VI PHÂN TÍCH (COVERAGE)</h3>
      <Card className="table-card ntk-coverage-card">
        {loading && <DataNotice>Đang tải metadata coverage từ summary và pipeline trace của backend…</DataNotice>}
        {requestError && <DataNotice>Không tải được một số metadata backend: {requestError}</DataNotice>}
        <div className="ntk-coverage-groups">
          {Object.entries(groupedRows).map(([group, groupRows]) => (
            <section className="ntk-coverage-group" key={group}>
              <h4>{group}</h4>
              <dl className="ntk-coverage-grid">
                {groupRows.map(([label, value]) => (
                  <div className="ntk-coverage-row" key={label}>
                    <dt>{label}</dt>
                    <dd>{label === 'Cache statistics'
                      ? <CacheStatistics cache={value} />
                      : <div className="ntk-coverage-value">{value ?? <em>{completed ? 'Backend chưa cung cấp metadata này' : 'Chưa có dữ liệu'}</em>}</div>}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
        {none && !loading && <DataNotice>Backend chưa cung cấp metadata coverage; không có số liệu nào được suy diễn.</DataNotice>}
        {zeroCandidates
          ? <p className="panel-note">Backend xác nhận scan này có 0 ứng viên. Điều đó không chứng minh rằng không tồn tại lỗ hổng; kết quả phụ thuộc ruleset và phạm vi phân tích được hỗ trợ.</p>
          : <p className="panel-note">Kết quả phụ thuộc ruleset, phạm vi CWE được hỗ trợ và heuristic triage. FULL_SOURCE_COVERAGE chỉ mô tả việc xử lý source đủ điều kiện theo cấu hình scan, không khẳng định bao phủ mọi loại CWE.</p>}
        {(partialCoverage || incompleteReasons !== null && incompleteReasons !== undefined) && <p className="panel-note">Backend báo phạm vi phân tích chưa đầy đủ; diễn giải kết quả trong giới hạn coverage và lý do thiếu hụt được liệt kê ở trên.</p>}
      </Card>
    </section>
  );
}