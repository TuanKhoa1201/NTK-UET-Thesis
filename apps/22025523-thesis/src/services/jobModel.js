export const STAGES = [
  ['PROJECT_INTAKE', 'Tiếp nhận dự án'],
  ['SOURCE_INVENTORY', 'Lập danh mục mã nguồn'],
  ['OPENGREP_DETECTION', 'OpenGrep — Phát hiện ứng viên'],
  ['CONTEXT_EXTRACTION', 'Trích xuất ngữ cảnh'],
  ['IRIS_PROGRAM_ANALYSIS', 'IRIS — Phân tích chương trình'],
  ['LLM_INFERENCE', 'Qwen LoRA — Phân loại API'],
  ['EVIDENCE_FUSION', 'Hợp nhất bằng chứng'],
  ['SAST_SCORING', 'Chấm điểm SAST'],
  ['ALERT_VERIFICATION', 'Xác minh cảnh báo'],
  ['REPORT_SYNTHESIS', 'Tổng hợp báo cáo']
];

export const CAT_LABEL = {
  COMPLETED: 'Hoàn thành',
  SKIPPED: 'Bỏ qua',
  FAILED: 'Thất bại',
  RUNNING: 'Đang thực thi',
  PENDING: 'Chưa bắt đầu',
  NOT_RUN: 'Không chạy (job đã FAILED)',
  UNKNOWN: 'Chưa có telemetry'
};

export const NO_CANDIDATE_NOTE = 'Qwen LoRA không được gọi vì giai đoạn phát hiện tĩnh không tạo ra ứng viên API cần phân loại.';

export function fmtMs(value) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  return Number.isFinite(number)
    ? `${number.toLocaleString('vi-VN', {minimumFractionDigits: 3, maximumFractionDigits: 3})} ms`
    : '—';
}

export function findKey(object, key, depth = 0) {
  if (!object || typeof object !== 'object' || depth > 6) return undefined;
  if (!Array.isArray(object) && object[key] !== undefined && object[key] !== null) return object[key];
  for (const value of Object.values(object)) {
    const found = findKey(value, key, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

export function findKeyLike(object, pattern, depth = 0) {
  if (!object || typeof object !== 'object' || depth > 6) return undefined;
  if (!Array.isArray(object)) {
    for (const [key, value] of Object.entries(object)) {
      if (pattern.test(key) && value !== null && value !== undefined && typeof value !== 'object') return {key, value};
    }
  }
  for (const value of Object.values(object)) {
    const found = findKeyLike(value, pattern, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function category(raw) {
  const text = String(raw || '').toUpperCase();
  if (text.includes('SKIP')) return 'SKIPPED';
  if (text.includes('FAIL') || text === 'ERROR') return 'FAILED';
  if (['COMPLETED', 'COMPLETE', 'SUCCESS', 'SUCCEEDED', 'DONE', 'PASSED'].includes(text)) return 'COMPLETED';
  if (['RUNNING', 'IN_PROGRESS', 'ACTIVE'].includes(text)) return 'RUNNING';
  if (['QUEUED', 'PENDING', 'NOT_STARTED'].includes(text)) return 'PENDING';
  return 'UNKNOWN';
}

function toStageNumber(value) {
  if (value && typeof value === 'object') return toStageNumber(value.stage_number ?? value.stage_key ?? value.key);
  if (Number.isInteger(value) && value >= 1 && value <= 10) return value;
  if (typeof value === 'string' && value) {
    const index = STAGES.findIndex(([key]) => key === value.toUpperCase());
    if (index >= 0) return index + 1;
    const digits = parseInt(value, 10);
    if (Number.isInteger(digits) && digits >= 1 && digits <= 10) return digits;
  }
  return null;
}

function rawStageNumber(stage, index) {
  return toStageNumber(stage?.stage_number ?? stage?.stage_no ?? stage?.number)
    ?? toStageNumber(stage?.stage_key ?? stage?.key ?? stage?.stage_id)
    ?? index + 1;
}

function failedStageNumber(job, byNumber) {
  const candidates = [job?.failed_stage, job?.failure_stage, job?.error?.stage, job?.error?.failed_stage];
  for (const item of candidates) {
    const number = toStageNumber(item);
    if (number) return number;
  }
  for (const [number, stage] of byNumber) {
    if (category(stage?.state ?? stage?.status) === 'FAILED') return number;
  }
  return toStageNumber(Number(job?.active_stage));
}

export function jobState(job) {
  return String(job?.state || '').toUpperCase();
}

export function resolveStages(job) {
  const list = Array.isArray(job?.stages) ? job.stages : [];
  const byNumber = new Map(list.map((stage, index) => [rawStageNumber(stage, index), stage]));
  const state = jobState(job);
  const failedAt = state === 'FAILED' ? failedStageNumber(job, byNumber) : null;
  const active = Number(job?.active_stage);
  return STAGES.map(([key, name], index) => {
    const number = index + 1;
    const raw = byNumber.get(number);
    let cat = category(raw?.state ?? raw?.status);
    if (state === 'FAILED') {
      if (number === failedAt) cat = 'FAILED';
      else if (failedAt && number > failedAt && ['PENDING', 'UNKNOWN', 'RUNNING'].includes(cat)) cat = 'NOT_RUN';
      else if (cat === 'RUNNING') cat = 'UNKNOWN';
    } else if (state === 'RUNNING' && number === active && ['PENDING', 'UNKNOWN'].includes(cat)) {
      cat = 'RUNNING';
    }
    const duration = raw?.duration_ms === null || raw?.duration_ms === undefined ? null : Number(raw.duration_ms);
    return {
      number, key, name, cat, label: CAT_LABEL[cat],
      duration: Number.isFinite(duration) ? duration : null,
      reason: raw?.reason ?? raw?.skip_reason ?? raw?.skipped_reason ?? null,
      summary: raw?.summary_metadata ?? null,
      elapsed: raw?.running_elapsed_ms,
      error: raw?.error_message ?? null
    };
  });
}

export function currentStageIndex(job) {
  const state = jobState(job);
  const stages = resolveStages(job);
  if (state === 'FAILED') {
    const failed = stages.find((stage) => stage.cat === 'FAILED');
    return failed ? failed.number - 1 : null;
  }
  if (state === 'COMPLETED') return 9;
  if (state === 'RUNNING') {
    const active = Number(job?.active_stage);
    return Number.isInteger(active) && active >= 1 && active <= 10 ? active - 1 : null;
  }
  return null;
}

export function errorInfo(job) {
  const raw = job?.error;
  const object = raw && typeof raw === 'object' ? raw : {};
  const steps = job?.next_steps ?? job?.actionable_steps ?? object.next_steps ?? object.actionable_steps ?? job?.hint ?? object.hint;
  return {
    code: job?.error_code ?? object.code ?? object.error_code ?? null,
    message: job?.error_message ?? object.message ?? object.error_message ?? (typeof raw === 'string' ? raw : null) ?? job?.message ?? null,
    limits: job?.resource_limits ?? job?.limits ?? object.resource_limits ?? object.limits ?? object.details ?? null,
    steps: steps ? (Array.isArray(steps) ? steps : [steps]) : []
  };
}

export function skipNote(stage, counts) {
  if (stage.cat !== 'SKIPPED') return stage.reason || null;
  const text = `${stage.reason || ''} ${JSON.stringify(stage.summary || {})}`;
  const confirmed = /no[_ -]?candidate/i.test(text);
  if (stage.number === 6 && confirmed) return NO_CANDIDATE_NOTE;
  return stage.reason || null;
}

const COVERAGE_KEYS = [
  ['Java files phát hiện', ['java_files_discovered', 'java_file_count', 'files_discovered']],
  ['Java files đã phân tích', ['java_files_analyzed', 'files_analyzed']],
  ['Java files bị bỏ qua', ['java_files_skipped', 'files_skipped']],
  ['Phạm vi CWE hỗ trợ', ['supported_cwes', 'supported_cwe']],
  ['Số rule áp dụng', ['applied_rule_count', 'rule_count']],
  ['Số ứng viên', ['candidate_count', 'candidates']],
  ['Số phân loại LLM', ['llm_classification_count', 'llm_classified_count']],
  ['Trạng thái coverage', ['coverage_status', 'coverage']],
  ['Java files đủ điều kiện', ['eligible_java_files']],
  ['Java files loại trừ', ['excluded_java_files']],
  ['Lý do loại trừ', ['per_reason_exclusions']],
  ['CWE hỗ trợ theo backend', ['supported_cwe_categories']],
  ['OpenGrep ruleset', ['opengrep_ruleset', 'ruleset_version']],
  ['Số rule đã áp dụng', ['rules_applied_count']],
  ['Ứng viên OpenGrep', ['opengrep_candidate_count']],
  ['API identities đã phân loại', ['unique_api_identities_classified']],
  ['GPU inference thực tế', ['actual_gpu_inference_calls']],
  ['Cache statistics', ['cache_statistics']],
  ['Lý do phân tích chưa đầy đủ', ['incomplete_analysis_reasons']],
  ['Thời gian E2E backend', ['total_e2e_duration_ms', 'total_e2e_elapsed_ms']]
];

export function coverageRows(job, counts, scan, trace) {
  const rows = COVERAGE_KEYS.map(([label, keys]) => {
    let value;
    for (const key of keys) {
      value = findKey(job, key);
      if (value !== undefined) break;
    }
    if (value === undefined) {
      for (const source of [scan, trace]) {
        for (const key of keys) {
          value = findKey(source, key);
          if (value !== undefined) break;
        }
        if (value !== undefined) break;
      }
    }
    const text = value === undefined ? null : typeof value === 'object' ? JSON.stringify(value) : String(value);
    return [label, text];
  });
  if (counts) {
    rows.push(['REPORT / REVIEW / SUPPRESS (từ findings backend)', `${counts.report} / ${counts.review} / ${counts.suppress}`]);
  }
  return rows;
}