const baseUrl = (import.meta.env.VITE_API_BASE_URL || 'https://admin-pc.tail856d55.ts.net').replace(/\/$/, '');

export class ApiError extends Error {
  constructor(message, {status, timedOut = false, cause} = {}) {
    super(message, {cause});
    this.name = 'ApiError';
    this.status = status;
    this.timedOut = timedOut;
  }
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 10000;
  const fetchOptions = {...options};
  delete fetchOptions.timeoutMs;
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, {once: true});

  try {
    const response = await fetch(`${baseUrl}${path}`, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        ...(options.body instanceof FormData ? {} : {'Content-Type': 'application/json'}),
        ...options.headers
      }
    });

    if (!response.ok) {
      const message = await response.text();
      throw new ApiError(message || `Yêu cầu thất bại (${response.status})`, {status: response.status});
    }
    if (response.status === 204) return null;

    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted && !options.signal?.aborted) {
      throw new ApiError('Máy chủ không phản hồi trong thời gian cho phép.', {timedOut: true, cause: error});
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

async function requestFile(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs ?? 60000);
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, {once: true});

  try {
    const response = await fetch(`${baseUrl}${path}`, {
      signal: controller.signal,
      headers: options.headers
    });
    if (!response.ok) {
      const message = await response.text();
      throw new ApiError(message || `Tải tệp thất bại (${response.status})`, {status: response.status});
    }
    return {
      blob: await response.blob(),
      contentType: response.headers.get('content-type') || '',
      disposition: response.headers.get('content-disposition') || ''
    };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted && !options.signal?.aborted) {
      throw new ApiError('Máy chủ không phản hồi trong thời gian cho phép.', {timedOut: true, cause: error});
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

async function optionalList(path, options = {}) {
  try {
    const data = await request(path, {...options, timeoutMs: 15000});
    const items = Array.isArray(data)
      ? data
      : data?.jobs ?? data?.scans ?? data?.items ?? data?.results ?? data?.data?.jobs ?? data?.data?.scans;
    return {supported: Array.isArray(items), items: Array.isArray(items) ? items : []};
  } catch (error) {
    if (error instanceof ApiError && [404, 405, 501].includes(error.status)) {
      return {supported: false, items: []};
    }
    throw error;
  }
}

export const api = {
  health: (options) => request('/api/health', options),
  model: (options) => request('/api/model', options),
  startGithubScan: (repositoryUrl, commitSha, options = {}) => {
    const body = {repo_url: repositoryUrl};
    if (commitSha) body.commit_sha = commitSha;
    return request('/api/scans', {
      ...options,
      method: 'POST',
      timeoutMs: 15 * 60 * 1000,
      body: JSON.stringify(body)
    });
  },
  createScanJob: (repoUrl, commitSha, options = {}, configuration = {}) => {
    const body = {
      repo_url: repoUrl,
      ...(commitSha ? {commit_sha: commitSha} : {}),
      ...Object.fromEntries(Object.entries(configuration).filter(([, value]) => value !== undefined && value !== ''))
    };
    return request('/api/scan-jobs', {
      ...options,
      method: 'POST',
      timeoutMs: 30000,
      body: JSON.stringify(body)
    });
  },
  scanJob: (jobId, options = {}) => request(`/api/scan-jobs/${encodeURIComponent(jobId)}`, {
    ...options,
    timeoutMs: 15000
  }),
  listScanJobs: (options) => optionalList('/api/scan-jobs', options),
  listScans: (options) => optionalList('/api/scans', options),
  pipelineTrace: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}/pipeline-trace`, {
    ...options,
    timeoutMs: 30000
  }),
  scan: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}`, options),
  scanSummary: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}/summary`, {
    ...options,
    timeoutMs: 30000
  }),
  findingsPage: (scanId, page = 1, pageSize = 50, options = {}) => {
    const {decision, ...rest} = options;
    const filter = decision ? `&decision=${encodeURIComponent(decision)}` : '';
    return request(
      `/api/scans/${encodeURIComponent(scanId)}/findings/page?page=${page}&page_size=${pageSize}${filter}`,
      {...rest, timeoutMs: 30000}
    );
  },
  findingDetail: (scanId, findingId, detailUrl, options = {}) => request(
    typeof detailUrl === 'string' && detailUrl.startsWith('/api/')
      ? detailUrl
      : `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`,
    {...options, timeoutMs: 30000}
  ),
  findings: (scanId, options = {}) => request(`/api/scans/${encodeURIComponent(scanId)}/findings`, {
    ...options,
    timeoutMs: options.timeoutMs ?? 60000
  }),
  finding: (id, options) => request(`/api/findings/${encodeURIComponent(id)}`, options),
  report: (scanId, options) => request(`/api/scans/${encodeURIComponent(scanId)}/report?format=json`, options),
  datasetManifest: (options = {}) => request('/api/datasets/manifest', {...options, timeoutMs: 30000}),
  datasetRecords: (datasetId, params = {}, options = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') query.set(key, String(value));
    });
    return request(`/api/datasets/${encodeURIComponent(datasetId)}/records?${query}`, {
      ...options,
      timeoutMs: 30000
    });
  },
  datasetExport: (datasetId, format, options = {}) => requestFile(
    `/api/datasets/${encodeURIComponent(datasetId)}/export?format=${encodeURIComponent(format)}`,
    options
  )
};

export async function checkBackend() {
  try {
    const status = await api.health();
    return {connected: true, status};
  } catch (error) {
    return {connected: false, error: error.message};
  }
}