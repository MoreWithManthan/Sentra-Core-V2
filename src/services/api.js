const BASE    = import.meta.env.VITE_API_URL ?? '';
const TIMEOUT = Number(import.meta.env.VITE_API_TIMEOUT ?? 30_000);

export class APIError extends Error {
  constructor(status, message, body = null) {
    super(message); this.name = 'APIError'; this.status = status; this.body = body;
  }
}

async function req(path, { method = 'GET', body, timeout = TIMEOUT } = {}) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(`${BASE}${path}`, {
      method, signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    clearTimeout(tid);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new APIError(res.status, err.detail ?? err.message ?? `HTTP ${res.status}`, err);
    }
    return res.json();
  } catch (e) {
    clearTimeout(tid);
    if (e.name === 'AbortError') throw new APIError(null, `Timeout after ${timeout}ms`);
    throw e;
  }
}

// Health
export const healthCheck      = () => req('/api/health');

// System
export const getStatsHistory  = () => req('/api/system/stats-history');
export const getProcesses     = () => req('/api/system/processes');
export const getDrives        = () => req('/api/system/drives');
export const getNetwork       = () => req('/api/system/network');
export const getStartupItems  = () => req('/api/system/startup-items');

// Actions
export const performCleanup   = (opts = {}) => req('/api/actions/cleanup', { method: 'POST', body: { deep_clean: false, ...opts } });
export const systemRepair     = () => req('/api/actions/system-repair', { method: 'POST' });
export const repairStatus     = () => req('/api/actions/repair-status');

// Intel (YARA rules)
export const updateIntelligence = () => req('/api/engine/update', { method: 'POST', timeout: 10_000 });
export const getIntelMetadata   = () => req('/api/engine/intel/metadata');

// Scans (REST fallback — UI uses the WebSocket flow via useScanWS)
export const runSecurityScan  = () => req('/api/engine/scan', { timeout: 60_000 });
export const runCustomScan    = (path, opts = {}) =>
  req('/api/engine/custom-scan', { method: 'POST', timeout: 180_000, body: { path, ...opts } });

// VirusTotal (still used for the manual scan/batch/test/key admin flows)
export const vtScanFile  = (filePath, uploadUnknown = false) =>
  req('/api/engine/vt-scan',  { method: 'POST', timeout: 90_000,  body: { file_path: filePath, upload_unknown: uploadUnknown } });
export const vtBatchScan = (filePaths, uploadUnknown = false) =>
  req('/api/engine/vt-batch', { method: 'POST', timeout: 300_000, body: { file_paths: filePaths, upload_unknown: uploadUnknown } });
export const getVtStatus        = ()     => req('/api/engine/vt-status');
export const setVtApiKey        = (key)  => req('/api/engine/vt-key', { method: 'POST', body: { api_key: key } });
export const testVtConnection   = ()     => req('/api/engine/vt-test', { method: 'POST', timeout: 30_000 });

// Multi-source threat intelligence (MalwareBazaar / OTX / AbuseIPDB / URLhaus + VT)
export const getIntelStatus     = ()               => req('/api/engine/intel-status');
export const setIntelKey        = (provider, key)  => req('/api/engine/intel-key', { method: 'POST', body: { provider, api_key: key } });
export const getClearedFilesCount = () => req('/api/engine/cleared-files-count');
export const checkIpReputation  = (ip)   => req('/api/system/network/vt-check', { method: 'POST', timeout: 30_000, body: { ip } });
export const checkStartupItemVt = (path) => req('/api/system/startup/vt-check', { method: 'POST', timeout: 30_000, body: { path } });

// History
export const getScanHistory   = (limit = 50)  => req(`/api/history/scans?limit=${limit}`);
export const getScanThreats   = (scanId)       => req(`/api/history/scans/${scanId}/threats`);
export const getLatestScan    = ()             => req('/api/history/latest');

// Report
export const downloadReport   = async (scanId = null) => {
  const body = scanId ? { scan_id: scanId } : {};
  const res  = await fetch(`${BASE}/api/reports/generate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('Report generation failed');
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `sentra-report-${Date.now()}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
};

// Schedule
export const getSchedule   = () => req('/api/schedule');
export const saveSchedule  = (cfg) => req('/api/schedule', { method: 'POST', body: cfg });

// Watcher
export const getWatcher    = () => req('/api/watcher');
export const saveWatcher   = (cfg) => req('/api/watcher', { method: 'POST', body: cfg });

// Defender
export const defenderStatus  = () => req('/api/system/defender/status');
export const defenderExclude = (path) => req('/api/system/defender/exclude', { method: 'POST', body: { path } });
