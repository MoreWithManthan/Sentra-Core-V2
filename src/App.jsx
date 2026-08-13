import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  healthCheck, getStartupItems, getScanHistory,
  updateIntelligence, performCleanup, systemRepair, setVtApiKey, getVtStatus,
} from './services/api';
import { useTelemetry, useScanWS } from './hooks/useWebSocket';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ToastProvider, useToast } from './components/Toast';
import { TopNav } from './components/TopNav';
import { VTKeyModal } from './components/VTKeyModal';
import { ScanModal } from './components/ScanModal';
import { CleanupModal } from './components/CleanupModal';
import { IntelModal } from './components/IntelModal';
import { StatusCards } from './components/StatusCards';
import { ShieldGauge } from './components/ShieldGauge';
import { SystemGraph } from './components/SystemGraph';
import { ProcessMonitor } from './components/ProcessMonitor';
import { ThreatFeed } from './components/ThreatFeed';
import { NetworkMonitor } from './components/NetworkMonitor';
import { StartupItems } from './components/StartupItems';
import { ScanHistory } from './components/ScanHistory';
import { SettingsPanel } from './components/SettingsPanel';

const THEME_VARS = {
  '':             {'--accent':'#22d3ee','--accent-dim':'rgba(34,211,238,.15)','--accent-glow':'rgba(34,211,238,.35)','--border-2':'rgba(34,211,238,.18)'},
  'theme-green':  {'--accent':'#4ade80','--accent-dim':'rgba(74,222,128,.15)','--accent-glow':'rgba(74,222,128,.35)','--border-2':'rgba(74,222,128,.18)'},
  'theme-amber':  {'--accent':'#fbbf24','--accent-dim':'rgba(251,191,36,.15)','--accent-glow':'rgba(251,191,36,.35)','--border-2':'rgba(251,191,36,.18)'},
  'theme-violet': {'--accent':'#a78bfa','--accent-dim':'rgba(167,139,250,.15)','--accent-glow':'rgba(167,139,250,.35)','--border-2':'rgba(167,139,250,.18)'},
};

function applyTheme(id) {
  const v = THEME_VARS[id] ?? THEME_VARS[''];
  Object.entries(v).forEach(([k,val]) => document.documentElement.style.setProperty(k,val));
  localStorage.setItem('sentra-theme', id);
}

/**
 * A flex child needs both `min-h-0` and `overflow-y-auto` to actually
 * scroll — without `min-h-0` it defaults to `min-height: auto` and never
 * shrinks small enough to trigger its own scrollbar.
 */
function Panel({ title, badge, action, children, style={} }) {
  return (
    <div className="flex flex-col rounded-2xl overflow-hidden" style={{background:'var(--surface)',border:'1px solid var(--border)',...style}}>
      {(title || action) && (
        <div className="flex items-center justify-between px-4 py-2.5 flex-shrink-0" style={{borderBottom:'1px solid var(--border)'}}>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider" style={{color:'var(--text-3)'}}>{title}</span>
            {badge != null && <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-md" style={{background:'var(--surface-3)',color:'var(--text-3)'}}>{badge}</span>}
          </div>
          {action}
        </div>
      )}
      <div className="flex-1 min-h-0 overflow-y-auto scrollbar p-3">{children}</div>
    </div>
  );
}

function AppContent() {
  const toast = useToast();
  const [theme, setTheme] = useState(() => localStorage.getItem('sentra-theme') || '');
  const [vtKey, setVtKey] = useState(() => localStorage.getItem('sentra_vt_key') || '');
  // Reflects the backend's actual .env/runtime state, not just localStorage —
  // these are two different things (see virustotal.py set_vt_api_key).
  const [vtConfigured, setVtConfigured] = useState(true);
  const vtAsked = useRef(localStorage.getItem('sentra_vt_asked') === 'true');
  const [tab, setTab] = useState('dashboard');
  const [modal, setModal] = useState(null);
  const [apiReady, setApiReady] = useState(false);
  const [intelResult, setIntelResult] = useState(null);
  const [updating, setUpdating] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const updateTimeoutRef = useRef(null);

  const [frozenNetwork, setFrozenNetwork] = useState([]);
  const [networkPaused, setNetworkPaused] = useState(false);
  const [startupData, setStartupData] = useState([]);
  const [historyData, setHistoryData] = useState([]);
  const [loadingStart, setLoadingStart] = useState(false);
  const [loadingHist, setLoadingHist] = useState(false);
  const [backendOs, setBackendOs] = useState('Windows');

  /**
   * The backend broadcasts a completion event on the telemetry
   * WebSocket when a background task finishes. This routes those
   * events to the right place instead of the caller having to poll.
   */
  const handleWsEvent = useCallback((msg) => {
    if (msg.type === 'intel_update_complete') {
      if (updateTimeoutRef.current) clearTimeout(updateTimeoutRef.current);
      setUpdating(false);
      setIntelResult(msg);
      setModal('intel');
    } else if (msg.type === 'intel_update_error') {
      if (updateTimeoutRef.current) clearTimeout(updateTimeoutRef.current);
      setUpdating(false);
      toast.push(msg.message || "Couldn't update threat definitions.", 'error');
    } else if (msg.type === 'repair_complete') {
      toast.push('System repair finished.', msg.error ? 'error' : 'success');
    } else if (msg.type === 'deep_optimize_complete') {
      toast.push(msg.error ? `Deep optimization failed: ${msg.error}` : 'Deep optimization finished.', msg.error ? 'error' : 'success');
    } else if (msg.type === 'scheduled_scan_complete') {
      const n = msg.results?.length || 0;
      toast.push(`Scheduled scan finished — ${n} item${n !== 1 ? 's' : ''} flagged.`, n ? 'warn' : 'success');
    }
  }, [toast]);

  const { data: telemetry, ready: wsReady } = useTelemetry(true, handleWsEvent);

  const {
    startScan, status: scanStatus, progress, threats, summary,
    vtProgress, errorMessage, infoMessage,
  } = useScanWS();
  const scanning = scanStatus === 'scanning' || scanStatus === 'started';

  useEffect(() => { applyTheme(theme); }, [theme]);

  useEffect(() => {
    const check = async () => {
      try {
        const h = await healthCheck();
        setApiReady(true);
        setBackendOs(h.os);
      } catch {
        setApiReady(false);
      }
    };
    check();
    const id = setInterval(check, 15000);
    return () => clearInterval(id);
  }, []);

  /**
   * The backend's VirusTotal-configured state is the source of truth,
   * not localStorage. This also self-heals: if the backend ever reports
   * "not configured" while a key is saved locally, push it back
   * automatically rather than requiring a manual re-save. Runs on mount
   * and every 30 seconds.
   */
  useEffect(() => {
    const checkAndHeal = async () => {
      try {
        const s = await getVtStatus();
        setVtConfigured(!!s.configured);
        if (!s.configured && vtKey) {
          await setVtApiKey(vtKey);
          setVtConfigured(true);
        }
      } catch { /* backend offline — the health-check effect already surfaces this */ }
    };
    checkAndHeal();
    const id = setInterval(checkAndHeal, 30_000);
    return () => clearInterval(id);
  }, [vtKey]);

  useEffect(() => {
    if (tab === 'startup') {
      setLoadingStart(true);
      getStartupItems().then(r => setStartupData(r.items||[])).finally(()=>setLoadingStart(false));
    }
    if (tab === 'history') {
      setLoadingHist(true);
      getScanHistory(50).then(r => setHistoryData(r.scans||[])).finally(()=>setLoadingHist(false));
    }
  }, [tab]);

  useEffect(() => {
    if (!networkPaused && telemetry?.network) {
      setFrozenNetwork(telemetry.network);
    }
  }, [telemetry?.network, networkPaused]);

  // A bad folder path returns a clear message here instead of a silent
  // "0 files, all clear" result.
  useEffect(() => { if (errorMessage) toast.push(errorMessage, 'error'); }, [errorMessage, toast.push]);
  useEffect(() => { if (infoMessage) toast.push(infoMessage, 'info'); }, [infoMessage, toast.push]);

  const handleScanClick = useCallback(() => {
    if (!vtAsked.current) { setModal('vtKey'); return; }
    setModal('scan');
  }, []);

  const handleVtKeySave = useCallback(async (key) => {
    localStorage.setItem('sentra_vt_key', key);
    localStorage.setItem('sentra_vt_asked', 'true');
    vtAsked.current = true;
    setVtKey(key);
    if (key) {
      try {
        await setVtApiKey(key);
        setVtConfigured(true);
        toast.push('VirusTotal key saved and active.', 'success');
      } catch (e) {
        toast.push(`Key saved, but activating it failed: ${e.message}`, 'warn');
      }
    }
    setModal('scan');
  }, [toast]);

  const handleVtKeySkip = useCallback(() => {
    localStorage.setItem('sentra_vt_asked', 'true');
    vtAsked.current = true;
    setModal('scan');
  }, []);

  const handleScanStart = useCallback(({ type, path, verify_vt, force_rescan }) => {
    setModal(null);
    startScan({ type, path, verify_vt, force_rescan }, {
      onComplete: (s) => {
        toast.push(
          s.threats_found > 0
            ? `Scan complete — ${s.threats_found} threat${s.threats_found !== 1 ? 's' : ''} found.`
            : 'Scan complete — system clean.',
          s.threats_found > 0 ? 'warn' : 'success',
        );
        if (tab === 'history') getScanHistory(50).then(r => setHistoryData(r.scans || [])).catch(() => {});
      },
    });
  }, [startScan, toast, tab]);

  const handleCleanupConfirm = useCallback(async ({ deepClean, runRepair } = {}) => {
    setCleaning(true);
    try {
      const r = await performCleanup({ deep_clean: !!deepClean });
      toast.push(r.message, 'success');
      if (runRepair) {
        await systemRepair();
        toast.push('System repair started — running in the background.', 'info');
      }
      setModal(null);
    } catch (e) {
      toast.push(`Optimization failed: ${e.message}`, 'error');
    } finally {
      setCleaning(false);
    }
  }, [toast]);

  /**
   * The immediate response only acknowledges that the update started —
   * the real result arrives later via handleWsEvent. A 90-second safety
   * timeout clears the loading state if the WebSocket connection drops
   * mid-update, so the button doesn't spin forever.
   */
  const handleUpdate = useCallback(async () => {
    setUpdating(true);
    try {
      await updateIntelligence();
      toast.push('Updating threat definitions in the background…', 'info');
      updateTimeoutRef.current = setTimeout(() => {
        setUpdating(false);
        toast.push('This is taking longer than usual — check back in a moment.', 'warn');
      }, 90_000);
    } catch (e) {
      setUpdating(false);
      toast.push(`Couldn't start the update: ${e.message}`, 'error');
    }
  }, [toast]);

  const handleTheme = useCallback((id) => { setTheme(id); applyTheme(id); }, []);

  const scanSummary = summary ?? null;

  const renderTab = () => {
    switch (tab) {
      case 'network':
        return (
          <Panel
            title="Network Connections"
            badge={frozenNetwork.length}
            action={
              <button
                onClick={() => setNetworkPaused(p => !p)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition-all"
                style={{
                  background: networkPaused ? 'var(--warn-dim)' : 'var(--surface-2)',
                  color: networkPaused ? 'var(--warn)' : 'var(--text-2)',
                  border: '1px solid var(--border)',
                }}
              >
                {networkPaused ? '▶ Resume' : '⏸ Pause'}
              </button>
            }
            style={{ flex: 1 }}
          >
            <NetworkMonitor connections={frozenNetwork} loading={frozenNetwork.length === 0} />
          </Panel>
        );
      case 'startup':
        return (
          <Panel title="Startup Items" badge={startupData.length} style={{ flex: 1 }}>
            <StartupItems items={startupData} loading={loadingStart} />
          </Panel>
        );
      case 'history':
        return (
          <Panel title="Scan History" badge={historyData.length} style={{ flex: 1 }}>
            <ScanHistory scans={historyData} loading={loadingHist} />
          </Panel>
        );
      case 'settings':
        return (
          // Bug fix: this wrapper was a plain block (`h-full overflow-hidden`
          // with no `display:flex`), so SettingsPanel's own `overflow-y-auto`
          // grid never had a bounded height to actually overflow *within* —
          // it just grew, and this wrapper silently clipped the excess
          // instead of scrolling. Making this a flex column gives the panel
          // a real height to size against, so its scrollbar now works.
          <div className="flex-1 min-h-0 h-full flex flex-col overflow-hidden">
            <SettingsPanel vtKey={vtKey} onVtKeyChange={setVtKey} theme={theme} onThemeChange={handleTheme} />
          </div>
        );
      default:
        return (
          <div className="flex flex-col gap-3 flex-1 overflow-hidden">
            <StatusCards telemetry={telemetry} scanSummary={scanSummary} />
            <div className="flex gap-3 flex-1 overflow-hidden">
              <Panel title="Process Intel" style={{ width: 240, flexShrink: 0 }}>
                <ProcessMonitor processes={telemetry?.processes} />
              </Panel>
              <div className="flex flex-col gap-3 flex-1 overflow-hidden">
                <ShieldGauge score={scanSummary?.shield_score ?? 100} scanComplete={!!scanSummary} scanning={scanning} />
                <SystemGraph history={telemetry?.history} currentMemory={telemetry?.memory ?? 0} />
                <ThreatFeed threats={threats} scanning={scanning} progress={progress} vtProgress={vtProgress} />
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: 'var(--bg)' }}>
      <TopNav
        activeTab={tab} onTabChange={setTab}
        theme={theme} onThemeChange={handleTheme}
        onScan={handleScanClick} onUpdate={handleUpdate} onCleanup={() => setModal('cleanup')}
        scanning={scanning} updating={updating} cleaning={cleaning}
        wsReady={wsReady} scanStatus={scanStatus}
      />

      <AnimatePresence>
        {!apiReady && (
          <motion.div initial={{ height: 0 }} animate={{ height: 32 }} exit={{ height: 0 }}
            className="flex items-center justify-center gap-2 text-[10px] flex-shrink-0"
            style={{ background: 'var(--danger-dim)', borderBottom: '1px solid rgba(248,113,113,.2)', color: 'var(--danger)' }}>
            <span className="w-1.5 h-1.5 rounded-full animate-blink" style={{ background: 'var(--danger)' }} />
            Backend offline — run: <code className="font-mono bg-black/20 px-1.5 py-0.5 rounded">python backend/main.py</code>
          </motion.div>
        )}
      </AnimatePresence>

      <main className="flex-1 overflow-hidden p-3">
        <AnimatePresence mode="wait">
          <motion.div key={tab} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }} transition={{ duration: 0.15 }} className="h-full flex flex-col">
            {renderTab()}
          </motion.div>
        </AnimatePresence>
      </main>

      <VTKeyModal open={modal === 'vtKey'} onSave={handleVtKeySave} onSkip={handleVtKeySkip} />
      <ScanModal
        open={modal === 'scan'}
        onClose={() => setModal(null)}
        onStart={handleScanStart}
      />
      <CleanupModal open={modal === 'cleanup'} onClose={() => !cleaning && setModal(null)} onConfirm={handleCleanupConfirm} loading={cleaning} os={backendOs} />
      <IntelModal open={modal === 'intel'} onClose={() => setModal(null)} result={intelResult} />
    </div>
  );
}

export default function App() {
  return <ErrorBoundary><ToastProvider><AppContent /></ToastProvider></ErrorBoundary>;
}
