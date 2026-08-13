import React, { useState, useEffect } from 'react';
import {
  saveSchedule, saveWatcher, defenderExclude, defenderStatus, getSchedule, getWatcher,
  getVtStatus, setVtApiKey, testVtConnection, getIntelStatus, setIntelKey, getClearedFilesCount,
} from '../services/api';
import { useToast } from './Toast';
import { ScheduleModal } from './ScheduleModal';
import { ModalBtn } from './Modal';

function Section({ title, children }) {
  return (
    <div className="rounded-2xl p-5 space-y-4" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
      <h3 className="text-[11px] font-bold uppercase tracking-wider" style={{ color: 'var(--accent)' }}>{title}</h3>
      {children}
    </div>
  );
}

/** Small always-active badge for keyless providers (MalwareBazaar / URLhaus), with a live request counter. */
function AlwaysActiveBadge({ name, usage }) {
  const requests = usage?.requests_made ?? 0;
  return (
    <div className="flex flex-col gap-0.5 py-2 px-3 rounded-xl" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold" style={{ color: 'var(--safe)' }}>
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--safe)' }} />
          {name}
        </span>
        <span className="text-xs font-bold font-mono" style={{ color: 'var(--accent)' }}>{requests}</span>
      </div>
      <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>
        No key needed · {requests} request{requests !== 1 ? 's' : ''} this session
      </span>
    </div>
  );
}

/** Key-entry row shared by OTX and AbuseIPDB — same pattern as the VT key input, plus a live request counter. */
function ProviderKeyRow({ label, hint, value, onChange, configured, onSave, usage }) {
  const [masked, setMasked] = useState(true);
  const requests = usage?.requests_made ?? 0;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold" style={{ color: 'var(--text)' }}>{label}</span>
        <div className="flex items-center gap-2">
          {configured && (
            <span className="text-[9px] font-mono" style={{ color: 'var(--accent)' }}>
              {requests} req{requests !== 1 ? 's' : ''}.
            </span>
          )}
          <span className="flex items-center gap-1.5 text-[9px]" style={{ color: configured ? 'var(--safe)' : 'var(--text-3)' }}>
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: configured ? 'var(--safe)' : 'var(--text-3)' }} />
            {configured ? 'Configured' : 'Not configured'}
          </span>
        </div>
      </div>
      <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{hint}</p>
      <div className="flex items-center gap-2 rounded-xl px-3 py-2.5" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
        <input type={masked ? 'password' : 'text'} value={value} onChange={e => onChange(e.target.value)}
          placeholder="Paste API key here…" className="flex-1 bg-transparent text-xs outline-none"
          style={{ color: 'var(--text)', caretColor: 'var(--accent)' }} />
        <button onClick={() => setMasked(m => !m)} className="text-[10px]" style={{ color: 'var(--text-3)' }}>{masked ? 'show' : 'hide'}</button>
      </div>
      <ModalBtn variant="ghost" onClick={onSave} className="w-full">Save Key</ModalBtn>
      {configured && usage?.last_result && (
        <p className="text-[9px] font-mono px-1 truncate" style={{ color: 'var(--text-3)' }} title={usage.last_result}>
          Last: {usage.last_result}
        </p>
      )}
    </div>
  );
}

export function SettingsPanel({ vtKey, onVtKeyChange, theme, onThemeChange }) {
  const toast = useToast();
  const [localKey,  setLocalKey]  = useState(vtKey || '');
  const [masked,    setMasked]    = useState(true);
  const [schedCfg,  setSchedCfg]  = useState(null);
  const [watchDirs, setWatchDirs] = useState('');
  const [schedOpen, setSchedOpen] = useState(false);
  const [schedLoading, setSchedLoading] = useState(false);
  const [defStatus, setDefStatus] = useState(null);
  const [vtStatus,  setVtStatus]  = useState(null);
  const [testing,   setTesting]   = useState(false);

  // New: additional threat-intel providers (MalwareBazaar, OTX, AbuseIPDB, URLhaus)
  const [intelStatus, setIntelStatusState] = useState(null);
  const [otxKey, setOtxKey] = useState('');
  const [abuseKey, setAbuseKey] = useState('');
  // New: cross-scan file memory count (Scan Memory section)
  const [clearedCount, setClearedCount] = useState(null);

  useEffect(() => {
    getSchedule().then(setSchedCfg).catch(() => {});
    getWatcher().then(r => setWatchDirs((r.watch_dirs || []).join('\n'))).catch(() => {});
    defenderStatus().then(setDefStatus).catch(() => {});
  }, []);

  // Poll VT status while Settings is open so the request counter and
  // configured state stay current without needing a manual refresh.
  useEffect(() => {
    const fetchStatus = () => getVtStatus().then(setVtStatus).catch(() => {});
    fetchStatus();
    const id = setInterval(fetchStatus, 5000);
    return () => clearInterval(id);
  }, []);

  // Same pattern for the newer providers' configured/active state.
  useEffect(() => {
    const fetchIntel = () => getIntelStatus().then(setIntelStatusState).catch(() => {});
    fetchIntel();
    const id = setInterval(fetchIntel, 10000);
    return () => clearInterval(id);
  }, []);

  // Scan Memory count — how many files are currently remembered as clean.
  useEffect(() => {
    const fetchCleared = () => getClearedFilesCount().then(r => setClearedCount(r.count)).catch(() => {});
    fetchCleared();
    const id = setInterval(fetchCleared, 10000);
    return () => clearInterval(id);
  }, []);

  const saveVtKey = async () => {
    const trimmed = localKey.trim();
    localStorage.setItem('sentra_vt_key', trimmed);
    onVtKeyChange(trimmed);
    try {
      await setVtApiKey(trimmed);
      toast.push('VirusTotal key saved and active — no restart needed.', 'success');
      getVtStatus().then(setVtStatus).catch(() => {});
    } catch (e) {
      toast.push(`Saved locally, but activating it on the backend failed: ${e.message}`, 'warn');
    }
  };

  const handleSaveIntelKey = async (provider, key) => {
    const trimmed = key.trim();
    try {
      await setIntelKey(provider, trimmed);
      const label = provider === 'otx' ? 'AlienVault OTX' : 'AbuseIPDB';
      toast.push(`${label} key saved and active.`, 'success');
      getIntelStatus().then(setIntelStatusState).catch(() => {});
    } catch (e) {
      toast.push(`Failed to save key: ${e.message}`, 'error');
    }
  };

  // Proves the key + counter actually work RIGHT NOW, without needing a
  // real threat to show up in a scan first. Uses the standard EICAR test
  // hash, which every AV vendor flags by design — a safe, well-defined
  // way to confirm the round-trip works.
  const handleTestConnection = async () => {
    setTesting(true);
    try {
      const r = await testVtConnection();
      if (r.status === 'success' || r.status === 'not_found') {
        toast.push(r.message || 'Connection confirmed.', 'success');
      } else if (r.status === 'no_key') {
        toast.push('Save a key first, then test the connection.', 'warn');
      } else {
        toast.push(r.message || 'Test failed.', 'error');
      }
      getVtStatus().then(setVtStatus).catch(() => {});
    } catch (e) {
      toast.push(`Connection test failed: ${e.message}`, 'error');
    } finally {
      setTesting(false);
    }
  };

  const handleScheduleSave = async (cfg) => {
    setSchedLoading(true);
    try { await saveSchedule(cfg); setSchedCfg(cfg); setSchedOpen(false); toast.push('Schedule saved.', 'success'); }
    catch { toast.push('Failed to save schedule.', 'error'); }
    finally { setSchedLoading(false); }
  };

  const handleWatcherSave = async (enabled) => {
    const dirs = watchDirs.split('\n').map(s => s.trim()).filter(Boolean);
    try { await saveWatcher({ enabled, watch_dirs: dirs }); toast.push(`Auto-scan ${enabled ? 'enabled' : 'disabled'}.`, 'success'); }
    catch { toast.push('Failed to update watcher.', 'error'); }
  };

  const handleDefenderExclude = async () => {
    try {
      const r = await defenderExclude('.');
      toast.push(r.message, r.status === 'success' ? 'success' : 'warn');
    } catch { toast.push('Defender exclusion failed.', 'error'); }
  };

  const THEMES = [
    { id: '',             color: '#22d3ee', label: 'Cyan'   },
    { id: 'theme-green',  color: '#4ade80', label: 'Green'  },
    { id: 'theme-amber',  color: '#fbbf24', label: 'Amber'  },
    { id: 'theme-violet', color: '#a78bfa', label: 'Violet' },
  ];

  return (
    // Bug fix: this grid previously had no bounded height (`overflow-y-auto`
    // with nothing to overflow within — see App.jsx's Settings wrapper fix),
    // so some sections never became reachable. `h-full min-h-0` gives it a
    // real height inside the now-flex parent, and its own scrollbar works.
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 overflow-y-auto scrollbar p-1 h-full min-h-0">
      <Section title="VirusTotal Integration">
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Free key at virustotal.com — 500 lookups/day, no file uploads.</p>
        <div className="flex items-center gap-2 rounded-xl px-3 py-2.5" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
          <input type={masked ? 'password' : 'text'} value={localKey} onChange={e => setLocalKey(e.target.value)}
            placeholder="Paste API key here…" className="flex-1 bg-transparent text-xs outline-none"
            style={{ color: 'var(--text)', caretColor: 'var(--accent)' }} />
          <button onClick={() => setMasked(m => !m)} className="text-[10px]" style={{ color: 'var(--text-3)' }}>{masked ? 'show' : 'hide'}</button>
        </div>
        <ModalBtn variant="primary" onClick={saveVtKey} className="w-full">Save Key</ModalBtn>
        <ModalBtn variant="ghost" onClick={handleTestConnection} loading={testing} className="w-full">
          Test Connection
        </ModalBtn>
        <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>
          Takes effect immediately. Add it to <code style={{ color: 'var(--text-2)' }}>.env</code> as{' '}
          <code style={{ color: 'var(--text-2)' }}>VT_API_KEY</code> too if you want it to survive a backend restart.
        </p>
      </Section>

      {/* VirusTotal Usage — the direct, live-updating answer to "is it actually being used" */}
      <Section title="VirusTotal Usage">
        {vtStatus ? (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ background: vtStatus.configured ? 'var(--safe)' : 'var(--danger)' }} />
              <span className="text-xs" style={{ color: 'var(--text)' }}>
                {vtStatus.configured ? 'API key configured and active' : 'No API key configured'}
              </span>
            </div>

            {vtStatus.configured && (
              <>
                <div className="grid grid-cols-3 gap-2">
                  <div className="flex flex-col items-center py-2.5 rounded-xl" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                    <span className="text-lg font-black font-mono" style={{ color: 'var(--accent)' }}>{vtStatus.requests_made}</span>
                    <span className="text-[9px] mt-0.5 text-center" style={{ color: 'var(--text-3)' }}>Requests this session</span>
                  </div>
                  <div className="flex flex-col items-center py-2.5 rounded-xl" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                    <span className="text-lg font-black font-mono" style={{ color: 'var(--accent)' }}>{vtStatus.cache_hits}</span>
                    <span className="text-[9px] mt-0.5 text-center" style={{ color: 'var(--text-3)' }}>Served from cache</span>
                  </div>
                  <div className="flex flex-col items-center py-2.5 rounded-xl" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                    <span className="text-lg font-black font-mono" style={{ color: 'var(--accent)' }}>{vtStatus.cache_entries}</span>
                    <span className="text-[9px] mt-0.5 text-center" style={{ color: 'var(--text-3)' }}>Cached results total</span>
                  </div>
                </div>

                {vtStatus.last_result ? (
                  <p className="text-[10px] font-mono px-3 py-2 rounded-lg" style={{ background: 'var(--surface-2)', color: 'var(--text-2)' }}>
                    Last check: <span style={{ color: 'var(--accent)' }}>{vtStatus.last_result}</span>
                  </p>
                ) : (
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                    No requests yet this session — click "Test Connection" above, run a Shield Scan,
                    or use a "Check Reputation" button anywhere in the app.
                  </p>
                )}

                <p className="text-[9px]" style={{ color: 'var(--text-3)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
                  This is separate from <b>Update Intel</b> (top bar) — that only refreshes YARA
                  malware-signature rules and has nothing to do with VirusTotal or this cache.
                </p>
              </>
            )}
          </div>
        ) : (
          <p className="text-[10px] animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
        )}
      </Section>

      {/* Additional threat-intel providers — checked before/alongside VirusTotal.
          MalwareBazaar and URLhaus need no key at all; OTX and AbuseIPDB use
          free keys the same way the VT key above works. */}
      <Section title="Additional Threat Intelligence">
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
          Every suspicious finding is checked against these before VirusTotal, so the free/unlimited tiers absorb most of the volume.
        </p>

        <div className="grid grid-cols-2 gap-2">
          <AlwaysActiveBadge name="MalwareBazaar" usage={intelStatus?.malwarebazaar_usage} />
          <AlwaysActiveBadge name="URLhaus" usage={intelStatus?.urlhaus_usage} />
        </div>

        <ProviderKeyRow
          label="AlienVault OTX"
          hint="Free key — high/uncapped quota. Used before VirusTotal for file-hash lookups."
          value={otxKey}
          onChange={setOtxKey}
          configured={intelStatus?.otx_configured}
          usage={intelStatus?.otx_usage}
          onSave={() => handleSaveIntelKey('otx', otxKey)}
        />

        <ProviderKeyRow
          label="AbuseIPDB"
          hint="Free key — 1,000 requests/day. Checked alongside VirusTotal for network connections."
          value={abuseKey}
          onChange={setAbuseKey}
          configured={intelStatus?.abuseipdb_configured}
          usage={intelStatus?.abuseipdb_usage}
          onSave={() => handleSaveIntelKey('abuseipdb', abuseKey)}
        />

        {/* Scope clarification — the most common source of confusion:
            AbuseIPDB/URLhaus showing 0 requests after a Deep or Custom
            scan is expected, not a bug. They only fire for network/IP
            checks, which only happen during Quick Scan or a manual
            "Check Reputation" click in the Network tab. */}
        <p className="text-[9px] leading-relaxed" style={{ color: 'var(--text-3)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
          <b>MalwareBazaar, OTX, and VirusTotal</b> check <b>files</b>, so they run during any scan type.{' '}
          <b>AbuseIPDB and URLhaus</b> check <b>network connections</b> only — they run during a Quick Scan
          (which includes network findings) or a manual "Check Reputation" click in the Network tab. A Deep
          or Custom scan will never show activity for AbuseIPDB/URLhaus — that's expected, not a bug.
        </p>
      </Section>

      <Section title="Scan Memory">
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
          Files that already passed a scan clean are remembered and skipped on future scans until they
          actually change (by path, size, and modified time) — no need to re-check the same unchanged file
          every time. Updating threat intel resets this, so everything gets one fresh look under the new rules.
        </p>
        <div className="flex items-center justify-between px-3 py-2.5 rounded-xl" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <span className="text-[11px] font-semibold" style={{ color: 'var(--text)' }}>Files remembered as clean</span>
          <span className="text-sm font-bold font-mono" style={{ color: 'var(--accent)' }}>
            {clearedCount ?? '—'}
          </span>
        </div>
        <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>
          Use "Force full re-scan" in the Shield Scan dialog to bypass this and check every file fresh.
        </p>
      </Section>

      <Section title="Scheduled Scans">
        <p className="text-xs" style={{ color: 'var(--text)' }}>
          {schedCfg?.enabled ? `${schedCfg.frequency} at ${String(schedCfg.hour).padStart(2,'0')}:00` : 'Disabled'}
        </p>
        {schedCfg?.next_run && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Next: {schedCfg.next_run.slice(0,16).replace('T',' ')}</p>}
        <ModalBtn variant="ghost" onClick={() => setSchedOpen(true)} className="w-full">Configure Schedule</ModalBtn>
        <ScheduleModal open={schedOpen} onClose={() => setSchedOpen(false)} config={schedCfg} onSave={handleScheduleSave} loading={schedLoading} />
      </Section>

      <Section title="Auto-Scan Watchdog">
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>One path per line. New executables are scanned automatically.</p>
        <textarea rows={3} value={watchDirs} onChange={e => setWatchDirs(e.target.value)}
          placeholder={"C:\\Users\\You\\Downloads\nC:\\Users\\You\\Desktop"}
          className="w-full text-[11px] font-mono rounded-xl px-3 py-2.5 outline-none resize-none"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text)', caretColor: 'var(--accent)' }} />
        <div className="flex gap-2">
          <ModalBtn variant="primary" onClick={() => handleWatcherSave(true)} className="flex-1">Enable</ModalBtn>
          <ModalBtn variant="ghost"   onClick={() => handleWatcherSave(false)} className="flex-1">Disable</ModalBtn>
        </div>
      </Section>

      <Section title="Windows Defender">
        {defStatus && (
          <p className="text-[10px]" style={{ color: 'var(--text-2)' }}>
            {defStatus.is_windows ? `Windows · Admin: ${defStatus.is_admin ? 'Yes' : 'No'}` : 'Not Windows — exclusion not needed'}
          </p>
        )}
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Prevents Defender from quarantining YARA rule files. Requires Administrator.</p>
        <ModalBtn variant="ghost" onClick={handleDefenderExclude} className="w-full">Add App Directory Exclusion</ModalBtn>
      </Section>

      <Section title="Accent Theme">
        <div className="grid grid-cols-2 gap-2">
          {THEMES.map(t => (
            <button key={t.id} onClick={() => onThemeChange(t.id)}
              className="flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all"
              style={{ background: theme === t.id ? `${t.color}18` : 'var(--surface-2)', border: `1px solid ${theme === t.id ? t.color+'44' : 'var(--border)'}` }}>
              <span className="w-4 h-4 rounded-full flex-shrink-0" style={{ background: t.color, boxShadow: `0 0 8px ${t.color}88` }} />
              <span className="text-[11px] font-semibold" style={{ color: theme === t.id ? t.color : 'var(--text-2)' }}>{t.label}</span>
            </button>
          ))}
        </div>
      </Section>

      <Section title="About">
        <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>SENTRA CORE <span style={{ color: 'var(--accent)' }}>v2.3.0</span></p>
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
          Multi-source threat intel (MalwareBazaar, OTX, AbuseIPDB, URLhaus) with per-provider usage tracking,
          digital-signature verification as a VirusTotal-not-found fallback, cross-scan file memory, and
          dynamic per-source attribution in reports.
        </p>
      </Section>
    </div>
  );
}
