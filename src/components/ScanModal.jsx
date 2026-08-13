import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Modal, ModalBtn } from './Modal';
import { getDrives, defenderStatus } from '../services/api';

const TYPES = [
  { id: 'quick',  icon: '⚡', label: 'Quick Scan',        desc: 'Temp dirs & downloads only', time: '~30s',      color: 'var(--safe)'   },
  { id: 'deep',   icon: '🔬', label: 'Deep Scan',         desc: 'Full system drive',           time: '2–5 min',   color: 'var(--warn)'   },
  { id: 'custom', icon: '📁', label: 'Custom Directory',  desc: 'Choose any path or drive',    time: 'Varies',    color: 'var(--accent)' },
];

export function ScanModal({ open, onClose, onStart }) {
  const [selected, setSelected]   = useState('quick');
  const [customPath, setCustomPath] = useState('');
  const [drives, setDrives]       = useState([]);
  const [drivesLoading, setDrivesLoading] = useState(false);
  const [verifyVt, setVerifyVt]   = useState(true);
  const [forceRescan, setForceRescan] = useState(false);
  const [adminInfo, setAdminInfo] = useState(null);

  useEffect(() => {
    defenderStatus().then(setAdminInfo).catch(() => {});
  }, []);

  useEffect(() => {
    if (selected !== 'custom' || drives.length) return;
    setDrivesLoading(true);
    getDrives().then(r => setDrives(r.drives || [])).catch(() => {}).finally(() => setDrivesLoading(false));
  }, [selected]);

  const canStart = selected !== 'custom' || customPath.trim();

  return (
    <Modal open={open} onClose={onClose} title="Shield Scan" subtitle="Choose scan type" icon="⚔️" width="max-w-md">
      <div className="space-y-2.5">
        {TYPES.map((t, i) => {
          const active = selected === t.id;
          return (
            <motion.button key={t.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }} onClick={() => setSelected(t.id)}
              className="w-full text-left flex items-center gap-3 px-4 py-3 rounded-xl transition-all"
              style={{ background: active ? `${t.color}18` : 'var(--surface-2)', border: `1px solid ${active ? t.color + '44' : 'var(--border)'}` }}>
              <div className="flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center transition-all"
                style={{ border: `2px solid ${active ? t.color : 'var(--text-3)'}`, background: active ? t.color : 'transparent' }}>
                {active && <div className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--bg)' }} />}
              </div>
              <span className="text-lg flex-shrink-0">{t.icon}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold" style={{ color: active ? t.color : 'var(--text)' }}>{t.label}</span>
                  <span className="text-[9px] font-mono px-2 py-0.5 rounded-md" style={{ background: 'var(--surface-3)', color: 'var(--text-3)' }}>{t.time}</span>
                </div>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{t.desc}</p>
              </div>
            </motion.button>
          );
        })}

        {/* Proactive warning — a non-elevated backend can't read most system
            folders, which is the most common reason Deep/Custom finds
            almost nothing. Better to say so now than leave a 0-file
            result unexplained afterward. */}
        {(selected === 'deep' || selected === 'custom') && adminInfo?.is_windows && !adminInfo?.is_admin && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="flex items-start gap-2 px-3 py-2.5 rounded-xl text-[10px]"
            style={{ background: 'var(--warn-dim)', color: 'var(--warn)', border: '1px solid rgba(251,191,36,.2)' }}>
            <span className="flex-shrink-0 mt-0.5">⚠</span>
            <span>Not running as Administrator — protected system folders will be skipped. Run the backend terminal as Administrator for a complete scan.</span>
          </motion.div>
        )}

        {selected === 'custom' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
            <input type="text" value={customPath} onChange={e => setCustomPath(e.target.value)}
              placeholder="e.g. C:\Users\You\Downloads"
              className="w-full text-xs rounded-xl px-3 py-2.5 outline-none font-mono"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text)', caretColor: 'var(--accent)' }}
              autoFocus />
            {drivesLoading && <p className="text-[10px] animate-pulse" style={{ color: 'var(--text-3)' }}>Loading drives…</p>}
            {drives.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {drives.map(d => (
                  <button key={d.mountpoint} onClick={() => setCustomPath(d.mountpoint)}
                    className="px-2.5 py-1 rounded-lg text-[10px] font-mono transition-all"
                    style={{ background: customPath === d.mountpoint ? 'var(--accent-dim)' : 'var(--surface-3)', color: customPath === d.mountpoint ? 'var(--accent)' : 'var(--text-2)', border: `1px solid ${customPath === d.mountpoint ? 'var(--border-2)' : 'var(--border)'}` }}>
                    {d.mountpoint} · {d.free_gb}GB free
                  </button>
                ))}
              </div>
            )}
          </motion.div>
        )}

        {/*
          Bug fix: this used to be a VirusTotal-only toggle, disabled
          entirely if no VT key was configured, and text hardcoded to
          "top 10 highest-risk files". Verification is now multi-source
          (MalwareBazaar + AlienVault OTX + VirusTotal for files;
          AbuseIPDB + URLhaus + VirusTotal for network findings) and
          MalwareBazaar/URLhaus need no key at all — so the toggle is
          always available, and every flagged item is checked, not just
          the top 10.
        */}
        <div className="flex items-center justify-between px-3 py-2.5 rounded-xl"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <div className="min-w-0 pr-2">
            <p className="text-[11px] font-semibold" style={{ color: 'var(--text)' }}>
              Verify every flagged item
            </p>
            <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>
              Checks all suspicious findings against MalwareBazaar, AlienVault OTX, and VirusTotal — no cutoff.
            </p>
          </div>
          <button
            onClick={() => setVerifyVt(v => !v)}
            className="w-9 h-5 rounded-full transition-all flex-shrink-0"
            style={{ background: verifyVt ? 'var(--accent)' : 'var(--surface-3)', position: 'relative' }}>
            <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
              style={{ background: 'white', left: verifyVt ? '18px' : '2px' }} />
          </button>
        </div>

        {/*
          New: files that already passed a previous scan clean are now
          remembered and skipped automatically until they change — see
          Settings → Scan Memory. This toggle bypasses that when you
          deliberately want a full fresh check of everything, e.g. right
          after adding a new API key or wanting to double-check with new
          eyes regardless of history.
        */}
        <div className="flex items-center justify-between px-3 py-2.5 rounded-xl"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <div className="min-w-0 pr-2">
            <p className="text-[11px] font-semibold" style={{ color: 'var(--text)' }}>
              Force full re-scan
            </p>
            <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>
              Re-check every file even if it passed a previous scan unchanged. Slower, but useful right after updating threat intel.
            </p>
          </div>
          <button
            onClick={() => setForceRescan(v => !v)}
            className="w-9 h-5 rounded-full transition-all flex-shrink-0"
            style={{ background: forceRescan ? 'var(--accent)' : 'var(--surface-3)', position: 'relative' }}>
            <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
              style={{ background: 'white', left: forceRescan ? '18px' : '2px' }} />
          </button>
        </div>

        <div className="flex gap-2 pt-1" style={{ borderTop: '1px solid var(--border)' }}>
          <ModalBtn variant="ghost" onClick={onClose} className="flex-1">Cancel</ModalBtn>
          <ModalBtn
            variant="primary"
            onClick={() => onStart({ type: selected, path: customPath.trim(), verify_vt: verifyVt, force_rescan: forceRescan })}
            disabled={!canStart}
            className="flex-1"
          >
            Start Scan
          </ModalBtn>
        </div>
      </div>
    </Modal>
  );
}
