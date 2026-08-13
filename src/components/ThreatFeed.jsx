import React, { useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

function riskLevel(s) {
  if (s > 75) return { label: 'CRITICAL', color: 'var(--danger)',  bg: 'var(--danger-dim)'  };
  if (s > 50) return { label: 'HIGH',     color: '#fb923c',        bg: 'rgba(251,146,60,.12)' };
  if (s > 25) return { label: 'MEDIUM',   color: 'var(--warn)',    bg: 'var(--warn-dim)'    };
  return             { label: 'LOW',      color: 'var(--accent)',  bg: 'var(--accent-dim)'  };
}

function vtBadgeColor(verdict) {
  if (verdict === 'malicious')  return { color: 'var(--danger)', bg: 'var(--danger-dim)' };
  if (verdict === 'suspicious') return { color: 'var(--warn)',   bg: 'var(--warn-dim)'   };
  if (verdict === 'clean')      return { color: 'var(--safe)',   bg: 'var(--safe-dim)'   };
  return { color: 'var(--text-3)', bg: 'var(--surface-3)' };
}

const SOURCE_LABELS = {
  malwarebazaar: 'MalwareBazaar',
  otx: 'OTX',
  virustotal: 'VT',
  signature: 'Signed',
  none: 'Unreviewed',
  'multi-source': 'Intel',
};

function ThreatRow({ t, index }) {
  const { label, color, bg } = riskLevel(t.risk_score);
  const fname = (t.file || '').split(/[\\/]/).pop();
  const vt = t.vt_checked ? vtBadgeColor(t.vt_verdict) : null;
  const vtLabel = SOURCE_LABELS[t.vt_source] || 'Intel';

  return (
    <motion.div
      initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      className="flex items-start gap-2.5 px-3 py-2 rounded-xl"
      style={{ background: 'var(--surface-3)', border: `1px solid ${color}22` }}
    >
      <span className="flex-shrink-0 text-[9px] font-bold font-mono px-1.5 py-0.5 rounded-md mt-0.5"
        style={{ background: bg, color, border: `1px solid ${color}33` }}>
        {label}
      </span>

      <div className="flex-1 min-w-0">
        <p className="text-[11px] font-mono truncate" style={{ color: 'var(--text)' }} title={t.file}>
          {fname}
        </p>
        <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
          {t.mitre_id && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded inline-block"
              style={{ background: 'var(--info-dim)', color: 'var(--info)', border: '1px solid rgba(129,140,248,.2)' }}>
              {t.mitre_id} · {t.mitre_name}
            </span>
          )}
          {vt && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded inline-block"
              style={{ background: vt.bg, color: vt.color, border: `1px solid ${vt.color}33` }}>
              {vtLabel}: {t.vt_verdict}
            </span>
          )}
          {!t.mitre_id && !vt && t.details?.[0] && (
            <p className="text-[9px] truncate" style={{ color: 'var(--text-3)' }}>{t.details[0]}</p>
          )}
        </div>
      </div>
      <span className="flex-shrink-0 text-[11px] font-bold font-mono" style={{ color }}>{t.risk_score}%</span>
    </motion.div>
  );
}

function ClearedRow({ t, index }) {
  const fname = (t.file || '').split(/[\\/]/).pop();
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 0.75 }}
      transition={{ delay: index * 0.02 }}
      className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl"
      style={{ background: 'var(--surface-3)' }}
    >
      <span className="flex-shrink-0 text-[10px]" style={{ color: 'var(--safe)' }}>✓</span>
      <p className="text-[10px] font-mono truncate flex-1" style={{ color: 'var(--text-3)' }} title={t.file}>
        {fname}
      </p>
      <span className="flex-shrink-0 text-[9px]" style={{ color: 'var(--safe)' }}>Confirmed clean</span>
    </motion.div>
  );
}

export function ThreatFeed({ threats, scanning, progress, vtProgress }) {
  const { active, cleared } = useMemo(() => {
    const active = [];
    const cleared = [];
    for (const t of threats || []) {
      (t.vt_cleared ? cleared : active).push(t);
    }
    active.sort((a, b) => b.risk_score - a.risk_score);
    return { active, cleared };
  }, [threats]);

  const pct   = progress?.total > 0 ? Math.round((progress.scanned / progress.total) * 100) : 0;
  const vtPct = vtProgress?.total > 0 ? Math.round((vtProgress.checked / vtProgress.total) * 100) : 0;

  return (
    <div className="flex flex-col rounded-2xl overflow-hidden flex-1"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>

      <div className="flex items-center justify-between px-4 py-2 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--border)' }}>
        <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
          Threat Feed
        </span>
        <span className="text-[9px] font-mono px-2 py-0.5 rounded-md"
          style={{ background: 'var(--surface-3)', color: 'var(--text-3)' }}>
          {active.length} active
        </span>
      </div>

      {scanning && !vtProgress && (
        <div className="flex-shrink-0 px-4 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[9px] font-mono truncate max-w-[200px]" style={{ color: 'var(--text-3)' }}>
              {progress?.current_file || 'Initializing…'}
            </span>
            <span className="text-[9px] font-mono flex-shrink-0 ml-2" style={{ color: 'var(--accent)' }}>
              {progress?.scanned || 0}/{progress?.total || '?'} · {pct}%
            </span>
          </div>
          <div className="h-1 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
            <motion.div className="h-full rounded-full" style={{ background: 'var(--accent)' }}
              animate={{ width: `${pct}%` }} transition={{ duration: 0.3 }} />
          </div>
        </div>
      )}

      {vtProgress && (
        <div className="flex-shrink-0 px-4 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[9px] font-mono" style={{ color: 'var(--info)' }}>
              Verifying against threat intelligence…
            </span>
            <span className="text-[9px] font-mono" style={{ color: 'var(--info)' }}>
              {vtProgress.checked}/{vtProgress.total}
            </span>
          </div>
          <div className="h-1 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
            <motion.div className="h-full rounded-full" style={{ background: 'var(--info)' }}
              animate={{ width: `${vtPct}%` }} transition={{ duration: 0.3 }} />
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto scrollbar p-3 space-y-1.5" style={{ maxHeight: 220 }}>
        <AnimatePresence mode="wait">
          {active.length === 0 && cleared.length === 0 ? (
            <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="flex items-center justify-center gap-2 py-6">
              <div className="w-2 h-2 rounded-full"
                style={{ background: scanning ? 'var(--accent)' : 'var(--safe)', boxShadow: `0 0 6px ${scanning ? 'var(--accent)' : 'var(--safe)'}` }} />
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>
                {scanning ? 'Scanning for threats…' : 'No threats detected — run a scan'}
              </span>
            </motion.div>
          ) : (
            <React.Fragment key="results">
              {active.map((t, i) => <ThreatRow key={t.id || `${t.file}-${i}`} t={t} index={i} />)}
              {cleared.length > 0 && (
                <div className="pt-2">
                  <p className="text-[9px] font-bold uppercase tracking-wider px-1 mb-1.5" style={{ color: 'var(--safe)' }}>
                    Verified safe ({cleared.length})
                  </p>
                  <div className="space-y-1">
                    {cleared.map((t, i) => <ClearedRow key={t.id || `${t.file}-c${i}`} t={t} index={i} />)}
                  </div>
                </div>
              )}
            </React.Fragment>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
