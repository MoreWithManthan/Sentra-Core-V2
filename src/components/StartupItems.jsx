import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { checkStartupItemVt } from '../services/api';

/**
 * Registry Run values often look like:
 *   "C:\Program Files\App\app.exe" --silent --minimized
 * A raw hash/isfile() check on that whole string will fail. This pulls
 * out just the executable path so the VT check endpoint gets something
 * that actually exists on disk.
 */
function extractExePath(raw) {
  if (!raw) return raw;
  const trimmed = raw.trim();
  if (trimmed.startsWith('"')) {
    const end = trimmed.indexOf('"', 1);
    if (end > 0) return trimmed.slice(1, end);
  }
  const match = trimmed.match(/^(.*?\.(exe|dll|bat|cmd|scr|ps1|vbs))(\s|$)/i);
  return match ? match[1] : trimmed.split(' ')[0];
}

const SOURCE_LABELS = {
  malwarebazaar: 'MalwareBazaar',
  otx: 'OTX',
  virustotal: 'VT',
  signature: 'Signed',
  none: 'Unreviewed',
};

export function StartupItems({ items = [], loading }) {
  const [vtResults, setVtResults] = useState({});   // path -> result
  const [checking, setChecking]   = useState({});   // path -> bool

  const handleCheck = async (item) => {
    const exePath = extractExePath(item.path);
    setChecking(prev => ({ ...prev, [item.path]: true }));
    try {
      const result = await checkStartupItemVt(exePath);
      setVtResults(prev => ({ ...prev, [item.path]: result }));
    } catch {
      setVtResults(prev => ({ ...prev, [item.path]: { status: 'error', message: 'Check failed' } }));
    } finally {
      setChecking(prev => ({ ...prev, [item.path]: false }));
    }
  };

  if (loading && items.length === 0) {
    return <div className="text-[10px] text-center py-10 animate-pulse" style={{ color: 'var(--text-3)' }}>Scanning startup items…</div>;
  }

  const suspicious = items.filter(i => i.suspicious);
  const clean      = items.filter(i => !i.suspicious);

  return (
    <div className="space-y-4">
      {suspicious.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--danger)' }}>
            ⚠ Suspicious ({suspicious.length})
          </p>
          <div className="space-y-2">
            {suspicious.map((item, i) => (
              <ItemRow key={item.path + i} item={item} index={i}
                vtResult={vtResults[item.path]} checking={!!checking[item.path]} onCheck={handleCheck} />
            ))}
          </div>
        </div>
      )}
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
          Known Items ({clean.length})
        </p>
        <div className="space-y-1.5">
          {clean.map((item, i) => (
            <ItemRow key={item.path + i} item={item} index={i}
              vtResult={vtResults[item.path]} checking={!!checking[item.path]} onCheck={handleCheck} />
          ))}
        </div>
      </div>
      {items.length === 0 && (
        <div className="text-center py-10">
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
            No startup items found (Windows only)
          </p>
        </div>
      )}
    </div>
  );
}

/**
 * The backend endpoint behind this now waterfalls MalwareBazaar -> OTX ->
 * VirusTotal (see threat_intel.check_file_reputation), so the result no
 * longer always carries VT-specific fields like malicious/total_engines —
 * it carries a `source` field instead, telling us which provider actually
 * answered.
 */
function VtBadgeOrButton({ item, vtResult, checking, onCheck }) {
  if (vtResult) {
    if (vtResult.status === 'success') {
      // Bug fix: this used to fall through to safe-green for ANYTHING
      // that wasn't 'malicious'/'suspicious' — including the new
      // 'unknown' (inconclusive) verdict, which incorrectly displayed as
      // confirmed-safe. Only a genuine 'clean' gets the green treatment;
      // everything else neutral.
      const color = vtResult.verdict === 'malicious' ? 'var(--danger)'
                   : vtResult.verdict === 'suspicious' ? 'var(--warn)'
                   : vtResult.verdict === 'clean' ? 'var(--safe)'
                   : 'var(--text-3)';
      const bg = vtResult.verdict === 'malicious' ? 'var(--danger-dim)'
               : vtResult.verdict === 'suspicious' ? 'var(--warn-dim)'
               : vtResult.verdict === 'clean' ? 'var(--safe-dim)'
               : 'var(--surface-3)';
      const sourceLabel = SOURCE_LABELS[vtResult.source] || 'Intel';
      return (
        <span className="flex-shrink-0 text-[9px] font-bold px-2 py-0.5 rounded-md" style={{ background: bg, color }}>
          {sourceLabel}: {vtResult.verdict}
        </span>
      );
    }
    return (
      <span className="flex-shrink-0 text-[9px]" style={{ color: 'var(--text-3)' }}>
        {vtResult.message || vtResult.status}
      </span>
    );
  }
  return (
    <button
      onClick={() => onCheck(item)}
      disabled={checking}
      className="flex-shrink-0 px-2 py-0.5 rounded-md text-[9px] font-bold transition-all disabled:opacity-50"
      style={{ background: 'var(--surface-3)', color: 'var(--accent)', border: '1px solid var(--border)' }}
    >
      {checking ? 'Checking…' : 'Check Reputation'}
    </button>
  );
}

function ItemRow({ item, index, vtResult, checking, onCheck }) {
  const color  = item.suspicious ? 'var(--danger)' : 'var(--safe)';
  const bg     = item.suspicious ? 'var(--danger-dim)' : 'var(--surface-2)';
  const border = item.suspicious ? 'rgba(248,113,113,.25)' : 'var(--border)';

  return (
    <motion.div
      initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03 }}
      className="flex items-start gap-3 px-3 py-2.5 rounded-xl"
      style={{ background: bg, border: `1px solid ${border}` }}
    >
      <div className="flex-shrink-0 w-5 h-5 rounded-md flex items-center justify-center text-xs mt-0.5"
        style={{ background: item.suspicious ? 'var(--danger-dim)' : 'var(--safe-dim)', color }}>
        {item.suspicious ? '!' : '✓'}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[11px] font-semibold" style={{ color: 'var(--text)' }}>{item.name}</p>
        <p className="text-[9px] font-mono truncate mt-0.5" style={{ color: 'var(--text-3)' }} title={item.path}>
          {item.path}
        </p>
        <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>{item.location}</p>
      </div>
      <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
        <span className="text-[9px] font-bold px-2 py-0.5 rounded-md"
          style={{ background: item.suspicious ? 'var(--danger-dim)' : 'var(--safe-dim)', color }}>
          {item.risk}
        </span>
        <VtBadgeOrButton item={item} vtResult={vtResult} checking={checking} onCheck={onCheck} />
      </div>
    </motion.div>
  );
}
