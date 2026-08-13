import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { checkIpReputation } from '../services/api';

/**
 * The backend endpoint behind this now merges AbuseIPDB + URLhaus +
 * VirusTotal (see threat_intel.check_ip_reputation_multi) instead of
 * calling VirusTotal alone, so the response shape changed from
 * {malicious, total_engines} to {verdict, sources, checked_sources}.
 */
function VtCell({ ip, result, checking, onCheck }) {
  if (result) {
    if (result.status === 'success') {
      // Explicit 'clean' check rather than defaulting anything-not-
      // malicious/suspicious to safe-green — keeps this correct even if a
      // future provider path returns a non-definitive verdict alongside
      // status:'success' (matches the same fix in StartupItems.jsx).
      const color = result.verdict === 'malicious' ? 'var(--danger)'
                   : result.verdict === 'suspicious' ? 'var(--warn)'
                   : result.verdict === 'clean' ? 'var(--safe)'
                   : 'var(--text-3)';
      const bg = result.verdict === 'malicious' ? 'var(--danger-dim)'
               : result.verdict === 'suspicious' ? 'var(--warn-dim)'
               : result.verdict === 'clean' ? 'var(--safe-dim)'
               : 'var(--surface-3)';
      const sourceCount = result.checked_sources?.length || 0;
      return (
        <span className="px-2 py-0.5 rounded-md text-[9px] font-bold" style={{ background: bg, color }}
          title={result.checked_sources?.join(', ') || ''}>
          {result.verdict} ({sourceCount} source{sourceCount !== 1 ? 's' : ''})
        </span>
      );
    }
    return <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>{result.message || result.status}</span>;
  }
  return (
    <button
      onClick={() => onCheck(ip)}
      disabled={checking}
      className="px-2 py-0.5 rounded-md text-[9px] font-bold transition-all disabled:opacity-50"
      style={{ background: 'var(--surface-3)', color: 'var(--accent)', border: '1px solid var(--border)' }}
    >
      {checking ? 'Checking…' : 'Check Reputation'}
    </button>
  );
}

export function NetworkMonitor({ connections = [], loading }) {
  const [vtResults, setVtResults] = useState({});   // remote_ip -> result
  const [checking, setChecking]   = useState({});   // remote_ip -> bool

  const handleCheck = async (ip) => {
    if (!ip) return;
    setChecking(prev => ({ ...prev, [ip]: true }));
    try {
      const result = await checkIpReputation(ip);
      setVtResults(prev => ({ ...prev, [ip]: result }));
    } catch (e) {
      setVtResults(prev => ({ ...prev, [ip]: { status: 'error', message: 'Check failed' } }));
    } finally {
      setChecking(prev => ({ ...prev, [ip]: false }));
    }
  };

  if (loading && connections.length === 0) {
    return <div className="text-[10px] text-center py-10 animate-pulse" style={{ color: 'var(--text-3)' }}>Loading connections…</div>;
  }
  if (connections.length === 0) {
    return <div className="text-[10px] text-center py-10" style={{ color: 'var(--text-3)' }}>No active connections detected</div>;
  }

  return (
    // Vertical scrolling is handled by the parent Panel; only horizontal scroll is needed here.
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Process</th>
            <th>PID</th>
            <th>Local</th>
            <th>Remote</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Threat Intel</th>
          </tr>
        </thead>
        <tbody>
          {connections.map((c, i) => (
            <motion.tr
              key={`${c.pid}-${c.remote}-${i}`}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.02 }}
            >
              <td style={{ color: 'var(--text)', fontWeight: 600 }}>{c.process}</td>
              <td>{c.pid}</td>
              <td className="font-mono">{c.local}</td>
              <td className="font-mono" style={{ color: c.suspicious ? 'var(--danger)' : 'var(--text-2)' }}>
                {c.remote}
              </td>
              <td>
                <span className="px-2 py-0.5 rounded-md text-[9px] font-bold"
                  style={{ background: 'var(--safe-dim)', color: 'var(--safe)' }}>
                  {c.status}
                </span>
              </td>
              <td>
                <span className="px-2 py-0.5 rounded-md text-[9px] font-bold"
                  style={{
                    background: c.suspicious ? 'var(--danger-dim)' : 'var(--safe-dim)',
                    color:      c.suspicious ? 'var(--danger)'     : 'var(--safe)',
                  }}>
                  {c.suspicious ? 'SUSPICIOUS' : 'OK'}
                </span>
              </td>
              <td>
                <VtCell
                  ip={c.remote_ip}
                  result={vtResults[c.remote_ip]}
                  checking={!!checking[c.remote_ip]}
                  onCheck={handleCheck}
                />
              </td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
