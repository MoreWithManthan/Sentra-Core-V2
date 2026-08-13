import React from 'react';
import { motion } from 'framer-motion';
import { downloadReport } from '../services/api';
import { useToast } from './Toast';

export function ScanHistory({ scans = [], loading, onRefresh }) {
  const toast = useToast();

  const handleDownload = async (scanId) => {
    try {
      await downloadReport(scanId);
      toast.push('Report downloaded.', 'success');
    } catch {
      toast.push('PDF generation failed — install reportlab.', 'error');
    }
  };

  if (loading && scans.length === 0) {
    return <div className="text-center py-12 text-[10px] animate-pulse" style={{ color: 'var(--text-3)' }}>Loading history…</div>;
  }

  if (scans.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>No scans recorded yet.</p>
        <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>Run a Shield Scan to start building history.</p>
      </div>
    );
  }

  return (
    // Vertical scrolling is handled by the parent Panel; only horizontal scroll is needed here.
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Type</th>
            <th>Date &amp; Time</th>
            <th>Files</th>
            <th>Threats</th>
            <th>Shield</th>
            <th>Duration</th>
            <th>Report</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s, i) => {
            const shieldColor = s.shield_score >= 80 ? 'var(--safe)' : s.shield_score >= 60 ? 'var(--warn)' : 'var(--danger)';
            return (
              <motion.tr key={s.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}>
                <td style={{ color: 'var(--text-3)' }}>{s.id}</td>
                <td>
                  <span className="px-2 py-0.5 rounded-md text-[9px] font-bold uppercase"
                    style={{ background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid var(--border-2)' }}>
                    {s.scan_type}
                  </span>
                </td>
                <td>{s.timestamp?.slice(0, 19).replace('T', ' ')}</td>
                <td>{s.files_scanned}</td>
                <td style={{ color: s.threats_found > 0 ? 'var(--danger)' : 'var(--safe)', fontWeight: 700 }}>
                  {s.threats_found}
                </td>
                <td style={{ color: shieldColor, fontWeight: 700 }}>{s.shield_score}%</td>
                <td>{s.duration_sec?.toFixed(1)}s</td>
                <td>
                  <button
                    onClick={() => handleDownload(s.id)}
                    className="px-2 py-0.5 rounded-md text-[9px] font-bold transition-all"
                    style={{ background: 'var(--surface-3)', color: 'var(--text-2)', border: '1px solid var(--border)' }}
                    onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent)'; }}
                    onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-2)'; }}
                  >
                    PDF ↓
                  </button>
                </td>
              </motion.tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
