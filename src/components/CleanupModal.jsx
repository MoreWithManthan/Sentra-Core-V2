import React, { useState } from 'react';
import { Modal, ModalBtn } from './Modal';

const DEEP_CLEAN_LABELS = {
  Windows: {
    title: 'Clean up Windows component store',
    detail: 'Frees disk space from superseded update files (DISM ResetBase).',
    warning: 'Permanent — you will not be able to individually roll back those updates afterward.',
  },
  Darwin: {
    title: 'Purge inactive memory and clear caches',
    detail: 'Frees RAM and disk space held by cached data.',
    warning: null,
  },
  Linux: {
    title: 'Clean package cache and trim logs',
    detail: 'Frees disk space used by the package manager cache and old systemd journal entries.',
    warning: null,
  },
};

export function CleanupModal({ open, onClose, onConfirm, loading, os = 'Windows' }) {
  const [deepClean, setDeepClean] = useState(false);
  const [runRepair, setRunRepair] = useState(false);
  const labels = DEEP_CLEAN_LABELS[os] || DEEP_CLEAN_LABELS.Windows;

  const handleConfirm = () => onConfirm({ deepClean, runRepair });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="System Optimization"
      subtitle="Choose what to run"
      icon="🚀"
      width="max-w-sm"
      closable={!loading}
    >
      <div className="space-y-3">
        <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <span className="text-xs flex-shrink-0" style={{ color: 'var(--safe)' }}>✓</span>
          <div>
            <p className="text-xs font-semibold" style={{ color: 'var(--text)' }}>Clear temp files &amp; flush DNS</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Always included — fast and safe</p>
          </div>
        </div>

        <label className="flex items-start gap-3 px-3 py-2.5 rounded-xl cursor-pointer"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <input type="checkbox" checked={deepClean} onChange={e => setDeepClean(e.target.checked)} className="mt-0.5" />
          <div>
            <p className="text-xs font-semibold" style={{ color: 'var(--text)' }}>{labels.title}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{labels.detail}</p>
            {labels.warning && (
              <p className="text-[10px] mt-1" style={{ color: 'var(--warn)' }}>{labels.warning}</p>
            )}
          </div>
        </label>

        {os === 'Windows' && (
          <label className="flex items-start gap-3 px-3 py-2.5 rounded-xl cursor-pointer"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
            <input type="checkbox" checked={runRepair} onChange={e => setRunRepair(e.target.checked)} className="mt-0.5" />
            <div>
              <p className="text-xs font-semibold" style={{ color: 'var(--text)' }}>Repair system files (SFC + DISM)</p>
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Checks for and repairs corrupted system files. Can take several minutes.</p>
            </div>
          </label>
        )}

        <div className="flex gap-2 pt-1">
          <ModalBtn variant="ghost" onClick={onClose} disabled={loading} className="flex-1">Cancel</ModalBtn>
          <ModalBtn variant="danger" onClick={handleConfirm} loading={loading} className="flex-1">Run</ModalBtn>
        </div>
      </div>
    </Modal>
  );
}
