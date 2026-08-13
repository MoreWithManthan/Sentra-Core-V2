import React from 'react';
import { Modal, ModalBtn } from './Modal';

export function IntelModal({ open, onClose, result }) {
  if (!result) return null;

  const ok = result.status === 'success';

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Intelligence Update"
      subtitle={ok ? 'Threat database refreshed' : 'Update incomplete'}
      icon={ok ? '✅' : '⚠️'}
      width="max-w-sm"
    >
      <div className="space-y-4">
        {/* Stats row */}
        {ok && (
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: String(result.rules_updated ?? 0), sub: 'Rules loaded' },
              { label: String(result.sources_ok ?? '—'), sub: 'Sources OK' },
              { label: String(result.sources_failed ?? 0), sub: 'Failed' },
            ].map(({ label, sub }) => (
              <div
                key={sub}
                className="flex flex-col items-center py-2.5 rounded-xl text-center"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
              >
                <span
                  className="text-sm font-bold font-mono"
                  style={{ color: sub === 'Failed' && label !== '0' ? 'var(--warn)' : 'var(--accent)' }}
                >
                  {label}
                </span>
                <span className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{sub}</span>
              </div>
            ))}
          </div>
        )}

        <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>
          {result.message}
        </p>

        <ModalBtn variant={ok ? 'primary' : 'ghost'} onClick={onClose} className="w-full">
          Got it
        </ModalBtn>
      </div>
    </Modal>
  );
}
