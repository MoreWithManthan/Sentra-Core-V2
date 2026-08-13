import React, { useState } from 'react';
import { Modal, ModalBtn } from './Modal';

export function ScheduleModal({ open, onClose, config, onSave, loading }) {
  const [enabled,   setEnabled]   = useState(config?.enabled   ?? false);
  const [scanType,  setScanType]  = useState(config?.scan_type ?? 'quick');
  const [frequency, setFrequency] = useState(config?.frequency ?? 'daily');
  const [hour,      setHour]      = useState(config?.hour      ?? 2);

  const handleSave = () => onSave({ enabled, scan_type: scanType, frequency, hour, minute: 0 });

  const Row = ({ label, children }) => (
    <div>
      <label className="text-[10px] font-bold uppercase tracking-wider block mb-1.5" style={{ color: 'var(--text-3)' }}>{label}</label>
      {children}
    </div>
  );

  const Select = ({ value, onChange, opts }) => (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="w-full text-xs rounded-xl px-3 py-2.5 outline-none"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text)' }}>
      {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );

  return (
    <Modal open={open} onClose={onClose} title="Schedule Scan" subtitle="Automatic background scanning" icon="🕐" width="max-w-sm">
      <div className="space-y-4">
        {/* Enable toggle */}
        <div className="flex items-center justify-between px-4 py-3 rounded-xl"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <div>
            <p className="text-xs font-bold" style={{ color: 'var(--text)' }}>Auto Scan</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Run scans automatically in the background</p>
          </div>
          <button onClick={() => setEnabled(e => !e)}
            className="w-11 h-6 rounded-full transition-all flex-shrink-0"
            style={{ background: enabled ? 'var(--accent)' : 'var(--surface-3)', position: 'relative' }}>
            <span className="absolute top-1 w-4 h-4 rounded-full transition-all"
              style={{ background: 'white', left: enabled ? '24px' : '4px' }} />
          </button>
        </div>

        {enabled && (
          <>
            <Row label="Scan Type">
              <Select value={scanType} onChange={setScanType} opts={[['quick','Quick (temp dirs)'],['deep','Deep (full system)']]} />
            </Row>
            <Row label="Frequency">
              <Select value={frequency} onChange={setFrequency} opts={[['daily','Daily'],['weekly','Weekly (Monday)'],['monthly','Monthly (1st)']]} />
            </Row>
            <Row label="Time">
              <select value={hour} onChange={e => setHour(Number(e.target.value))}
                className="w-full text-xs rounded-xl px-3 py-2.5 outline-none"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text)' }}>
                {Array.from({ length: 24 }, (_, i) => (
                  <option key={i} value={i}>{String(i).padStart(2,'0')}:00</option>
                ))}
              </select>
            </Row>
          </>
        )}

        {config?.next_run && (
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
            Next run: {config.next_run.slice(0,19).replace('T',' ')}
          </p>
        )}

        <div className="flex gap-2 pt-1" style={{ borderTop: '1px solid var(--border)' }}>
          <ModalBtn variant="ghost" onClick={onClose} className="flex-1">Cancel</ModalBtn>
          <ModalBtn variant="primary" onClick={handleSave} loading={loading} className="flex-1">Save Schedule</ModalBtn>
        </div>
      </div>
    </Modal>
  );
}
