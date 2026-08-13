import React, { useState } from 'react';
import { Modal, ModalBtn } from './Modal';

/**
 * Shown the first time a user clicks Shield Scan (if no VT key saved).
 * After they save or skip, the flag is persisted so it won't appear again.
 */
export function VTKeyModal({ open, onSave, onSkip }) {
  const [key, setKey] = useState('');
  const [masked, setMasked] = useState(true);
  const [err, setErr] = useState('');

  const handleSave = () => {
    const trimmed = key.trim();
    if (trimmed && trimmed.length < 20) {
      setErr('API key looks too short — please double-check it.');
      return;
    }
    setErr('');
    onSave(trimmed); // empty string = user typed nothing but clicked save
  };

  const handleSkip = () => {
    setErr('');
    setKey('');
    onSkip();
  };

  return (
    <Modal
      open={open}
      onClose={handleSkip}
      title="VirusTotal Integration"
      subtitle="Scan threats against 70+ antivirus engines"
      icon="🔐"
      width="max-w-sm"
    >
      <div className="space-y-4">
        {/* Benefits row */}
        <div className="grid grid-cols-3 gap-2">
          {[
            { label: '500/day', sub: 'Free quota' },
            { label: '70+ AVs', sub: 'Engines' },
            { label: 'Hash only', sub: 'No uploads' },
          ].map(({ label, sub }) => (
            <div
              key={label}
              className="flex flex-col items-center py-2.5 px-2 rounded-xl text-center"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
            >
              <span className="text-xs font-bold font-mono" style={{ color: 'var(--accent)' }}>{label}</span>
              <span className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{sub}</span>
            </div>
          ))}
        </div>

        {/* Key input */}
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
            API Key
          </label>
          <div
            className="flex items-center gap-2 rounded-xl px-3 py-2.5 transition-all"
            style={{ background: 'var(--surface-2)', border: `1px solid ${err ? 'rgba(248,113,113,0.4)' : 'var(--border-2)'}` }}
          >
            <input
              type={masked ? 'password' : 'text'}
              value={key}
              onChange={e => { setKey(e.target.value); setErr(''); }}
              placeholder="Paste your key here…"
              className="flex-1 bg-transparent text-xs outline-none"
              style={{ color: 'var(--text)', caretColor: 'var(--accent)' }}
              autoFocus
            />
            <button
              onClick={() => setMasked(m => !m)}
              className="text-t3 hover:text-t2 transition-colors text-[10px] select-none"
            >
              {masked ? 'show' : 'hide'}
            </button>
          </div>
          {err && <p className="text-[10px] mt-1.5" style={{ color: 'var(--danger)' }}>{err}</p>}
        </div>

        {/* Link */}
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
          Free key at{' '}
          <a
            href="https://www.virustotal.com/gui/join-us"
            target="_blank"
            rel="noopener noreferrer"
            className="underline transition-colors"
            style={{ color: 'var(--accent)' }}
          >
            virustotal.com ↗
          </a>
          . Only file hashes are sent — your files stay local.
        </p>

        {/* Actions */}
        <div className="flex gap-2 pt-1">
          <ModalBtn variant="ghost" onClick={handleSkip} className="flex-1">
            Skip for now
          </ModalBtn>
          <ModalBtn variant="primary" onClick={handleSave} className="flex-1">
            Save &amp; Continue
          </ModalBtn>
        </div>
      </div>
    </Modal>
  );
}
