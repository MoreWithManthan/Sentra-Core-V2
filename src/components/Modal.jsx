import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';

/**
 * Base modal — every popup in SENTRA CORE uses this.
 * Props:
 *   open       boolean
 *   onClose    () => void  (called on backdrop click or Escape key)
 *   title      string
 *   subtitle   string (optional)
 *   icon       string (emoji / symbol, optional)
 *   width      string tailwind max-w class, default "max-w-md"
 *   children   ReactNode
 *   closable   boolean (default true) — show × button and allow backdrop close
 */
export function Modal({ open, onClose, title, subtitle, icon, width = 'max-w-md', children, closable = true }) {
  // Close on Escape
  useEffect(() => {
    if (!open || !closable) return;
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, closable, onClose]);

  const content = (
    <AnimatePresence>
      {open && (
        <motion.div
          className="modal-backdrop"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          onClick={closable ? onClose : undefined}
        >
          <motion.div
            className={`relative w-full ${width} mx-4`}
            initial={{ opacity: 0, y: 18, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.97 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal card */}
            <div
              className="relative overflow-hidden rounded-2xl shadow-modal"
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border-2)',
              }}
            >
              {/* Subtle top accent line */}
              <div
                className="h-px w-full"
                style={{ background: 'linear-gradient(90deg, transparent, var(--accent), transparent)' }}
              />

              {/* Header */}
              <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-4"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <div className="flex items-center gap-3">
                  {icon && (
                    <div
                      className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center text-lg"
                      style={{ background: 'var(--accent-dim)', border: '1px solid var(--border-2)' }}
                    >
                      {icon}
                    </div>
                  )}
                  <div>
                    <h2 className="text-sm font-bold tracking-wider text-t1 uppercase"
                      style={{ letterSpacing: '0.12em' }}>
                      {title}
                    </h2>
                    {subtitle && (
                      <p className="text-xs text-t2 mt-0.5">{subtitle}</p>
                    )}
                  </div>
                </div>
                {closable && (
                  <button
                    onClick={onClose}
                    className="flex-shrink-0 w-7 h-7 rounded-lg flex items-center justify-center text-t3 transition-all duration-150"
                    style={{ background: 'var(--surface-2)' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--surface-3)'; e.currentTarget.style.color = 'var(--text)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'var(--surface-2)'; e.currentTarget.style.color = 'var(--text-3)'; }}
                    aria-label="Close"
                  >
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                  </button>
                )}
              </div>

              {/* Body */}
              <div className="px-6 py-5">{children}</div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  return createPortal(content, document.body);
}

/* ── Shared button styles used inside modals ───────────────────────────────── */
export function ModalBtn({ variant = 'ghost', onClick, disabled, loading, children, className = '' }) {
  const base = 'inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold tracking-wider uppercase transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed select-none';

  const styles = {
    primary: {
      background: 'var(--accent)',
      color: '#060d18',
      border: 'none',
    },
    danger: {
      background: 'var(--danger-dim)',
      color: 'var(--danger)',
      border: '1px solid rgba(248,113,113,0.25)',
    },
    ghost: {
      background: 'var(--surface-2)',
      color: 'var(--text-2)',
      border: '1px solid var(--border)',
    },
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={`${base} ${className}`}
      style={styles[variant]}
    >
      {loading && (
        <svg className="animate-spin" width="12" height="12" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="32" strokeDashoffset="12"/>
        </svg>
      )}
      {children}
    </button>
  );
}
