import React, { createContext, useContext, useState, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';

/* ── Context ─────────────────────────────────────────────────────────────── */
const ToastCtx = createContext(null);

let _toastId = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const push = useCallback((message, type = 'info', duration = 4500) => {
    const id = ++_toastId;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
    return id;
  }, []);

  const dismiss = useCallback((id) => setToasts(prev => prev.filter(t => t.id !== id)), []);

  return (
    <ToastCtx.Provider value={{ push, dismiss }}>
      {children}
      {createPortal(
        <div className="fixed bottom-6 right-6 z-[100] flex flex-col gap-2 pointer-events-none">
          <AnimatePresence mode="popLayout">
            {toasts.map(t => (
              <motion.div
                key={t.id}
                layout
                initial={{ opacity: 0, x: 24, scale: 0.95 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: 24, scale: 0.95 }}
                transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                className="pointer-events-auto"
              >
                <div
                  className="flex items-start gap-3 px-4 py-3 rounded-xl min-w-[260px] max-w-[380px]"
                  style={{
                    background: 'var(--surface-2)',
                    border: `1px solid ${
                      t.type === 'error'   ? 'rgba(248,113,113,0.3)' :
                      t.type === 'success' ? 'rgba(74,222,128,0.3)' :
                      t.type === 'warn'    ? 'rgba(251,191,36,0.3)' :
                                             'var(--border-2)'
                    }`,
                    boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
                  }}
                >
                  {/* Icon dot */}
                  <div
                    className="flex-shrink-0 w-2 h-2 rounded-full mt-1"
                    style={{
                      background:
                        t.type === 'error'   ? 'var(--danger)' :
                        t.type === 'success' ? 'var(--safe)' :
                        t.type === 'warn'    ? 'var(--warn)' :
                                               'var(--accent)',
                      boxShadow:
                        t.type === 'error'   ? '0 0 6px var(--danger)' :
                        t.type === 'success' ? '0 0 6px var(--safe)' :
                        t.type === 'warn'    ? '0 0 6px var(--warn)' :
                                               '0 0 6px var(--accent)',
                    }}
                  />
                  <p className="text-xs text-t1 leading-relaxed flex-1">{t.message}</p>
                  <button
                    onClick={() => dismiss(t.id)}
                    className="flex-shrink-0 text-t3 hover:text-t2 transition-colors"
                    aria-label="Dismiss"
                  >
                    <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
                      <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                  </button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>,
        document.body
      )}
    </ToastCtx.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error('useToast must be inside <ToastProvider>');
  return ctx;
}
