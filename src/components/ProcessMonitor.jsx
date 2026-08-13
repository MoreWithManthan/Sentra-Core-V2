import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

function cpuColor(p) {
  return p > 60 ? 'var(--danger)' : p > 30 ? 'var(--warn)' : 'var(--accent)';
}

function Row({ proc, index }) {
  const c = cpuColor(proc.cpu_percent);
  return (
    <motion.div
      initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.02 }}
      className="flex flex-col gap-1 px-3 py-2 rounded-xl"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-mono truncate" style={{ color: 'var(--text)' }} title={proc.name}>
          {proc.name}
        </span>
        <span className="text-[11px] font-bold font-mono flex-shrink-0" style={{ color: c }}>
          {proc.cpu_percent.toFixed(1)}%
        </span>
      </div>
      <div className="h-[3px] rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
        <motion.div
          initial={{ width: 0 }} animate={{ width: `${Math.min(proc.cpu_percent, 100)}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
          className="h-full rounded-full"
          style={{ background: c, boxShadow: `0 0 6px ${c}88` }}
        />
      </div>
    </motion.div>
  );
}

/**
 * This component does not manage its own scroll — the parent Panel
 * wrapper owns vertical scrolling for every tab.
 */
export function ProcessMonitor({ processes, error }) {
  const list = processes || [];

  return (
    <div className="flex flex-col gap-2">
      {error && (
        <p className="text-[10px] px-2 py-1.5 rounded-lg" style={{ background: 'var(--danger-dim)', color: 'var(--danger)' }}>
          {error}
        </p>
      )}
      <AnimatePresence mode="popLayout">
        {list.length > 0
          ? list.map((p, i) => <Row key={p.name} proc={p} index={i} />)
          : !error && (
            <div className="flex gap-1 justify-center py-6">
              {[0,1,2].map(i => (
                <motion.div key={i} className="w-1.5 h-1.5 rounded-full"
                  style={{ background: 'var(--accent)' }}
                  animate={{ opacity: [0.3,1,0.3], y: [0,-4,0] }}
                  transition={{ duration: 1, repeat: Infinity, delay: i * 0.2 }}
                />
              ))}
            </div>
          )
        }
      </AnimatePresence>
    </div>
  );
}
