import React from 'react';
import { motion } from 'framer-motion';

function Card({ label, value, unit, color, index }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className="flex flex-col gap-1 px-4 py-3 rounded-xl flex-1 min-w-0"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
    >
      <span className="text-[9px] font-bold uppercase tracking-wider truncate" style={{ color: 'var(--text-3)' }}>
        {label}
      </span>
      <div className="flex items-end gap-0.5">
        <span className="text-xl font-black font-mono leading-none" style={{ color }}>
          {value ?? '—'}
        </span>
        {unit && <span className="text-[10px] pb-0.5" style={{ color: 'var(--text-3)' }}>{unit}</span>}
      </div>
    </motion.div>
  );
}

export function StatusCards({ telemetry, scanSummary }) {
  const cpu     = telemetry?.cpu     ?? null;
  const mem     = telemetry?.memory  ?? null;
  const procs   = telemetry?.processes?.length ?? null;
  const shield  = scanSummary?.shield_score ?? null;
  const threats = scanSummary?.threats_found ?? null;

  const cpuC  = cpu  === null ? 'var(--text-2)' : cpu  > 80 ? 'var(--danger)' : cpu  > 50 ? 'var(--warn)' : 'var(--safe)';
  const memC  = mem  === null ? 'var(--text-2)' : mem  > 80 ? 'var(--danger)' : mem  > 50 ? 'var(--warn)' : 'var(--accent)';
  const shC   = shield === null ? 'var(--text-2)' : shield >= 80 ? 'var(--safe)' : shield >= 60 ? 'var(--warn)' : 'var(--danger)';
  const thC   = threats > 0 ? 'var(--danger)' : 'var(--safe)';

  return (
    <div className="flex gap-2">
      <Card label="CPU" value={cpu !== null ? cpu : null} unit="%" color={cpuC} index={0} />
      <Card label="Memory" value={mem !== null ? mem : null} unit="%" color={memC} index={1} />
      <Card label="Processes" value={procs} color="var(--accent)" index={2} />
      <Card label="Shield" value={shield !== null ? shield : null} unit="%" color={shC} index={3} />
      <Card label="Threats" value={threats !== null ? threats : null} color={thC} index={4} />
    </div>
  );
}
