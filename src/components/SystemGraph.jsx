import React, { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

/* Dynamic RAM colour based on current memory % (Feature 18) */
function ramColor(memPct) {
  if (memPct > 80) return { line: '#f87171', fill: 'rgba(248,113,113,' };
  if (memPct > 50) return { line: '#fbbf24', fill: 'rgba(251,191,36,'  };
  return                    { line: '#4ade80', fill: 'rgba(74,222,128,' };
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="px-3 py-2 rounded-xl text-[10px] font-mono space-y-1"
      style={{ background: 'var(--surface-3)', border: '1px solid var(--border-2)', boxShadow: '0 8px 24px rgba(0,0,0,.5)' }}>
      <p style={{ color: 'var(--text-3)' }}>{payload[0]?.payload?.time}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.stroke }}>
          {p.name}: <b>{p.value}%</b>
        </p>
      ))}
    </div>
  );
}

export function SystemGraph({ history = [], currentMemory = 0 }) {
  const data = useMemo(() =>
    (history || []).map(e => ({ time: e.time, CPU: e.cpu, RAM: e.memory || 0 })),
    [history]
  );

  const ram = ramColor(currentMemory);
  const hasRam = data.some(d => d.RAM > 0);

  return (
    <div className="flex flex-col gap-2 px-4 pt-3 pb-2 rounded-2xl"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>

      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
          System Activity
        </span>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-[10px]" style={{ color: 'var(--accent)' }}>
            <span className="w-5 h-0.5 rounded inline-block" style={{ background: 'var(--accent)' }} /> CPU
          </span>
          {hasRam && (
            <span className="flex items-center gap-1.5 text-[10px]" style={{ color: ram.line }}>
              <span className="w-5 h-0.5 rounded inline-block" style={{ background: ram.line }} /> RAM
            </span>
          )}
          <span className="flex items-center gap-1 text-[9px] font-mono" style={{ color: 'var(--text-3)' }}>
            <span className="w-1.5 h-1.5 rounded-full animate-blink" style={{ background: 'var(--safe)' }} />
            LIVE
          </span>
        </div>
      </div>

      {/* Chart — 180px tall, GlassWire-style */}
      <div style={{ height: 180 }}>
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <p className="text-[10px] animate-pulse" style={{ color: 'var(--text-3)' }}>Waiting for data…</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 4, right: 0, left: -32, bottom: 0 }}>
              <defs>
                <linearGradient id="cpuG" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="var(--accent)" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity={0}    />
                </linearGradient>
                <linearGradient id="ramG" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor={ram.line} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={ram.line} stopOpacity={0}   />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="1 4" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis dataKey="time" stroke="var(--text-3)" fontSize={8} axisLine={false} tickLine={false} dy={4} interval="preserveStartEnd" />
              <YAxis stroke="var(--text-3)" fontSize={8} axisLine={false} tickLine={false} domain={[0,100]} tickCount={5} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="CPU" stroke="var(--accent)" strokeWidth={2}
                fill="url(#cpuG)" dot={false} isAnimationActive={false} />
              {hasRam && (
                <Area type="monotone" dataKey="RAM" stroke={ram.line} strokeWidth={1.5}
                  fill="url(#ramG)" dot={false} isAnimationActive={false} />
              )}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
