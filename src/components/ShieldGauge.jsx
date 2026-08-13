import React from 'react';
import { motion } from 'framer-motion';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';

const LEVELS = [
  { min: 80, color: '#4ade80', label: 'Protected',  bg: 'var(--safe-dim)' },
  { min: 60, color: '#fbbf24', label: 'Caution',    bg: 'var(--warn-dim)' },
  { min: 40, color: '#fb923c', label: 'At Risk',    bg: 'rgba(251,146,60,0.12)' },
  { min: 0,  color: '#f87171', label: 'Critical',   bg: 'var(--danger-dim)' },
];

function getLevel(score) {
  return LEVELS.find(l => score >= l.min) ?? LEVELS[LEVELS.length - 1];
}

export function ShieldGauge({ score = 100, scanComplete = false, scanning = false }) {
  const level = getLevel(Math.round(score));

  return (
    <div
      className="flex items-center gap-6 p-5 rounded-2xl"
      style={{ background: level.bg, border: `1px solid ${level.color}22` }}
    >
      {/* Gauge with optional scan ring */}
      <div className="relative flex-shrink-0 w-20 h-20">
        {/* Rotating scan ring (during scan) */}
        {scanning && (
          <motion.div
            className="absolute inset-0 rounded-full animate-scan"
            style={{
              border: '2px solid transparent',
              borderTopColor: 'var(--accent)',
              borderRightColor: 'var(--accent)',
              opacity: 0.6,
              margin: '-4px',
            }}
          />
        )}

        {/* Pulse ring (after scan complete) */}
        {!scanning && scanComplete && (
          <motion.div
            className="absolute inset-0 rounded-full animate-pulse-ring"
            style={{
              border: `1px solid ${level.color}66`,
              margin: '-6px',
            }}
          />
        )}

        <CircularProgressbar
          value={Math.round(score)}
          text={`${Math.round(score)}`}
          styles={buildStyles({
            pathColor: level.color,
            textColor: level.color,
            trailColor: 'rgba(255,255,255,0.05)',
            pathTransitionDuration: 0.8,
            textSize: '24px',
            strokeLinecap: 'round',
          })}
        />
      </div>

      {/* Info */}
      <div className="flex-1">
        <h3 className="text-[10px] font-bold uppercase tracking-wider2 mb-0.5" style={{ color: 'var(--text-3)' }}>
          Shield Health
        </h3>
        <motion.p
          key={level.label}
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-lg font-black"
          style={{ color: level.color }}
        >
          {level.label}
        </motion.p>
        <p className="text-[10px] mt-1 font-mono" style={{ color: 'var(--text-3)' }}>
          {scanning
            ? 'Scanning in progress…'
            : scanComplete
            ? `Last scan complete`
            : 'No scan run yet'}
        </p>
      </div>

      {/* Score breakdown (after scan) */}
      {scanComplete && !scanning && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex flex-col items-end gap-1"
        >
          <span className="text-[9px] font-mono uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Score</span>
          <span className="text-3xl font-black font-mono leading-none" style={{ color: level.color }}>
            {Math.round(score)}
            <span className="text-base" style={{ color: 'var(--text-3)' }}>%</span>
          </span>
        </motion.div>
      )}
    </div>
  );
}
