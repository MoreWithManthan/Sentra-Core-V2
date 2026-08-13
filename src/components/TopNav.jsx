import React from 'react';
import { motion } from 'framer-motion';

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'network',   label: 'Network'   },
  { id: 'startup',   label: 'Startup'   },
  { id: 'history',   label: 'History'   },
  { id: 'settings',  label: 'Settings'  },
];

const THEMES = [
  { id: '',             color: '#22d3ee' },
  { id: 'theme-green',  color: '#4ade80' },
  { id: 'theme-amber',  color: '#fbbf24' },
  { id: 'theme-violet', color: '#a78bfa' },
];

function Btn({ onClick, loading, disabled, children, primary }) {
  return (
    <motion.button
      onClick={onClick} disabled={disabled || loading}
      whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all select-none disabled:opacity-40"
      style={{
        background: primary ? 'var(--accent-dim)' : 'var(--surface-2)',
        border: `1px solid ${primary ? 'var(--border-2)' : 'var(--border)'}`,
        color: primary ? 'var(--accent)' : 'var(--text-2)',
      }}
    >
      {loading && (
        <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeDasharray="32" strokeDashoffset="12"/>
        </svg>
      )}
      {children}
    </motion.button>
  );
}

export function TopNav({
  activeTab, onTabChange,
  theme, onThemeChange,
  onScan, onUpdate, onCleanup,
  scanning, updating, cleaning,
  wsReady, scanStatus,
}) {
  const busy = scanning || updating || cleaning;

  return (
    <nav
      className="flex items-center gap-4 px-5 h-12 flex-shrink-0 select-none"
      style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 mr-2 flex-shrink-0">
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center text-sm font-black"
          style={{ background: 'var(--accent-dim)', border: '1px solid var(--border-2)', color: 'var(--accent)' }}
        >S</div>
        <span className="text-[11px] font-black tracking-widest uppercase hidden sm:block" style={{ color: 'var(--text)' }}>
          SENTRA
        </span>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 flex-1">
        {TABS.map(t => {
          const active = activeTab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => onTabChange(t.id)}
              className="relative px-3 py-1 rounded-lg text-[11px] font-semibold transition-all"
              style={{ color: active ? 'var(--accent)' : 'var(--text-3)', background: active ? 'var(--accent-dim)' : 'transparent' }}
            >
              {t.label}
              {active && (
                <motion.div
                  layoutId="nav-indicator"
                  className="absolute inset-0 rounded-lg"
                  style={{ background: 'var(--accent-dim)', border: '1px solid var(--border-2)', zIndex: -1 }}
                />
              )}
            </button>
          );
        })}
      </div>

      {/* Scan badge */}
      {scanning && (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-mono flex-shrink-0"
          style={{ background: 'var(--accent-dim)', border: '1px solid var(--border-2)', color: 'var(--accent)' }}>
          <span className="w-1.5 h-1.5 rounded-full animate-blink" style={{ background: 'var(--accent)' }} />
          Scanning…
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-1.5 flex-shrink-0">
        <Btn onClick={onUpdate} loading={updating} disabled={busy}>Update Intel</Btn>
        <Btn onClick={onCleanup} loading={cleaning} disabled={busy}>Optimize</Btn>
        <Btn onClick={onScan} loading={scanning} disabled={busy} primary>Shield Scan</Btn>
      </div>

      {/* Divider */}
      <div className="w-px h-5 flex-shrink-0" style={{ background: 'var(--border)' }} />

      {/* Themes */}
      <div className="flex items-center gap-1.5 flex-shrink-0">
        {THEMES.map(t => (
          <motion.button
            key={t.id} whileHover={{ scale: 1.3 }} whileTap={{ scale: 0.8 }}
            onClick={() => onThemeChange(t.id)}
            className="w-3.5 h-3.5 rounded-full"
            style={{
              background: t.color,
              boxShadow: theme === t.id
                ? `0 0 0 2px var(--bg), 0 0 0 3.5px ${t.color}`
                : `0 0 4px ${t.color}66`,
            }}
          />
        ))}
      </div>

      {/* WS status dot */}
      <div
        className={`w-2 h-2 rounded-full flex-shrink-0 ${wsReady ? 'animate-pulse-ring' : ''}`}
        style={{ background: wsReady ? 'var(--safe)' : 'var(--danger)' }}
        title={wsReady ? 'Live data connected' : 'Live data disconnected'}
      />
    </nav>
  );
}
