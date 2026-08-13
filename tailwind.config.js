/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       'var(--bg)',
        surface:  'var(--surface)',
        's2':     'var(--surface-2)',
        's3':     'var(--surface-3)',
        border:   'var(--border)',
        accent:   'var(--accent)',
        safe:     'var(--safe)',
        warn:     'var(--warn)',
        danger:   'var(--danger)',
        info:     'var(--info)',
        't1':     'var(--text)',
        't2':     'var(--text-2)',
        't3':     'var(--text-3)',
      },
      borderColor: {
        DEFAULT: 'var(--border)',
      },
      boxShadow: {
        glow:     '0 0 16px var(--accent-glow)',
        'glow-sm':'0 0 8px var(--accent-dim)',
        panel:    '0 8px 32px rgba(0,0,0,0.4)',
        modal:    '0 24px 64px rgba(0,0,0,0.6)',
      },
      fontFamily: {
        mono: ['ui-monospace', 'JetBrains Mono', 'Fira Code', 'monospace'],
      },
      letterSpacing: {
        wider2: '0.15em',
        wider3: '0.25em',
      },
    },
  },
  plugins: [],
};
