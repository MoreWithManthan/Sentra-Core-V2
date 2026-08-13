import React from 'react';

export class ErrorBoundary extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(e, info) { console.error('ErrorBoundary caught:', e, info); }

  render() {
    if (this.state.error) {
      return (
        <div
          className="h-screen w-full flex items-center justify-center p-6"
          style={{ background: 'var(--bg)' }}
        >
          <div
            className="max-w-md w-full p-8 rounded-2xl"
            style={{ background: 'var(--surface)', border: '1px solid rgba(248,113,113,0.3)' }}
          >
            <div className="flex items-center gap-3 mb-4">
              <div
                className="w-9 h-9 rounded-xl flex items-center justify-center text-lg"
                style={{ background: 'var(--danger-dim)', border: '1px solid rgba(248,113,113,0.25)' }}
              >
                ⚠️
              </div>
              <h2 className="text-sm font-black uppercase tracking-wider" style={{ color: 'var(--danger)' }}>
                Render Error
              </h2>
            </div>

            <p className="text-xs font-mono mb-4" style={{ color: 'var(--text-2)' }}>
              {this.state.error?.message}
            </p>

            <div className="flex gap-2">
              <button
                onClick={() => this.setState({ error: null })}
                className="flex-1 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all"
                style={{ background: 'var(--danger-dim)', border: '1px solid rgba(248,113,113,0.25)', color: 'var(--danger)' }}
              >
                Retry
              </button>
              <button
                onClick={() => window.location.reload()}
                className="flex-1 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
              >
                Reload
              </button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
