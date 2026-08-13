import { useEffect, useRef, useState, useCallback } from 'react';

const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

/* ── Telemetry WebSocket (1-second live data) ────────────────────────────── */
/**
 * The backend broadcasts non-telemetry events (intel_update_complete,
 * repair_complete, etc.) on this same connection. Messages of type
 * "telemetry" update `data` as usual; everything else is routed to the
 * `onEvent` callback instead of overwriting the telemetry state.
 */
export function useTelemetry(enabled = true, onEvent) {
  const [data,  setData]  = useState(null);
  const [ready, setReady] = useState(false);
  const ws = useRef(null);
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;   // always latest, without re-triggering the connect effect

  useEffect(() => {
    if (!enabled) return;
    let reconnectTimer;
    let stopped = false;

    function connect() {
      if (stopped) return;
      try {
        const socket = new WebSocket(`${WS_BASE}/ws/telemetry`);
        ws.current = socket;

        socket.onopen  = () => setReady(true);
        socket.onclose = () => {
          setReady(false);
          if (!stopped) reconnectTimer = setTimeout(connect, 3000);
        };
        socket.onerror = () => socket.close();
        socket.onmessage = (e) => {
          try {
            const msg = JSON.parse(e.data);
            if (msg.type === 'telemetry') {
              setData(msg);
            } else if (onEventRef.current) {
              onEventRef.current(msg);
            }
          } catch {}
        };
      } catch {}
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(reconnectTimer);
      ws.current?.close();
    };
  }, [enabled]);

  return { data, ready };
}

/* ── Scan WebSocket (streaming results) ──────────────────────────────────── */
export function useScanWS() {
  const wsRef = useRef(null);
  const [status, setStatus] = useState('idle');   // idle | started | scanning | complete | error
  const [progress, setProgress] = useState({ scanned: 0, total: 0, current_file: '' });
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState(null);
  const [vtProgress, setVtProgress] = useState(null);       // { checked, total } while VT verification runs
  const [errorMessage, setErrorMessage] = useState(null);    // clear reason for a failed or empty scan
  const [infoMessage, setInfoMessage] = useState(null);

  const startScan = useCallback((config, { onThreat, onComplete, onError } = {}) => {
    wsRef.current?.close();
    setThreats([]);
    setSummary(null);
    setProgress({ scanned: 0, total: 0, current_file: '' });
    setVtProgress(null);
    setErrorMessage(null);
    setInfoMessage(null);
    setStatus('started');

    const socket = new WebSocket(`${WS_BASE}/ws/scan`);
    wsRef.current = socket;

    socket.onopen = () => socket.send(JSON.stringify(config));

    socket.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        switch (msg.type) {
          case 'started':
            setStatus('scanning');
            break;
          case 'progress':
            setProgress({ scanned: msg.scanned, total: msg.total, current_file: msg.current_file });
            break;
          case 'info':
            setInfoMessage(msg.message);
            break;
          case 'threat':
            setThreats(prev => [...prev, msg.data]);
            onThreat?.(msg.data);
            break;
          case 'vt_start':
            setVtProgress({ checked: 0, total: msg.count });
            break;
          case 'vt_result':
            setVtProgress(prev => prev ? { ...prev, checked: prev.checked + 1 } : null);
            // Bug fix: previously matched by `(t.file || '').endsWith(msg.file)`
            // — filename-based matching. Two different files sharing the
            // same basename (different folders, different hashes) would
            // incorrectly inherit each other's verdict, since both would
            // match `endsWith`. Every result now carries a unique `id`
            // assigned server-side (see ScanResult.id in models.py); we
            // match strictly on that instead.
            setThreats(prev => prev.map(t =>
              (msg.id && t.id === msg.id)
                ? { ...t, vt_checked: true, vt_verdict: msg.verdict, vt_source: msg.source }
                : t
            ));
            break;
          case 'complete':
            setVtProgress(null);
            setSummary(msg);
            setStatus('complete');
            onComplete?.(msg);
            socket.close();
            break;
          case 'error':
            setStatus('error');
            setErrorMessage(msg.message);
            onError?.(msg.message);
            socket.close();
            break;
        }
      } catch {}
    };

    socket.onerror = () => {
      setStatus('error');
      setErrorMessage('Connection to the scan engine was lost.');
    };
    socket.onclose = () => {
      setStatus(prev => (prev === 'scanning' || prev === 'started') ? 'idle' : prev);
    };
  }, []);

  const cancel = useCallback(() => {
    wsRef.current?.close();
    setStatus('idle');
  }, []);

  return { startScan, cancel, status, progress, threats, summary, vtProgress, errorMessage, infoMessage };
}
