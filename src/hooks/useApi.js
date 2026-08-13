import { useState, useCallback, useEffect, useRef } from 'react';

export function useApi() {
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);

  const call = useCallback(async (fn, ...args) => {
    setLoading(true); setError(null);
    try {
      const r = await fn(...args);
      return r;
    } catch (e) {
      setError(e.message);
      throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  return { loading, error, call };
}

/**
 * Polls fn every `interval` ms while `enabled` is true.
 * Key stability fix: on error, keeps the last good data instead of clearing it.
 * Only shows the error state after 3 consecutive failures.
 */
export function usePolling(fn, interval = 3000, enabled = true) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);
  const mounted   = useRef(true);
  const failures  = useRef(0);

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    if (!enabled) return;

    const tick = async () => {
      setLoading(true);
      try {
        const res = await fn();
        if (!mounted.current) return;
        setData(res);
        setError(null);
        failures.current = 0;
      } catch (e) {
        if (!mounted.current) return;
        failures.current += 1;
        // Only surface error after 3 consecutive failures to avoid flicker
        if (failures.current >= 3) setError(e.message);
        // Crucially: do NOT clear data — keep showing last good values
      } finally {
        if (mounted.current) setLoading(false);
      }
    };

    tick();
    const id = setInterval(tick, interval);
    return () => clearInterval(id);
  }, [fn, interval, enabled]);

  return { data, loading, error };
}
