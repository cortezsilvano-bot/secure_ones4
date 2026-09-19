import { useCallback, useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';

import { hasBackend, runScan } from '../services/ipc';
import type { Dashboard } from '../types';

export interface ScanState {
  /** Null until the first scan returns. */
  dashboard: Dashboard | null;
  scanning: boolean;
  /** Set only when the scan itself could not run at all. */
  error: string | null;
  rescan: () => void;
}

/**
 * Own the scan lifecycle for the whole app.
 *
 * The previous dashboard is kept while a re-scan runs, so the UI updates in
 * place rather than flashing empty -- an empty dashboard means "we did not
 * look", and showing that during a refresh would be a lie about coverage.
 */
export function useScan(): ScanState {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [scanning, setScanning] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Guard against overlapping scans from impatient clicking.
  const inFlight = useRef(false);

  const rescan = useCallback(() => {
    if (inFlight.current) return;
    inFlight.current = true;
    setScanning(true);
    setError(null);

    runScan()
      .then((result) => {
        if (!mounted.current) return;
        setDashboard(result);
      })
      .catch((e: unknown) => {
        if (!mounted.current) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        inFlight.current = false;
        if (mounted.current) setScanning(false);
      });
  }, []);

  useEffect(rescan, [rescan]);

  // The backend scans on its own schedule and the tray can ask for one. Both
  // must reach the open window, or it sits showing results the backend has
  // already superseded.
  useEffect(() => {
    if (!hasBackend()) return;

    const unlisteners: Array<() => void> = [];
    let cancelled = false;

    const attach = (event: string, handler: (payload: unknown) => void) => {
      listen(event, (e) => handler(e.payload)).then((fn) => {
        if (cancelled) fn();
        else unlisteners.push(fn);
      });
    };

    // A background scan already has its results; adopt them rather than
    // running the whole thing again.
    attach('background-scan-completed', (payload) => {
      if (!mounted.current || !payload) return;
      setDashboard(payload as Dashboard);
      setError(null);
    });

    attach('tray-scan-requested', () => rescan());

    return () => {
      cancelled = true;
      unlisteners.forEach((fn) => fn());
    };
  }, [rescan]);

  return { dashboard, scanning, error, rescan };
}
