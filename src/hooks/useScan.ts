import { useCallback, useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';

import { getRouterEnvironment, hasBackend, runScan } from '../services/ipc';
import type { Dashboard, RouterEnvironment } from '../types';

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
  const generation = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Guard against overlapping scans from impatient clicking.
  const inFlight = useRef(false);

  const adoptDashboard = useCallback(async (result: Dashboard) => {
    const environment = await getRouterEnvironment();
    if (!mounted.current) return;
    generation.current = Math.max(generation.current, environment.generation);
    if (result.routerGeneration !== generation.current) {
      // A late old response must not erase a newer valid dashboard either.
      setDashboard((current) => current?.routerGeneration === generation.current ? current : null);
      return;
    }
    setDashboard((previous) => previous && previous.scannedAt > result.scannedAt ? previous : result);
    setError(null);
  }, []);

  const rescan = useCallback(() => {
    if (inFlight.current) return;
    inFlight.current = true;
    setScanning(true);
    setError(null);

    runScan()
      .then(adoptDashboard)
      .catch((e: unknown) => {
        if (!mounted.current) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        inFlight.current = false;
        if (mounted.current) setScanning(false);
      });
  }, [adoptDashboard]);

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
      void adoptDashboard(payload as Dashboard).catch((e: unknown) => {
        if (mounted.current) setError(String(e));
      });
    });

    attach('router-context-changed', (payload) => {
      const environment = payload as RouterEnvironment;
      if (!mounted.current || !environment || environment.generation <= generation.current) return;
      const initial = generation.current === 0;
      generation.current = environment.generation;
      setDashboard((current) => current && current.routerGeneration < environment.generation ? null : current);
      if (!initial) setError(environment.reason ?? 'The network or selected router changed. Run a new scan.');
    });

    attach('tray-scan-requested', () => rescan());

    return () => {
      cancelled = true;
      unlisteners.forEach((fn) => fn());
    };
  }, [rescan, adoptDashboard]);

  return { dashboard, scanning, error, rescan };
}
