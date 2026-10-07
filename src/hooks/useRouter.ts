import { useCallback, useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { cancelRouterScan, getRouterEnvironment, getRouterStatus, hasBackend, scanRouter, scanAsusRouter, selectRouter } from '../services/ipc';
import type { AsusLoginOptions } from '../services/ipc';
import type { Known, RouterEnvironment, RouterReport } from '../types';

export function useRouter() {
  const [environment, setEnvironment] = useState<RouterEnvironment | null>(null);
  const [status, setStatus] = useState<Known<RouterReport>>({ state: 'not_scanned' });
  const [loading, setLoading] = useState(false);
  const mounted = useRef(false);
  const generation = useRef(0);
  const operation = useRef(0);

  const adoptEnvironment = useCallback((next: RouterEnvironment) => {
    if (!mounted.current || next.generation < generation.current) return false;
    if (next.generation > generation.current && generation.current !== 0) {
      operation.current += 1;
      setLoading(false);
      setStatus({ state: 'unavailable', data: next.reason ?? 'The network or selected router changed. Scan the current router to refresh results.' });
    }
    generation.current = next.generation;
    setEnvironment(next);
    return true;
  }, []);

  const inspect = useCallback(async (confirmedGeneration?: number, login?: AsusLoginOptions) => {
    const request = ++operation.current;
    setLoading(true);
    try {
      const next = await getRouterEnvironment();
      if (!mounted.current || operation.current !== request || next.generation < generation.current) return;
      generation.current = next.generation;
      setEnvironment({ ...next, reason: next.selectedId ? null : next.reason });
      setStatus({ state: 'not_scanned' });
      if (confirmedGeneration !== undefined && confirmedGeneration !== next.generation) {
        setStatus({ state: 'permission_required', data: 'The router or network changed. Review the selected router before confirming another scan.' });
        return;
      }
      const result = confirmedGeneration === undefined
        ? await getRouterStatus(next.generation)
        : login ? await scanAsusRouter(confirmedGeneration, login) : await scanRouter(confirmedGeneration);
      if (!mounted.current || operation.current !== request || generation.current !== next.generation) return;
      if (result.state === 'known' && result.data.facts.target?.networkGeneration !== next.generation) return;
      setStatus(result);
    } catch (error) {
      if (mounted.current && operation.current === request) {
        setStatus({ state: 'unavailable', data: String(error) });
      }
    } finally {
      if (login) { login.password = ''; login.username = ''; login.certificatePem = ''; }
      if (mounted.current && operation.current === request) setLoading(false);
    }
  }, []);

  const select = useCallback(async (targetId: string) => {
    try {
      const next = await selectRouter(targetId, generation.current);
      if (adoptEnvironment(next)) void inspect();
    } catch (error) {
      if (mounted.current) setStatus({ state: 'unavailable', data: String(error) });
    }
  }, [adoptEnvironment, inspect]);

  const cancel = useCallback(async () => {
    // Invalidate the frontend request immediately, including one still awaiting IPC startup.
    operation.current += 1;
    setLoading(false);
    setStatus({ state: 'unavailable', data: 'Router scan cancelled. Unfinished checks were not evaluated.' });
    try { await cancelRouterScan(generation.current); }
    catch (error) {
      if (mounted.current) setStatus({ state: 'unavailable', data: `The cancellation request failed: ${String(error)}` });
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    let dispose: (() => void) | undefined;
    let disposed = false;
    const start = async () => {
      if (hasBackend()) {
        dispose = await listen<RouterEnvironment>('router-context-changed', (event) => adoptEnvironment(event.payload));
        if (disposed) { dispose(); return; }
      }
      void inspect();
    };
    void start().catch((error) => {
      if (mounted.current) setStatus({ state: 'unavailable', data: String(error) });
    });
    return () => { disposed = true; mounted.current = false; operation.current += 1; dispose?.(); };
  }, [adoptEnvironment, inspect]);

  return { environment, status, loading, inspect, cancel, select };
}
