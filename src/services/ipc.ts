// The only place the UI talks to the backend.
//
// Every call is a named, typed command. There is no generic pass-through, so
// the set of things the frontend can ask the OS to do is exactly the set of
// functions exported below.

import { invoke } from '@tauri-apps/api/core';

import type {
  Dashboard,
  DefenderFacts,
  DeletionSummary,
  DeviceList,
  FeedStatus,
  FixAction,
  FixResult,
  HelpTarget,
  Known,
  PrivacyReport,
  RefreshSummary,
  RouterReport,
  SavedRouterReport,
  RouterEnvironment,
  ScanRecord,
  SettingsView,
  SweepSummary,
  TimelineEntry,
  Trust,
} from '../types';

/** True when running inside the Tauri shell rather than a bare browser tab. */
export function hasBackend(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

const NO_BACKEND =
  'The security engine is not running. This window is a plain browser tab; ' +
  'launch the SENTRY desktop app to collect real data.';

/**
 * Invoke a command that returns a `Known<T>`, degrading to an explicit
 * `unavailable` rather than throwing. A failed call is a coverage gap the user
 * should see, not an exception that silently blanks a panel.
 */
async function callKnown<T>(command: string, args?: Record<string, unknown>): Promise<Known<T>> {
  if (!hasBackend()) return { state: 'unavailable', data: NO_BACKEND };

  try {
    return await invoke<Known<T>>(command, args);
  } catch (e) {
    return {
      state: 'unavailable',
      data: `The backend rejected "${command}": ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

// --- Scanning ---------------------------------------------------------------

/**
 * Run a scan and return the whole dashboard.
 *
 * Throws only when the backend is absent or the scan task itself died. A module
 * that failed is not an error here -- it arrives inside the payload as that
 * module's own not-determined state.
 */
export async function runScan(): Promise<Dashboard> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<Dashboard>('run_scan');
}

// --- Individual collectors --------------------------------------------------

export function getDefenderStatus(): Promise<Known<DefenderFacts>> {
  return callKnown<DefenderFacts>('get_defender_status');
}

// --- Vulnerability feeds ----------------------------------------------------

/** How current each cached feed is. Returns an empty list without a backend. */
export async function getFeedStatus(): Promise<FeedStatus[]> {
  if (!hasBackend()) return [];
  try {
    return await invoke<FeedStatus[]>('get_feed_status');
  } catch {
    return [];
  }
}

/**
 * Download the latest vulnerability data.
 *
 * Refreshes public security data over the internet. Slow by design: NVD
 * permits one request every six seconds, so this takes minutes on a machine
 * with a lot installed. Progress arrives as `vuln-refresh-progress` events.
 */
export async function refreshVulnerabilityData(): Promise<RefreshSummary> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<RefreshSummary>('refresh_vulnerability_data');
}

export async function cancelVulnerabilityRefresh(): Promise<void> {
  if (!hasBackend()) return;
  try {
    await invoke('cancel_vulnerability_refresh');
  } catch {
    // Cancelling a refresh that already finished is not an error.
  }
}

// --- Devices ----------------------------------------------------------------

/** The current device list, read passively from Windows' own neighbour cache. */
export function getDevices(): Promise<Known<DeviceList>> {
  return callKnown<DeviceList>('get_devices');
}

/**
 * Actively sweep the local network.
 *
 * An explicit active LAN sweep. Router inspection also generates local traffic.
 */
export async function discoverDevices(): Promise<SweepSummary> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<SweepSummary>('discover_devices');
}

export async function cancelDeviceDiscovery(): Promise<void> {
  if (!hasBackend()) return;
  try {
    await invoke('cancel_device_discovery');
  } catch {
    // Cancelling a sweep that already finished is not an error.
  }
}

export async function setDeviceTrust(deviceId: string, trust: Trust): Promise<void> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  await invoke('set_device_trust', { deviceId, trust });
}

export async function renameDevice(deviceId: string, name: string): Promise<void> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  await invoke('rename_device', { deviceId, name });
}

// --- Router -----------------------------------------------------------------

/** What SENTRY established about the router, and what it could not. */
export function getRouterStatus(generation: number): Promise<Known<RouterReport>> {
  return callKnown<RouterReport>('get_router_status', { generation });
}

export async function getRouterHistory(): Promise<SavedRouterReport[]> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<SavedRouterReport[]>('get_router_history', { limit: 20 });
}

/** Only call after the user confirms active checks for this exact generation. */
export function scanRouter(generation: number): Promise<Known<RouterReport>> {
  return callKnown<RouterReport>('scan_router', { generation, confirmed: true });
}

export interface AsusLoginOptions {
  username: string;
  password: string;
  httpsPort: number;
  certificatePem: string;
  supportRegion: 'unknown' | 'eu' | 'other';
}

/** One explicit login; never persist these arguments or reuse them for refresh. */
export async function scanAsusRouter(generation: number, options: AsusLoginOptions): Promise<Known<RouterReport>> {
  if (!hasBackend()) return { state: 'unavailable', data: NO_BACKEND };
  try {
    return await invoke<Known<RouterReport>>('scan_asus_router', { generation, confirmed: true, options });
  } catch {
    // Do not display an IPC exception that might contain rejected secret arguments.
    return { state: 'unavailable', data: 'The ASUS scan command could not complete. Credentials were not saved.' };
  }
}

export async function getRouterEnvironment(): Promise<RouterEnvironment> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<RouterEnvironment>('get_router_environment');
}

export async function selectRouter(targetId: string, generation: number): Promise<RouterEnvironment> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<RouterEnvironment>('select_router', { targetId, generation });
}

export async function cancelRouterScan(generation: number): Promise<void> {
  if (!hasBackend()) return;
  await invoke('cancel_router_scan', { generation });
}

// --- Timeline, history and privacy ------------------------------------------

/** Plain-typed call for commands that return a value rather than a `Known`. */
async function callPlain<T>(command: string, fallback: T, args?: Record<string, unknown>): Promise<T> {
  if (!hasBackend()) return fallback;
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    console.error(`${command} failed`, e);
    return fallback;
  }
}

export function getTimeline(limit = 100): Promise<TimelineEntry[]> {
  return callPlain<TimelineEntry[]>('get_timeline', [], { limit });
}

export function getScanHistory(limit = 60): Promise<ScanRecord[]> {
  return callPlain<ScanRecord[]>('get_scan_history', [], { limit });
}

export async function getPrivacyReport(): Promise<PrivacyReport | null> {
  return callPlain<PrivacyReport | null>('get_privacy_report', null);
}

// --- Settings ---------------------------------------------------------------

export function getSettings(): Promise<SettingsView> {
  return callPlain<SettingsView>('get_settings', { hasNvdApiKey: false, scanOnStart: false });
}

/** Pass null to remove the stored key. */
export async function setNvdApiKey(key: string | null): Promise<void> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  await invoke('set_nvd_api_key', { key });
}

export async function setScanOnStart(enabled: boolean): Promise<void> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  await invoke('set_scan_on_start', { enabled });
}

/** Clears what SENTRY learned about this PC; keeps the downloaded public feeds. */
export async function deleteLocalData(): Promise<DeletionSummary> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<DeletionSummary>('delete_local_data');
}

export async function deleteEverything(): Promise<DeletionSummary> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<DeletionSummary>('delete_everything');
}

// --- Applying fixes ---------------------------------------------------------

/**
 * Apply one fix.
 *
 * `action` is a value from a fixed set the backend defines; there is no way to
 * ask it to run something arbitrary. A fix needing administrator rights is
 * refused with an explanation rather than attempted and failed.
 */
export async function applyFix(action: FixAction, findingId?: string): Promise<FixResult> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  return invoke<FixResult>('apply_fix', { action, findingId, confirmed: true });
}

/**
 * Open the Windows page where a manual recommendation is carried out.
 *
 * Changes nothing. `target` is a value from a fixed set, and the backend turns
 * it into a constant; the page opened is never built from a string that came
 * from here.
 */
export async function openHelpTarget(target: HelpTarget): Promise<void> {
  if (!hasBackend()) throw new Error(NO_BACKEND);
  await invoke('open_help_target', { target });
}
