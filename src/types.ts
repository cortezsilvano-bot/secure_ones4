// ---------------------------------------------------------------------------
// Hand-written projections of the Rust types in src-tauri/src. The backend is
// the source of truth; when a struct changes there, change it here too.
// ---------------------------------------------------------------------------

/**
 * A fact the backend either established, or explicitly did not.
 *
 * Counterpart of `Known<T>` in src-tauri/src/security/known.rs. There is no way
 * to read the value without acknowledging it might not exist, which is the
 * whole point: rendering an unknown as "Safe" is the bug this type prevents.
 */
export type Known<T> =
  | { state: 'known'; data: T }
  | { state: 'not_scanned' }
  | { state: 'permission_required'; data: string }
  | { state: 'unsupported'; data: string }
  | { state: 'unavailable'; data: string };

export function isKnown<T>(k: Known<T>): k is { state: 'known'; data: T } {
  return k.state === 'known';
}

export function knownValue<T>(k: Known<T>): T | null {
  return k.state === 'known' ? k.data : null;
}

/** Short label for a not-determined state, for compact tiles. */
export function unknownLabel<T>(k: Known<T>): string {
  switch (k.state) {
    case 'not_scanned':
      return 'Not scanned';
    case 'permission_required':
      return 'Permission required';
    case 'unsupported':
      return 'Not supported';
    case 'unavailable':
      return 'Unable to determine';
    default:
      return 'Unknown';
  }
}

/** The backend's own explanation, for detail views. */
export function unknownDetail<T>(k: Known<T>): string {
  switch (k.state) {
    case 'not_scanned':
      return 'This check has not run yet.';
    case 'permission_required':
    case 'unsupported':
    case 'unavailable':
      return k.data;
    default:
      return '';
  }
}

// --- Severity ---------------------------------------------------------------

/** Mirrors `Severity` in src-tauri/src/findings/mod.rs. */
export type Severity = 'Safe' | 'Attention' | 'Warning' | 'Critical';

/**
 * What a badge can display. `Unknown` exists only in the UI: the backend never
 * calls something Unknown, it returns a non-`known` state and the UI renders
 * that as Unknown.
 */
export type DisplaySeverity = Severity | 'Unknown';

export type Confidence = 'confirmed' | 'likely' | 'potential';
export type FixRisk = 'safe' | 'caution' | 'manual';
export type FindingStatus = 'open' | 'resolved' | 'dismissed' | 'allowlisted';

/** Mirrors `Action` in src-tauri/src/findings/mod.rs. */
export type FixAction =
  | 'enable_removable_drive_scanning'
  | 'enable_archive_scanning'
  | 'enable_script_scanning'
  | 'enable_pua_blocking'
  | 'run_quick_scan'
  | 'update_definitions';

export interface FixResult {
  succeeded: boolean;
  detail: string;
  undoHint: string | null;
  /** True when the change would work with administrator rights. */
  needsAdmin: boolean;
}

/** Mirrors `Finding` in src-tauri/src/findings/mod.rs. */
export interface Finding {
  id: string;
  ruleId: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  whatHappened: string;
  whyItMatters: string;
  affectedAsset: string | null;
  remediation: string | null;
  /** The fix SENTRY can apply. Null means you have to do it yourself. */
  fixAction: FixAction | null;
  autoFix: boolean;
  autoFixRisk: FixRisk | null;
  evidence: string[];
  references: string[];
  status: FindingStatus;
  source: string;
}

// --- Score ------------------------------------------------------------------

export type Coverage = 'complete' | 'partial' | 'incomplete';

export interface ScoreLine {
  delta: number;
  reason: string;
  findingId: string;
  severity: Severity;
}

/** Mirrors `SecurityScore` in src-tauri/src/security/score.rs. */
export interface SecurityScore {
  /** Null when coverage is too thin for a number to mean anything. */
  score: number | null;
  coverage: Coverage;
  gaps: string[];
  lines: ScoreLine[];
  modulesReporting: number;
  modulesTotal: number;
}

// --- Dashboard --------------------------------------------------------------

export interface TileVerdict {
  severity: Severity;
  message: string;
}

export interface OverviewTile {
  id: string;
  title: string;
  category: string;
  status: Known<TileVerdict>;
  lastChecked: string | null;
}

/** Mirrors `Dashboard` in src-tauri/src/engine/mod.rs. */
export interface Dashboard {
  score: SecurityScore;
  tiles: OverviewTile[];
  findings: Finding[];
  scannedAt: string;
  /** Null when the software inventory could not be read. */
  programsInstalled: number | null;
}

// --- Vulnerability feeds ----------------------------------------------------

/** Mirrors `FeedStatus` in src-tauri/src/ipc/vulnerabilities.rs. */
export interface FeedStatus {
  feed: string;
  lastSuccess: string | null;
  /** Null means the feed has never been refreshed successfully. */
  ageDays: number | null;
  recordCount: number;
  version: string | null;
  lastError: string | null;
}

export interface RefreshSummary {
  kevEntries: number;
  productsLookedUp: number;
  productsSkipped: number;
  cvesCached: number;
  epssScored: number;
  /** Partial success is normal; these name what did not refresh. */
  problems: string[];
}

/** Emitted as `vuln-refresh-progress` while a refresh runs. */
export interface RefreshProgress {
  stage: string;
  completed: number;
  total: number;
  detail: string;
}

// --- Devices ----------------------------------------------------------------

export type Trust = 'none' | 'trusted' | 'flagged';
export type DeviceKind = 'router' | 'thiscomputer' | 'unknown';

/** Mirrors `DeviceRow` in src-tauri/src/ipc/devices.rs. */
export interface DeviceRow {
  id: string;
  /** Best available name: user's label, hostname, manufacturer, then address. */
  label: string;
  mac: string | null;
  ip: string | null;
  vendor: string | null;
  hostname: string | null;
  displayName: string | null;
  deviceType: DeviceKind;
  trust: Trust;
  /** Phones randomise their MAC, so no manufacturer can be looked up. */
  macIsRandom: boolean;
  isGateway: boolean;
  isSelf: boolean;
  firstSeen: string | null;
  lastSeen: string;
  /** False for a device known from an earlier scan that did not answer. */
  currentlyVisible: boolean;
}

export interface DeviceList {
  devices: DeviceRow[];
  /** How many of them answered during this scan. */
  visibleNow: number;
  vendorRegistryAvailable: boolean;
  evidence: string[];
}

export interface SweepSummary {
  addressesProbed: number;
  devicesFound: number;
  subnet: string | null;
  durationMs: number;
  /** False when cancelled or skipped: a short list is not the whole network. */
  conclusive: boolean;
  skippedReason: string | null;
  evidence: string[];
}

// --- Router -----------------------------------------------------------------

/** Mirrors `PortMapping` in src-tauri/src/collectors/network/ssdp.rs. */
export interface PortMapping {
  externalPort: number;
  internalPort: number;
  internalClient: string;
  protocol: string;
  description: string;
  enabled: boolean;
}

export interface AdminPort {
  port: number;
  service: string | null;
  /** True when the admin password would cross the network unencrypted. */
  isPlaintext: boolean;
}

/** Mirrors `RouterFacts` in src-tauri/src/collectors/network/router.rs. */
export interface RouterFacts {
  gateway: string | null;
  manufacturer: string | null;
  model: string | null;
  firmware: string | null;
  upnpEnabled: boolean;
  /** Null means the list could not be read -- not that there are none. */
  portForwards: PortMapping[] | null;
  forwardsUnavailableReason: string | null;
  adminPorts: AdminPort[];
  /** Facts that would need the router's own password to establish. */
  requiresRouterLogin: string[];
  /** Facts that cannot be established from inside the network at all. */
  cannotDetermine: string[];
  evidence: string[];
  collectedAt: string;
}

// --- Timeline, history and privacy ------------------------------------------

export interface TimelineEntry {
  occurredAt: string;
  kind: 'scan_completed' | 'finding_opened' | 'finding_resolved' | 'device_seen';
  title: string;
  detail: string | null;
  severity: string | null;
}

export interface ScanRecord {
  startedAt: string;
  status: string;
  /** Null where coverage was too thin for a score to mean anything. */
  score: number | null;
  modulesReporting: number | null;
  modulesTotal: number | null;
  findings: number | null;
}

export interface StoredData {
  label: string;
  count: number;
  description: string;
}

export interface OutboundEndpoint {
  name: string;
  url: string;
  sends: string;
  lastContacted: string | null;
}

/** Mirrors `PrivacyReport` in src-tauri/src/ipc/history.rs. */
export interface PrivacyReport {
  databasePath: string;
  databaseBytes: number;
  stored: StoredData[];
  endpoints: OutboundEndpoint[];
  neverDoes: string[];
}

// --- Settings ---------------------------------------------------------------

/** Mirrors `SettingsView` in src-tauri/src/ipc/settings.rs. */
export interface SettingsView {
  /** Whether a key is stored. The key itself never returns to the UI. */
  hasNvdApiKey: boolean;
  scanOnStart: boolean;
}

export interface DeletionSummary {
  tablesCleared: string[];
  rowsDeleted: number;
}

// --- Raw collector payloads -------------------------------------------------

/** Mirrors `DefenderFacts` in src-tauri/src/collectors/defender.rs. */
export interface DefenderFacts {
  amServiceEnabled: boolean | null;
  antivirusEnabled: boolean | null;
  antispywareEnabled: boolean | null;
  realTimeProtectionEnabled: boolean | null;
  behaviorMonitorEnabled: boolean | null;
  onAccessProtectionEnabled: boolean | null;
  ioavProtectionEnabled: boolean | null;
  isTamperProtected: boolean | null;
  amRunningMode: string | null;
  antivirusSignatureVersion: string | null;
  antivirusSignatureLastUpdated: string | null;
  antivirusSignatureAgeDays: number | null;
  quickScanAgeDays: number | null;
  fullScanAgeDays: number | null;
  evidence: string[];
  collectedAt: string;
}

// --- Formatting helpers -----------------------------------------------------

/** "Today, 8:32 AM" / "Yesterday, 4:10 PM" / "17 Sep, 8:32 AM". */
export function formatTimestamp(iso: string | null): string {
  if (!iso) return 'Never';

  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'Unknown';

  const time = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  const today = new Date();
  const sameDay = (a: Date, b: Date) => a.toDateString() === b.toDateString();

  if (sameDay(d, today)) return `Today, ${time}`;

  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  if (sameDay(d, yesterday)) return `Yesterday, ${time}`;

  return `${d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })}, ${time}`;
}
